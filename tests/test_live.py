"""Live detection loop: replay end to end, batching, SOC outage, response safety, shedding."""

import errno
import json
import logging
import os
import re
import threading
import time
from dataclasses import fields
from datetime import UTC, datetime, timedelta

import numpy as np
import pandas as pd
import pytest
from pcap_factory import CLIENT, T0, tcp_session, udp_exchange, write_pcap
from scapy.layers.inet import IP, TCP
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from idps.capture import flows_from_pcap
from idps.capture.flow import Flow
from idps.config import Settings
from idps.detect.bundle import Bundle, load_bundle, save_bundle
from idps.features import FEATURE_COLUMNS, MODEL_FEATURES, extraction_meta
from idps.live.__main__ import main
from idps.live.config import LiveSettings
from idps.live.detector import LiveDetector
from idps.live.metrics import Metrics
from idps.live.sinks import JsonlSink, SocSink
from idps.respond.engine import ResponseEngine
from idps.soc_client import MAX_BATCH, Outbox, Prediction, SocError, SocRejectedError
from soc.api.routes.alerts import AlertBatch

META = extraction_meta("nfstream", 120, 120)
ATTACKER = "10.10.1.10"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in [n for n in os.environ if n.startswith("IDPS_")]:
        monkeypatch.delenv(name)


# --- A tiny model: dst_port 80 is the attack, everything else is benign ---------------------------

def _train(meta) -> Bundle:
    rng = np.random.default_rng(0)
    rows, labels = [], []
    for label, ports in (("BENIGN", (53, 443, 8080, 0)), ("DDoS", (80,))):
        for _ in range(120):
            r = dict.fromkeys(MODEL_FEATURES, 0.0)
            r.update(dst_port=float(rng.choice(ports)), protocol=6.0,
                     fwd_packets=float(rng.integers(1, 60)), fwd_bytes=float(rng.integers(60, 5000)))
            rows.append(r)
            labels.append(label)
    X, enc = pd.DataFrame(rows)[MODEL_FEATURES], LabelEncoder().fit(labels)
    model = XGBClassifier(n_estimators=20, max_depth=3, random_state=0)
    model.fit(X, enc.transform(labels))
    return Bundle("xgboost", model, enc, list(MODEL_FEATURES), meta, {"mode": "test"}, {})


@pytest.fixture(scope="module")
def model_file(tmp_path_factory):
    return save_bundle(_train(META), tmp_path_factory.mktemp("model") / "tiny.joblib")


@pytest.fixture(scope="module")
def bundle(model_file):
    return load_bundle(model_file, live_meta=META, live_columns=FEATURE_COLUMNS)


# --- Traffic ---------------------------------------------------------------------------------------

def attack_packets(src=CLIENT, n=6, t0=T0):
    """n TCP sessions to port 80 from `src`, one second apart (n distinct flows)."""
    packets = []
    for i in range(n):
        for p in tcp_session(sport=40000 + i, dport=80, t0=t0 + i):
            if p[IP].src == CLIENT:
                p[IP].src = src
            if p[IP].dst == CLIENT:
                p[IP].dst = src
            del p[IP].chksum, p[TCP].chksum
            packets.append(p)
    return packets


def make_flow(dst_port=80, i=0, end_ms=None) -> Flow:
    values = dict.fromkeys((f.name for f in fields(Flow)), 0)
    start = 1_700_000_000_000 + i * 10
    values.update(src_ip=ATTACKER, dst_ip="10.10.2.10", src_port=40000 + i, dst_port=dst_port,
                  protocol=6, start_ms=start, end_ms=end_ms or start + 5, fwd_packets=20,
                  fwd_bytes=1200)
    return Flow(**values)


class ListSink:
    def __init__(self):
        self.alerts = []
        self.blocks = []

    def submit_blocks(self, events):
        self.blocks.extend(events)

    def submit(self, alerts):
        self.alerts.extend(alerts)

    def pending(self):
        return 0

    def checkpoint(self):
        pass

    def close(self):
        pass


class FakeBlocker:
    def __init__(self):
        self.ensured, self.blocked = 0, []

    def ensure_ruleset(self):
        self.ensured += 1

    def block(self, ip, ttl_seconds):
        self.blocked.append(ip)

    def unblock(self, ip):
        pass


def detector(bundle, sink, *, engine=None, live=False, outbox_capacity=None, **overrides):
    overrides.setdefault("metrics_seconds", 3600.0)
    engine = engine or ResponseEngine(Settings(dry_run=True), blocker=FakeBlocker())
    return LiveDetector(bundle, engine, sink, LiveSettings(**overrides), META, live=live,
                        outbox_capacity=outbox_capacity)


def wait_for(condition, timeout=5.0):
    """Poll instead of sleeping a fixed time."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return
        time.sleep(0.01)
    raise AssertionError("condition not met in time")


def quiet_engine():
    """Dry-run engine that allowlists the attacker: no block-driven explanations in the way."""
    return ResponseEngine(Settings(dry_run=True, allowlist=["10.10.1.0/24"]), blocker=FakeBlocker())


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- Replay end to end (CLI) -----------------------------------------------------------------------

def test_replay_writes_alerts_with_explanations_and_the_soc_accepts_them(model_file, tmp_path, caplog):
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=3) + udp_exchange())
    out = tmp_path / "alerts.jsonl"
    with caplog.at_level(logging.INFO, logger="idps.live"):
        code = main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out)])
    assert code == 0
    alerts = lines(out)
    assert len(alerts) == 3  # the DNS exchange is benign
    for a in alerts:
        assert a["predicted_class"] == "DDoS" and a["dst_port"] == 80
        top = a["explanation"]["top_features"]
        assert len(top) == 5 and a["explanation"]["method"] == "shap"
        assert top[0]["feature"] == "dst_port"
    AlertBatch.model_validate({"alerts": alerts})  # exactly what POST /ingest/alerts accepts
    final = [json.loads(r.message) for r in caplog.records if '"event": "metrics"' in r.message][-1]
    assert final["flows"] == 4 and final["alerts"] == 3 and final["explained"] == 3
    assert final["shap_ms_per_alert"]["n"] == 3
    assert final["latency_flow_end_to_alert_s"]["n"] == 0  # replay: no latency recorded
    assert (out.stat().st_mode & 0o777) == 0o600


def test_benign_traffic_produces_no_alerts(model_file, tmp_path):
    pcap = write_pcap(tmp_path / "benign.pcap", udp_exchange())
    out = tmp_path / "alerts.jsonl"
    assert main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out)]) == 0
    assert lines(out) == []


def test_max_flows_stops_early(model_file, tmp_path):
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=6))
    out = tmp_path / "alerts.jsonl"
    assert main(["--pcap", str(pcap), "--model", str(model_file), "--alerts-file", str(out),
                 "--max-flows", "2"]) == 0
    assert len(lines(out)) == 2


# --- Fail closed -----------------------------------------------------------------------------------

def test_a_model_trained_with_another_extractor_refuses_to_start(tmp_path, capsys):
    path = save_bundle(_train(extraction_meta("scapy", 60, 120)), tmp_path / "scapy.joblib")
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    out = tmp_path / "alerts.jsonl"
    code = main(["--pcap", str(pcap), "--model", str(path), "--alerts-file", str(out)])
    assert code == 2
    err = capsys.readouterr().err
    assert "differ" in err and "refusing to run without a model" in err
    assert not out.exists()


def test_missing_or_tampered_model_refuses_to_start(model_file, tmp_path, capsys):
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    out = tmp_path / "alerts.jsonl"
    argv = ["--pcap", str(pcap), "--alerts-file", str(out)]
    assert main([*argv, "--model", str(tmp_path / "nope.joblib")]) == 2
    tampered = tmp_path / "tampered.joblib"
    tampered.write_bytes(model_file.read_bytes() + b"x")
    (tmp_path / "tampered.joblib.sha256").write_text(model_file.with_name(
        model_file.name + ".sha256").read_text())
    assert main([*argv, "--model", str(tampered)]) == 2
    assert "cannot load the model" in capsys.readouterr().err
    assert not out.exists()


def test_a_half_configured_soc_is_an_error_not_a_silent_fallback(model_file, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IDPS_SOC_URL", "https://soc.example")
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    assert main(["--pcap", str(pcap), "--model", str(model_file),
                 "--alerts-file", str(tmp_path / "a.jsonl")]) == 2
    assert "IDPS_SOC_SENSOR_TOKEN" in capsys.readouterr().err


def test_a_plain_http_soc_is_refused(model_file, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IDPS_SOC_URL", "http://soc.example")
    monkeypatch.setenv("IDPS_SOC_TOKEN", "idps_sensor_x")  # the short alias works too
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    assert main(["--pcap", str(pcap), "--model", str(model_file)]) == 2
    assert "https" in capsys.readouterr().err


# --- SOC down / SOC unset --------------------------------------------------------------------------

def test_soc_down_keeps_alerts_in_the_outbox_and_detection_continues(bundle, tmp_path):
    attempts = []

    def down(batch):
        attempts.append(len(batch))
        raise SocError("cannot reach the SOC")

    metrics = Metrics()
    outbox = Outbox(tmp_path / "outbox.json", max_alerts=1000, merge=True)
    sink = SocSink(down, outbox, metrics, retry_seconds=0.01, max_retry_seconds=0.02)
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=5))
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker)
    det = LiveDetector(bundle, engine, sink, LiveSettings(batch_size=2, metrics_seconds=3600),
                       META, metrics=metrics, live=False, outbox_capacity=1000)
    det.run(flows_from_pcap(pcap))
    assert metrics.counts["flows"] == 5 and metrics.counts["alerts"] == 5
    assert blocker.blocked == [CLIENT]  # blocking did not wait for, or depend on, the SOC
    wait_for(lambda: len(attempts) >= 2)  # the sender retried in the background
    assert sink.pending() == 5 and metrics.counts["alerts_sent"] == 0
    sink.close()
    saved = Outbox(tmp_path / "outbox.json")
    assert len(saved) == 5  # kept on disk for the next run

    # The SOC comes back: a new run sends what is waiting.
    received = []
    sink2 = SocSink(lambda batch: received.extend(batch) or {}, Outbox(tmp_path / "outbox.json"),
                    Metrics(), retry_seconds=0.01)
    wait_for(lambda: len(received) >= 5)
    sink2.close()
    assert len(received) == 5 and len(Outbox(tmp_path / "outbox.json")) == 0


def test_a_batch_the_soc_refuses_is_dropped_not_retried_forever(tmp_path):
    metrics, calls = Metrics(), []

    def refuse(batch):
        calls.append(batch)
        raise SocRejectedError("HTTP 422")

    sink = SocSink(refuse, Outbox(None), metrics, start=False)
    sink.submit([{"a": 1}, {"a": 2}])
    assert sink.drain() is True
    assert len(calls) == 1 and metrics.counts["alerts_rejected"] == 2 and sink.pending() == 0


def test_posts_never_exceed_the_soc_batch_limit(tmp_path):
    sizes = []
    sink = SocSink(lambda b: sizes.append(len(b)) or {}, Outbox(None, merge=True), Metrics(),
                   start=False)
    sink.submit([{"i": i} for i in range(MAX_BATCH + 120)])
    sink.submit([{"i": i} for i in range(30)])  # tops up the partial batch
    assert sink.drain()
    assert sizes == [MAX_BATCH, 150] and max(sizes) <= MAX_BATCH


def test_without_a_soc_alerts_go_to_the_jsonl_file(bundle, tmp_path):
    metrics = Metrics()
    sink = JsonlSink(tmp_path / "sub" / "alerts.jsonl", metrics)
    detector(bundle, sink).run(iter([make_flow(80, i) for i in range(3)] + [make_flow(443, 9)]))
    sink.close()
    assert [a["src_port"] for a in lines(tmp_path / "sub" / "alerts.jsonl")] == [40000, 40001, 40002]


def test_a_failing_alert_file_never_stops_detection(bundle, tmp_path):
    metrics = Metrics()
    sink = JsonlSink(tmp_path / "alerts.jsonl", metrics)
    sink._file.close()  # simulate the disk going away
    det = LiveDetector(bundle, ResponseEngine(Settings(), blocker=FakeBlocker()), sink,
                       LiveSettings(batch_size=2), META, metrics=metrics, live=False)
    det.run(iter([make_flow(80, i) for i in range(4)]))
    assert metrics.counts["flows"] == 4 and metrics.counts["alerts_dropped"] == 4


# --- Response engine -------------------------------------------------------------------------------

def test_dry_run_never_calls_the_blocker(bundle):
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=True), blocker=blocker)
    det = detector(bundle, ListSink(), engine=engine)
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert det.metrics.counts["would_block"] == 1 and det.metrics.counts["blocked"] == 0
    assert blocker.blocked == [] and blocker.ensured == 0


def test_real_blocking_blocks_the_attacker_once(bundle):
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker)
    det = detector(bundle, ListSink(), engine=engine)
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert blocker.blocked == [ATTACKER] and det.metrics.counts["blocked"] == 1


def test_an_allowlisted_source_is_never_blocked_but_is_still_alerted(bundle):
    blocker, sink = FakeBlocker(), ListSink()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.0/24"]), blocker=blocker)
    det = detector(bundle, sink, engine=engine)
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert blocker.blocked == [] and len(sink.alerts) == 8
    assert det.metrics.counts["blocked"] == 0


def test_the_alert_floor_does_not_change_blocking(bundle):
    blocker, sink = FakeBlocker(), ListSink()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=["10.10.1.1"]), blocker=blocker)
    det = detector(bundle, sink, engine=engine, min_alert_confidence=1.0)  # nothing reaches 1.0
    det.run(iter([make_flow(80, i) for i in range(8)]))
    assert sink.alerts == [] and det.metrics.counts["below_floor"] == 8
    assert blocker.blocked == [ATTACKER]


def test_a_crashing_response_engine_does_not_stop_detection(bundle):
    class Broken:
        dry_run = True

        def handle(self, detection):
            raise RuntimeError("boom")

    sink = ListSink()
    det = LiveDetector(bundle, Broken(), sink, LiveSettings(), META, live=False)
    det.run(iter([make_flow(80, i) for i in range(3)]))
    assert len(sink.alerts) == 3 and det.metrics.counts["response_errors"] == 3


# --- Batching ----------------------------------------------------------------------------------------

def spy_batches(det):
    sizes, real = [], det.handle_batch

    def wrapper(flows):
        sizes.append(len(flows))
        return real(flows)

    det.handle_batch = wrapper
    return sizes


def test_batches_flush_on_size(bundle):
    det = detector(bundle, ListSink(), batch_size=3, batch_seconds=60.0)
    sizes = spy_batches(det)
    det.run(iter([make_flow(80, i) for i in range(7)]))
    assert sizes == [3, 3, 1]  # two full batches, then the last one at the end


def test_batches_flush_on_time_even_when_no_more_flows_arrive(bundle):
    release, sink = threading.Event(), ListSink()

    def quiet_link():
        yield make_flow(80, 0)
        yield make_flow(80, 1)
        release.wait(10)  # nothing else arrives, like an idle interface

    det = detector(bundle, sink, batch_size=100, batch_seconds=0.1)
    sizes = spy_batches(det)
    worker = threading.Thread(target=det.run, args=(quiet_link(),))
    worker.start()
    deadline = time.time() + 5
    while not sink.alerts and time.time() < deadline:
        time.sleep(0.02)
    assert sizes == [2] and len(sink.alerts) == 2  # flushed by the timer, source still open
    release.set()
    worker.join(5)
    assert not worker.is_alive()


def test_stopping_flushes_the_last_batch(bundle):
    release, stop, sink = threading.Event(), threading.Event(), ListSink()

    def source():
        yield from (make_flow(80, i) for i in range(3))
        release.wait(10)

    det = detector(bundle, sink, batch_size=100, batch_seconds=60.0)
    worker = threading.Thread(target=det.run, args=(source(), stop))
    worker.start()
    time.sleep(0.5)
    assert sink.alerts == []  # still waiting for a full batch
    stop.set()  # what SIGTERM does
    worker.join(5)
    assert not worker.is_alive() and len(sink.alerts) == 3
    release.set()


def test_a_failing_capture_flushes_what_it_read_and_then_raises(bundle):
    def source():
        yield make_flow(80, 0)
        yield make_flow(80, 1)
        raise OSError("interface went down")

    sink = ListSink()
    with pytest.raises(OSError, match="interface went down"):
        detector(bundle, sink, batch_size=100, batch_seconds=60.0).run(source())
    assert len(sink.alerts) == 2


# --- Shedding and bounds -----------------------------------------------------------------------------

def test_explanations_are_shed_before_alerts_and_counted(bundle):
    sink = ListSink()
    det = detector(bundle, sink, engine=quiet_engine(), batch_size=10, max_explanations_per_batch=2)
    det.run(iter([make_flow(80, i) for i in range(10)]))
    assert len(sink.alerts) == 10  # every alert still goes out
    explained = [a for a in sink.alerts if a["explanation"]["top_features"]]
    assert len(explained) == 2
    assert det.metrics.counts["explanations_shed"] == 8 and det.metrics.counts["explained"] == 2


def test_a_full_outbox_sheds_explanations_first_then_drops_the_oldest_alerts(bundle):
    metrics = Metrics()
    sink = SocSink(lambda b: (_ for _ in ()).throw(SocError("down")),
                   Outbox(None, max_alerts=4, merge=True), metrics, retry_seconds=60, start=False)
    det = LiveDetector(bundle, quiet_engine(), sink,
                       LiveSettings(batch_size=10, metrics_seconds=3600), META, metrics=metrics,
                       live=False, outbox_capacity=4)
    det.run(iter([make_flow(80, i) for i in range(30)]))
    assert metrics.counts["alerts"] == 30
    assert sink.pending() == 4  # the cap holds
    assert metrics.counts["alerts_dropped"] == 26  # counted, not silent
    # Batch 1 had room (explained); once the outbox was nearly full, explanations were shed.
    assert metrics.counts["explained"] == 10 and metrics.counts["explanations_shed"] == 20
    newest = sink.outbox.batches[-1]
    assert [a["src_port"] for a in newest][-1] == 40029  # the newest alerts are the ones kept


def test_outbox_trims_exactly_to_its_cap():
    box = Outbox(None, max_alerts=10, merge=True)
    assert box.add([{"i": i} for i in range(7)]) == 0
    assert box.add([{"i": i} for i in range(7, 14)]) == 4
    assert [a["i"] for b in box.batches for a in b] == list(range(4, 14))


def test_metrics_report_latency_and_shap_time_when_live(bundle, caplog):
    sink = ListSink()
    det = detector(bundle, sink, live=True, batch_size=5)
    det.run(iter([make_flow(80, i, end_ms=int(time.time() * 1000) - 1500) for i in range(5)]))
    snap = det.metrics.snapshot()
    assert snap["latency_flow_end_to_alert_s"]["n"] == 5
    assert 1.4 <= snap["latency_flow_end_to_alert_s"]["p50"] < 5
    shap = snap["shap_ms_per_alert"]
    # The plan's budget (< 50 ms) is checked by hand on the real model, not here: CI machines vary.
    assert shap["n"] == 5 and shap["p95"] is not None and shap["p95"] > 0
    assert json.loads(json.dumps(snap)) == snap
    assert set(snap) >= {"flows_per_s", "alerts", "blocks", "dropped"}


def test_the_background_keeps_the_first_benign_flows(bundle):
    det = detector(bundle, ListSink(), background_size=3, batch_size=4)
    det.run(iter([make_flow(443, i) for i in range(10)]))
    assert len(det._background) == 3
    assert [r["dst_port"] for r in det._background] == [443.0] * 3


# --- Reply direction: never block the protected server -----------------------------------------------

SERVER = "192.168.10.50"
SERVER_NET = "192.168.10.0/24"


def reply_flow(i=0, src=SERVER, dst=ATTACKER) -> Flow:
    """What NFStream reports when the first captured packet was the server's reply."""
    flow = make_flow(80, i)
    values = {f.name: getattr(flow, f.name) for f in fields(Flow)}
    values.update(src_ip=src, dst_ip=dst, src_port=80, dst_port=50000 + i, protocol=6)
    return Flow(**values)


class _RecordingEngine:
    dry_run = True

    def __init__(self, real):
        self.real, self.detections = real, []
        self.policy = real.policy

    def handle(self, detection):
        self.detections.append(detection)
        return self.real.handle(detection)


def test_block_candidate_rules():
    from idps.live.detector import block_candidate

    base = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": 6}
    reply = {**base, "src_port": 80, "dst_port": 50000}
    assert block_candidate(reply) == "2.2.2.2"
    assert block_candidate({**reply, "protocol": 17}) == "2.2.2.2"
    assert block_candidate({**reply, "protocol": 1}) == "1.1.1.1"  # not TCP/UDP
    assert block_candidate({**base, "src_port": 50000, "dst_port": 80}) == "1.1.1.1"  # forward
    assert block_candidate({**base, "src_port": 0, "dst_port": 0}) == "1.1.1.1"
    assert block_candidate({**base, "src_port": 40000, "dst_port": 50000}) == "1.1.1.1"  # both high
    assert block_candidate({**base, "src_port": 80, "dst_port": 8080}) == "1.1.1.1"  # both low
    assert block_candidate({**base, "src_port": 32768, "dst_port": 50000}) == "1.1.1.1"


def test_a_reply_flow_leads_to_a_detection_for_the_attacker_not_the_server(bundle, monkeypatch):
    import idps.live.detector as module

    # The tiny model keys on dst_port 80; a real model (DDoS, PortScan) also flags such replies.
    monkeypatch.setattr(module, "score_frame", lambda b, df: [Prediction("DDoS", 0.99)] * len(df))
    blocker, sink = FakeBlocker(), ListSink()
    engine = _RecordingEngine(ResponseEngine(
        Settings(dry_run=False, allowlist=[SERVER_NET]), blocker=blocker))
    det = detector(bundle, sink, engine=engine)
    det.run(iter([reply_flow(i) for i in range(6)]))
    assert {d.src_ip for d in engine.detections} == {ATTACKER}
    assert blocker.blocked == [ATTACKER]
    assert det.metrics.counts["reply_direction"] == 6
    assert {a["src_ip"] for a in sink.alerts} == {SERVER}  # the alert shows the flow as observed


def test_an_allowlisted_server_is_never_blocked_even_as_a_forward_looking_source(bundle):
    # The heuristic can be fooled (attacker sends from port 80 to a high port; or the server's
    # flow looks forward): the allowlist is what keeps the server safe.
    blocker = FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=False, allowlist=[SERVER_NET]), blocker=blocker)
    det = detector(bundle, ListSink(), engine=engine)
    forward = [make_flow(80, i) for i in range(8)]
    forward = [Flow(**{**{f.name: getattr(x, f.name) for f in fields(Flow)}, "src_ip": SERVER})
               for x in forward]
    det.run(iter(forward))
    assert blocker.blocked == [] and det.metrics.counts["blocked"] == 0


def test_blocks_are_audited_with_their_explanation_even_when_shedding(bundle, caplog):
    sink = ListSink()
    engine = ResponseEngine(Settings(dry_run=True), blocker=FakeBlocker())
    det = detector(bundle, sink, engine=engine, max_explanations_per_batch=0)
    with caplog.at_level(logging.WARNING, logger="idps.respond"):
        det.run(iter([make_flow(80, i) for i in range(6)]))
    record = json.loads(next(r.message for r in caplog.records if "would_block" in r.message))
    assert record["explanation"]["top_features"]  # the why is there although the budget was 0


# --- Robustness: bad batches, draining, SOC configuration errors -------------------------------------

def test_a_failing_batch_is_logged_counted_and_never_handled_twice(bundle, monkeypatch, caplog):
    import idps.live.detector as module

    real, calls = module.alert_payload, []

    def flaky(row, pred, explanation=None):
        calls.append(row["src_port"])
        if len(calls) == 2:
            raise RuntimeError("bug")
        return real(row, pred, explanation)

    monkeypatch.setattr(module, "alert_payload", flaky)
    sink = ListSink()
    engine = _RecordingEngine(quiet_engine())
    det = detector(bundle, sink, engine=engine, batch_size=3)
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        det.run(iter([make_flow(80, i) for i in range(6)]))
    assert det.metrics.counts["batch_errors"] == 1
    assert any("failed and was skipped" in r.message for r in caplog.records)
    # batch 1 (flows 0-2) died on its 2nd alert: its detections were handled once, not retried
    stamps = [d.timestamp for d in engine.detections]
    assert len(stamps) == len(set(stamps)) == 5  # none twice; flow 2 died with its batch
    assert len(sink.alerts) == 3  # batch 2 went through; detection did not end
    assert det.metrics.snapshot()["errors"]["batch"] == 1


def test_stop_scores_every_flow_that_was_read(bundle):
    produced, stop, scored = [], threading.Event(), []
    started = threading.Event()

    def source():
        for i in range(40):
            produced.append(i)
            yield make_flow(80, i)

    det = detector(bundle, ListSink(), batch_size=5, batch_seconds=60.0)
    real = det.handle_batch

    def slow(flows):
        started.set()
        time.sleep(0.15)  # scoring is slower than the capture, so flows pile up in the queue
        scored.extend(flows)
        return real(flows)

    det.handle_batch = slow
    worker = threading.Thread(target=det.run, args=(source(), stop))
    worker.start()
    assert started.wait(5)
    stop.set()
    worker.join(10)
    assert not worker.is_alive()
    counts = det.metrics.counts
    # nothing is lost silently: every flow the generator produced was scored or counted as discarded
    assert len(scored) + counts["flows_discarded"] == len(produced)
    assert len(scored) > 5  # the queue was drained into the final batches, not dropped


def test_max_flows_discards_and_counts_the_surplus(bundle):
    det = detector(bundle, ListSink(), batch_size=2, batch_seconds=60.0)
    det.run(iter([make_flow(80, i) for i in range(50)]), max_flows=4)
    counts = det.metrics.counts
    assert counts["flows"] == 4  # exactly the limit is scored
    assert counts["flows"] + counts["flows_discarded"] <= 50


def test_the_final_snapshot_has_a_sane_flow_rate(bundle):
    det = detector(bundle, ListSink())
    snap = det.run(iter([make_flow(443, i) for i in range(20)]))
    assert snap["flows"] == 20 and snap["flows_per_s"] > 0


@pytest.mark.parametrize("status", [401, 403, 404])
def test_soc_configuration_errors_keep_the_alerts_and_log_once(status, caplog):
    metrics, calls = Metrics(), []

    def wrong_config(batch):
        calls.append(len(batch))
        raise SocRejectedError(f"HTTP {status}", status)

    sink = SocSink(wrong_config, Outbox(None), metrics, start=False)
    sink.submit([{"a": 1}, {"a": 2}])
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        for _ in range(3):
            assert sink.drain() is False
    assert sink.pending() == 2 and metrics.counts["alerts_rejected"] == 0  # kept, not dropped
    assert metrics.counts["soc_config_errors"] == 3
    assert len([r for r in caplog.records if "check IDPS_SOC_URL" in r.message]) == 1
    assert metrics.snapshot()["errors"]["soc_config"] == 3


# --- Outbox file hygiene -----------------------------------------------------------------------------

def test_outbox_load_validates_rechunks_and_trims(tmp_path):
    path = tmp_path / "outbox.json"
    alerts = [{"i": i} for i in range(1200)]
    path.write_text(json.dumps({"version": 1, "batches": [alerts[:700], alerts[700:]]}))
    box = Outbox(path, max_alerts=1100)
    assert [len(b) for b in box.batches] == [MAX_BATCH, MAX_BATCH, 100]
    assert box.batches[0][0] == {"i": 100}  # the oldest 100 were trimmed


@pytest.mark.parametrize("content", ["not json", '{"batches": [[1, 2]]}', '{"batches": "x"}',
                                     '{"nothing": 1}'])
def test_a_corrupt_outbox_is_moved_aside_not_overwritten(tmp_path, content):
    path = tmp_path / "outbox.json"
    path.write_text(content)
    box = Outbox(path)
    assert len(box) == 0 and not path.exists()
    (kept,) = list(tmp_path.glob("outbox.json.corrupt-*"))
    assert kept.read_text() == content


def test_an_oversized_outbox_file_is_not_read(tmp_path, monkeypatch):
    import idps.soc_client as module

    monkeypatch.setattr(module, "MAX_OUTBOX_FILE_BYTES", 10)
    path = tmp_path / "outbox.json"
    path.write_text(json.dumps({"batches": [[{"a": 1}]]}))
    assert len(Outbox(path)) == 0 and list(tmp_path.glob("outbox.json.corrupt-*"))


def test_outbox_files_are_private_and_symlinks_are_refused(tmp_path):
    path = tmp_path / "outbox.json"
    box = Outbox(path)
    box.add([{"a": 1}])
    assert (path.stat().st_mode & 0o777) == 0o600
    target = tmp_path / "target.txt"
    target.write_text("precious")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(OSError, match="symbolic link"):
        Outbox(link).save()
    assert target.read_text() == "precious" and len(Outbox(link)) == 0
    with pytest.raises(OSError):
        JsonlSink(link, Metrics())
    assert target.read_text() == "precious"


def test_an_oversized_post_is_a_rejection_not_a_valueerror():
    from idps.soc_client import SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_x")
    with pytest.raises(SocRejectedError):
        client.post_alerts([{}] * (MAX_BATCH + 1))


# --- Configuration and the token ---------------------------------------------------------------------

def test_bare_soc_variable_names_are_ignored(monkeypatch):
    for name in ("SOC_URL", "SOC_TOKEN", "SOC_SENSOR_TOKEN", "SOC_CA_FILE", "soc_url", "soc_token"):
        monkeypatch.setenv(name, "https://evil.example" if "URL" in name.upper() else "x")
    s = LiveSettings()
    assert s.soc_url is None and s.soc_token is None and s.soc_ca_file is None
    monkeypatch.setenv("IDPS_SOC_TOKEN", "  idps_sensor_abc  ")
    assert LiveSettings().soc_token.get_secret_value() == "idps_sensor_abc"  # stripped


@pytest.mark.parametrize("token", ["idps sensor", "idps_sensor\nX-Evil: 1", "idps\x07sensor"])
def test_a_token_with_whitespace_or_control_characters_exits_2_without_echoing_it(
        model_file, tmp_path, monkeypatch, capsys, token):
    monkeypatch.setenv("IDPS_SOC_URL", "https://soc.example")
    monkeypatch.setenv("IDPS_SOC_SENSOR_TOKEN", token)
    pcap = write_pcap(tmp_path / "attack.pcap", attack_packets(n=1))
    assert main(["--pcap", str(pcap), "--model", str(model_file)]) == 2
    err = capsys.readouterr().err
    assert "token" in err and token not in err and "X-Evil" not in err


def test_the_token_never_reaches_the_logs(bundle, tmp_path, caplog):
    from idps.soc_client import SocClient

    secret = "idps_sensor_SUPERSECRETVALUE"
    client = SocClient("http://127.0.0.1:9", secret, timeout=1)  # nothing listens on port 9
    metrics = Metrics()
    sink = SocSink(client.post_alerts, Outbox(None), metrics, start=False)
    sink.submit([{"a": 1}])
    with caplog.at_level(logging.DEBUG):
        assert sink.drain() is False
        with pytest.raises(SocError) as caught:
            client.post_alerts([{"a": 1}])
    assert secret not in caplog.text and secret not in str(caught.value)
    assert secret not in repr(LiveSettings(soc_url="https://s", soc_token=secret))


def test_header_errors_do_not_quote_the_token(monkeypatch):
    from idps.soc_client import SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_SECRET1")

    def explode(*a, **k):
        raise ValueError("Invalid header value b'Bearer idps_sensor_SECRET1'")

    monkeypatch.setattr(client._opener, "open", explode)
    with pytest.raises(SocError) as caught:
        client.post_alerts([{"a": 1}])
    assert "SECRET1" not in str(caught.value) and "SECRET1" not in repr(caught.value.__cause__)


def test_startup_errors_of_the_capture_exit_2_and_close_the_sink(model_file, tmp_path, monkeypatch, capsys):
    import idps.live.__main__ as cli

    def boom(*a, **k):
        raise ValueError("no such interface")

    monkeypatch.setattr("idps.capture.flows_from_interface", boom)
    out = tmp_path / "alerts.jsonl"
    assert cli.main(["--interface", "nope0", "--model", str(model_file),
                     "--alerts-file", str(out)]) == 2
    assert "cannot start the capture" in capsys.readouterr().err


# --- Heartbeat: keeps NFStream's flow clock moving on a quiet link ------------------------------

HB_KEY = ("10.10.1.2", 50000)


def heartbeat_flow(i=0, **changes) -> Flow:
    from idps.live.heartbeat import HEARTBEAT_DST, HEARTBEAT_PORT

    values = dict.fromkeys((f.name for f in fields(Flow)), 0)
    start = 1_700_000_000_000 + i * 1000
    values.update(src_ip=HB_KEY[0], dst_ip=HEARTBEAT_DST, src_port=HB_KEY[1],
                  dst_port=HEARTBEAT_PORT, protocol=17, start_ms=start, end_ms=start + 120_000,
                  fwd_packets=120, fwd_bytes=120 * 29)
    values.update(changes)
    return Flow(**values)


class FakeHeartbeat:
    key = HB_KEY


def test_is_heartbeat_matches_only_our_own_socket():
    from idps.live.heartbeat import is_heartbeat

    assert is_heartbeat(heartbeat_flow(), HB_KEY)
    assert not is_heartbeat(heartbeat_flow(), None)  # no heartbeat running: nothing is dropped
    assert not is_heartbeat(make_flow(9), HB_KEY)  # TCP to port 9
    assert not is_heartbeat(heartbeat_flow(dst_ip="10.10.2.10"), HB_KEY)
    assert not is_heartbeat(heartbeat_flow(protocol=6), HB_KEY)
    # An attacker broadcasting to the same address and port is not our heartbeat ...
    assert not is_heartbeat(heartbeat_flow(src_ip="10.10.1.10", src_port=4444), HB_KEY)
    assert not is_heartbeat(heartbeat_flow(src_port=50001), HB_KEY)
    # ... and neither is a flow that got an answer.
    assert not is_heartbeat(heartbeat_flow(bwd_packets=1), HB_KEY)


def test_heartbeat_flows_never_reach_the_model_sink_or_engine(bundle):
    sink = ListSink()
    engine = _RecordingEngine(ResponseEngine(Settings(dry_run=True), blocker=FakeBlocker()))
    det = detector(bundle, sink, engine=engine)
    det.heartbeat = FakeHeartbeat()
    det.run(iter([heartbeat_flow(i) for i in range(5)] + [make_flow(80, i) for i in range(8)]))
    assert det.metrics.counts["heartbeat_flows"] == 5
    assert det.metrics.counts["flows"] == 8  # only the real flows were scored
    assert sink.alerts, "the real flows must produce alerts, or this test checks nothing"
    assert all(a["dst_ip"] != "255.255.255.255" for a in sink.alerts)
    assert engine.detections, "the real flows must reach the engine"
    assert all(d.src_ip != HB_KEY[0] for d in engine.detections)


def test_a_batch_of_only_heartbeats_is_a_no_op(bundle):
    sink = ListSink()
    det = detector(bundle, sink)
    det.heartbeat = FakeHeartbeat()
    assert det.handle_batch([heartbeat_flow(0), heartbeat_flow(1)]) == []
    assert det.metrics.counts["flows"] == 0 and det.metrics.counts["batch_errors"] == 0


def test_foreign_broadcasts_are_scored_and_nothing_is_dropped_without_a_heartbeat(bundle):
    sink = ListSink()
    det = detector(bundle, sink)
    det.heartbeat = FakeHeartbeat()
    det.handle_batch([heartbeat_flow(0, src_ip="10.10.1.10", src_port=4444)])
    assert det.metrics.counts["flows"] == 1 and det.metrics.counts["heartbeat_flows"] == 0
    det.heartbeat = None
    det.handle_batch([heartbeat_flow(1)])
    assert det.metrics.counts["flows"] == 2


class FakeSocket:
    def __init__(self, *args, fail=0, error=errno.ENETDOWN):
        self.options, self.sent, self.closed = [], [], False
        self.fail, self.error, self.connected = fail, error, None  # fail the first `fail` sends

    def setsockopt(self, level, option, value):
        self.options.append((option, value))

    def connect(self, address):
        self.connected = address

    def getsockname(self):
        return HB_KEY

    def send(self, data):
        if self.fail > 0:
            self.fail -= 1
            raise OSError(self.error, os.strerror(self.error))
        self.sent.append((data, self.connected))

    def close(self):
        self.closed = True


@pytest.fixture
def bindtodevice(monkeypatch):
    import socket

    monkeypatch.setattr(socket, "SO_BINDTODEVICE", 25, raising=False)  # Linux's value
    return 25


def test_heartbeat_sends_broadcasts_bound_to_the_interface_until_stopped(bindtodevice):
    from idps.live.heartbeat import HEARTBEAT_DST, HEARTBEAT_PAYLOAD, HEARTBEAT_PORT, Heartbeat

    sock = FakeSocket()
    hb = Heartbeat("lab_attack", interval=0.01, sock_factory=lambda *a: sock)
    hb.start()
    assert hb.key == HB_KEY
    wait_for(lambda: len(sock.sent) >= 3)
    hb.stop()
    hb.stop()  # idempotent
    assert sock.closed
    assert (bindtodevice, b"lab_attack\0") in sock.options
    assert set(sock.sent) == {(HEARTBEAT_PAYLOAD, (HEARTBEAT_DST, HEARTBEAT_PORT))}


def test_heartbeat_permanent_start_failure_closes_the_socket_and_raises(bindtodevice):
    from idps.live.heartbeat import Heartbeat

    sock = FakeSocket(fail=1, error=errno.ENODEV)
    hb = Heartbeat("nope0", sock_factory=lambda *a: sock)
    with pytest.raises(OSError):
        hb.start()
    assert sock.closed


def test_heartbeat_temporary_failure_is_retried_and_recovers(bindtodevice, caplog):
    from idps.live.heartbeat import Heartbeat

    sock = FakeSocket(fail=3)  # the interface is down for the first three tries
    hb = Heartbeat("lab_attack", interval=0.01, sock_factory=lambda *a: sock)
    with caplog.at_level(logging.INFO, logger="idps.live"):
        hb.start()  # does not raise
        assert hb.failing
        wait_for(lambda: len(sock.sent) >= 2)
        hb.stop()
    assert not hb.failing
    failures = [r for r in caplog.records if "failed" in r.getMessage()]
    assert len(failures) == 1  # logged once per streak
    assert any("works again" in r.getMessage() for r in caplog.records)


def test_heartbeat_without_so_bindtodevice_raises_oserror(monkeypatch):
    import socket

    from idps.live.heartbeat import Heartbeat

    monkeypatch.delattr(socket, "SO_BINDTODEVICE", raising=False)
    with pytest.raises(OSError, match="Linux only"):
        Heartbeat("lab_attack", sock_factory=FakeSocket).start()


def test_heartbeat_interval_must_be_positive():
    from idps.live.heartbeat import Heartbeat

    with pytest.raises(ValueError):
        Heartbeat("lab_attack", interval=0)


# --- block reports to the SOC -----------------------------------------------------------------

def _run_attack(bundle, sink, tmp_path, dry_run, n=5, blocker=None):
    blocker = blocker or FakeBlocker()
    engine = ResponseEngine(Settings(dry_run=dry_run, allowlist=["10.10.1.1"]), blocker=blocker)
    detector(bundle, sink, engine=engine).run(
        flows_from_pcap(write_pcap(tmp_path / "a.pcap", attack_packets(n=n))))
    return blocker


def test_a_real_block_is_reported_once_with_the_right_fields(bundle, tmp_path):
    sink = ListSink()
    blocker = _run_attack(bundle, sink, tmp_path, dry_run=False)
    assert blocker.blocked == [CLIENT]
    assert len(sink.blocks) == 1
    ev = sink.blocks[0]
    assert set(ev) == {"event", "ip", "reason", "expires_at", "source"}
    assert (ev["event"], ev["ip"], ev["source"]) == ("blocked", CLIENT, "auto")
    assert re.fullmatch(r"\d+ flows >= [\d.]+ confidence \(.+\) in \d+s", ev["reason"])
    expires = datetime.fromisoformat(ev["expires_at"])
    assert expires.tzinfo is not None
    assert abs((expires - datetime.now(UTC)).total_seconds() - 900) < 30


def test_dry_run_reports_no_block(bundle, tmp_path):
    sink = ListSink()
    _run_attack(bundle, sink, tmp_path, dry_run=True)
    assert sink.blocks == []


def test_a_failed_block_is_not_reported(bundle, tmp_path):
    from idps.respond.nft import BlockerError

    class Failing(FakeBlocker):
        def block(self, ip, ttl_seconds):
            raise BlockerError("nft failed")

    sink = ListSink()
    _run_attack(bundle, sink, tmp_path, dry_run=False, n=3, blocker=Failing())
    assert sink.blocks == []


_NOW = datetime.now(UTC)  # fixed, so that equal events compare equal


def _event(ip="203.0.113.7", seconds=600):
    return {"event": "blocked", "ip": ip, "reason": "r", "source": "auto",
            "expires_at": (_NOW + timedelta(seconds=seconds)).isoformat()}


def test_blocks_are_retried_while_the_soc_is_down_then_delivered():
    metrics, up, sent = Metrics(), [False], []

    def post_blocks(batch):
        if not up[0]:
            raise SocError("down")
        sent.extend(batch)
        return {}

    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False, post_blocks=post_blocks)
    sink.submit_blocks([_event()])
    assert sink.drain() is False and sent == [] and metrics.counts["blocks_sent"] == 0
    up[0] = True
    assert sink.drain() is True
    assert sent == [_event()] and metrics.counts["blocks_sent"] == 1
    assert sink._pending_blocks() == 0


def test_a_refused_block_batch_is_dropped_and_counted():
    metrics, calls = Metrics(), []

    def refuse(batch):
        calls.append(batch)
        raise SocRejectedError("HTTP 422", 422)

    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False, post_blocks=refuse)
    sink.submit_blocks([_event(), _event("203.0.113.8")])
    assert sink.drain() is True
    assert len(calls) == 1 and metrics.counts["blocks_rejected"] == 2
    assert sink._pending_blocks() == 0


def test_the_block_queue_is_bounded_and_drops_the_oldest(monkeypatch):
    from idps.live import sinks

    monkeypatch.setattr(sinks, "MAX_QUEUED_BLOCKS", 3)
    metrics, sent = Metrics(), []
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False,
                   post_blocks=lambda b: sent.extend(b) or {})
    sink.submit_blocks([_event(f"203.0.113.{i}") for i in range(5)])
    assert metrics.counts["blocks_dropped"] == 2
    sink.drain()
    assert [e["ip"] for e in sent] == ["203.0.113.2", "203.0.113.3", "203.0.113.4"]
    assert Metrics().snapshot()["dropped"]["blocks"] == 0
    assert metrics.snapshot()["dropped"]["blocks"] == 2


def test_block_batches_respect_the_soc_limit():
    from idps.soc_client import MAX_BLOCK_EVENTS

    sizes = []
    sink = SocSink(lambda b: {}, Outbox(None), Metrics(), start=False,
                   post_blocks=lambda b: sizes.append(len(b)) or {})
    sink.submit_blocks([_event() for _ in range(MAX_BLOCK_EVENTS + 5)])
    sink.drain()
    assert sizes == [MAX_BLOCK_EVENTS, 5]


def test_the_jsonl_sink_writes_blocks_with_a_type(tmp_path):
    sink = JsonlSink(tmp_path / "alerts.jsonl", Metrics())
    sink.submit_blocks([_event()])
    sink.close()
    assert lines(tmp_path / "alerts.jsonl") == [{"type": "block", **_event()}]


def test_the_client_posts_blocks_to_ingest_blocks_with_the_bearer_token(monkeypatch):
    from idps.soc_client import SocClient

    client = SocClient("http://127.0.0.1:9", "idps_sensor_TOK")
    seen = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"blocked": 1, "unblocked": 0}'

    def fake_open(request, timeout):
        seen.update(url=request.full_url, auth=request.get_header("Authorization"),
                    body=json.loads(request.data))
        return Resp()

    monkeypatch.setattr(client._opener, "open", fake_open)
    assert client.post_blocks([_event()]) == {"blocked": 1, "unblocked": 0}
    assert seen == {"url": "http://127.0.0.1:9/ingest/blocks",
                    "auth": "Bearer idps_sensor_TOK", "body": {"events": [_event()]}}
    with pytest.raises(SocRejectedError):
        client.post_blocks([_event()] * 101)


def test_a_block_reported_by_the_sensor_client_shows_in_the_socs_blocks_list(
        client, sensor_token, analyst_headers, monkeypatch):
    from idps.soc_client import SocClient

    sensor = SocClient("http://127.0.0.1:9", sensor_token)

    def via_testclient(request, timeout):
        r = client.post(request.full_url.removeprefix("http://127.0.0.1:9"),
                        content=request.data, headers=dict(request.header_items()))

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return r.content
        assert r.status_code == 201, r.text
        return Resp()

    monkeypatch.setattr(sensor._opener, "open", via_testclient)
    sink = SocSink(sensor.post_alerts, Outbox(None), Metrics(), start=False,
                   post_blocks=sensor.post_blocks)
    sink.submit_blocks([_event()])
    assert sink.drain() is True
    items = client.get("/blocks", headers=analyst_headers).json()["items"]
    assert [(b["ip"], b["source"]) for b in items] == [("203.0.113.7", "auto")]


@pytest.mark.parametrize("error", [
    SocRejectedError("HTTP 404", 404), SocRejectedError("HTTP 401", 401), SocError("HTTP 500"),
])
def test_alerts_are_delivered_while_the_block_endpoint_fails(error, caplog):
    metrics, got = Metrics(), []

    def failing(batch):
        raise error

    sink = SocSink(lambda b: got.extend(b) or {}, Outbox(None), metrics, start=False,
                   post_blocks=failing)
    sink.submit([{"a": 1}])
    sink.submit_blocks([_event()])
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        assert sink.drain() is False  # blocks are still queued
        assert sink.drain() is False
    assert got == [{"a": 1}] and metrics.counts["alerts_sent"] == 1
    assert sink._pending_blocks() == 1 and metrics.counts["blocks_sent"] == 0
    assert len([r for r in caplog.records if "block reports cannot be delivered" in r.message]) == 1


def test_a_block_failure_streak_is_logged_again_after_a_success(caplog):
    state = {"fail": True}

    def post_blocks(batch):
        if state["fail"]:
            raise SocError("down")
        return {}

    sink = SocSink(lambda b: {}, Outbox(None), Metrics(), start=False, post_blocks=post_blocks)
    sink.submit_blocks([_event()])
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        sink.drain()
        state["fail"] = False
        sink.drain()
        state["fail"] = True
        sink.submit_blocks([_event()])
        sink.drain()
    assert len([r for r in caplog.records if "cannot be delivered" in r.message]) == 2


def test_close_with_pending_blocks_logs_the_loss(caplog):
    def down(batch):
        raise SocError("down")

    sink = SocSink(lambda b: {}, Outbox(None), Metrics(), start=False, post_blocks=down)
    sink.submit_blocks([_event(), _event("203.0.113.8")])
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        sink.close()
    assert "2 block report(s) were not delivered and are lost" in caplog.text


def test_requeue_overflow_drops_the_oldest_and_counts(monkeypatch, caplog):
    from idps.live import sinks

    monkeypatch.setattr(sinks, "MAX_QUEUED_BLOCKS", 3)
    metrics = Metrics()
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False,
                   post_blocks=lambda b: (_ for _ in ()).throw(SocError("down")))
    sink.submit_blocks([_event("203.0.113.1"), _event("203.0.113.2")])

    # While a batch is in flight, new events queue up; the failed batch then goes back in front.
    def failing(batch):
        sink.submit_blocks([_event("203.0.113.3"), _event("203.0.113.4")])
        raise SocError("down")

    sink.post_blocks = failing
    with caplog.at_level(logging.ERROR, logger="idps.live"):
        sink.drain()
    assert metrics.counts["blocks_dropped"] == 1
    assert [e["ip"] for e in sink._blocks] == ["203.0.113.2", "203.0.113.3", "203.0.113.4"]
    assert "dropped the 1 oldest" in caplog.text


def test_expired_block_events_are_dropped_before_posting_and_counted(caplog):
    metrics, sent = Metrics(), []
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False,
                   post_blocks=lambda b: sent.extend(b) or {})
    gone, alive = _event("203.0.113.1", seconds=-10), _event("203.0.113.2")
    sink.submit_blocks([gone, alive])
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        assert sink.drain() is True
    assert sent == [alive] and metrics.counts["blocks_dropped"] == 1
    assert "already ended" in caplog.text


def test_a_failing_block_file_counts_blocks_not_alerts(tmp_path):
    sink = JsonlSink(tmp_path / "alerts.jsonl", Metrics())
    sink._file.close()
    sink.submit_blocks([_event()])
    assert sink.metrics.counts["blocks_dropped"] == 1 and sink.metrics.counts["alerts_dropped"] == 0


def test_blocks_without_a_block_sender_are_counted_and_logged_once(caplog):
    metrics = Metrics()
    sink = SocSink(lambda b: {}, Outbox(None), metrics, start=False)
    with caplog.at_level(logging.WARNING, logger="idps.live"):
        sink.submit_blocks([_event()])
        sink.submit_blocks([_event()])
    assert metrics.counts["blocks_dropped"] == 2
    assert caplog.text.count("no post_blocks") == 1
