"""SOC API: sensor status reports (POST /sensor/status, GET /sensors/status)."""

import copy
import json
from datetime import UTC, datetime, timedelta

import pytest

from soc.api import auth
from soc.api.models import SensorStatus, SensorToken


def report(**overrides) -> dict:
    base = {
        "dry_run": True, "blocking_enabled": False, "interface": "eth1", "mode": "live",
        "model": {"name": "xgboost", "checksum_ok": True},
        "policy": {"confidence_threshold": 0.9, "min_flows": 5, "window_seconds": 60.0,
                   "min_alert_confidence": 0.5, "block_ttl_seconds": 900,
                   "unblock_grace_seconds": 3600, "max_analyst_blocks": 1000},
        "allowlist": ["10.10.1.1/32", "10.10.2.0/24"], "allowlist_total": 2,
        "outbox_pending": 3, "shap_p95_ms": 12.5,
        "heartbeat": {"enabled": True, "ok": True},
        "counters": {"flows": 100, "alerts": 7, "blocked": 0, "would_block": 2},
        "sensor_version": "0.1.0", "sent_at": "2026-11-13T10:00:00+00:00",
    }
    return base | overrides


def post(client, headers, body):
    return client.post("/sensor/status", headers=headers, json=body)


def test_a_sensor_can_post_status_and_users_can_read_it(client, sensor_headers, analyst_headers):
    r = post(client, sensor_headers, report())
    assert r.status_code == 200 and "last_seen_at" in r.json()
    got = client.get("/sensors/status", headers=analyst_headers)
    assert got.status_code == 200
    (s,) = got.json()["sensors"]
    assert s["name"] == "sensor-1" and s["online"] is True and s["revoked"] is False
    assert s["status"]["policy"]["confidence_threshold"] == 0.9
    assert s["status"]["allowlist"] == ["10.10.1.1/32", "10.10.2.0/24"]
    assert s["status"]["counters"] == {"flows": 100, "alerts": 7, "blocked": 0, "would_block": 2}
    assert set(s) == {"sensor_id", "name", "revoked", "last_seen_at", "online", "status"}


def test_the_get_includes_the_socs_own_allowlist(client, analyst_headers):
    body = client.get("/sensors/status", headers=analyst_headers).json()
    assert body["soc_allowlist"] == ["10.10.1.1/32", "10.10.2.1/32", "10.10.1.2/32", "10.10.2.2/32"]
    assert body["sensors"] == []


def test_a_sensor_never_seen_has_null_status_and_is_offline(client, sensor_token, analyst_headers):
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"] is None and s["last_seen_at"] is None and s["online"] is False


def test_auth(client, sensor_headers, analyst_headers, admin_headers):
    assert client.post("/sensor/status", json=report()).status_code == 401
    bad = {"Authorization": "Bearer idps_sensor_nope"}
    assert post(client, bad, report()).status_code == 401
    # a user's token is not a sensor token
    assert post(client, analyst_headers, report()).status_code == 401
    assert post(client, admin_headers, report()).status_code == 401
    # and a sensor token is not a user token
    assert client.get("/sensors/status", headers=sensor_headers).status_code == 401
    assert client.get("/sensors/status").status_code == 401


def test_a_revoked_sensor_cannot_post(client, soc_app, sensor_headers):
    with soc_app.state.session_factory() as db:
        db.query(SensorToken).update({"revoked": True})
        db.commit()
    assert post(client, sensor_headers, report()).status_code == 401


def test_status_is_an_upsert_one_row_per_sensor(client, soc_app, sensor_headers, analyst_headers):
    post(client, sensor_headers, report(outbox_pending=1))
    post(client, sensor_headers, report(outbox_pending=9))
    with soc_app.state.session_factory() as db:
        assert db.query(SensorStatus).count() == 1
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["outbox_pending"] == 9


def test_two_sensors_keep_separate_status(client, soc_app, sensor_headers, analyst_headers):
    with soc_app.state.session_factory() as db:
        other = auth.create_sensor_token(db, "sensor-2")
    post(client, sensor_headers, report(interface="eth1"))
    post(client, {"Authorization": f"Bearer {other}"}, report(interface=None, mode="replay"))
    by_name = {s["name"]: s for s in
               client.get("/sensors/status", headers=analyst_headers).json()["sensors"]}
    assert by_name["sensor-1"]["status"]["interface"] == "eth1"
    assert by_name["sensor-2"]["status"]["mode"] == "replay"


def test_online_means_seen_within_two_minutes(client, soc_app, sensor_headers, analyst_headers):
    post(client, sensor_headers, report())

    def age(seconds):
        with soc_app.state.session_factory() as db:
            row = db.query(SensorStatus).one()
            row.last_seen_at = datetime.now(UTC) - timedelta(seconds=seconds)
            db.commit()
        return client.get("/sensors/status", headers=analyst_headers).json()["sensors"][0]

    assert age(60)["online"] is True
    stale = age(121)
    assert stale["online"] is False and stale["status"] is not None  # last report still shown


def test_a_revoked_sensor_is_listed_but_never_online(client, soc_app, sensor_headers,
                                                     analyst_headers):
    post(client, sensor_headers, report())
    with soc_app.state.session_factory() as db:
        db.query(SensorToken).update({"revoked": True})
        db.commit()
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["revoked"] is True and s["online"] is False


def test_last_seen_is_the_servers_clock_not_the_sensors(client, sensor_headers, analyst_headers):
    post(client, sensor_headers, report(sent_at="2001-01-01T00:00:00+00:00"))
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    seen = datetime.fromisoformat(s["last_seen_at"])
    assert abs(datetime.now(UTC) - seen) < timedelta(seconds=30) and s["online"] is True


def test_no_tokens_or_hashes_in_the_listing(client, sensor_token, sensor_headers, analyst_headers):
    post(client, sensor_headers, report())
    text = client.get("/sensors/status", headers=analyst_headers).text
    assert sensor_token not in text and "token_hash" not in text and "idps_sensor_" not in text
    from soc.api import security
    assert security.hash_sensor_token(sensor_token) not in text


def _mut(path, value):
    body = copy.deepcopy(report())
    target = body
    *head, last = path
    for key in head:
        target = target[key]
    target[last] = value
    return body


@pytest.mark.parametrize("body", [
    {**report(), "extra": 1},                                  # unknown top-level field
    _mut(["policy", "extra"], 1),                              # unknown nested field
    _mut(["mode"], "other"),
    _mut(["interface"], "x" * 65),
    _mut(["model", "name"], "x" * 65),
    _mut(["allowlist"], ["10.0.0.1"] * 101),                   # too many entries
    _mut(["allowlist"], ["x" * 65]),                           # entry too long
    _mut(["allowlist"], "10.0.0.1"),                           # not a list
    _mut(["sensor_version"], "v" * 33),
    _mut(["outbox_pending"], -1),
    _mut(["outbox_pending"], 10**9),
    _mut(["shap_p95_ms"], -1),
    _mut(["policy", "confidence_threshold"], 1.5),
    _mut(["policy", "window_seconds"], 0),
    _mut(["counters", "flows"], -1),
    _mut(["counters", "flows"], 2**60),
    _mut(["counters", "extra"], 1),
    _mut(["dry_run"], "maybe"),
    {k: v for k, v in report().items() if k != "policy"},      # missing required block
])
def test_invalid_reports_are_refused(client, sensor_headers, body):
    assert post(client, sensor_headers, body).status_code == 422


def test_nan_is_refused(client, sensor_headers):
    text = json.dumps(report()).replace('"shap_p95_ms": 12.5', '"shap_p95_ms": NaN')
    assert "NaN" in text
    r = client.post("/sensor/status", headers={**sensor_headers, "Content-Type": "application/json"},
                    content=text)
    assert r.status_code == 422


def test_boundary_values_are_accepted(client, sensor_headers):
    ok = report(allowlist=["a" * 64] * 100, interface=None, shap_p95_ms=None,
                sensor_version=None, sent_at=None)
    assert post(client, sensor_headers, ok).status_code == 200


def test_posting_status_does_not_fill_the_audit_log(client, sensor_headers, admin_headers):
    for _ in range(3):
        post(client, sensor_headers, report())
    entries = client.get("/admin/audit", headers=admin_headers).json()
    items = entries["items"] if isinstance(entries, dict) else entries
    assert not [e for e in items if "status" in e["action"]]


def test_allowlist_total_is_optional_and_bounded(client, sensor_headers, analyst_headers):
    body = report()
    del body["allowlist_total"]  # an older sensor
    assert post(client, sensor_headers, body).status_code == 200
    assert post(client, sensor_headers, report(allowlist_total=-1)).status_code == 422
    assert post(client, sensor_headers, report(allowlist_total=250)).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["allowlist_total"] == 250


def test_the_upsert_retries_once_after_an_integrity_error(client, soc_app, sensor_headers,
                                                          monkeypatch):
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    real, calls = Session.commit, []

    def flaky(self):
        calls.append(1)
        if len(calls) == 1:  # another first report won the race
            raise IntegrityError("insert", {}, Exception("duplicate"))
        return real(self)

    monkeypatch.setattr(Session, "commit", flaky)
    assert post(client, sensor_headers, report(outbox_pending=4)).status_code == 200
    assert len(calls) == 2
    with soc_app.state.session_factory() as db:
        (row,) = db.query(SensorStatus).all()
        assert row.payload["outbox_pending"] == 4


def test_a_second_integrity_error_is_not_swallowed(client, sensor_headers, monkeypatch):
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    def always(self):
        raise IntegrityError("insert", {}, Exception("duplicate"))

    monkeypatch.setattr(Session, "commit", always)
    with pytest.raises(IntegrityError):
        post(client, sensor_headers, report())


def test_a_stored_row_that_no_longer_validates_does_not_break_the_listing(
        client, soc_app, sensor_headers, analyst_headers, caplog):
    import logging

    from soc.api.routes import sensors

    with soc_app.state.session_factory() as db:
        other = auth.create_sensor_token(db, "sensor-2")
    post(client, sensor_headers, report())
    post(client, {"Authorization": f"Bearer {other}"}, report())
    with soc_app.state.session_factory() as db:
        row = db.query(SensorStatus).filter_by(sensor_id=1).one()
        row.payload = {"dry_run": "garbage", "unknown": 1}
        db.commit()
    sensors._warned_bad_row = False
    with caplog.at_level(logging.WARNING, logger="soc.api"):
        r = client.get("/sensors/status", headers=analyst_headers)
        client.get("/sensors/status", headers=analyst_headers)
    assert r.status_code == 200
    by_name = {s["name"]: s for s in r.json()["sensors"]}
    assert by_name["sensor-1"]["status"] is None and by_name["sensor-1"]["last_seen_at"]
    assert by_name["sensor-2"]["status"] is not None
    assert len([m for m in caplog.records if "no longer validates" in m.message]) == 1


def test_every_policy_value_the_sensor_can_have_is_accepted(client, sensor_headers):
    """The sensor's own limits (idps/config.py) must fit the SOC's, or its status always 422s."""
    from idps.config import Settings

    fields = Settings.model_fields
    grace = next(m.le for m in fields["unblock_grace_seconds"].metadata if hasattr(m, "le"))
    ttl = next(m.le for m in fields["block_ttl_seconds"].metadata if hasattr(m, "le"))
    cap = next(m.le for m in fields["max_analyst_blocks"].metadata if hasattr(m, "le"))
    policy = report()["policy"] | {"unblock_grace_seconds": grace, "block_ttl_seconds": ttl,
                                   "max_analyst_blocks": cap}
    assert post(client, sensor_headers, report(policy=policy)).status_code == 200
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(unblock_grace_seconds=grace + 1)


# --- faithfulness ---------------------------------------------------------------------------

METHOD = {"mean_drop": 0.377, "ratio_to_random": 38.6, "label_flip_rate": 0.42,
          "share_flows_beating_random": 1.0}


def faith(**overrides):
    base = {"model": "xgboost", "model_matches": True, "flows": 100, "top_k": 5,
            "random_mean_drop": 0.0097, "methods": {"shap": METHOD, "lime": METHOD}}
    return base | overrides


def test_faithfulness_is_accepted_and_returned(client, sensor_headers, analyst_headers):
    assert post(client, sensor_headers, report(faithfulness=faith())).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["faithfulness"] == faith() | {"model_check": None}  # none sent


def test_faithfulness_may_have_one_method_and_is_optional(client, sensor_headers, analyst_headers):
    only = faith(methods={"shap": METHOD})
    assert post(client, sensor_headers, report(faithfulness=only)).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["faithfulness"]["methods"] == {"shap": METHOD}
    assert post(client, sensor_headers, report()).status_code == 200  # older sensor
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    assert s["status"]["faithfulness"] is None
    assert post(client, sensor_headers, report(faithfulness=None)).status_code == 200


@pytest.mark.parametrize("bad", [
    faith(extra=1),
    faith(model=""),
    faith(model="x" * 65),
    faith(model_matches="maybe"),
    faith(flows=0),
    faith(top_k=0),
    faith(top_k=1001),
    faith(random_mean_drop=2),
    faith(methods={}),
    faith(methods={"other": METHOD}),
    faith(methods={"shap": {**METHOD, "extra": 1}}),
    faith(methods={"shap": {**METHOD, "ratio_to_random": -1e10}}),
    faith(model_check="other"),
    faith(methods={"shap": {**METHOD, "label_flip_rate": 1.5}}),
    faith(methods={"shap": {**METHOD, "share_flows_beating_random": -0.1}}),
    faith(methods={"shap": {**METHOD, "mean_drop": 5}}),
    faith(methods={"shap": {k: v for k, v in METHOD.items() if k != "mean_drop"}}),
    faith(methods={"shap": METHOD, "lime": "x"}),
])
def test_faithfulness_bounds(client, sensor_headers, bad):
    assert post(client, sensor_headers, report(faithfulness=bad)).status_code == 422


def test_null_and_negative_ratios_and_model_check_are_accepted(client, sensor_headers,
                                                               analyst_headers):
    worst = faith(model_check="digest", methods={
        "shap": {**METHOD, "ratio_to_random": None, "mean_drop": -0.3},
        "lime": {**METHOD, "ratio_to_random": -4.2}})
    assert post(client, sensor_headers, report(faithfulness=worst)).status_code == 200
    (s,) = client.get("/sensors/status", headers=analyst_headers).json()["sensors"]
    f = s["status"]["faithfulness"]
    assert f["model_check"] == "digest"
    assert f["methods"]["shap"]["ratio_to_random"] is None
    assert f["methods"]["lime"]["ratio_to_random"] == -4.2
    assert post(client, sensor_headers, report(faithfulness=faith(model_check="name"))
                ).status_code == 200
