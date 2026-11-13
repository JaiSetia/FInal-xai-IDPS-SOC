import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useLiveRefresh } from "../useLiveRefresh";
import { api, query } from "../api/client";
import {
  ALERT_STATUSES, type AlertDetail as AlertDetailT, type AlertStatus, type Block, type CaseDetail,
  type CaseSummary, type Page,
} from "../api/types";
import {
  Card, ErrorText, Pill, Segmented, SeverityBadge, Timeline, useAction, useLoad, useNow, type TimelineItem,
} from "../components/common";
import ExplanationChart from "../components/ExplanationChart";
import { dateTime, endpoint, label, num, percent, protocolName } from "../format";

/** Alert detail with its explanation (wireframe screen 2). */

/** Time of day, with the date too when it isn't the same day as `ref`. */
const time = (v: string | number, ref?: string | number) => {
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return String(v);
  const r = ref === undefined ? null : new Date(ref);
  return r && !Number.isNaN(r.getTime()) && r.toDateString() !== d.toDateString()
    ? d.toLocaleString() : d.toLocaleTimeString();
};

/** "+2 min" between the end of the flow and the SOC receiving it. */
function delayText(fromMs: number, to: string): string | null {
  const ms = Date.parse(to) - fromMs;
  if (!Number.isFinite(ms) || ms < 0) return null;
  if (ms < 60_000) return `+${Math.round(ms / 1000)} s`;
  return `+${Math.round(ms / 60_000)} min`;
}

const sameSource = (alert: AlertDetailT, b: Block) => b.sensor_id === alert.sensor_id && b.ip === alert.src_ip;

/** When a block ended, or will end; Infinity for one with no end. */
function blockEnd(b: Block): number {
  const end = b.unblocked_at ?? b.expires_at;
  return end ? Date.parse(end) : Infinity;
}

/** The block of this alert's source on its sensor that is in force now, if any. A sensor that
 *  re-blocks an address only extends the existing block (its blocked_at stays the old one), so
 *  this looks at every block of the address, whenever it started. */
export function activeBlock(alert: AlertDetailT, blocks: Block[], now = Date.now()): Block | undefined {
  return blocks.find((b) => sameSource(alert, b) && b.active && blockEnd(b) > now);
}

/** Blocks of this alert's source on its sensor that belong in its story: the block it caused, and
 *  blocks in force at any time from the start of the flow until an hour after the alert arrived. */
export function relatedBlocks(alert: AlertDetailT, blocks: Block[]): Block[] {
  const from = alert.start_ms;
  const to = Date.parse(alert.received_at) + 3600_000;
  return blocks
    .filter((b) => sameSource(alert, b))
    .filter((b) => b.alert_id === alert.id || (Date.parse(b.blocked_at) <= to && blockEnd(b) >= from))
    .slice(0, 10);
}

export function timeline(alert: AlertDetailT, blocks: Block[], now = Date.now()): TimelineItem[] {
  const method = typeof alert.explanation?.method === "string" ? alert.explanation.method.toUpperCase() : null;
  const ref = alert.received_at;
  const received = Date.parse(alert.received_at);
  const events: (TimelineItem & { t: number })[] = [
    { key: "flow", t: alert.start_ms, at: time(alert.start_ms, ref),
      text: `flow seen: ${protocolName(alert.protocol)} ${endpoint(alert.src_ip, alert.src_port, alert.protocol)} → ${endpoint(alert.dst_ip, alert.dst_port, alert.protocol)}` },
    { key: "scored", t: received, at: time(alert.received_at, ref), tone: "accent",
      text: `scored ${alert.predicted_class} ${percent(alert.confidence, 2)}${method ? `, explained (${method})` : ""}` },
  ];
  for (const b of blocks) {
    const started = Date.parse(b.blocked_at);
    // Say how a block relates to this alert: caused by it, already in force, or started later.
    const how = b.alert_id === alert.id ? "" : started < alert.start_ms ? " (already in force)"
      : started > received ? " (later block of this address)" : "";
    events.push({ key: `b${b.id}`, t: started, at: time(b.blocked_at, ref), tone: "danger",
      text: `${b.ip} blocked (${b.source})${how}: ${b.reason}` });
    if (b.unblocked_at) {
      events.push({ key: `u${b.id}`, t: Date.parse(b.unblocked_at), at: time(b.unblocked_at, ref), text: "unblocked" });
    } else if (b.expires_at) {
      const e = Date.parse(b.expires_at);
      events.push({ key: `e${b.id}`, t: e, at: time(b.expires_at, ref),
        text: e <= now ? "block expired by itself" : "block ends" });
    }
  }
  return events.sort((a, b) => a.t - b.t).map(({ t: _t, ...item }) => item);
}

export default function AlertDetail() {
  const { id: rawId } = useParams();
  // Only numeric ids reach the API path (a crafted link like /alerts/..%2Fadmin must not).
  const id = /^\d{1,18}$/.test(rawId ?? "") ? rawId! : "0";
  // A fresh page per alert: nothing (data, notice, chosen case) carries over to the next one, and
  // no action can target one alert while another is still on screen.
  return <AlertPage key={id} id={id} />;
}

function AlertPage({ id }: { id: string }) {
  const { data: alert, error, setData } = useLoad(() => api<AlertDetailT>(`/alerts/${id}`), [id]);
  const srcIp = alert?.src_ip;
  const blocks = useLoad(
    () => (srcIp ? api<Page<Block>>(`/blocks${query({ ip: srcIp, limit: 100 })}`) : Promise.resolve(null)), [srcIp]);
  const { data: cases } = useLoad(
    () => api<Page<CaseSummary>>(`/cases${query({ status: "open", limit: 100 })}`), []);
  const act = useAction();
  // Blocks start and end without an alert for this page: refresh them, and re-check expiry each 15 s.
  useLiveRefresh(blocks.reload, undefined, 30_000);
  const now = useNow(15_000);
  const [notice, setNotice] = useState<string | null>(null);
  const [caseId, setCaseId] = useState("");
  const [newCase, setNewCase] = useState("");

  if (error) return <ErrorText error={error} />;
  if (!alert) return <p className="muted">Loading…</p>;

  const allBlocks = blocks.data?.items ?? [];
  const related = relatedBlocks(alert, allBlocks);
  const blocked = activeBlock(alert, allBlocks, now);
  const delay = delayText(alert.end_ms, alert.received_at);
  const blockLink = `/response${query({ ip: alert.src_ip, sensor: alert.sensor_id, reason: `alert #${alert.id}: ${alert.predicted_class}` })}`;

  async function setStatus(status: AlertStatus) {
    if (status === alert!.status) return;
    setNotice(null);
    const updated = await act.run(() =>
      api<AlertDetailT>(`/alerts/${id}`, { method: "PATCH", json: { status } }));
    if (updated) setData(updated);
  }

  async function addToCase() {
    if (!caseId) return;
    setNotice(null);
    const c = await act.run(() => api<CaseDetail>(`/cases/${caseId}/alerts`, {
      method: "POST", json: { alert_ids: [alert!.id] } }));
    if (c) {
      setData({ ...alert!, case_id: c.id });
      setNotice(`Added to case #${c.id}.`);
    }
  }

  async function createCase() {
    const title = newCase.trim();
    if (!title) return;
    setNotice(null);
    const c = await act.run(() => api<CaseDetail>("/cases", {
      method: "POST", json: { title, alert_ids: [alert!.id] } }));
    if (c) {
      setData({ ...alert!, case_id: c.id });
      setNotice(`Created case #${c.id}.`);
      setNewCase("");
    }
  }

  return (
    <>
      <nav aria-label="Breadcrumb" className="small-text">
        <Link to="/alerts">← Alerts</Link>
      </nav>
      <div className="page-head" style={{ justifyContent: "flex-start" }}>
        <h1>{alert.predicted_class} · alert #{alert.id}</h1>
        <SeverityBadge severity={alert.severity} />
        <Pill tone="neutral">confidence {percent(alert.confidence, 1)}</Pill>
        {blocked && <Pill tone="danger">source blocked · {blocked.source}</Pill>}
      </div>
      <ErrorText error={act.error} />
      <div className="notice" role="status" aria-live="polite">{notice}</div>

      <div className="grid cols-detail">
        <div className="stack">
          <Card title="Flow">
            <dl className="kv">
              <dt>Source</dt>
              <dd>
                <span className="mono">{endpoint(alert.src_ip, alert.src_port, alert.protocol)}</span>{" "}
                <Link className="small-text" to={`/alerts${query({ ip: alert.src_ip })}`}>all alerts involving this IP</Link>
              </dd>
              <dt>Destination</dt><dd className="mono">{endpoint(alert.dst_ip, alert.dst_port, alert.protocol)}</dd>
              <dt>Protocol</dt><dd>{protocolName(alert.protocol)}</dd>
              <dt>Flow time</dt><dd>{dateTime(alert.start_ms)} → {time(alert.end_ms, alert.start_ms)}</dd>
              <dt>Received</dt>
              <dd>
                {dateTime(alert.received_at)}
                {delay && <span className="muted small-text"> ({delay} after the flow ended)</span>}
              </dd>
              <dt>Anomaly score</dt>
              <dd>{num(alert.anomaly_score)} {alert.anomaly_score !== null && <span className="muted small-text">Isolation Forest</span>}</dd>
              <dt>Sensor</dt><dd>#{alert.sensor_id}</dd>
              <dt>Case</dt><dd>{alert.case_id ? <Link to={`/cases/${alert.case_id}`}>#{alert.case_id}</Link> : "—"}</dd>
            </dl>
          </Card>

          <Card title="Triage">
            <div className="stack" style={{ gap: 14 }}>
              <Segmented<AlertStatus> label="Status" value={alert.status} onChange={(s) => void setStatus(s)} disabled={act.busy}
                options={ALERT_STATUSES.map((s) => ({ value: s, label: label(s) }))} />
              {blocked ? (
                <p style={{ margin: 0 }}>
                  {alert.src_ip} is blocked on sensor #{alert.sensor_id}
                  {blocked.expires_at ? ` until ${dateTime(blocked.expires_at)}` : ""}.{" "}
                  <Link to="/response">See it on Response</Link>
                </p>
              ) : (
                <div>
                  <Link className="button-link danger" to={blockLink}>Block source IP…</Link>
                  <p className="muted small-text" style={{ margin: "6px 0 0" }}>
                    Opens the block form with {alert.src_ip} and sensor #{alert.sensor_id} filled in; you choose how long.
                  </p>
                </div>
              )}
              {alert.case_id ? (
                <p style={{ margin: 0 }}>In <Link to={`/cases/${alert.case_id}`}>case #{alert.case_id}</Link>.</p>
              ) : (
                <>
                  <div className="row-actions" style={{ alignItems: "flex-end" }}>
                    <label className="field" style={{ flex: "1 1 160px" }}>Add to open case
                      <select value={caseId} onChange={(e) => setCaseId(e.target.value)}>
                        <option value="">Choose…</option>
                        {(cases?.items ?? []).map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
                      </select>
                    </label>
                    <button disabled={!caseId || act.busy} onClick={addToCase}>Add</button>
                  </div>
                  <div className="row-actions" style={{ alignItems: "flex-end" }}>
                    <label className="field" style={{ flex: "1 1 160px" }}>Or open a new case
                      <input value={newCase} maxLength={200} onChange={(e) => setNewCase(e.target.value)}
                        placeholder="Case title" />
                    </label>
                    <button disabled={!newCase.trim() || act.busy} onClick={createCase}>Create</button>
                  </div>
                </>
              )}
            </div>
          </Card>

          <Card title="What happened">
            <ErrorText error={blocks.error} />
            <Timeline items={timeline(alert, related, now)} />
            {blocks.data && related.length === 0 && (
              <p className="muted small-text" style={{ margin: "10px 0 0" }}>No block of {alert.src_ip} on this sensor around this alert.</p>
            )}
          </Card>
        </div>

        <div className="stack">
          <Card title="Why the model flagged this flow">
            <ExplanationChart explanation={alert.explanation} />
            <Link className="button-link" style={{ marginTop: 16 }} to={`/assistant${query({ alert: alert.id })}`}>
              Explain this alert with the assistant
            </Link>
          </Card>
          <Card title="Can I trust it?">
            <p className="muted" style={{ margin: 0 }}>
              How faithful this model's explanations are (how much more confidence drops when its top features
              are removed than when random ones are) appears here once sensors report their model to the SOC.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
