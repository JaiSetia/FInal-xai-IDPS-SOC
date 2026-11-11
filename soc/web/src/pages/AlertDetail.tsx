import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, query } from "../api/client";
import { ALERT_STATUSES, type Action, type AlertDetail as AlertDetailT, type CaseDetail, type CaseSummary, type Page } from "../api/types";
import { Card, ErrorText, SeverityBadge, useAction, useLoad } from "../components/common";
import ExplanationChart from "../components/ExplanationChart";
import { dateTime, endpoint, label, num, percent, protocolName } from "../format";

export default function AlertDetail() {
  const { id: rawId } = useParams();
  // Only numeric ids reach the API path (a crafted link like /alerts/..%2Fadmin must not).
  const id = /^\d{1,18}$/.test(rawId ?? "") ? rawId! : "0";
  const { data: alert, error, setData } = useLoad(() => api<AlertDetailT>(`/alerts/${id}`), [id]);
  const { data: cases } = useLoad(
    () => api<Page<CaseSummary>>(`/cases${query({ status: "open", limit: 100 })}`), []);
  const act = useAction();
  const [notice, setNotice] = useState<string | null>(null);
  const [caseId, setCaseId] = useState("");
  const [newCase, setNewCase] = useState("");

  if (error) return <ErrorText error={error} />;
  if (!alert) return <p className="muted">Loading…</p>;

  async function setStatus(status: string) {
    const updated = await act.run(() =>
      api<AlertDetailT>(`/alerts/${id}`, { method: "PATCH", json: { status } }));
    if (updated) setData(updated);
  }

  async function blockSource() {
    if (!alert) return;
    const ok = window.confirm(
      `Ask sensor ${alert.sensor_id} to block ${alert.src_ip}? The block expires automatically.`);
    if (!ok) return;
    const action = await act.run(() => api<Action>("/actions", {
      method: "POST",
      json: { kind: "block_ip", ip: alert.src_ip, sensor_id: alert.sensor_id,
        reason: `alert #${alert.id}: ${alert.predicted_class}` },
    }));
    if (action) setNotice(`Block requested (action #${action.id}, ${action.status}).`);
  }

  async function addToCase() {
    if (!caseId) return;
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
      <p><Link to="/alerts">← Alerts</Link></p>
      <h1>Alert #{alert.id}: {alert.predicted_class} <SeverityBadge severity={alert.severity} /></h1>
      <ErrorText error={act.error} />
      {notice && <div className="notice">{notice}</div>}
      <div className="grid cols-2">
        <Card title="Flow">
          <dl className="kv">
            <dt>Source</dt><dd className="mono">{endpoint(alert.src_ip, alert.src_port, alert.protocol)}</dd>
            <dt>Destination</dt><dd className="mono">{endpoint(alert.dst_ip, alert.dst_port, alert.protocol)}</dd>
            <dt>Protocol</dt><dd>{protocolName(alert.protocol)}</dd>
            <dt>Flow time</dt><dd>{dateTime(alert.start_ms)} → {dateTime(alert.end_ms)}</dd>
            <dt>Received</dt><dd>{dateTime(alert.received_at)}</dd>
            <dt>Confidence</dt><dd>{percent(alert.confidence, 1)}</dd>
            <dt>Anomaly score</dt><dd>{num(alert.anomaly_score)}</dd>
            <dt>Sensor</dt><dd>#{alert.sensor_id}</dd>
            <dt>Case</dt><dd>{alert.case_id ? <Link to={`/cases/${alert.case_id}`}>#{alert.case_id}</Link> : "—"}</dd>
          </dl>
        </Card>
        <Card title="Triage">
          <div className="row-actions" style={{ marginBottom: 12 }}>
            {ALERT_STATUSES.map((s) => (
              <button key={s} disabled={act.busy || alert.status === s}
                className={alert.status === s ? "primary" : ""} onClick={() => setStatus(s)}>
                {label(s)}
              </button>
            ))}
          </div>
          <div className="row-actions" style={{ marginBottom: 12 }}>
            <button className="danger" disabled={act.busy} onClick={blockSource}>
              Block source IP
            </button>
          </div>
          {!alert.case_id && (
            <>
              <div className="toolbar">
                <label className="field">Add to open case
                  <select value={caseId} onChange={(e) => setCaseId(e.target.value)}>
                    <option value="">choose…</option>
                    {(cases?.items ?? []).map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
                  </select>
                </label>
                <button disabled={!caseId || act.busy} onClick={addToCase}>Add</button>
              </div>
              <div className="toolbar">
                <label className="field">Or open a new case
                  <input value={newCase} maxLength={200} onChange={(e) => setNewCase(e.target.value)}
                    placeholder="Case title" />
                </label>
                <button disabled={!newCase.trim() || act.busy} onClick={createCase}>Create</button>
              </div>
            </>
          )}
        </Card>
      </div>
      <Card title="Why the model flagged this flow">
        <ExplanationChart explanation={alert.explanation} />
      </Card>
    </>
  );
}
