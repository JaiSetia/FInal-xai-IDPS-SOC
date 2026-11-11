import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { CASE_STATUSES, type CaseDetail as CaseDetailT, type Note } from "../api/types";
import { Card, ErrorText, SeverityBadge, useAction, useLoad } from "../components/common";
import { dateTime, endpoint } from "../format";

export default function CaseDetail() {
  const { id: rawId } = useParams();
  // Only numeric ids reach the API path (a crafted link like /alerts/..%2Fadmin must not).
  const id = /^\d{1,18}$/.test(rawId ?? "") ? rawId! : "0";
  const navigate = useNavigate();
  const { data: c, error, setData, reload } = useLoad(() => api<CaseDetailT>(`/cases/${id}`), [id]);
  const act = useAction();
  const [note, setNote] = useState("");

  if (error) return <ErrorText error={error} />;
  if (!c) return <p className="muted">Loading…</p>;

  async function setStatus(status: string) {
    const updated = await act.run(() => api<CaseDetailT>(`/cases/${id}`, { method: "PATCH", json: { status } }));
    if (updated) setData(updated);
  }

  async function addNote() {
    const n = await act.run(() => api<Note>(`/cases/${id}/notes`, { method: "POST", json: { text: note.trim() } }));
    if (n) {
      setData({ ...c!, notes: [...c!.notes, n] });
      setNote("");
    }
  }

  async function detach(alertId: number) {
    const ok = await act.run(() => api(`/cases/${id}/alerts/${alertId}`, { method: "DELETE" }));
    if (ok !== undefined) void reload();
  }

  async function remove() {
    if (!window.confirm(`Delete case #${c!.id}? Its notes are deleted; its alerts stay.`)) return;
    const ok = await act.run(() => api(`/cases/${id}`, { method: "DELETE" }));
    if (ok !== undefined) navigate("/cases");
  }

  return (
    <>
      <p><Link to="/cases">← Cases</Link></p>
      <h1>Case #{c.id}: {c.title}</h1>
      <ErrorText error={act.error} />
      <Card title="Status" actions={<button className="danger" onClick={remove} disabled={act.busy}>Delete case</button>}>
        <div className="row-actions">
          {CASE_STATUSES.map((s) => (
            <button key={s} className={c.status === s ? "primary" : ""} disabled={act.busy || c.status === s}
              onClick={() => setStatus(s)}>{s}</button>
          ))}
        </div>
        <p className="muted">Opened {dateTime(c.created_at)} · updated {dateTime(c.updated_at)}</p>
      </Card>
      <Card title={`Alerts (${c.alerts.length})`}>
        <div className="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Severity</th><th>Class</th><th>Source</th><th>Destination</th><th>Received</th><th /></tr></thead>
            <tbody>
              {c.alerts.map((a) => (
                <tr key={a.id}>
                  <td><Link to={`/alerts/${a.id}`}>{a.id}</Link></td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td>{a.predicted_class}</td>
                  <td className="mono">{endpoint(a.src_ip, a.src_port, a.protocol)}</td>
                  <td className="mono">{endpoint(a.dst_ip, a.dst_port, a.protocol)}</td>
                  <td>{dateTime(a.received_at)}</td>
                  <td><button disabled={act.busy} onClick={() => detach(a.id)}>Remove</button></td>
                </tr>
              ))}
              {c.alerts.length === 0 && <tr><td colSpan={7} className="muted">Add alerts from an alert's page.</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Notes">
        {c.notes.map((n) => (
          <div key={n.id} style={{ borderBottom: "1px solid var(--border)", padding: "8px 0" }}>
            <div className="muted" style={{ fontSize: 12 }}>{n.author ?? "unknown"} · {dateTime(n.created_at)}</div>
            <div style={{ whiteSpace: "pre-wrap" }}>{n.text}</div>
          </div>
        ))}
        <div style={{ marginTop: 10 }}>
          <textarea value={note} maxLength={10_000} onChange={(e) => setNote(e.target.value)} placeholder="Add a note" />
          <button className="primary" style={{ marginTop: 6 }} disabled={!note.trim() || act.busy} onClick={addNote}>
            Add note
          </button>
        </div>
      </Card>
    </>
  );
}
