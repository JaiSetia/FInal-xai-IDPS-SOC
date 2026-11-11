import { useState } from "react";
import { api, query } from "../api/client";
import type { Action, ActionStatus, Page } from "../api/types";
import { Card, ErrorText, useAction, useLoad } from "../components/common";
import { dateTime, label } from "../format";

const STATUSES: ActionStatus[] = ["pending", "confirmed", "executed", "failed", "rejected"];

export default function Actions() {
  const [status, setStatus] = useState<string>("pending");
  const { data, error, reload } = useLoad(
    () => api<Page<Action>>(`/actions${query({ status, limit: 200 })}`), [status]);
  const act = useAction();

  async function decide(a: Action, decision: "confirm" | "reject") {
    const ip = String(a.params.ip ?? "");
    if (decision === "confirm" && !window.confirm(`Confirm: ${label(a.kind)} ${ip} on sensor #${a.sensor_id}?`)) return;
    const done = await act.run(() => api<Action>(`/actions/${a.id}/${decision}`, { method: "POST" }));
    if (done) void reload();
  }

  return (
    <>
      <h1>Actions</h1>
      <p className="muted">
        Requests sent to sensors. Suggestions from the assistant wait here as <b>pending</b> until an
        analyst confirms or rejects them; nothing runs before that.
      </p>
      <Card>
        <div className="toolbar">
          <label className="field">Status
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">any</option>
              {STATUSES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
        </div>
        <ErrorText error={error ?? act.error} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>#</th><th>Created</th><th>Action</th><th>Target</th><th>Sensor</th><th>Reason</th>
                <th>Proposed by</th><th>Status</th><th /></tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map((a) => (
                <tr key={a.id}>
                  <td>{a.id}</td>
                  <td>{dateTime(a.created_at)}</td>
                  <td>{label(a.kind)}</td>
                  <td className="mono">{String(a.params.ip ?? "")}</td>
                  <td>#{a.sensor_id}</td>
                  <td>{a.reason}</td>
                  <td>{a.proposed_by}</td>
                  <td>{a.status}{a.result && a.status === "failed" ? <span className="muted"> ({JSON.stringify(a.result)})</span> : null}</td>
                  <td>
                    {a.status === "pending" && (
                      <div className="row-actions">
                        <button className="primary" disabled={act.busy} onClick={() => decide(a, "confirm")}>Confirm</button>
                        <button disabled={act.busy} onClick={() => decide(a, "reject")}>Reject</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
              {data?.items.length === 0 && <tr><td colSpan={9} className="muted">Nothing here.</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
