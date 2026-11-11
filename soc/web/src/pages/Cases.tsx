import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, query } from "../api/client";
import { CASE_STATUSES, type CaseDetail, type CaseSummary, type Page } from "../api/types";
import { Card, ErrorText, useAction, useLoad } from "../components/common";
import { dateTime } from "../format";

export default function Cases() {
  const navigate = useNavigate();
  const [status, setStatus] = useState("");
  const [title, setTitle] = useState("");
  const { data, error } = useLoad(() => api<Page<CaseSummary>>(`/cases${query({ status, limit: 200 })}`), [status]);
  const act = useAction();

  async function create() {
    const c = await act.run(() => api<CaseDetail>("/cases", { method: "POST", json: { title: title.trim(), alert_ids: [] } }));
    if (c) navigate(`/cases/${c.id}`);
  }

  return (
    <>
      <h1>Cases</h1>
      <Card>
        <div className="toolbar">
          <label className="field">Status
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">any</option>
              {CASE_STATUSES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
          <form className="toolbar" style={{ marginLeft: "auto", marginBottom: 0 }}
            onSubmit={(e) => { e.preventDefault(); if (title.trim()) void create(); }}>
            <label className="field">New case
              <input value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} placeholder="Title" />
            </label>
            <button className="primary" disabled={!title.trim() || act.busy}>Create</button>
          </form>
        </div>
        <ErrorText error={error ?? act.error} />
        <div className="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Title</th><th>Status</th><th>Alerts</th><th>Updated</th></tr></thead>
            <tbody>
              {(data?.items ?? []).map((c) => (
                <tr key={c.id}>
                  <td>{c.id}</td>
                  <td><Link to={`/cases/${c.id}`}>{c.title}</Link></td>
                  <td>{c.status}</td>
                  <td>{c.alert_count}</td>
                  <td>{dateTime(c.updated_at)}</td>
                </tr>
              ))}
              {data?.items.length === 0 && <tr><td colSpan={5} className="muted">No cases.</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
