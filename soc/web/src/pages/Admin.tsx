import { useState } from "react";
import { api, query } from "../api/client";
import type { AdminUser, AuditEntry, Page, Role, Sensor } from "../api/types";
import { useAuth } from "../auth";
import { Card, ErrorText, useAction, useLoad } from "../components/common";
import { dateTime } from "../format";

function Users() {
  const { me } = useAuth();
  const { data, error, reload } = useLoad(() => api<AdminUser[]>("/admin/users"), []);
  const act = useAction();
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" as Role });
  const [notice, setNotice] = useState<string | null>(null);

  async function create() {
    const u = await act.run(() => api<AdminUser>("/admin/users", { method: "POST", json: form }));
    if (u) {
      setForm({ username: "", password: "", role: "analyst" });
      setNotice(`Created ${u.role} ${u.username}.`);
      void reload();
    }
  }

  async function call(path: string, json?: unknown) {
    const r = await act.run(() => api<AdminUser>(path, { method: json ? "PATCH" : "POST", json }));
    if (r) void reload();
  }

  async function resetPassword(u: AdminUser) {
    const password = window.prompt(`New password for ${u.username} (at least 12 characters):`);
    if (!password) return;
    const r = await act.run(() => api<AdminUser>(`/admin/users/${u.id}/reset-password`, { method: "POST", json: { password } }));
    if (r) setNotice(`Password reset for ${u.username}; their existing sessions were signed out.`);
  }

  return (
    <Card title="Users">
      <ErrorText error={error ?? act.error} />
      {notice && <div className="notice">{notice}</div>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Role</th><th>State</th><th>Created</th><th /></tr></thead>
          <tbody>
            {(data ?? []).map((u) => (
              <tr key={u.id}>
                <td>{u.username}{u.id === me?.id && <span className="muted"> (you)</span>}</td>
                <td>
                  <select value={u.role} disabled={act.busy}
                    onChange={(e) => call(`/admin/users/${u.id}/role`, { role: e.target.value })}>
                    <option value="analyst">analyst</option>
                    <option value="admin">admin</option>
                  </select>
                </td>
                <td>{u.disabled ? "disabled" : "active"}</td>
                <td>{dateTime(u.created_at)}</td>
                <td className="row-actions">
                  <button disabled={act.busy} onClick={() => call(`/admin/users/${u.id}/${u.disabled ? "enable" : "disable"}`)}>
                    {u.disabled ? "Enable" : "Disable"}
                  </button>
                  <button disabled={act.busy} onClick={() => resetPassword(u)}>Reset password</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <form className="toolbar" style={{ marginTop: 12 }} onSubmit={(e) => { e.preventDefault(); void create(); }}>
        <label className="field">Username
          <input value={form.username} maxLength={64} required onChange={(e) => setForm({ ...form, username: e.target.value })} />
        </label>
        <label className="field">Password (12+ characters)
          <input type="password" autoComplete="new-password" value={form.password} minLength={12} required
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </label>
        <label className="field">Role
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <button className="primary" disabled={act.busy}>Add user</button>
      </form>
    </Card>
  );
}

function Sensors() {
  const { data, error, reload } = useLoad(() => api<Sensor[]>("/admin/sensors"), []);
  const act = useAction();
  const [name, setName] = useState("");
  const [token, setToken] = useState<{ name: string; token: string } | null>(null);

  async function create() {
    const s = await act.run(() => api<Sensor & { token: string }>("/admin/sensors", { method: "POST", json: { name: name.trim() } }));
    if (s) {
      setToken({ name: s.name, token: s.token });
      setName("");
      void reload();
    }
  }

  async function revoke(s: Sensor) {
    if (!window.confirm(`Revoke sensor ${s.name}? It can no longer send alerts.`)) return;
    const r = await act.run(() => api<Sensor>(`/admin/sensors/${s.id}/revoke`, { method: "POST" }));
    if (r) void reload();
  }

  return (
    <Card title="Sensors">
      <ErrorText error={error ?? act.error} />
      {token && (
        <div className="card" style={{ background: "var(--surface-2)" }}>
          <b>Token for {token.name}</b>. Copy it now: it is shown only once.
          <pre className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{token.token}</pre>
          <button onClick={() => setToken(null)}>I've stored it</button>
        </div>
      )}
      <table>
        <thead><tr><th>#</th><th>Name</th><th>State</th><th>Created</th><th /></tr></thead>
        <tbody>
          {(data ?? []).map((s) => (
            <tr key={s.id}>
              <td>{s.id}</td><td>{s.name}</td><td>{s.revoked ? "revoked" : "active"}</td>
              <td>{dateTime(s.created_at)}</td>
              <td>{!s.revoked && <button disabled={act.busy} onClick={() => revoke(s)}>Revoke</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <form className="toolbar" style={{ marginTop: 12 }} onSubmit={(e) => { e.preventDefault(); if (name.trim()) void create(); }}>
        <label className="field">New sensor name
          <input value={name} maxLength={64} onChange={(e) => setName(e.target.value)} placeholder="lab-sensor" />
        </label>
        <button className="primary" disabled={!name.trim() || act.busy}>Add sensor</button>
      </form>
    </Card>
  );
}

function Audit() {
  const [actor, setActor] = useState("");
  const { data, error } = useLoad(() => api<Page<AuditEntry>>(`/admin/audit${query({ actor, limit: 200 })}`), [actor]);
  return (
    <Card title="Audit log">
      <div className="toolbar">
        <label className="field">Actor
          <input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="any" />
        </label>
      </div>
      <ErrorText error={error} />
      <div className="table-wrap">
        <table>
          <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
          <tbody>
            {(data?.items ?? []).map((e) => (
              <tr key={e.id}>
                <td>{dateTime(e.at)}</td>
                <td>{e.actor_type}: {e.actor_name}</td>
                <td>{e.action}</td>
                <td className="mono">{e.target}</td>
                <td className="mono muted" style={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {JSON.stringify(e.details)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export default function Admin() {
  return (
    <>
      <h1>Admin</h1>
      <Users />
      <Sensors />
      <Audit />
    </>
  );
}
