import { useState } from "react";
import { Link } from "react-router-dom";
import { api, query } from "../api/client";
import type { Action, Block, Page } from "../api/types";
import { Card, ErrorText, useAction, useLoad } from "../components/common";
import { dateTime } from "../format";

export default function Blocks() {
  const [active, setActive] = useState(true);
  const { data, error, reload } = useLoad(
    () => api<Page<Block>>(`/blocks${query({ active: active ? true : undefined, limit: 200 })}`), [active]);
  const act = useAction();
  const [notice, setNotice] = useState<string | null>(null);

  async function unblock(b: Block) {
    if (!window.confirm(`Ask sensor #${b.sensor_id} to unblock ${b.ip}?`)) return;
    const a = await act.run(() => api<Action>("/actions", {
      method: "POST",
      json: { kind: "unblock_ip", ip: b.ip, sensor_id: b.sensor_id, reason: `analyst unblock of block #${b.id}` },
    }));
    if (a) {
      setNotice(`Unblock requested (action #${a.id}). The list updates when the sensor reports back.`);
      void reload();
    }
  }

  return (
    <>
      <h1>Blocks</h1>
      <Card>
        <div className="toolbar">
          <label className="field">Show
            <select value={active ? "active" : "all"} onChange={(e) => setActive(e.target.value === "active")}>
              <option value="active">active only</option>
              <option value="all">all</option>
            </select>
          </label>
        </div>
        <ErrorText error={error ?? act.error} />
        {notice && <div className="notice">{notice}</div>}
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>IP</th><th>Sensor</th><th>Source</th><th>Reason</th><th>Blocked</th><th>Expires</th>
                <th>Alert</th><th /></tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map((b) => (
                <tr key={b.id}>
                  <td className="mono">{b.ip}</td>
                  <td>#{b.sensor_id}</td>
                  <td>{b.source}</td>
                  <td>{b.reason}</td>
                  <td>{dateTime(b.blocked_at)}</td>
                  <td>{b.active ? dateTime(b.expires_at) : `ended ${dateTime(b.unblocked_at ?? b.expires_at)}`}</td>
                  <td>{b.alert_id ? <Link to={`/alerts/${b.alert_id}`}>#{b.alert_id}</Link> : "—"}</td>
                  <td>{b.active && <button disabled={act.busy} onClick={() => unblock(b)}>Unblock</button>}</td>
                </tr>
              ))}
              {data?.items.length === 0 && <tr><td colSpan={8} className="muted">No blocks.</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
