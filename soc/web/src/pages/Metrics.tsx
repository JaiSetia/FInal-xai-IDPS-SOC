import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, query } from "../api/client";
import { SEVERITIES, type MetricsSummary } from "../api/types";
import { Card, ErrorText, useLoad } from "../components/common";
import { percent } from "../format";

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="card stat" style={{ marginBottom: 0 }}>
      <div className="value">{value}</div>
      <div className="label">{label}</div>
    </div>
  );
}

// SVG presentation attributes don't resolve CSS variables, so read the theme's actual colours
// (and follow light/dark changes).
function useThemeColours() {
  const read = () => {
    const css = getComputedStyle(document.documentElement);
    const get = (name: string) => css.getPropertyValue(name).trim();
    return { accent: get("--accent"), muted: get("--muted"), border: get("--border"), surface: get("--surface") };
  };
  const [colours, setColours] = useState(read);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const update = () => setColours(read());
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);
  return colours;
}

function seconds(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  const s = ms / 1000;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

export default function Metrics() {
  const c = useThemeColours();
  const axis = { fill: c.muted, fontSize: 12 };
  const tooltip = { background: c.surface, border: `1px solid ${c.border}` };
  const [hours, setHours] = useState(24);
  const { data: m, error } = useLoad(() => api<MetricsSummary>(`/metrics/summary${query({ hours })}`), [hours]);

  const series = (m?.alerts_per_bucket ?? []).map((b) => ({
    t: new Date(b.start).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), count: b.count }));
  const byClass = Object.entries(m?.by_class ?? {}).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count }));
  const latency = m?.detection_latency;

  return (
    <>
      <h1>Metrics</h1>
      <div className="toolbar">
        <label className="field">Window
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {[1, 6, 24, 72, 168].map((h) => <option key={h} value={h}>last {h} h</option>)}
          </select>
        </label>
      </div>
      <ErrorText error={error} />
      {m && (
        <>
          <div className="grid cols-4" style={{ marginBottom: 16 }}>
            <Stat label="Alerts" value={m.alerts_total} />
            <Stat label="Active blocks" value={m.active_blocks} />
            <Stat label={`False-positive rate (${m.false_positives}/${m.triaged} triaged)`} value={percent(m.false_positive_rate, 1)} />
            <Stat label="Detection latency p50 / p95"
              value={`${seconds(latency?.p50_ms)} / ${seconds(latency?.p95_ms)}`} />
          </div>
          <div className="grid cols-2">
            <Card title="Alerts over time">
              <div style={{ height: 240 }}>
                <ResponsiveContainer>
                  <LineChart data={series} margin={{ top: 8, right: 12, bottom: 0, left: -10 }}>
                    <CartesianGrid stroke={c.border} strokeDasharray="3 3" />
                    <XAxis dataKey="t" tick={axis} stroke={c.border} minTickGap={24} />
                    <YAxis allowDecimals={false} tick={axis} stroke={c.border} />
                    <Tooltip contentStyle={tooltip} />
                    <Line type="monotone" dataKey="count" stroke={c.accent} strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card title="Alerts by class">
              <div style={{ height: 240 }}>
                <ResponsiveContainer>
                  <BarChart data={byClass} layout="vertical" margin={{ top: 4, right: 12, bottom: 0, left: 40 }}>
                    <CartesianGrid stroke={c.border} strokeDasharray="3 3" horizontal={false} />
                    <XAxis type="number" allowDecimals={false} tick={axis} stroke={c.border} />
                    <YAxis type="category" dataKey="name" width={110} tick={axis} stroke={c.border} />
                    <Tooltip contentStyle={tooltip} />
                    <Bar dataKey="count" fill={c.accent} radius={[0, 3, 3, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card title="By severity">
              <table>
                <tbody>
                  {SEVERITIES.slice().reverse().map((s) => (
                    <tr key={s}><td><span className={`badge sev-${s}`}>{s}</span></td><td>{m.by_severity[s] ?? 0}</td></tr>
                  ))}
                </tbody>
              </table>
            </Card>
            <Card title="Top source IPs">
              <table>
                <thead><tr><th>IP</th><th>Alerts</th></tr></thead>
                <tbody>
                  {m.top_sources.map((s) => <tr key={s.ip}><td className="mono">{s.ip}</td><td>{s.count}</td></tr>)}
                  {m.top_sources.length === 0 && <tr><td colSpan={2} className="muted">No alerts in this window.</td></tr>}
                </tbody>
              </table>
            </Card>
          </div>
        </>
      )}
    </>
  );
}
