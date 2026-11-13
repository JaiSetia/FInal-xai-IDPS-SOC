import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, query } from "../api/client";
import { SEVERITIES, type Action, type Alert, type Block, type MetricsSummary, type Page, type Severity } from "../api/types";
import {
  Card, ConfidenceBar, Countdown, ErrorText, PageHead, Pill, SeverityBadge, StatusText, useLoad, useNow,
} from "../components/common";
import { endpoint, percent } from "../format";
import { useLiveRefresh } from "../useLiveRefresh";
import { actionSummary, who } from "./Response";
import type { Topology } from "./TopologyMap";

/** Threat Center, the home page (wireframe screen 1): map, KPIs, classes, live alerts,
 *  firewall, pending decisions, sensor health and a topology summary.
 *  Cards whose data the sensors don't report yet (class by day, sensor health) say so
 *  instead of showing made-up numbers. */

const WorldMap = lazy(() => import("./WorldMap"));

export const TC_WINDOWS = [1, 24, 168];
const DEFAULT_HOURS = 24;
const LIVE_ROWS = 10;
const SEV_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function windowText(h: number): string {
  return h < 24 ? `Last ${h} h` : h === 24 ? "Last 24 h" : `Last ${h / 24} days`;
}

function seconds(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  const s = ms / 1000;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

/** "just now", "4 min ago", "3 h ago", "2 d ago". */
export function ago(iso: string, now: number): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:.]+)$/i;

/** Where the search box sends a query: an alert number, an IP, or a class name.
 *  The API matches class names exactly, so a known class is matched ignoring case, and a
 *  part of a name ("dos") picks the class when only one known class contains it. */
export function searchTarget(raw: string, knownClasses: string[] = []): string | null {
  const q = raw.trim();
  if (!q) return null;
  if (/^#?\d+$/.test(q)) return `/alerts/${q.replace("#", "")}`;
  if (IP_RE.test(q)) return `/alerts${query({ ip: q })}`;
  const lower = q.toLowerCase();
  const known = knownClasses.filter((c) => c !== OTHER);
  const exact = known.find((c) => c.toLowerCase() === lower);
  const partial = known.filter((c) => c.toLowerCase().includes(lower));
  const name = exact ?? (partial.length === 1 ? partial[0] : q);
  return `/alerts${query({ class: name })}`;
}

/** The API folds rare classes into this bucket; it isn't a real class name to filter by. */
const OTHER = "(other)";

/** Bars for alerts per time bucket; the tallest bucket is drawn darker. */
function SparkBars({ counts }: { counts: number[] }) {
  if (counts.length === 0) return null;
  const w = 130;
  const h = 54;
  const max = Math.max(1, ...counts);
  const step = w / counts.length;
  const peak = counts.indexOf(Math.max(...counts));
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden="true" className="sparkbars">
      {counts.map((c, i) => {
        const bh = Math.max(2, (c / max) * (h - 4));
        return <rect key={i} x={i * step + step * 0.15} y={h - bh} width={Math.max(1, step * 0.7)} height={bh}
          rx={Math.min(2, step * 0.3)} className={i === peak && c > 0 ? "peak" : undefined} />;
      })}
    </svg>
  );
}

function Kpi({ title, value, sub, children }: { title: string; value: string; sub?: string; children?: ReactNode }) {
  return (
    <Card title={title} className="kpi">
      <div className="kpi-body">
        <div>
          <div className="kpi-value">{value}</div>
          {sub && <div className="muted small-text">{sub}</div>}
        </div>
        {children}
      </div>
    </Card>
  );
}

type SortKey = "newest" | "severity" | "confidence";

function LiveAlerts({ blocks }: { blocks: Block[] }) {
  const navigate = useNavigate();
  const now = useNow(10_000);
  const [sort, setSort] = useState<SortKey>("newest");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [fresh, setFresh] = useState<Set<number>>(new Set());
  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);
  const { data, error, setData, reload } = useLoad(
    () => api<Page<Alert>>(`/alerts${query({ severity: severity || undefined, limit: LIVE_ROWS })}`).then((p) => p.items),
    [severity]);

  const live = useLiveRefresh(reload, useCallback((a: Alert) => {
    if (severity && a.severity !== severity) return;
    setData((rows) => (rows && !rows.some((r) => r.id === a.id) ? [a, ...rows].slice(0, LIVE_ROWS) : rows));
    setFresh((s) => new Set(s).add(a.id));
    // The highlight animation lasts 1.6 s; forget the id after that.
    const t = setTimeout(() => {
      timers.current.delete(t);
      setFresh((s) => { const next = new Set(s); next.delete(a.id); return next; });
    }, 2000);
    timers.current.add(t);
  }, [severity, setData]));

  // An address's newest unexpired active block decides its Response column.
  const blockedBy = useMemo(() => {
    const m = new Map<string, Block["source"]>();
    for (const b of blocks) {
      if (b.active && (!b.expires_at || Date.parse(b.expires_at) > now) && !m.has(b.ip)) m.set(b.ip, b.source);
    }
    return m;
  }, [blocks, now]);

  const rows = useMemo(() => {
    const list = [...(data ?? [])];
    if (sort === "severity") list.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.id - a.id);
    else if (sort === "confidence") list.sort((a, b) => b.confidence - a.confidence || b.id - a.id);
    else list.sort((a, b) => b.id - a.id);
    return list;
  }, [data, sort]);

  return (
    <Card title="Live alerts" className="tc-live" actions={
      <div className="row-actions" style={{ alignItems: "center" }}>
        <label className="field inline">Sort
          <select value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
            <option value="newest">newest</option>
            <option value="severity">severity</option>
            <option value="confidence">confidence</option>
          </select>
        </label>
        <label className="field inline">Severity
          <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
            <option value="">any</option>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <span className="muted small-text">
          <span className={`live-dot ${live ? "on" : "off"}`} />{live ? "Live" : "Live feed offline"}
        </span>
      </div>
    }>
      <ErrorText error={error} />
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Class</th><th>Source → target</th><th>Confidence</th><th>Severity</th><th>Status</th><th>Response</th></tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const src = blockedBy.get(a.src_ip);
              return (
                <tr key={a.id} className={`clickable${fresh.has(a.id) ? " fresh" : ""}`} onClick={() => navigate(`/alerts/${a.id}`)}>
                  <td>
                    <Link to={`/alerts/${a.id}`} onClick={(e) => e.stopPropagation()}><b>{a.predicted_class}</b></Link>
                    <div className="muted small-text">#{a.id} · {ago(a.received_at, now)}</div>
                  </td>
                  <td className="mono">{a.src_ip} → {endpoint(a.dst_ip, a.dst_port, a.protocol)}</td>
                  <td><ConfidenceBar value={a.confidence} digits={1} /></td>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td><StatusText value={a.status} /></td>
                  <td>{src ? <Pill tone="danger">blocked · {src}</Pill> : <Pill>observe</Pill>}</td>
                </tr>
              );
            })}
            {data && rows.length === 0 && (
              <tr><td colSpan={6} className="muted">No alerts yet{severity ? ` with severity ${severity}` : ""}.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <Link to="/alerts">Open all alerts →</Link>
    </Card>
  );
}

function Firewall({ blocks, more, error }: { blocks: Block[] | null; more: boolean; error: string | null }) {
  const now = useNow();
  // Hide a block once its time has run out, before the next refresh drops it.
  const active = (blocks ?? []).filter((b) => b.active && (!b.expires_at || Date.parse(b.expires_at) > now));
  const n = `${active.length}${more ? "+" : ""}`;
  return (
    <Card title="Firewall · nftables" actions={blocks && <Pill tone={active.length ? "danger" : "neutral"}>{n} active</Pill>}>
      <ErrorText error={error} />
      <ul className="queue-list tc-stacked">
        {active.slice(0, 3).map((b) => (
          <li key={b.id} className="tc-block">
            <div className="tc-block-head">
              <Link to={`/alerts${query({ ip: b.ip })}`} className="mono"><b>{b.ip}</b></Link>
              <Countdown start={b.blocked_at} end={b.expires_at} />
            </div>
            <span className="muted small-text">{b.source} · {b.reason || "no reason given"}</span>
          </li>
        ))}
        {blocks && active.length === 0 && <li className="muted">No address is blocked right now.</li>}
      </ul>
      <Link to="/response">{active.length > 3 ? `All ${n} blocks →` : "All blocks →"}</Link>
    </Card>
  );
}

function Decisions() {
  const pending = useLoad(() => api<Page<Action>>(`/actions${query({ status: "pending", limit: 20 })}`), []);
  // Pending actions don't change with alerts, so this polls instead of following the live feed.
  const reloadPending = pending.reload;
  useEffect(() => {
    const id = setInterval(() => void reloadPending(), 15_000);
    return () => clearInterval(id);
  }, [reloadPending]);
  const items = pending.data?.items ?? [];
  const n = pending.data ? (pending.data.next_cursor ? `${items.length}+` : String(items.length)) : null;
  return (
    <Card title="Needs your decision" actions={n !== null && <Pill tone={items.length ? "warn" : "neutral"}>{n} pending</Pill>}>
      <ErrorText error={pending.error} />
      <ul className="queue-list tc-stacked">
        {items.slice(0, 3).map((a) => (
          <li key={a.id}>
            <span className="eyebrow">Proposed by {who(a)}</span>
            <b>{actionSummary(a)}</b>
            {a.reason && <span className="muted">“{a.reason}”</span>}
          </li>
        ))}
        {pending.data && items.length === 0 && <li className="muted">Nothing waits for a decision.</li>}
      </ul>
      {items.length > 0 && <Link to="/response" className="button-link">Decide in Response →</Link>}
      <p className="muted small-text" style={{ margin: "10px 0 0" }}>
        The sensor polls every 5 s; its allowlist and dry-run setting still apply.
      </p>
    </Card>
  );
}

function SensorHealth() {
  return (
    <Card title="Sensor health" actions={<Pill>waiting for data</Pill>}>
      <p className="muted" style={{ margin: 0 }}>
        Sensors don't report their status to the SOC yet (model, heartbeat, outbox, allowlist).
        This card fills in once they do.
      </p>
    </Card>
  );
}

function TopologySummary({ hours }: { hours: number }) {
  const { data, error, reload } = useLoad(() => api<Topology>(`/topology${query({ hours })}`), [hours]);
  useLiveRefresh(reload, undefined, 60_000);
  const edges = [...(data?.edges ?? [])].sort((a, b) => b.count - a.count).slice(0, 4);
  return (
    <Card title="Topology" actions={<Link to="/maps">Open →</Link>}>
      <ErrorText error={error} />
      {data && (
        <>
          <p className="muted small-text" style={{ marginTop: 0 }}>
            {data.nodes.length} hosts · {data.edges.length} links, {windowText(hours).toLowerCase()}
          </p>
          <ul className="queue-list">
            {edges.map((e) => (
              <li key={`${e.src}>${e.dst}`} className="tc-edge">
                <span className="mono wrap-anywhere">{e.src} → {e.dst}</span>
                <span className={`badge sev-${e.max_severity}`} title={`highest severity: ${e.max_severity}`}>
                  {e.count}<span className="sr-only"> alerts, highest severity {e.max_severity}</span>
                </span>
              </li>
            ))}
            {edges.length === 0 && <li className="muted">No traffic with alerts in this window.</li>}
          </ul>
        </>
      )}
    </Card>
  );
}

function Classes({ m }: { m: MetricsSummary }) {
  const byClass = Object.entries(m.by_class).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...byClass.map(([, c]) => c));
  return (
    <Card title="Attack classes" className="tc-classes">
      {byClass.length === 0
        ? <p className="muted">No alerts in this window.</p>
        : (
          <ul className="class-bars">
            {byClass.slice(0, 6).map(([name, count]) => (
              <li key={name}>
                {name === OTHER
                  ? <span className="muted">other classes</span>
                  : <Link to={`/alerts${query({ class: name })}`}>{name}</Link>}
                <span className="class-track" aria-hidden="true"><span style={{ width: `${(count / max) * 100}%` }} /></span>
                <span className="num">{count.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        )}
      <p className="muted small-text">
        Totals for the window. A day-by-day view needs per-day counts from the API (planned).
      </p>
      <h3 style={{ marginTop: 14 }}>Top source IPs</h3>
      <ul className="queue-list">
        {m.top_sources.slice(0, 4).map((s) => (
          <li key={s.ip} className="tc-edge">
            <Link to={`/alerts${query({ ip: s.ip })}`} className="mono">{s.ip}</Link>
            <span className="muted">{s.count.toLocaleString()} alerts</span>
          </li>
        ))}
        {m.top_sources.length === 0 && <li className="muted">None in this window.</li>}
      </ul>
    </Card>
  );
}

export default function ThreatCenter() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const asked = Number(params.get("hours"));
  const hours = TC_WINDOWS.includes(asked) ? asked : DEFAULT_HOURS;
  const [search, setSearch] = useState("");

  const metrics = useLoad(() => api<MetricsSummary>(`/metrics/summary${query({ hours })}`), [hours]);
  const blocks = useLoad(() => api<Page<Block>>(`/blocks${query({ active: true, limit: 200 })}`), []);
  const reloadAll = useCallback(() => { void metrics.reload(); void blocks.reload(); }, [metrics.reload, blocks.reload]);
  useLiveRefresh(reloadAll);

  function onSearch(e: FormEvent) {
    e.preventDefault();
    const to = searchTarget(search, Object.keys(metrics.data?.by_class ?? {}));
    if (to) navigate(to);
  }

  const m = metrics.data;
  const latency = m?.detection_latency;
  const classLine = m
    ? Object.entries(m.by_class).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([c, n]) => `${c} ${n.toLocaleString()}`).join(" · ")
    : "";

  return (
    <>
      <PageHead title="Threat Center">
        <form role="search" onSubmit={onSearch} className="tc-search">
          <input type="search" aria-label="Search alerts" value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="IP, alert #, or class" />
          <button type="submit">Search</button>
        </form>
        <label className="field inline">Window
          <select value={hours} onChange={(e) => {
            const h = Number(e.target.value);
            setParams(h === DEFAULT_HOURS ? {} : { hours: String(h) }, { replace: true });
          }}>
            {TC_WINDOWS.map((h) => <option key={h} value={h}>{windowText(h)}</option>)}
          </select>
        </label>
      </PageHead>
      <ErrorText error={metrics.error} />

      <div className="tc-row1">
        <div className="stack">
          <Suspense fallback={<Card title="Live attack map"><p className="muted">Loading map…</p></Card>}>
            <WorldMap hours={hours} compact />
          </Suspense>
        </div>
        <div className="stack">
          <div className="tc-kpis">
            <Kpi title="Alerts" value={m ? m.alerts_total.toLocaleString() : "…"} sub={classLine || undefined}>
              <SparkBars counts={(m?.alerts_per_bucket ?? []).map((b) => b.count)} />
            </Kpi>
            <Kpi title="Detection latency (p50)" value={seconds(latency?.p50_ms)}
              sub={latency ? `p95 ${seconds(latency.p95_ms)}` : undefined} />
            <Kpi title="Active blocks" value={m ? String(m.active_blocks) : "…"} />
            <Kpi title="False positives" value={m ? percent(m.false_positive_rate, 1) : "…"}
              sub={m ? `${m.false_positives} of ${m.triaged} triaged` : undefined} />
          </div>
          <p className="muted small-text" style={{ margin: 0 }}>
            A flow is reported when it ends (120 s idle timeout), so alerts trail the traffic by about 2 minutes.
          </p>
          {m && <Classes m={m} />}
        </div>
      </div>

      <LiveAlerts blocks={blocks.data?.items ?? []} />

      <div className="tc-row3">
        <Firewall blocks={blocks.data?.items ?? null} more={!!blocks.data?.next_cursor} error={blocks.error} />
        <Decisions />
        <SensorHealth />
        <TopologySummary hours={hours} />
      </div>
    </>
  );
}
