import "@xyflow/react/dist/style.css";
import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, query } from "../api/client";
import type { Severity } from "../api/types";
import { ErrorText, SeverityBadge, useLoad } from "../components/common";
import { useLiveRefresh } from "../useLiveRefresh";

interface TopoNode { ip: string; alert_count: number; max_severity: Severity }
interface TopoEdge { src: string; dst: string; count: number; max_severity: Severity }
interface Topology { hours: number; nodes: TopoNode[]; edges: TopoEdge[] }

interface SimNode extends SimulationNodeDatum { id: string }

/** Stable positions from a short force simulation (deterministic: fixed seed positions). */
function layout(topo: Topology): Map<string, { x: number; y: number }> {
  const n = topo.nodes.length;
  const nodes: SimNode[] = topo.nodes.map((t, i) => ({
    id: t.ip,
    x: 400 + 300 * Math.cos((2 * Math.PI * i) / Math.max(n, 1)),
    y: 300 + 300 * Math.sin((2 * Math.PI * i) / Math.max(n, 1)),
  }));
  const links: SimulationLinkDatum<SimNode>[] = topo.edges.map((e) => ({ source: e.src, target: e.dst }));
  const sim = forceSimulation(nodes)
    .force("link", forceLink<SimNode, SimulationLinkDatum<SimNode>>(links).id((d) => d.id).distance(170))
    .force("charge", forceManyBody().strength(-500))
    .force("collide", forceCollide(70))
    .force("center", forceCenter(400, 300))
    .stop();
  for (let i = 0; i < 300; i++) sim.tick();
  return new Map(nodes.map((d) => [d.id, { x: d.x ?? 0, y: d.y ?? 0 }]));
}

function subnet(ip: string): string {
  if (ip.includes(":")) return "IPv6";
  const parts = ip.split(".");
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : "";
}

export default function TopologyMap() {
  const navigate = useNavigate();
  const [hours, setHours] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const { data, error, reload } = useLoad(() => api<Topology>(`/topology${query({ hours })}`), [hours]);
  const live = useLiveRefresh(reload);

  // The force layout is the slow part: recompute it only when the data changes.
  const positions = useMemo(() => (data ? layout(data) : new Map<string, { x: number; y: number }>()), [data]);
  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], edges: [] as Edge[] };
    const pos = positions;
    const nodes: Node[] = data.nodes.map((t) => ({
      id: t.ip,
      position: pos.get(t.ip) ?? { x: 0, y: 0 },
      data: {
        label: (
          <div>
            <div className="mono" style={{ fontWeight: 600 }}>{t.ip}</div>
            <div className="muted" style={{ fontSize: 11 }}>{subnet(t.ip)} · {t.alert_count} alerts</div>
          </div>
        ),
      },
      className: `topo-node sev-border-${t.max_severity}${selected === t.ip ? " selected" : ""}`,
      style: { width: 170 },
    }));
    const edges: Edge[] = data.edges.map((e) => ({
      id: `${e.src}->${e.dst}`,
      source: e.src,
      target: e.dst,
      label: String(e.count),
      animated: e.max_severity === "high" || e.max_severity === "critical",
      className: `topo-edge sev-stroke-${e.max_severity}`,
      labelStyle: { fill: "var(--text)", fontSize: 11 },
      labelBgStyle: { fill: "var(--surface)" },
      markerEnd: { type: MarkerType.ArrowClosed },
    }));
    return { nodes, edges };
  }, [data, positions, selected]);

  const sel = data?.nodes.find((n) => n.ip === selected) ?? null;
  const selEdges = data?.edges.filter((e) => e.src === selected || e.dst === selected) ?? [];

  return (
    <>
      <h1>Network topology</h1>
      <div className="toolbar">
        <label className="field">Window
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {[1, 6, 24, 72, 168].map((h) => <option key={h} value={h}>last {h} h</option>)}
          </select>
        </label>
        <span className="muted">Hosts seen in alerts. Arrows point from source to target; moving lines are high or critical.</span>
        <span className="muted" style={{ marginLeft: "auto" }}>
          <span className={`live-dot ${live ? "on" : "off"}`} />{live ? "Live" : "Live feed offline"}
        </span>
      </div>
      <ErrorText error={error} />
      <div className="grid cols-topo">
        <div className="card topo-canvas" style={{ padding: 0 }}>
          {data && data.nodes.length === 0 ? (
            <p className="muted" style={{ padding: 16 }}>No alerts in this window.</p>
          ) : (
            <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.2} nodesConnectable={false}
              onNodeClick={(_, n) => setSelected(n.id)} onPaneClick={() => setSelected(null)}
              proOptions={{ hideAttribution: false }}>
              <Background />
              <Controls showInteractive={false} />
            </ReactFlow>
          )}
        </div>
        <div className="card">
          {sel ? (
            <>
              <h2 className="mono">{sel.ip}</h2>
              <p>{sel.alert_count} alerts · highest <SeverityBadge severity={sel.max_severity} /></p>
              <table>
                <thead><tr><th>Flow</th><th>Alerts</th></tr></thead>
                <tbody>
                  {selEdges.map((e) => (
                    <tr key={`${e.src}-${e.dst}`}>
                      <td className="mono">{e.src === sel.ip ? `→ ${e.dst}` : `← ${e.src}`}</td>
                      <td>{e.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <button style={{ marginTop: 10 }} onClick={() => navigate(`/alerts?ip=${encodeURIComponent(sel.ip)}`)}>
                Show its alerts
              </button>
            </>
          ) : (
            <p className="muted">Click a host to see who it talks to.</p>
          )}
        </div>
      </div>
    </>
  );
}
