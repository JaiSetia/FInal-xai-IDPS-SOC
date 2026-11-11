import { geoEqualEarth, geoGraticule10, geoInterpolate, geoPath } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { useMemo, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import countriesTopo from "world-atlas/countries-110m.json";
import { api, query } from "../api/client";
import type { Severity } from "../api/types";
import { Card, ErrorText, SeverityBadge, useLoad } from "../components/common";
import { useLiveRefresh } from "../useLiveRefresh";

interface GeoPoint {
  ip: string;
  count: number;
  max_severity: Severity;
  lat: number;
  lon: number;
  country: string | null;
  city: string | null;
  source: "geoip" | "demo";
}

interface GeoAttacks {
  hours: number;
  home: { lat: number; lon: number; label: string } | null;
  geoip_status: string;
  demo: boolean;
  points: GeoPoint[];
  unlocated_sources: number;
}

const WIDTH = 960;
const HEIGHT = 500;

const topo = countriesTopo as unknown as Topology<{ countries: GeometryCollection }>;
const COUNTRIES = feature(topo, topo.objects.countries) as FeatureCollection<Geometry>;

export default function WorldMap() {
  const [hours, setHours] = useState(24);
  const [hot, setHot] = useState<Set<string>>(new Set());
  const { data, error, reload } = useLoad(() => api<GeoAttacks>(`/geo/attacks${query({ hours })}`), [hours]);

  const live = useLiveRefresh(reload, (a) => {
    // briefly highlight the arc from this alert's source
    setHot((s) => new Set(s).add(a.src_ip));
    setTimeout(() => setHot((s) => {
      const next = new Set(s);
      next.delete(a.src_ip);
      return next;
    }), 4000);
  });

  const projection = useMemo(() => geoEqualEarth().fitExtent([[8, 8], [WIDTH - 8, HEIGHT - 8]], { type: "Sphere" }), []);
  const path = useMemo(() => geoPath(projection), [projection]);
  const land = useMemo(() => COUNTRIES.features.map((f: Feature<Geometry>, i: number) => (
    <path key={i} d={path(f) ?? ""} className="map-land" />
  )), [path]);

  const points = data?.points ?? [];
  const maxCount = Math.max(1, ...points.map((p) => p.count));
  const home = data?.home ?? null;

  function arc(p: GeoPoint): string {
    if (!home) return "";
    const interp = geoInterpolate([p.lon, p.lat], [home.lon, home.lat]);
    const coords = Array.from({ length: 33 }, (_, i) => interp(i / 32));
    return path({ type: "LineString", coordinates: coords }) ?? "";
  }

  const homeXY = home ? projection([home.lon, home.lat]) : null;

  return (
    <>
      <h1>Attack map</h1>
      <div className="toolbar">
        <label className="field">Window
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {[1, 6, 24, 72, 168].map((h) => <option key={h} value={h}>last {h} h</option>)}
          </select>
        </label>
        <span className="muted" style={{ marginLeft: "auto" }}>
          <span className={`live-dot ${live ? "on" : "off"}`} />{live ? "Live" : "Live feed offline"}
        </span>
      </div>
      <ErrorText error={error} />
      {data && (
        <>
          {data.geoip_status !== "ok" && (
            <div className="card notice-box">
              Public addresses can't be placed on the map: {data.geoip_status}. See docs/soc.md.
            </div>
          )}
          {data.demo && (
            <div className="card notice-box">
              <b>Demo locations.</b> Lab (private) addresses are shown at made-up places marked
              “Demo:”. They are not real attacker locations.
            </div>
          )}
          {!home && (
            <div className="card notice-box">
              Set IDPS_SOC_HOME_LAT and IDPS_SOC_HOME_LON to draw attack lines to the protected site.
            </div>
          )}
          <Card>
            <svg className="map-svg" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img"
              aria-label={`World map of ${points.length} attack sources`}>
              <path d={path({ type: "Sphere" }) ?? ""} className="map-sphere" />
              <path d={path(geoGraticule10()) ?? ""} className="map-graticule" />
              {land}
              {home && points.map((p) => (
                <path key={`arc-${p.ip}`} d={arc(p)}
                  className={`map-arc sev-stroke-${p.max_severity}${hot.has(p.ip) ? " hot" : ""}`} />
              ))}
              {points.map((p) => {
                const xy = projection([p.lon, p.lat]);
                if (!xy) return null;
                const r = 3 + 9 * Math.sqrt(p.count / maxCount);
                return (
                  <circle key={p.ip} cx={xy[0]} cy={xy[1]} r={r}
                    className={`map-point sev-fill-${p.max_severity}${p.source === "demo" ? " demo" : ""}${hot.has(p.ip) ? " hot" : ""}`}>
                    <title>{`${p.ip} · ${p.count} alerts · ${p.city ?? ""} ${p.country ?? ""}${p.source === "demo" ? " (demo location)" : ""}`}</title>
                  </circle>
                );
              })}
              {homeXY && (
                <g className="map-home">
                  <circle cx={homeXY[0]} cy={homeXY[1]} r={6} />
                  <text x={homeXY[0] + 9} y={homeXY[1] + 4}>{home!.label}</text>
                </g>
              )}
            </svg>
            <p className="muted" style={{ marginBottom: 0 }}>
              {points.length} sources placed
              {data.unlocated_sources ? `, ${data.unlocated_sources} with no known location (private or unknown addresses)` : ""}.
              Dot size: number of alerts. Colour: highest severity.
              {data.demo && " Dashed outline: demo location, not real."}
            </p>
            {data.geoip_status === "ok" && (
              <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
                This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.
              </p>
            )}
          </Card>
          <Card title="Sources on the map">
            <div className="table-wrap">
              <table>
                <thead><tr><th>Source IP</th><th>Alerts</th><th>Highest severity</th><th>Location</th></tr></thead>
                <tbody>
                  {points.slice(0, 50).map((p) => (
                    <tr key={p.ip}>
                      <td className="mono">{p.ip}</td>
                      <td>{p.count}</td>
                      <td><SeverityBadge severity={p.max_severity} /></td>
                      <td>{[p.city, p.country].filter(Boolean).join(", ") || "—"}
                        {p.source === "demo" && <span className="muted"> (not real)</span>}</td>
                    </tr>
                  ))}
                  {points.length === 0 && <tr><td colSpan={4} className="muted">No located sources in this window.</td></tr>}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </>
  );
}
