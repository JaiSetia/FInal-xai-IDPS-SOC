import { geoEqualEarth, geoGraticule10, geoInterpolate, geoPath } from "d3-geo";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
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

/** World attack map for the Maps page; the page owns the time window. `compact` (the Threat
 *  Center) draws only the map card, with the setup notices as one line under it. */
export default function WorldMap({ hours, compact = false }: { hours: number; compact?: boolean }) {
  const [hot, setHot] = useState<Set<string>>(new Set());
  const { data, error, reload } = useLoad(() => api<GeoAttacks>(`/geo/attacks${query({ hours })}`), [hours]);

  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  useEffect(() => () => { timers.current.forEach(clearTimeout); }, []);
  useLiveRefresh(reload, (a) => {
    // briefly highlight the arc from this alert's source
    setHot((s) => new Set(s).add(a.src_ip));
    const t = setTimeout(() => {
      timers.current.delete(t);
      setHot((s) => {
        const next = new Set(s);
        next.delete(a.src_ip);
        return next;
      });
    }, 4000);
    timers.current.add(t);
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

  // Compact (Threat Center grid): always one card, so the grid cell never empties or splits.
  if (compact && !data) {
    return (
      <Card title="Live attack map">
        <ErrorText error={error} />
        {!error && <p className="muted">Loading map…</p>}
      </Card>
    );
  }

  return (
    <>
      <ErrorText error={error} />
      {data && (
        <>
          {!compact && data.geoip_status !== "ok" && (
            <div className="card notice-box">
              Public addresses can't be placed on the map: {data.geoip_status}. See docs/soc.md.
            </div>
          )}
          {!compact && data.demo && (
            <div className="card notice-box">
              <b>Demo locations.</b> Lab (private) addresses are shown at made-up places marked
              “Demo:”. They are not real attacker locations.
            </div>
          )}
          {!compact && !home && (
            <div className="card notice-box">
              Set IDPS_SOC_HOME_LAT and IDPS_SOC_HOME_LON to draw attack lines to the protected site.
            </div>
          )}
          <Card title={compact ? "Live attack map" : "Where attacks come from"}
            actions={compact ? <Link to={`/maps${query({ view: "world", hours: hours === 1 ? undefined : hours })}`}>Open maps →</Link> : undefined}>
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
            {compact && (data.geoip_status !== "ok" || data.demo || !home) && (
              <p className="muted small-text" style={{ marginBottom: 0 }}>
                {data.demo && "Lab addresses are shown at made-up demo locations. "}
                {data.geoip_status !== "ok" && `Public addresses can't be placed: ${data.geoip_status}. `}
                {!home && "No protected site set (IDPS_SOC_HOME_LAT / IDPS_SOC_HOME_LON), so no attack lines."}
              </p>
            )}
            {data.geoip_status === "ok" && (
              <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
                This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.
              </p>
            )}
          </Card>
          {!compact && <Card title="Sources on the map">
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
          </Card>}
        </>
      )}
    </>
  );
}
