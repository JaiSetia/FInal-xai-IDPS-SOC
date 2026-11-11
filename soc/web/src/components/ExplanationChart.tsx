import type { Explanation } from "../api/types";
import { num } from "../format";

interface Row {
  feature: string;
  value: number | null;
  contribution: number;
}

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const finite = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** Keep only well-formed rows: the server validates explanations, but the chart must
 *  never crash the page on something unexpected. */
function rows(explanation: unknown): Row[] {
  const list = explanation && typeof explanation === "object"
    ? (explanation as { top_features?: unknown }).top_features : undefined;
  if (!Array.isArray(list)) return [];
  const out: Row[] = [];
  for (const item of list.slice(0, 50)) {
    if (!item || typeof item !== "object") continue;
    const f = item as Record<string, unknown>;
    const feature = str(f.feature);
    const contribution = finite(f.contribution);
    if (feature && contribution !== null) out.push({ feature, value: finite(f.value), contribution });
  }
  return out;
}

/** Horizontal bars of the top feature contributions (SHAP or LIME), centred on zero.
 *  Red pushes toward the predicted class, blue away from it. */
export default function ExplanationChart({ explanation }: { explanation: Explanation | unknown }) {
  const features = rows(explanation);
  if (features.length === 0) return <p className="muted">No explanation was sent with this alert.</p>;
  const e = explanation as Record<string, unknown>;
  const method = str(e.method);
  const cls = str(e.predicted_class);
  const space = str(e.output_space);
  const max = Math.max(...features.map((f) => Math.abs(f.contribution)), 1e-9);

  return (
    <div>
      <p className="muted" style={{ marginTop: 0 }}>
        {method ? method.toUpperCase() : "Explanation"}{cls ? ` of “${cls}”` : ""}
        {space ? ` (contributions in ${space.replace(/_/g, " ")})` : ""}.
        Red pushes toward this class, blue away from it.
      </p>
      {features.map((f, i) => {
        const c = f.contribution;
        const width = `${(Math.abs(c) / max) * 50}%`;
        return (
          <div className="shap-row" key={`${i}-${f.feature}`} title={`${f.feature} = ${f.value ?? "—"}`}>
            <span className="mono" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
              {f.feature} <span className="muted">= {num(f.value, 2)}</span>
            </span>
            <div className="shap-bar-track" aria-hidden="true">
              <div className="shap-axis" />
              <div className={`shap-bar ${c >= 0 ? "pos" : "neg"}`} style={{ width }} />
            </div>
            <span className="mono" style={{ textAlign: "right" }}>{c >= 0 ? "+" : ""}{num(c, 3)}</span>
          </div>
        );
      })}
    </div>
  );
}
