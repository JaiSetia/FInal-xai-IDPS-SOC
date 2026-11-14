// Shapes returned by the SOC API (see soc/api/routes/*.py and docs/soc.md).

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "acknowledged" | "false_positive" | "resolved";
export type ActionKind = "block_ip" | "unblock_ip";
export type ActionStatus = "pending" | "confirmed" | "rejected" | "executed" | "failed";
export type CaseStatus = "open" | "investigating" | "closed";
export type Role = "analyst" | "admin";

export const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];
export const ALERT_STATUSES: AlertStatus[] = ["new", "acknowledged", "false_positive", "resolved"];
export const CASE_STATUSES: CaseStatus[] = ["open", "investigating", "closed"];

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface Alert {
  id: number;
  sensor_id: number;
  received_at: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  start_ms: number;
  end_ms: number;
  predicted_class: string;
  confidence: number;
  anomaly_score: number | null;
  severity: Severity;
  status: AlertStatus;
  case_id: number | null;
}

export interface FeatureContribution {
  feature: string;
  value: number | null;
  contribution: number | null;
}

export interface Explanation {
  method?: string;
  predicted_class?: string;
  confidence?: number;
  base_value?: number | null;
  output_space?: string;
  top_features?: FeatureContribution[];
}

export interface AlertDetail extends Alert {
  explanation: Explanation;
}

export interface Block {
  id: number;
  sensor_id: number;
  ip: string;
  reason: string;
  source: "auto" | "analyst";
  alert_id: number | null;
  blocked_at: string;
  expires_at: string | null;
  unblocked_at: string | null;
  active: boolean;
}

export interface Action {
  id: number;
  kind: ActionKind;
  params: Record<string, unknown>;
  reason: string;
  proposed_by: string;
  proposed_by_user_id: number | null;
  sensor_id: number;
  status: ActionStatus;
  created_at: string;
  decided_by_id: number | null;
  decided_at: string | null;
  result: Record<string, unknown> | null;
  completed_at: string | null;
}

export interface CaseSummary {
  id: number;
  title: string;
  status: CaseStatus;
  created_by_id: number | null;
  created_at: string;
  updated_at: string;
  alert_count: number;
}

export interface Note {
  id: number;
  case_id: number;
  author_id: number | null;
  author: string | null;
  text: string;
  created_at: string;
}

export interface CaseDetail extends CaseSummary {
  notes: Note[];
  alerts: Alert[];
}

export interface MetricsSummary {
  hours: number;
  since: string;
  bucket_seconds: number;
  alerts_total: number;
  alerts_per_bucket: { start: string; count: number }[];
  by_class: Record<string, number>;
  by_severity: Record<string, number>;
  top_sources: { ip: string; count: number }[];
  triaged: number;
  false_positives: number;
  false_positive_rate: number | null;
  detection_latency: { p50_ms: number | null; p95_ms: number | null; samples: number };
  active_blocks: number;
  /** Dry-run block decisions in the window. */
  would_blocks?: number;
  /** Last 7 UTC days, oldest first, non-zero pairs only. Outliers are in `anomaly_per_day`. */
  by_class_per_day?: { day: string; class: string; count: number }[];
  /** Isolation Forest outliers per day, last 7 UTC days, non-zero only. */
  anomaly_per_day?: { day: string; count: number }[];
}

export interface AdminUser {
  id: number;
  username: string;
  role: Role;
  disabled: boolean;
  created_at: string;
}

export interface Sensor {
  id: number;
  name: string;
  revoked: boolean;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor_type: string;
  actor_name: string;
  action: string;
  target: string;
  details: Record<string, unknown>;
}

// --- Phase 3: sensor status, would-block events, class by day ---------------------------

export interface SensorPolicy {
  confidence_threshold: number;
  min_flows: number;
  window_seconds: number;
  min_alert_confidence: number;
  block_ttl_seconds: number;
  unblock_grace_seconds: number;
  max_analyst_blocks: number;
}

export interface SensorReport {
  dry_run: boolean;
  blocking_enabled: boolean;
  interface: string | null;
  mode: "live" | "replay";
  model: { name: string; checksum_ok: boolean };
  /** null for analysts: only admins see the policy and allowlists. */
  policy: SensorPolicy | null;
  allowlist: string[] | null;
  /** Full allowlist size; the list itself is capped at 100. Missing from older sensors. */
  allowlist_total?: number;
  outbox_pending: number;
  /** The model's explanation-faithfulness test (offline deletion test); missing from older sensors. */
  faithfulness?: Faithfulness | null;
  shap_p95_ms: number | null;
  heartbeat: { enabled: boolean; ok: boolean };
  counters: { flows: number; alerts: number; blocked: number; would_block: number };
  sensor_version: string | null;
  sent_at: string | null;
}

export interface FaithfulnessMethod {
  mean_drop: number;
  /** null when removing random features changed nothing; negative when worse than random. */
  ratio_to_random: number | null;
  label_flip_rate: number;
  share_flows_beating_random: number;
}

export interface Faithfulness {
  model: string;
  model_matches: boolean;
  /** "digest": compared by model file checksum; "name": only the algorithm name (older reports). */
  model_check?: "digest" | "name" | null;
  flows: number;
  top_k: number;
  random_mean_drop: number;
  methods: { shap?: FaithfulnessMethod; lime?: FaithfulnessMethod };
}

export interface SensorState {
  sensor_id: number;
  name: string;
  revoked: boolean;
  last_seen_at: string | null;
  online: boolean;
  status: SensorReport | null;
}

export interface SensorsStatus {
  /** null for analysts (redacted). */
  soc_allowlist: string[] | null;
  redacted?: boolean;
  sensors: SensorState[];
}

export interface WouldBlock {
  id: number;
  sensor_id: number;
  ip: string;
  reason: string;
  source: "auto" | "analyst";
  alert_id: number | null;
  at: string;
  ttl_seconds: number | null;
}

// --- Live map: extra fields and messages on /ws/alerts ------------------------------------

export interface GeoLocation {
  lat: number;
  lon: number;
  country: string | null;
  city: string | null;
  /** "demo": a made-up location for a private (lab) address, never a real one. */
  source: "geoip" | "demo";
}

/** An alert as the live feed sends it: the stored alert plus its source's map location. */
export interface LiveAlert extends Alert {
  src_geo?: GeoLocation | null;
}

export interface LiveBlockEvent {
  type: "block";
  event: "blocked" | "unblocked" | "would_block";
  sensor_id: number;
  ip: string;
  source: "auto" | "analyst";
  at: string;
  expires_at: string | null;
  ttl_seconds: number | null;
  reason: string;
  geo: GeoLocation | null;
}
