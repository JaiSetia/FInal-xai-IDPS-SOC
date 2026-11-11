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
