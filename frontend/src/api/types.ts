export type Json =
  null | boolean | number | string | Json[] | { [key: string]: Json };
export type Risk = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Decision = "ALLOW" | "DENY";
export type Action = "ALLOW" | "FLAG" | "REDACT" | "BLOCK";
export type Mode = "scripted" | "live";
export type Variant = "baseline" | "protected";
export type Tool = "read_document" | "search_database" | "send_email";
export interface SystemStatus {
  backend: { available: boolean };
  database: { connected: boolean };
  ai_provider: { configured: boolean; connection_verified: false };
  version: string;
}
export interface Health {
  status: "healthy";
  application: string;
  version: string;
}
export interface FirewallEvent {
  decision_id: string;
  session_id: string;
  tool_name: string;
  decision: Decision;
  risk_level: Risk;
  policy_id: string;
  reason: string;
  timestamp: string;
  arguments_summary: Record<string, Json>;
  metadata: Record<string, Json>;
}
export interface FirewallStats {
  total_evaluations: number;
  allowed_actions: number;
  blocked_actions: number;
  high_risk_events: number;
  critical_risk_events: number;
}
export interface Policies {
  valid: boolean;
  default_decision: string;
  deny_overrides_allow: boolean;
  rules: Record<string, Json>[];
  baseline_guards: string[];
}
export interface Indicator {
  rule_id: string;
  category: string;
  severity: Risk;
  description: string;
  view: string;
  start: number;
  end: number;
  evidence_hash: string;
  match_strength: number;
  recommended_action: Action;
  weight: number;
  educational_quote: boolean;
}
export interface Scan {
  scan_id: string;
  session_id: string;
  source_tool: string;
  source_identifier: string;
  detected: boolean;
  classification: "SAFE" | "SUSPICIOUS" | "PROMPT_INJECTION" | "SCAN_ERROR";
  risk_score: number;
  risk_level: Risk;
  confidence: number;
  confidence_description: string;
  action: Action;
  categories: string[];
  indicators: Indicator[];
  normalization_steps: string[];
  content_hash: string;
  content_length: number;
  timestamp: string;
  firewall_decision_id: string | null;
  tool_execution_id: string | null;
  detector_version: string;
  explanation: string;
  classifier_status: string;
}
export interface ScanStats {
  total_scans: number;
  detected_threats: number;
  blocked_threats: number;
  flagged_threats: number;
  redacted_threats: number;
  average_risk_score: number;
}
export interface Execution {
  id: string;
  tool_name: string;
  arguments: Record<string, Json>;
  status: string;
  result: Record<string, Json> | null;
  created_at: string;
}
export interface Session {
  id: string;
  name: string | null;
  status: string;
  created_at: string;
}
export interface Message {
  id: string;
  role: string;
  content: string;
  tool_calls: Record<string, Json>[] | null;
  tool_call_id: string | null;
  created_at: string;
}
export interface SessionDetail extends Session {
  messages: Message[];
  tool_executions: Execution[];
  simulated_emails: Record<string, Json>[];
}
export interface ChatReply {
  session_id: string;
  response: string;
  tool_calls: Execution[];
}
export interface Scenario {
  id: string;
  name: string;
  description: string;
  category: string;
  difficulty: string;
  objective: string;
  entry_point: string;
  expected_controls: string[];
  success_criteria: string;
  benign: boolean;
  version: number;
  supported_modes: Mode[];
  payload?: string;
  task?: string;
  resources?: Json;
}
export interface RunSummary {
  run_id: string;
  scenario_id: string;
  mode: Mode;
  status: string;
  is_simulation: true;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
}
export interface Result {
  outcome: "SUCCESS" | "FAILURE" | "INCONCLUSIVE" | "ERROR";
  attack_success: boolean | null;
  execution_status: string;
  error_code: string | null;
  mode: Mode;
  is_simulation: true;
  benign?: boolean;
  objective?: string;
  success_criteria?: string;
  unauthorized_tool_attempts?: number;
  tool_requests?: number;
  tools_executed?: number;
  blocked_actions?: number;
  confidential_data_accessed?: boolean;
  simulated_exfiltration?: boolean;
  injections_detected?: number;
  critical_content_quarantined?: number;
  legitimate_task_completed?: boolean;
  duration_seconds?: number;
  provider_requests?: number;
  final_response?: string;
  interpretation?: string;
  evidence?: string[];
  outbox?: Json[];
}
export interface RunDetail extends RunSummary {
  configuration: {
    scenario: Scenario;
    label: string;
    model: string | null;
    provider: string;
    variants: Variant[];
    [key: string]: unknown;
  };
  results: Partial<Record<Variant, Result>>;
  comparison: {
    paired: boolean;
    note?: string;
    observed_prevention?: boolean;
    [key: string]: unknown;
  };
  trace_summary: Record<string, number>;
  cancel_requested: boolean;
}
export interface Trace {
  trace_id: string;
  run_id: string;
  variant: Variant;
  step: number;
  timestamp: string;
  event_type: string;
  details: Record<string, Json>;
}
export interface Admission {
  run_id: string;
  status: "QUEUED";
  mode: Mode;
  is_simulation: true;
}
export interface VariantStats {
  results: number;
  attack_successes: number;
  conclusive_attacks: number;
  attack_success_rate: number | null;
  false_positive_rate: number | null;
  legitimate_task_completion_rate: number | null;
  blocked_actions: number;
  unauthorized_tool_attempts: number;
  injections_detected: number;
  critical_content_quarantined: number;
  legitimate_tasks_completed: number;
  errors: number;
  inconclusive: number;
  provider_errors: number;
  [key: string]: number | null;
}
export interface SimulationStats {
  total_simulations: number;
  modes: Record<
    Mode,
    { total_runs: number; variants: Record<Variant, VariantStats> }
  >;
  interpretation: string;
}
