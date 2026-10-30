/**
 * Written by hand to match the backend contracts:
 *   - app/schemas/auth.py       (RegisterRequest, LoginRequest, UserPublic, MessageResponse)
 *   - app/api/v1/endpoints/auth.py (status codes, Retry-After on 429)
 *   - app/core/errors.py       (422 validation error shape, 401/403/404/500 shape)
 *
 * Not generated from an OpenAPI spec: if the backend schemas change,
 * update these types by hand.
 */

/** Mirrors app.models.user.UserRole. */
export type UserRole = "admin" | "member";

/** Mirrors app.schemas.auth.UserPublic. Never includes a password or
 * anything session-related -- the backend guarantees that, not this type. */
export interface UserPublic {
  id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  created_at: string; // ISO 8601, as serialized by Pydantic's datetime
}

/** Mirrors app.schemas.auth.RegisterRequest. */
export interface RegisterRequest {
  email: string;
  password: string;
  full_name?: string | null;
}

/** Mirrors app.schemas.auth.LoginRequest. */
export interface LoginRequest {
  email: string;
  password: string;
}

/** Mirrors app.schemas.auth.MessageResponse. */
export interface MessageResponse {
  detail: string;
}

/** One field error as FastAPI/Pydantic's RequestValidationError.errors()
 * serializes it -- the exact shape returned by the 422 handler in
 * app/core/errors.py. */
export interface ValidationErrorItem {
  loc: (string | number)[];
  msg: string;
  type: string;
}

/** The two error body shapes the backend actually returns (see
 * app/core/errors.py): a plain `{ detail: string }` for 401/403/404/409/429/503,
 * or `{ detail: "Validation error", errors: [...] }` for 422. */
export type ApiErrorBody =
  | { detail: string; errors?: undefined }
  | { detail: "Validation error"; errors: ValidationErrorItem[] };

/**
 * Targets, scans and scan modules. Mirrors:
 *   - app/schemas/targets.py       (Target*)
 *   - app/schemas/scans.py         (Scan*)
 *   - app/schemas/scan_modules.py  (ScanModule*)
 * Also written by hand: update if the backend schemas change.
 */

/**
 * Mirrors app.models.scan.ScanStatus exactly (all 7 values, including
 * CANCELLING).
 */
export type ScanStatusValue =
  | "pending"
  | "queued"
  | "running"
  | "cancelling"
  | "completed"
  | "failed"
  | "cancelled";

/** Mirrors app.models.scan_module_run.ScanModuleRunStatus. */
export type ScanModuleRunStatusValue = "pending" | "running" | "completed" | "failed" | "skipped";

/** Mirrors app.schemas.targets.TargetPublic. */
export interface TargetPublic {
  id: string;
  owner_id: string;
  name: string;
  base_url: string;
  description: string | null;
  is_authorized: boolean;
  authorization_reference: string | null;
  authorized_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TargetListResponse {
  items: TargetPublic[];
}

/** Mirrors app.schemas.targets.TargetCreateRequest. */
export interface TargetCreateRequest {
  name: string;
  base_url: string;
  description?: string | null;
}

/** Mirrors app.schemas.targets.TargetAuthorizeRequest. */
export interface TargetAuthorizeRequest {
  authorization_reference: string;
}

/** Mirrors app.schemas.scan_modules.ScanModulePublic. */
export interface ScanModulePublic {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  version: string;
}

export interface ScanModuleListResponse {
  items: ScanModulePublic[];
}

/**
 * Recon results. Mirrors app/engines/recon/schemas.py and
 * app/engines/recon/persistence.py. `result` on ScanModuleRunPublic has
 * this shape for the "recon" and "advanced_recon" modules (both use
 * build_persisted_result, with different collector slugs in `modules`).
 * The diagnostic module always has result: null. See
 * features/scans/recon-results-view.tsx, which checks module_slug before
 * reading it.
 */

/** Mirrors app.engines.recon.schemas.ObservationNature. */
export type ReconObservationNature = "observed" | "inferred" | "unknown" | "not_applicable" | "error";

/** Mirrors app.engines.recon.schemas.CollectorStatus. */
export type ReconCollectorStatusValue = "ok" | "partial" | "not_applicable" | "error";

/** Mirrors app.engines.recon.schemas.Observation.to_dict(). `value` is
 * deliberately `unknown` -- its shape varies per collector/key and is
 * rendered defensively (see recon-results-view.tsx's renderValue). */
export interface ReconObservation {
  key: string;
  value: unknown;
  nature: ReconObservationNature;
  note: string | null;
}

/** Mirrors app.engines.recon.schemas.CollectorResult.to_dict(), plus
 * the optional `_storage_note` app/engines/recon/persistence.py adds
 * when a collector's observations were dropped to fit the storage
 * size cap (never silently -- see that module's docstring). */
export interface ReconCollectorResultPublic {
  collector: string;
  status: ReconCollectorStatusValue;
  collected_at: string;
  duration_ms: number;
  observations: ReconObservation[];
  evidence: Record<string, unknown>;
  errors: string[];
  source: string;
  confidence: "low" | "medium" | "high";
  _storage_note?: string;
}

/** Mirrors app.engines.recon.persistence.build_persisted_result's
 * return shape exactly -- this is what ends up in
 * ScanModuleRunPublic.result for the "recon" module slug. */
export interface ReconPersistedResult {
  modules: Record<string, ReconCollectorResultPublic>;
  fingerprint_snapshot: {
    observations: Record<string, Record<string, unknown>>;
    incomplete_collectors: string[];
  };
  storage_truncated: boolean;
  truncated_collectors: string[];
}

/** Mirrors app.schemas.scans.ScanModuleRunPublic. */
export interface ScanModuleRunPublic {
  id: string;
  scan_module_id: string;
  /** Which module this run actually is (e.g. "recon", "diagnostic") --
   * read off the module relationship server-side, never inferred from
   * ordering. */
  module_slug: string;
  status: ScanModuleRunStatusValue;
  started_at: string | null;
  finished_at: string | null;
  /**
   * Null for modules that don't store a structured result (diagnostic)
   * or haven't finished. Read as a ReconPersistedResult when module_slug
   * is "recon", "advanced_recon", "web_vuln_assessment",
   * "active_web_testing" or "discovery_fuzzing": they all use
   * build_persisted_result, so `modules` is keyed by each module's
   * collector/check slugs.
   * - web_vuln_assessment: http, headers, cookies, tls, security_headers,
   *   cors, info_disclosure, http_methods, tls_config, injection_surface,
   *   api_security.
   * - active_web_testing: http, api_discovery, xss_reflected,
   *   sqli_differential, http_param_testing, api_security_active.
   * - discovery_fuzzing: one "discovery_fuzzing" slug, with observations
   *   keyed by the tested wordlist entry, each valued
   *   `{status_code, observation_type, is_redirect, location, tested_at}`.
   * `fingerprint_snapshot` is present but unused outside the recon
   * modules.
   */
  result: ReconPersistedResult | null;
}

/** Mirrors app.models.scan_finding.Severity. */
export type FindingSeverityValue = "info" | "low" | "medium" | "high" | "critical";

/** Mirrors app.models.scan_finding.Confidence. */
export type FindingConfidenceValue = "low" | "medium" | "high" | "confirmed";

/**
 * Mirrors app.schemas.scans.ScanFindingPublic. Recon modules only
 * produce observations, never findings. `evidence` contains
 * `owasp_category`/`impact` (added by Finding.to_dict()) plus
 * `_check`/`_dedup_key`/`_detected_at`. The underscore fields aren't
 * meant as main display fields, but are safe to show in a "raw
 * evidence" section: secrets are redacted before storage.
 */
export interface ScanFindingPublic {
  id: string;
  scan_module_id: string | null;
  title: string;
  description: string | null;
  severity: FindingSeverityValue;
  confidence: FindingConfidenceValue;
  affected_url: string | null;
  cwe_id: string | null;
  evidence: Record<string, unknown>;
  remediation: string | null;
  created_at: string;
  /**
   * Optional triage status. Always present (the backend defaults every
   * row to "open").
   */
  status: FindingStatusValue;
}

/** Mirrors app.schemas.scans.ScanPublic. */
export interface ScanPublic {
  id: string;
  target_id: string;
  initiated_by_id: string;
  status: ScanStatusValue;
  started_at: string | null;
  finished_at: string | null;
  cancel_requested_at: string | null;
  created_at: string;
  updated_at: string;
  module_runs: ScanModuleRunPublic[];
  /**
   * Empty for scans that didn't run a findings-producing module
   * (web_vuln_assessment, active_web_testing). Findings from different
   * modules are told apart by `scan_module_id`, matched against
   * `module_runs[].scan_module_id`, not by check slug.
   */
  findings: ScanFindingPublic[];
}

export interface ScanListResponse {
  items: ScanPublic[];
}

/** Mirrors app.schemas.scans.ScanCreateRequest. */
export interface ScanCreateRequest {
  target_id: string;
  modules?: string[] | null;
  /**
   * Required (true) when `modules` includes an active module; ignored
   * otherwise. It can be omitted: the backend defaults to `false`.
   */
  active_testing_confirmed?: boolean;
}

/** Mirrors app.schemas.scans.ScanStatusResponse -- the small, cheap
 * payload the frontend polls (see lib/hooks/use-scan-status.ts). */
export interface ScanStatusResponse {
  id: string;
  status: ScanStatusValue;
  started_at: string | null;
  finished_at: string | null;
  cancel_requested_at: string | null;
}

/** Mirrors app.schemas.scans.ScanEventPublic. */
export interface ScanEventPublic {
  id: string;
  event_type: string;
  message: string | null;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface ScanEventListResponse {
  items: ScanEventPublic[];
}

/** A scan is non-terminal (still something a human might wait on, and
 * the only states a poller needs to keep polling for). */
export const ACTIVE_SCAN_STATUSES: ScanStatusValue[] = [
  "pending",
  "queued",
  "running",
  "cancelling",
];

/** Mirrors app.schemas.scans.ScanRerunRequest. */
export interface ScanRerunRequest {
  active_testing_confirmed?: boolean;
}

// ---------------------------------------------------------------------
// GET /dashboard/stats. Mirrors app.schemas.dashboard.*.
// Every field is owner-scoped data from a SQL aggregate (see
// app/services/dashboard.py). Nothing is optional: a zero is always
// sent as 0.
// ---------------------------------------------------------------------

export interface DashboardSeverityCount {
  severity: string;
  count: number;
}

export interface DashboardModuleUsageCount {
  module_slug: string;
  module_name: string;
  run_count: number;
}

export interface DashboardFindingsTrendPoint {
  date: string; // ISO date (YYYY-MM-DD)
  count: number;
}

export interface DashboardRecentScan {
  id: string;
  target_id: string;
  target_name: string;
  status: ScanStatusValue;
  created_at: string;
  finished_at: string | null;
}

export interface DashboardRecentFinding {
  id: string;
  scan_id: string;
  target_name: string;
  title: string;
  severity: string;
  confidence: string;
  created_at: string;
}

export interface DashboardPlatformStatus {
  database_reachable: boolean;
  redis_reachable: boolean;
}

export interface DashboardStats {
  total_targets: number;
  authorized_targets: number;
  scans_completed: number;
  scans_running: number;
  scans_failed: number;
  scans_total: number;
  findings_total: number;
  findings_by_severity: DashboardSeverityCount[];
  findings_trend: DashboardFindingsTrendPoint[];
  recent_scans: DashboardRecentScan[];
  recent_findings: DashboardRecentFinding[];
  module_usage: DashboardModuleUsageCount[];
  platform_status: DashboardPlatformStatus;
}

// ---------------------------------------------------------------------
// /findings. Mirrors app.schemas.findings.*. Unlike ScanFindingPublic
// (one scan), this is the global shape with target and category info.
// ---------------------------------------------------------------------

export type FindingStatusValue = "open" | "in_review" | "resolved" | "false_positive";

export interface FindingPublic {
  id: string;
  scan_id: string;
  target_id: string;
  target_name: string;
  module_slug: string | null;
  category: string;
  title: string;
  description: string | null;
  severity: string;
  confidence: string;
  status: FindingStatusValue;
  affected_url: string | null;
  cwe_id: string | null;
  evidence: Record<string, unknown>;
  remediation: string | null;
  created_at: string;
}

export interface FindingListResponse {
  items: FindingPublic[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingListParams {
  target_id?: string;
  scan_id?: string;
  severity?: string;
  confidence?: string;
  category?: string;
  status?: FindingStatusValue;
  search?: string;
  sort_by?: "created_at" | "severity" | "confidence";
  sort_desc?: boolean;
  page?: number;
  page_size?: number;
}

export interface FindingStatusUpdateRequest {
  status: FindingStatusValue;
}

// ---------------------------------------------------------------------
// /scan-profiles. Mirrors app.schemas.scan_profiles.*.
// ---------------------------------------------------------------------

export interface ScanProfilePublic {
  id: string;
  owner_id: string | null;
  name: string;
  description: string | null;
  module_slugs: string[];
  active_testing_confirmed_default: boolean;
  is_builtin: boolean;
  created_at: string;
}

export interface ScanProfileListResponse {
  items: ScanProfilePublic[];
}

export interface ScanProfileCreateRequest {
  name: string;
  description?: string | null;
  module_slugs: string[];
  active_testing_confirmed_default?: boolean;
}

// ---------------------------------------------------------------------
// /reports. Mirrors app.schemas.reports.*.
// Report files are never fetched through apiFetch (JSON only): the
// download is a plain same-origin link to
// /api/v1/reports/{id}/download, which sends the session cookie
// automatically (see features/reports/api.ts).
// ---------------------------------------------------------------------

export type ReportFormatValue = "pdf" | "html";
export type ReportStatusValue = "pending" | "generating" | "ready" | "failed";

export interface ReportPublic {
  id: string;
  scan_id: string;
  generated_by_id: string;
  format: ReportFormatValue;
  status: ReportStatusValue;
  completed_at: string | null;
  created_at: string;
}

export interface ReportListResponse {
  items: ReportPublic[];
}

export interface ReportCreateRequest {
  scan_id: string;
  format?: ReportFormatValue;
}

/** Thrown by the API client for any non-2xx response. `status` lets
 * callers branch on 401 vs 409 vs 429 etc. without re-parsing the body. */
export class ApiError extends Error {
  readonly status: number;
  readonly body: ApiErrorBody | null;
  /** Present only on 429, mirrors the backend's Retry-After header
   * (app/api/v1/endpoints/auth.py sets it on every 429). */
  readonly retryAfterSeconds: number | null;

  constructor(status: number, body: ApiErrorBody | null, retryAfterSeconds: number | null) {
    super(body?.detail ?? `Request failed with status ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
