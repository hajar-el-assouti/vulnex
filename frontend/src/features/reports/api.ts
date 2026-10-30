import { apiFetch } from "@/lib/api/client";
import type { ReportCreateRequest, ReportListResponse, ReportPublic } from "@/types/api";

export function listReports(scanId?: string, signal?: AbortSignal): Promise<ReportListResponse> {
  const query = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "";
  return apiFetch<ReportListResponse>(`/reports${query}`, { method: "GET", signal });
}

export function getReport(reportId: string, signal?: AbortSignal): Promise<ReportPublic> {
  return apiFetch<ReportPublic>(`/reports/${reportId}`, { method: "GET", signal });
}

/** Generation is synchronous on the backend, so this usually returns
 * "ready" or "failed". "pending"/"generating" are still handled by the
 * UI since the schema allows them. */
export function createReport(data: ReportCreateRequest): Promise<ReportPublic> {
  return apiFetch<ReportPublic>("/reports", { method: "POST", body: data });
}

/** Same-origin download URL, used by a plain link so the session cookie
 * is sent automatically (apiFetch is JSON only). The backend checks
 * ownership, status and file existence, and returns 404 otherwise. */
export function reportDownloadUrl(reportId: string): string {
  return `/api/v1/reports/${reportId}/download`;
}
