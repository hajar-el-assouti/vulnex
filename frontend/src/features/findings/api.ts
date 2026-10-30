import { apiFetch } from "@/lib/api/client";
import type {
  FindingListParams,
  FindingListResponse,
  FindingPublic,
  FindingStatusUpdateRequest,
} from "@/types/api";

function buildQuery(params: FindingListParams | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  if (params.target_id) search.set("target_id", params.target_id);
  if (params.scan_id) search.set("scan_id", params.scan_id);
  if (params.severity) search.set("severity", params.severity);
  if (params.confidence) search.set("confidence", params.confidence);
  if (params.category) search.set("category", params.category);
  if (params.status) search.set("status", params.status);
  if (params.search) search.set("search", params.search);
  if (params.sort_by) search.set("sort_by", params.sort_by);
  if (params.sort_desc !== undefined) search.set("sort_desc", String(params.sort_desc));
  if (params.page !== undefined) search.set("page", String(params.page));
  if (params.page_size !== undefined) search.set("page_size", String(params.page_size));
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

/**
 * Global findings list across scans. Different from a single scan's
 * ScanPublic.findings.
 */
export function listFindings(
  params?: FindingListParams,
  signal?: AbortSignal,
): Promise<FindingListResponse> {
  return apiFetch<FindingListResponse>(`/findings${buildQuery(params)}`, {
    method: "GET",
    signal,
  });
}

export function getFinding(findingId: string, signal?: AbortSignal): Promise<FindingPublic> {
  return apiFetch<FindingPublic>(`/findings/${findingId}`, { method: "GET", signal });
}

export function updateFindingStatus(
  findingId: string,
  data: FindingStatusUpdateRequest,
): Promise<FindingPublic> {
  return apiFetch<FindingPublic>(`/findings/${findingId}/status`, {
    method: "PATCH",
    body: data,
  });
}
