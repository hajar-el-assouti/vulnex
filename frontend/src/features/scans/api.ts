import { apiFetch } from "@/lib/api/client";
import type {
  ScanCreateRequest,
  ScanEventListResponse,
  ScanListResponse,
  ScanModuleListResponse,
  ScanPublic,
  ScanRerunRequest,
  ScanStatusResponse,
} from "@/types/api";

export function listScans(
  targetId?: string,
  signal?: AbortSignal,
): Promise<ScanListResponse> {
  const query = targetId ? `?target_id=${encodeURIComponent(targetId)}` : "";
  return apiFetch<ScanListResponse>(`/scans${query}`, { method: "GET", signal });
}

export function getScan(scanId: string, signal?: AbortSignal): Promise<ScanPublic> {
  return apiFetch<ScanPublic>(`/scans/${scanId}`, { method: "GET", signal });
}

/** Deliberately hits the small, cheap /status endpoint -- not GET
 * /scans/{id} -- see app/api/v1/endpoints/scans.py::get_scan_status's
 * own docstring. This is what useScanStatus polls on a timer. */
export function getScanStatus(
  scanId: string,
  signal?: AbortSignal,
): Promise<ScanStatusResponse> {
  return apiFetch<ScanStatusResponse>(`/scans/${scanId}/status`, { method: "GET", signal });
}

export function getScanEvents(
  scanId: string,
  signal?: AbortSignal,
): Promise<ScanEventListResponse> {
  return apiFetch<ScanEventListResponse>(`/scans/${scanId}/events`, { method: "GET", signal });
}

export function createScan(data: ScanCreateRequest): Promise<ScanPublic> {
  return apiFetch<ScanPublic>("/scans", { method: "POST", body: data });
}

export function cancelScan(scanId: string): Promise<ScanPublic> {
  return apiFetch<ScanPublic>(`/scans/${scanId}/cancel`, { method: "POST" });
}

/**
 * Re-runs the original scan's modules through the normal create_scan()
 * path. active_testing_confirmed is never copied from the original scan
 * and must be sent on every call (default false).
 */
export function rerunScan(scanId: string, data?: ScanRerunRequest): Promise<ScanPublic> {
  return apiFetch<ScanPublic>(`/scans/${scanId}/rerun`, {
    method: "POST",
    body: data ?? { active_testing_confirmed: false },
  });
}

export function listScanModules(signal?: AbortSignal): Promise<ScanModuleListResponse> {
  return apiFetch<ScanModuleListResponse>("/scan-modules", { method: "GET", signal });
}
