import { apiFetch } from "@/lib/api/client";
import type {
  ScanProfileCreateRequest,
  ScanProfileListResponse,
  ScanProfilePublic,
} from "@/types/api";

export function listScanProfiles(signal?: AbortSignal): Promise<ScanProfileListResponse> {
  return apiFetch<ScanProfileListResponse>("/scan-profiles", { method: "GET", signal });
}

export function createScanProfile(data: ScanProfileCreateRequest): Promise<ScanProfilePublic> {
  return apiFetch<ScanProfilePublic>("/scan-profiles", { method: "POST", body: data });
}

/** Rejected by the backend with 403 for a built-in profile -- callers
 * only offer this for profiles where `is_builtin` is false. */
export function deleteScanProfile(profileId: string): Promise<void> {
  return apiFetch<void>(`/scan-profiles/${profileId}`, { method: "DELETE" });
}
