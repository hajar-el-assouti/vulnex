import { apiFetch } from "@/lib/api/client";
import type {
  TargetAuthorizeRequest,
  TargetCreateRequest,
  TargetListResponse,
  TargetPublic,
} from "@/types/api";

export function listTargets(signal?: AbortSignal): Promise<TargetListResponse> {
  return apiFetch<TargetListResponse>("/targets", { method: "GET", signal });
}

export function getTarget(targetId: string): Promise<TargetPublic> {
  return apiFetch<TargetPublic>(`/targets/${targetId}`, { method: "GET" });
}

export function createTarget(data: TargetCreateRequest): Promise<TargetPublic> {
  return apiFetch<TargetPublic>("/targets", { method: "POST", body: data });
}

export function authorizeTarget(
  targetId: string,
  data: TargetAuthorizeRequest,
): Promise<TargetPublic> {
  return apiFetch<TargetPublic>(`/targets/${targetId}/authorize`, {
    method: "POST",
    body: data,
  });
}
