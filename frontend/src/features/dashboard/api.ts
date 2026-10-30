import { apiFetch } from "@/lib/api/client";
import type { DashboardStats } from "@/types/api";

/**
 * Every field is real, owner-scoped data from
 * app/services/dashboard.py.
 */
export function getDashboardStats(signal?: AbortSignal): Promise<DashboardStats> {
  return apiFetch<DashboardStats>("/dashboard/stats", { method: "GET", signal });
}
