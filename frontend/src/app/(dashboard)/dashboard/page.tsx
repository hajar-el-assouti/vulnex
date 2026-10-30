import type { Metadata } from "next";

import { DashboardContent } from "@/features/dashboard/dashboard-content";

export const metadata: Metadata = { title: "Dashboard — VULNEX" };

/**
 * Every number on this page (stat cards, risk chart, recent scans,
 * recent findings) comes from GET /dashboard/stats, owner-scoped. See
 * DashboardContent for the single fetch everything renders from.
 */
export default function DashboardPage() {
  return <DashboardContent />;
}
