"use client";

import * as React from "react";

import { DashboardOverview } from "@/features/scans/dashboard-overview";
import { RiskDistributionChart } from "@/components/dashboard/risk-distribution-chart";
import { RecentFindingsPanel } from "@/components/dashboard/recent-findings-panel";
import { toUiSeverity } from "@/components/dashboard/severity-badge";
import { getDashboardStats } from "@/features/dashboard/api";
import type { DashboardStats } from "@/types/api";

/**
 * Owns the single GET /dashboard/stats fetch for the whole dashboard
 * page, so the stat cards, the risk-distribution chart, and the recent
 * findings panel all render from one consistent snapshot rather than
 * three separate requests that could race and disagree.
 */
export function DashboardContent() {
  const [stats, setStats] = React.useState<DashboardStats | null>(null);
  const [error, setError] = React.useState(false);

  React.useEffect(() => {
    const controller = new AbortController();
    getDashboardStats(controller.signal)
      .then(setStats)
      .catch((err) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(true);
      });
    return () => controller.abort();
  }, []);

  const loading = stats === null && !error;
  // `null` means "no data to show yet" (still loading, or the fetch
  // failed) -- both components treat that as an explicit non-state,
  // never a fabricated empty/zero result.
  const riskData =
    !error && stats
      ? stats.findings_by_severity.map((s) => ({ severity: toUiSeverity(s.severity), count: s.count }))
      : null;
  const recentFindings = !error && stats ? stats.recent_findings : null;

  return (
    <div className="flex flex-col gap-6">
      <DashboardOverview stats={stats} error={error} />

      <div className="grid gap-4 lg:grid-cols-2">
        <RiskDistributionChart data={riskData} />
        <RecentFindingsPanel findings={recentFindings} loading={loading} />
      </div>
    </div>
  );
}
