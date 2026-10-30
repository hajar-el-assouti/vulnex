"use client";

import Link from "next/link";
import { Clock, Loader2, ScanSearch, ShieldAlert } from "lucide-react";

import { StatCard } from "@/components/dashboard/stat-card";
import { EmptyState } from "@/components/dashboard/empty-state";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanStatusBadge, type ScanStatus } from "@/components/dashboard/scan-status-badge";
import type { DashboardStats } from "@/types/api";

function formatDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

function severityCount(stats: DashboardStats | null, severity: string): number | null {
  if (!stats) return null;
  return stats.findings_by_severity.find((s) => s.severity === severity)?.count ?? 0;
}

interface DashboardOverviewProps {
  /** `null` while loading; the parent (dashboard page) owns the single
   * GET /dashboard/stats fetch so this, the risk chart, and the
   * activity panel all render from one consistent snapshot rather than
   * racing three separate requests. */
  stats: DashboardStats | null;
  error: boolean;
}

/**
 * "Total scans" and severity stat cards plus the recent scans list,
 * from app/services/dashboard.py. 0 means "computed, really zero";
 * `null` means not available, handled by StatCard.
 */
export function DashboardOverview({ stats, error }: DashboardOverviewProps) {
  const loading = stats === null && !error;

  return (
    <>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Total scans"
          icon={ScanSearch}
          value={!error ? stats?.scans_total ?? null : null}
        />
        <StatCard
          label="Critical"
          icon={ShieldAlert}
          value={!error ? severityCount(stats, "critical") : null}
          accentClassName="text-severity-critical"
        />
        <StatCard
          label="High"
          icon={ShieldAlert}
          value={!error ? severityCount(stats, "high") : null}
          accentClassName="text-severity-high"
        />
        <StatCard
          label="Medium"
          icon={ShieldAlert}
          value={!error ? severityCount(stats, "medium") : null}
          accentClassName="text-severity-medium"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base text-foreground">Scans récents</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              Chargement...
            </div>
          ) : stats && stats.recent_scans.length > 0 ? (
            <ul className="flex flex-col gap-3">
              {stats.recent_scans.map((scan) => (
                <li key={scan.id} className="flex items-center justify-between gap-3 text-sm">
                  <Link href={`/scans/${scan.id}`} className="font-mono text-xs hover:underline">
                    {scan.target_name}
                  </Link>
                  <span className="text-muted-foreground">{formatDate(scan.created_at)}</span>
                  <ScanStatusBadge status={scan.status as ScanStatus} />
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              icon={Clock}
              title="Aucun scan récent"
              description="Lancez un scan depuis la page Cibles pour le voir apparaître ici."
            />
          )}
        </CardContent>
      </Card>
    </>
  );
}
