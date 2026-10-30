import Link from "next/link";
import { Activity, Loader2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/dashboard/empty-state";
import { SeverityBadge, toUiSeverity } from "@/components/dashboard/severity-badge";
import type { DashboardRecentFinding } from "@/types/api";

function formatDate(value: string): string {
  return new Date(value).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

interface RecentFindingsPanelProps {
  /** `null` while loading; see dashboard-content.tsx, which owns the
   * single GET /dashboard/stats fetch this is sliced from. */
  findings: DashboardRecentFinding[] | null;
  loading: boolean;
}

/**
 * Recent findings from GET /dashboard/stats. An empty array (as
 * opposed to null/loading) means "no findings yet" and shows the
 * EmptyState.
 */
export function RecentFindingsPanel({ findings, loading }: RecentFindingsPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Activité récente</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
            Chargement...
          </div>
        ) : findings && findings.length > 0 ? (
          <ul className="flex flex-col gap-3">
            {findings.map((finding) => (
              <li key={finding.id} className="flex items-center justify-between gap-3 text-sm">
                <Link
                  href={`/scans/${finding.scan_id}`}
                  className="min-w-0 flex-1 truncate hover:underline"
                >
                  {finding.title}
                </Link>
                <span className="shrink-0 text-xs text-muted-foreground">{finding.target_name}</span>
                <SeverityBadge severity={toUiSeverity(finding.severity)} />
                <span className="shrink-0 text-xs text-muted-foreground">
                  {formatDate(finding.created_at)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState
            icon={Activity}
            title="Aucune activité récente"
            description="L'historique d'activité (scans, cibles, rapports) s'affichera ici."
          />
        )}
      </CardContent>
    </Card>
  );
}
