"use client";

import * as React from "react";
import Link from "next/link";
import { ArrowLeft, FileText, Loader2, ScanSearch, XCircle } from "lucide-react";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/dashboard/empty-state";
import { ScanStatusBadge, type ScanStatus } from "@/components/dashboard/scan-status-badge";
import { cancelScan, getScan, getScanEvents } from "@/features/scans/api";
import { ActiveWebTestingFindingsView } from "@/features/scans/active-web-testing-findings-view";
import { ReconResultsView } from "@/features/scans/recon-results-view";
import { RerunScanAction } from "@/features/scans/rerun-scan-action";
import { WebVulnFindingsView } from "@/features/scans/web-vuln-findings-view";
import { useScanStatus } from "@/lib/hooks/use-scan-status";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import { MODULE_LABELS } from "@/features/scans/module-labels";
import type { ScanEventPublic, ScanModuleRunPublic, ScanPublic } from "@/types/api";

const CANCELLABLE_STATUSES: ScanStatus[] = ["pending", "queued", "running"];
const TERMINAL_STATUSES: ScanStatus[] = ["completed", "failed", "cancelled"];

function formatDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

export function ScanDetailView({ scanId }: { scanId: string }) {
  const [scan, setScan] = React.useState<ScanPublic | null>(null);
  const [events, setEvents] = React.useState<ScanEventPublic[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [isCancelling, setIsCancelling] = React.useState(false);

  // The cheap /status endpoint drives polling (see useScanStatus's own
  // docstring for why that's a separate endpoint from GET /scans/{id}).
  const { status, isPolling } = useScanStatus(
    scanId,
    scan
      ? {
          id: scan.id,
          status: scan.status,
          started_at: scan.started_at,
          finished_at: scan.finished_at,
          cancel_requested_at: scan.cancel_requested_at,
        }
      : undefined,
  );

  const loadFull = React.useCallback(
    (signal?: AbortSignal) => {
      return Promise.all([getScan(scanId, signal), getScanEvents(scanId, signal)])
        .then(([scanResponse, eventsResponse]) => {
          setScan(scanResponse);
          setEvents(eventsResponse.items);
        })
        .catch((err) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(getApiErrorMessage(err));
        });
    },
    [scanId],
  );

  React.useEffect(() => {
    const controller = new AbortController();
    void loadFull(controller.signal);
    return () => controller.abort();
  }, [loadFull]);

  // Whenever the cheap status poll reports a new status, re-fetch the
  // full scan (module runs) and events -- the status-only payload
  // intentionally doesn't carry those, so this is the one place they
  // get refreshed as the scan progresses.
  const lastSeenStatus = React.useRef<string | null>(null);
  React.useEffect(() => {
    if (!status || status.status === lastSeenStatus.current) return;
    lastSeenStatus.current = status.status;
    const controller = new AbortController();
    void loadFull(controller.signal);
    return () => controller.abort();
  }, [status, loadFull]);

  async function handleCancel() {
    if (!scan) return;
    setIsCancelling(true);
    try {
      const updated = await cancelScan(scan.id);
      setScan(updated);
      toast.success("Annulation demandée.");
    } catch (err) {
      toast.error(getApiErrorMessage(err));
    } finally {
      setIsCancelling(false);
    }
  }

  const currentStatus = (status?.status ?? scan?.status) as ScanStatus | undefined;
  const canCancel = currentStatus ? CANCELLABLE_STATUSES.includes(currentStatus) : false;
  const canRerun = currentStatus ? TERMINAL_STATUSES.includes(currentStatus) : false;

  return (
    <div className="flex flex-col gap-4">
      <Button variant="ghost" size="sm" asChild className="w-fit">
        <Link href="/scans">
          <ArrowLeft className="size-4" />
          Retour aux scans
        </Link>
      </Button>

      <Card>
        <CardHeader className="flex-row items-center justify-between gap-3">
          <CardTitle className="text-base text-foreground">
            Scan <span className="font-mono text-sm text-muted-foreground">{scanId}</span>
          </CardTitle>
          <div className="flex items-center gap-2">
            {currentStatus && <ScanStatusBadge status={currentStatus} />}
            {isPolling && <Loader2 className="size-4 animate-spin text-muted-foreground" />}
            {canCancel && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleCancel}
                disabled={isCancelling}
              >
                {isCancelling ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <XCircle className="size-4" />
                )}
                Annuler
              </Button>
            )}
            {canRerun && scan && <RerunScanAction scanId={scan.id} moduleRuns={scan.module_runs} />}
            {canRerun && scan && (
              <Button variant="outline" size="sm" asChild>
                <Link href={`/reports?scan_id=${scan.id}`}>
                  <FileText className="size-4" />
                  Rapports
                </Link>
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}

          {!scan && !error ? (
            <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              Chargement du scan...
            </div>
          ) : scan ? (
            <>
              <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
                <div>
                  <dt className="text-muted-foreground">Cible</dt>
                  <dd className="font-mono text-xs">{scan.target_id}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Démarré le</dt>
                  <dd>{formatDate(scan.started_at)}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Terminé le</dt>
                  <dd>{formatDate(scan.finished_at)}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Annulation demandée</dt>
                  <dd>{formatDate(scan.cancel_requested_at)}</dd>
                </div>
              </dl>

              <div>
                <h3 className="mb-2 text-sm font-medium text-foreground">Modules</h3>
                {scan.module_runs.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Module</TableHead>
                        <TableHead>Statut</TableHead>
                        <TableHead>Démarré le</TableHead>
                        <TableHead>Terminé le</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {scan.module_runs.map((run) => (
                        <TableRow key={run.id}>
                          <TableCell className="text-sm">
                            {MODULE_LABELS[run.module_slug] ?? run.module_slug}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline">{run.status}</Badge>
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {formatDate(run.started_at)}
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {formatDate(run.finished_at)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <p className="text-sm text-muted-foreground">Aucun module enregistré.</p>
                )}
              </div>

              {scan.module_runs
                .filter(
                  (run: ScanModuleRunPublic): run is ScanModuleRunPublic & { result: NonNullable<ScanModuleRunPublic["result"]> } =>
                    // advanced_recon, web_vuln_assessment,
                    // active_web_testing and discovery_fuzzing store
                    // the same result shape as recon (see
                    // ReconPersistedResult in types/api.ts), so the
                    // same viewer renders all of them.
                    (run.module_slug === "recon" ||
                      run.module_slug === "advanced_recon" ||
                      run.module_slug === "web_vuln_assessment" ||
                      run.module_slug === "active_web_testing" ||
                      run.module_slug === "discovery_fuzzing") &&
                    run.result !== null,
                )
                .map((run) => (
                  <div key={run.id}>
                    <h3 className="mb-2 text-sm font-medium text-foreground">
                      {run.module_slug === "advanced_recon"
                        ? "Résultats de reconnaissance avancée"
                        : run.module_slug === "web_vuln_assessment"
                          ? "Contrôles exécutés (analyse de vulnérabilités)"
                          : run.module_slug === "active_web_testing"
                            ? "Contrôles exécutés (tests actifs)"
                            : run.module_slug === "discovery_fuzzing"
                              ? "Chemins découverts (Quick Scan)"
                              : "Résultats de reconnaissance"}
                    </h3>
                    <ReconResultsView result={run.result} />
                  </div>
                ))}

              {(() => {
                // `scan.findings` is one array for every module in
                // the scan. Split it by `scan_module_id`, matched
                // against each module run, so a scan that ran both
                // web_vuln_assessment and active_web_testing never
                // shows the same finding in both sections.
                const webVulnRun = scan.module_runs.find((run) => run.module_slug === "web_vuln_assessment");
                const activeTestingRun = scan.module_runs.find((run) => run.module_slug === "active_web_testing");
                const webVulnFindings = webVulnRun
                  ? scan.findings.filter((f) => f.scan_module_id === webVulnRun.scan_module_id)
                  : [];
                const activeTestingFindings = activeTestingRun
                  ? scan.findings.filter((f) => f.scan_module_id === activeTestingRun.scan_module_id)
                  : [];
                return (
                  <>
                    {webVulnRun?.status === "completed" && (
                      <div>
                        <h3 className="mb-2 text-sm font-medium text-foreground">
                          Findings (analyse de vulnérabilités)
                        </h3>
                        <WebVulnFindingsView findings={webVulnFindings} />
                      </div>
                    )}

                    {activeTestingRun?.status === "completed" && (
                      <div>
                        <h3 className="mb-2 text-sm font-medium text-foreground">
                          Findings (tests actifs)
                        </h3>
                        <ActiveWebTestingFindingsView findings={activeTestingFindings} />
                      </div>
                    )}
                  </>
                );
              })()}

              <div>
                <h3 className="mb-2 text-sm font-medium text-foreground">Journal d&apos;événements</h3>
                {events && events.length > 0 ? (
                  <ul className="flex flex-col gap-2 text-sm">
                    {events.map((event) => (
                      <li key={event.id} className="flex items-baseline gap-3">
                        <span className="w-40 shrink-0 font-mono text-xs text-muted-foreground">
                          {formatDate(event.created_at)}
                        </span>
                        <Badge variant="outline" className="shrink-0">
                          {event.event_type}
                        </Badge>
                        <span className="text-muted-foreground">{event.message}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted-foreground">Aucun événement pour le moment.</p>
                )}
              </div>
            </>
          ) : (
            <EmptyState
              icon={ScanSearch}
              title="Scan introuvable"
              description="Ce scan n'existe pas ou ne vous appartient pas."
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
