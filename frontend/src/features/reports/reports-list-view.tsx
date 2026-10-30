"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { toast } from "sonner";
import { Download, FileText, Loader2, X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/dashboard/empty-state";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { createReport, listReports, reportDownloadUrl } from "@/features/reports/api";
import { listScans } from "@/features/scans/api";
import { listTargets } from "@/features/targets/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import type { ReportFormatValue, ReportPublic, ReportStatusValue, ScanPublic } from "@/types/api";

const TERMINAL_SCAN_STATUSES = new Set(["completed", "failed", "cancelled"]);

const STATUS_LABELS: Record<ReportStatusValue, string> = {
  pending: "En attente",
  generating: "Génération...",
  ready: "Prêt",
  failed: "Échoué",
};

const STATUS_VARIANTS: Record<ReportStatusValue, "secondary" | "default" | "success" | "destructive"> = {
  pending: "secondary",
  generating: "default",
  ready: "success",
  failed: "destructive",
};

function formatDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

/**
 * Reports page: generate a PDF or HTML report from any finished scan
 * (completed, failed or cancelled), list generated reports, and
 * download them through the authenticated download endpoint.
 */
export function ReportsListView() {
  const searchParams = useSearchParams();
  const scanIdFilter = searchParams.get("scan_id") ?? undefined;

  const [reports, setReports] = React.useState<ReportPublic[] | null>(null);
  const [error, setError] = React.useState(false);

  const [eligibleScans, setEligibleScans] = React.useState<ScanPublic[]>([]);
  const [targetNames, setTargetNames] = React.useState<Record<string, string>>({});
  const [selectedScanId, setSelectedScanId] = React.useState<string>(scanIdFilter ?? "");
  const [selectedFormat, setSelectedFormat] = React.useState<ReportFormatValue>("pdf");
  const [generating, setGenerating] = React.useState(false);

  const loadReports = React.useCallback(
    (signal?: AbortSignal) => {
      return listReports(scanIdFilter, signal).then((response) => {
        setError(false);
        setReports(response.items);
      });
    },
    [scanIdFilter],
  );

  React.useEffect(() => {
    const controller = new AbortController();
    loadReports(controller.signal).catch((err) => {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setError(true);
    });
    return () => controller.abort();
  }, [loadReports]);

  React.useEffect(() => {
    const controller = new AbortController();
    Promise.all([listScans(undefined, controller.signal), listTargets(controller.signal)])
      .then(([scansResponse, targetsResponse]) => {
        setEligibleScans(scansResponse.items.filter((s) => TERMINAL_SCAN_STATUSES.has(s.status)));
        const names: Record<string, string> = {};
        targetsResponse.items.forEach((t) => {
          names[t.id] = t.name;
        });
        setTargetNames(names);
      })
      .catch((err) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        // Non-fatal: the generation form just stays empty -- the
        // reports list above still works independently.
      });
    return () => controller.abort();
  }, []);

  async function handleGenerate() {
    if (!selectedScanId) return;
    setGenerating(true);
    try {
      const report = await createReport({ scan_id: selectedScanId, format: selectedFormat });
      setReports((prev) => (prev ? [report, ...prev] : [report]));
      toast.success(
        report.status === "ready"
          ? "Rapport généré avec succès."
          : "Génération du rapport lancée.",
      );
    } catch (error) {
      toast.error(getApiErrorMessage(error));
    } finally {
      setGenerating(false);
    }
  }

  const loading = reports === null && !error;

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <CardTitle className="text-base text-foreground">Rapports</CardTitle>
          {scanIdFilter && (
            <Button variant="outline" size="sm" asChild>
              <Link href="/reports">
                Scan : <span className="font-mono text-xs">{scanIdFilter}</span>
                <X className="size-3" />
              </Link>
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end gap-3 rounded-md border border-border p-4">
        <div className="flex flex-col gap-1">
          <span className="text-xs text-muted-foreground">Scan (terminé)</span>
          <Select value={selectedScanId} onValueChange={setSelectedScanId}>
            <SelectTrigger className="w-72">
              <SelectValue placeholder="Choisir un scan terminé..." />
            </SelectTrigger>
            <SelectContent>
              {eligibleScans.length === 0 ? (
                <div className="px-2 py-1.5 text-sm text-muted-foreground">
                  Aucun scan terminé disponible.
                </div>
              ) : (
                eligibleScans.map((scan) => (
                  <SelectItem key={scan.id} value={scan.id}>
                    {targetNames[scan.target_id] ?? scan.target_id} — {formatDate(scan.finished_at)}
                  </SelectItem>
                ))
              )}
            </SelectContent>
          </Select>
        </div>

        <div className="flex flex-col gap-1">
          <span className="text-xs text-muted-foreground">Format</span>
          <Select value={selectedFormat} onValueChange={(v) => setSelectedFormat(v as ReportFormatValue)}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="pdf">PDF</SelectItem>
              <SelectItem value="html">HTML</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Button onClick={handleGenerate} disabled={!selectedScanId || generating}>
          {generating && <Loader2 className="size-4 animate-spin" />}
          Générer le rapport
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" />
          Chargement...
        </div>
      ) : error ? (
        <EmptyState
          icon={FileText}
          title="Impossible de charger les rapports"
          description="Une erreur est survenue lors du chargement. Réessayez."
        />
      ) : reports && reports.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Scan</TableHead>
              <TableHead>Format</TableHead>
              <TableHead>Statut</TableHead>
              <TableHead>Généré le</TableHead>
              <TableHead className="text-right">Téléchargement</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {reports.map((report) => (
              <TableRow key={report.id}>
                <TableCell className="text-sm">
                  <Link href={`/scans/${report.scan_id}`} className="font-mono text-xs hover:underline">
                    {report.scan_id}
                  </Link>
                </TableCell>
                <TableCell className="text-sm uppercase">{report.format}</TableCell>
                <TableCell>
                  <Badge variant={STATUS_VARIANTS[report.status]}>{STATUS_LABELS[report.status]}</Badge>
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {formatDate(report.completed_at ?? report.created_at)}
                </TableCell>
                <TableCell className="text-right">
                  {report.status === "ready" ? (
                    <Button variant="outline" size="sm" asChild>
                      <a href={reportDownloadUrl(report.id)}>
                        <Download className="size-4" />
                        Télécharger
                      </a>
                    </Button>
                  ) : (
                    <span className="text-xs text-muted-foreground">—</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : (
        <EmptyState
          icon={FileText}
          title="Aucun rapport disponible"
          description="Générez un rapport à partir d'un scan terminé ci-dessus pour le voir apparaître ici."
        />
      )}
      </CardContent>
    </Card>
  );
}
