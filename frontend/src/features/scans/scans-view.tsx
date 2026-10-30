"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Loader2, ScanSearch, X } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/dashboard/empty-state";
import { ScanStatusBadge, type ScanStatus } from "@/components/dashboard/scan-status-badge";
import { NewScanForm } from "@/features/scans/new-scan-form";
import { listScans } from "@/features/scans/api";
import { listTargets } from "@/features/targets/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import type { ScanPublic, TargetPublic } from "@/types/api";

const STATUS_FILTERS: { value: string; label: string }[] = [
  { value: "all", label: "Tous les statuts" },
  { value: "pending", label: "En attente" },
  { value: "queued", label: "En file" },
  { value: "running", label: "En cours" },
  { value: "cancelling", label: "Annulation..." },
  { value: "completed", label: "Terminé" },
  { value: "failed", label: "Échoué" },
  { value: "cancelled", label: "Annulé" },
];

function formatDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}

export function ScansView() {
  const searchParams = useSearchParams();
  const targetIdFilter = searchParams.get("target_id") ?? undefined;

  const [scans, setScans] = React.useState<ScanPublic[] | null>(null);
  const [targets, setTargets] = React.useState<TargetPublic[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [statusFilter, setStatusFilter] = React.useState("all");

  React.useEffect(() => {
    const controller = new AbortController();
    Promise.all([listScans(targetIdFilter, controller.signal), listTargets(controller.signal)])
      .then(([scansResponse, targetsResponse]) => {
        setScans(scansResponse.items);
        setTargets(targetsResponse.items);
      })
      .catch((err) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(getApiErrorMessage(err));
      });
    return () => controller.abort();
  }, [targetIdFilter]);

  const targetsById = React.useMemo(() => {
    const map = new Map<string, TargetPublic>();
    for (const target of targets ?? []) map.set(target.id, target);
    return map;
  }, [targets]);

  const authorizedTargets = React.useMemo(
    () => (targets ?? []).filter((t) => t.is_authorized),
    [targets],
  );

  const visibleScans = React.useMemo(() => {
    if (!scans) return [];
    if (statusFilter === "all") return scans;
    return scans.filter((scan) => scan.status === statusFilter);
  }, [scans, statusFilter]);

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <CardTitle className="text-base text-foreground">Scans</CardTitle>
          {targetIdFilter && targetsById.get(targetIdFilter) && (
            <Button variant="outline" size="sm" asChild>
              <Link href="/scans">
                Cible : {targetsById.get(targetIdFilter)?.name}
                <X className="size-3" />
              </Link>
            </Button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUS_FILTERS.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <NewScanForm authorizedTargets={authorizedTargets} defaultTargetId={targetIdFilter} />
        </div>
      </CardHeader>
      <CardContent>
        {error && (
          <p className="pb-4 text-sm text-destructive" role="alert">
            {error}
          </p>
        )}

        {scans === null && !error ? (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
            Chargement des scans...
          </div>
        ) : visibleScans.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Cible</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Modules</TableHead>
                <TableHead>Démarré le</TableHead>
                <TableHead>Terminé le</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visibleScans.map((scan) => (
                <TableRow key={scan.id} className="cursor-pointer">
                  <TableCell>
                    <Link href={`/scans/${scan.id}`} className="hover:underline">
                      {targetsById.get(scan.target_id)?.name ?? scan.target_id}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <ScanStatusBadge status={scan.status as ScanStatus} />
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {scan.module_runs.length}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDate(scan.started_at)}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDate(scan.finished_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="py-6">
            <EmptyState
              icon={ScanSearch}
              title="Aucun scan"
              description="Lancez un scan depuis une cible autorisée pour voir apparaître son suivi ici."
              action={
                authorizedTargets.length > 0 ? (
                  <NewScanForm authorizedTargets={authorizedTargets} defaultTargetId={targetIdFilter} />
                ) : undefined
              }
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
