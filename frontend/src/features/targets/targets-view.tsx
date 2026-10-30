"use client";

import * as React from "react";
import Link from "next/link";
import { Target as TargetIcon, Loader2, ScanSearch } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/dashboard/empty-state";
import { TargetForm } from "@/features/targets/target-form";
import { AuthorizeTargetAction } from "@/features/targets/authorize-target-action";
import { listTargets } from "@/features/targets/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import type { TargetPublic } from "@/types/api";

function formatDate(value: string): string {
  return new Date(value).toLocaleString("fr-FR", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function TargetsView() {
  const [targets, setTargets] = React.useState<TargetPublic[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const controller = new AbortController();
    listTargets(controller.signal)
      .then((response) => setTargets(response.items))
      .catch((err) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(getApiErrorMessage(err));
      });
    return () => controller.abort();
  }, []);

  function handleCreated(target: TargetPublic) {
    setTargets((current) => [target, ...(current ?? [])]);
  }

  function handleAuthorized(updated: TargetPublic) {
    setTargets((current) =>
      (current ?? []).map((t) => (t.id === updated.id ? updated : t)),
    );
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-base text-foreground">Cibles autorisées</CardTitle>
        <TargetForm onCreated={handleCreated} />
      </CardHeader>
      <CardContent>
        {error && (
          <p className="pb-4 text-sm text-destructive" role="alert">
            {error}
          </p>
        )}

        {targets === null && !error ? (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
            Chargement des cibles...
          </div>
        ) : targets && targets.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nom</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Statut d&apos;autorisation</TableHead>
                <TableHead>Référence</TableHead>
                <TableHead>Ajoutée le</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {targets.map((target) => (
                <TableRow key={target.id}>
                  <TableCell className="font-medium text-foreground">{target.name}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {target.base_url}
                  </TableCell>
                  <TableCell>
                    {target.is_authorized ? (
                      <Badge variant="success">Autorisée</Badge>
                    ) : (
                      <Badge variant="secondary">Non autorisée</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {target.authorization_reference ?? "—"}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDate(target.created_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      {!target.is_authorized && (
                        <AuthorizeTargetAction target={target} onAuthorized={handleAuthorized} />
                      )}
                      <Button variant="ghost" size="sm" asChild>
                        <Link href={`/scans?target_id=${target.id}`}>
                          <ScanSearch className="size-4" />
                          Scans
                        </Link>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <div className="py-6">
            <EmptyState
              icon={TargetIcon}
              title="Aucune cible pour le moment"
              description="Ajoutez une cible puis enregistrez sa référence d'autorisation avant de pouvoir lancer un scan dessus."
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
