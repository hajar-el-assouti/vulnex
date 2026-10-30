"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Loader2, RotateCcw } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { rerunScan } from "@/features/scans/api";
import { MODULE_LABELS } from "@/features/scans/module-labels";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import type { ScanModuleRunPublic } from "@/types/api";

interface RerunScanActionProps {
  scanId: string;
  moduleRuns: ScanModuleRunPublic[];
}

/**
 * Re-runs the original scan's modules through POST /scans/{id}/rerun
 * (the normal create_scan() path). active_testing_confirmed is never
 * copied from the original scan: if an active module is part of the
 * rerun, the user has to tick the confirmation again.
 */
export function RerunScanAction({ scanId, moduleRuns }: RerunScanActionProps) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [confirmed, setConfirmed] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);

  const includesActiveTesting = moduleRuns.some((run) => run.module_slug === "active_web_testing");

  async function handleConfirm() {
    setSubmitting(true);
    try {
      const scan = await rerunScan(scanId, { active_testing_confirmed: confirmed });
      toast.success("Nouveau scan lancé.");
      setOpen(false);
      router.push(`/scans/${scan.id}`);
    } catch (err) {
      toast.error(getApiErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Sheet
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setConfirmed(false);
      }}
    >
      <SheetTrigger asChild>
        <Button variant="outline" size="sm">
          <RotateCcw className="size-4" />
          Relancer
        </Button>
      </SheetTrigger>
      <SheetContent side="right" className="w-96">
        <SheetHeader>
          <SheetTitle>Relancer ce scan</SheetTitle>
        </SheetHeader>

        <p className="text-sm text-muted-foreground">
          Un nouveau scan sera lancé sur la même cible avec exactement les mêmes modules :
        </p>
        <ul className="flex flex-col gap-1 text-sm">
          {moduleRuns.map((run) => (
            <li key={run.id} className="rounded-md border p-2">
              {MODULE_LABELS[run.module_slug] ?? run.module_slug}
            </li>
          ))}
        </ul>

        {includesActiveTesting && (
          <Alert variant="destructive">
            <AlertDescription className="flex flex-col gap-2">
              <span>
                Ce nouveau scan exécutera à nouveau le module{" "}
                <strong>Tests actifs de vulnérabilités</strong>, qui envoie de vraies requêtes de
                test à la cible. L&apos;autorisation n&apos;est jamais reportée depuis le scan
                d&apos;origine -- elle doit être renouvelée explicitement ici.
              </span>
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-0.5 size-4"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>
                  Je comprends et j&apos;autorise à nouveau l&apos;envoi de requêtes de test
                  actives à cette cible.
                </span>
              </label>
            </AlertDescription>
          </Alert>
        )}

        <Button
          onClick={handleConfirm}
          disabled={submitting || (includesActiveTesting && !confirmed)}
          className="mt-2"
        >
          {submitting && <Loader2 className="animate-spin" aria-hidden="true" />}
          Confirmer et relancer
        </Button>
      </SheetContent>
    </Sheet>
  );
}
