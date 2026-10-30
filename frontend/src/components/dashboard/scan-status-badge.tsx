import { Badge } from "@/components/ui/badge";

/**
 * Matches the backend's `scan_status` enum exactly, including
 * CANCELLING (see app/models/scan.py).
 */
export type ScanStatus =
  | "pending"
  | "queued"
  | "running"
  | "cancelling"
  | "completed"
  | "failed"
  | "cancelled";

const LABELS: Record<ScanStatus, string> = {
  pending: "En attente",
  queued: "En file",
  running: "En cours",
  cancelling: "Annulation...",
  completed: "Terminé",
  failed: "Échoué",
  cancelled: "Annulé",
};

const VARIANTS: Record<
  ScanStatus,
  "secondary" | "default" | "success" | "destructive" | "outline"
> = {
  pending: "secondary",
  queued: "secondary",
  running: "default",
  cancelling: "outline",
  completed: "success",
  failed: "destructive",
  cancelled: "outline",
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return <Badge variant={VARIANTS[status]}>{LABELS[status]}</Badge>;
}
