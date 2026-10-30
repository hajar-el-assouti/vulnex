import type { Metadata } from "next";

import { ScanDetailView } from "@/features/scans/scan-detail-view";

export const metadata: Metadata = { title: "Détail du scan — VULNEX" };

/**
 * Real scan detail + status polling + events + cancel, all wired to
 * /api/v1/scans/{id}, /status, /events and /cancel. Polling (see
 * lib/hooks/use-scan-status.ts) is plain HTTP on a timer, never
 * WebSocket/SSE, and stops once the scan reaches a terminal status.
 */
export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <ScanDetailView scanId={id} />;
}
