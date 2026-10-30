"use client";

import { useEffect, useRef, useState } from "react";

import { getScanStatus } from "@/features/scans/api";
import type { ScanStatusResponse, ScanStatusValue } from "@/types/api";

/** Mirrors app/models/scan.py's TERMINAL_SCAN_STATUSES -- once a scan
 * reaches one of these it is never overwritten by a late worker, so
 * polling for it further would be wasted requests. */
const TERMINAL_STATUSES: ScanStatusValue[] = ["completed", "failed", "cancelled"];

const POLL_INTERVAL_MS = 3000;

interface UseScanStatusResult {
  status: ScanStatusResponse | null;
  /** Human-readable message if the last poll failed; polling stops on
   * error rather than retrying forever against a possibly-dead endpoint. */
  error: string | null;
  isPolling: boolean;
}

/**
 * Polls GET /scans/{id}/status at a fixed interval until the scan
 * reaches a terminal status, then stops. Aborts the request and clears
 * the timer on unmount or when `scanId` changes, so leaving the page
 * never leaves a poll running.
 *
 * `initialStatus` seeds the first render (e.g. from a server-fetched
 * ScanPublic). If it is already terminal, polling is skipped.
 */
export function useScanStatus(
  scanId: string,
  initialStatus?: ScanStatusResponse | null,
): UseScanStatusResult {
  const [status, setStatus] = useState<ScanStatusResponse | null>(initialStatus ?? null);
  const [error, setError] = useState<string | null>(null);
  const [isPolling, setIsPolling] = useState(
    () => !(initialStatus && TERMINAL_STATUSES.includes(initialStatus.status)),
  );

  // Only used to seed the very first effect run; intentionally not a
  // reactive dependency -- re-passing a new initialStatus object on
  // every parent render must not restart polling.
  const initialStatusRef = useRef(initialStatus);

  useEffect(() => {
    const seeded = initialStatusRef.current;
    if (seeded && TERMINAL_STATUSES.includes(seeded.status)) {
      setIsPolling(false);
      return;
    }

    let stopped = false;
    const controller = new AbortController();
    let timeoutId: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      try {
        const next = await getScanStatus(scanId, controller.signal);
        if (stopped) return;
        setStatus(next);
        setError(null);
        if (TERMINAL_STATUSES.includes(next.status)) {
          setIsPolling(false);
          return;
        }
        timeoutId = setTimeout(poll, POLL_INTERVAL_MS);
      } catch (err) {
        if (stopped || (err instanceof DOMException && err.name === "AbortError")) {
          return;
        }
        setError(
          err instanceof Error ? err.message : "Impossible de récupérer le statut du scan",
        );
        setIsPolling(false);
      }
    }

    setIsPolling(true);
    void poll();

    return () => {
      stopped = true;
      controller.abort();
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };
  }, [scanId]);

  return { status, error, isPolling };
}
