import type { Metadata } from "next";
import { Suspense } from "react";

import { ScansView } from "@/features/scans/scans-view";

export const metadata: Metadata = { title: "Scans — VULNEX" };

/**
 * Scan list from /api/v1/scans. Scans run the selected modules (see
 * features/scans/new-scan-form.tsx).
 */
export default function ScansPage() {
  return (
    <Suspense>
      <ScansView />
    </Suspense>
  );
}
