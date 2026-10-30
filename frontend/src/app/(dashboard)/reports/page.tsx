import type { Metadata } from "next";
import { Suspense } from "react";

import { ReportsListView } from "@/features/reports/reports-list-view";

export const metadata: Metadata = { title: "Reports — VULNEX" };

/**
 * Report generation (PDF/HTML) and authenticated download, backed by
 * POST/GET /api/v1/reports and GET /api/v1/reports/{id}/download.
 * ReportsListView reads an optional ?scan_id= filter with
 * useSearchParams, so the page needs a Suspense boundary.
 */
export default function ReportsPage() {
  return (
    <Suspense>
      <ReportsListView />
    </Suspense>
  );
}
