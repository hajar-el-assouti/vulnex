import type { Metadata } from "next";

import { TargetsView } from "@/features/targets/targets-view";

export const metadata: Metadata = { title: "Targets — VULNEX" };

/**
 * Real target data from /api/v1/targets (app/api/v1/endpoints/targets.py)
 * -- creation and authorization are both wired to the actual backend,
 * not placeholders. Data fetching and interactivity live in the client
 * component below (TargetsView) so this file can stay a plain server
 * component that only owns the page's metadata.
 */
export default function TargetsPage() {
  return <TargetsView />;
}
