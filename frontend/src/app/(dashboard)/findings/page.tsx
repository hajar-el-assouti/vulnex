import type { Metadata } from "next";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FindingsListView } from "@/features/findings/findings-list-view";

export const metadata: Metadata = { title: "Findings — VULNEX" };

/**
 * Global findings page: filters, search, sort, pagination, detail view
 * and status updates, backed by GET/PATCH /api/v1/findings.
 */
export default function FindingsPage() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base text-foreground">Vulnérabilités détectées</CardTitle>
      </CardHeader>
      <CardContent>
        <FindingsListView />
      </CardContent>
    </Card>
  );
}
