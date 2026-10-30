"use client";

import { PieChart } from "lucide-react";
import { Cell, Pie, PieChart as RePieChart, ResponsiveContainer, Tooltip } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/dashboard/empty-state";
import type { Severity } from "@/components/dashboard/severity-badge";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  informational: "var(--severity-info)",
};

interface RiskDistributionChartProps {
  /** `null` means "no scan/finding endpoint to source this from yet" --
   * renders an explicit empty state instead of an empty or fabricated
   * chart. An empty array (vs null) would mean "endpoint exists, there
   * really are zero findings", which is a different, real state this
   * component is ready to render correctly once that's true. */
  data: { severity: Severity; count: number }[] | null;
}

export function RiskDistributionChart({ data }: RiskDistributionChartProps) {
  const hasData = data !== null && data.some((d) => d.count > 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Répartition des risques</CardTitle>
      </CardHeader>
      <CardContent>
        {hasData ? (
          <ResponsiveContainer width="100%" height={240}>
            <RePieChart>
              <Pie
                data={data}
                dataKey="count"
                nameKey="severity"
                innerRadius={60}
                outerRadius={90}
                paddingAngle={2}
              >
                {data.map((entry) => (
                  <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "var(--popover)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-md)",
                  color: "var(--popover-foreground)",
                }}
              />
            </RePieChart>
          </ResponsiveContainer>
        ) : (
          <EmptyState
            icon={PieChart}
            title="Aucune donnée de vulnérabilité"
            description="Ce graphique s'affichera dès que des scans auront produit des résultats."
          />
        )}
      </CardContent>
    </Card>
  );
}
