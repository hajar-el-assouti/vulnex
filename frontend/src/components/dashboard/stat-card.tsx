import type { LucideIcon } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface StatCardProps {
  label: string;
  icon: LucideIcon;
  value?: number | null;
  accentClassName?: string;
}

/**
 * `value` is `null | undefined` whenever the backing endpoint doesn't
 * exist yet -- rendered as "—", never a fabricated number. Once scan
 * endpoints ship, callers pass a real count and the dash disappears on
 * its own.
 */
export function StatCard({ label, icon: Icon, value, accentClassName }: StatCardProps) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle>{label}</CardTitle>
        <Icon className={cn("size-4 text-muted-foreground", accentClassName)} aria-hidden="true" />
      </CardHeader>
      <CardContent>
        <p className="text-2xl font-semibold tabular-nums">
          {value === null || value === undefined ? (
            <span className="text-muted-foreground" aria-label="Donnée non disponible">
              —
            </span>
          ) : (
            value.toLocaleString("fr-FR")
          )}
        </p>
      </CardContent>
    </Card>
  );
}
