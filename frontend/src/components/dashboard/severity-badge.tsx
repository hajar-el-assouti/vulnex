import { Badge } from "@/components/ui/badge";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

const LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

const VARIANTS: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge variant={VARIANTS[severity]}>{LABELS[severity]}</Badge>;
}

/**
 * The backend's Severity enum (app/models/scan_finding.py) calls its
 * lowest level "info", while this component uses "informational". This
 * mapping is the one place that difference is handled, so every
 * feature reading a raw backend severity (findings page, dashboard)
 * goes through it. An unknown value falls back to "informational"
 * instead of crashing the render.
 */
export function toUiSeverity(raw: string): Severity {
  if (raw === "info") return "informational";
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") return raw;
  return "informational";
}
