"use client";

import * as React from "react";
import { ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { EmptyState } from "@/components/dashboard/empty-state";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { FindingConfidenceValue, FindingSeverityValue, ScanFindingPublic } from "@/types/api";

/**
 * Shows the findings of a completed `active_web_testing` run. Same
 * ScanFindingPublic data as WebVulnFindingsView, filtered to this
 * module.
 *
 * The caller (scan-detail-view.tsx) only passes the findings whose
 * `scan_module_id` matches this scan's `active_web_testing` run, so a
 * scan that also ran `web_vuln_assessment` never shows the same finding
 * twice.
 *
 * These findings come from real test requests sent to the target, so
 * they are shown in a separate section from the passive findings,
 * never merged into one table. Confidence is capped at MEDIUM by the
 * engine's checks, so the same "never auto-confirmed" banner is shown.
 *
 * XSS safety: every string below (title, description, affected_url,
 * evidence, including any reflected marker or response fragment) comes
 * from the target and is untrusted. It is rendered as plain JSX text,
 * never with dangerouslySetInnerHTML, so React escapes it: a target that
 * reflects "<script>" is just shown as text.
 */

const SEVERITY_LABELS: Record<FindingSeverityValue, string> = {
  info: "Info",
  low: "Faible",
  medium: "Moyenne",
  high: "Élevée",
  critical: "Critique",
};

const SEVERITY_ORDER: FindingSeverityValue[] = ["critical", "high", "medium", "low", "info"];

const CONFIDENCE_LABELS: Record<FindingConfidenceValue, string> = {
  low: "Faible",
  medium: "Moyenne",
  high: "Élevée",
  confirmed: "Confirmée",
};

const CONFIDENCE_ORDER: FindingConfidenceValue[] = ["confirmed", "high", "medium", "low"];

// `evidence._check` is the registry slug
// (app/engines/active_web_testing/registry.py) that produced this
// finding -- same convention as web-vuln-findings-view.tsx.
const CATEGORY_LABELS: Record<string, string> = {
  xss_reflected: "XSS réfléchie",
  sqli_differential: "Injection SQL différentielle",
  http_param_testing: "Paramètres HTTP",
  api_security_active: "Sécurité API",
};

function findingCategory(finding: ScanFindingPublic): string {
  const check = finding.evidence["_check"];
  return typeof check === "string" ? check : "autre";
}

function renderEvidenceValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function httpMethod(finding: ScanFindingPublic): string | null {
  const method = finding.evidence["_http_method"];
  return typeof method === "string" ? method : null;
}

function FindingEvidence({ finding }: { finding: ScanFindingPublic }) {
  const entries = Object.entries(finding.evidence).filter(
    ([key]) => key !== "owasp_category" && key !== "impact" && key !== "_http_method",
  );
  return (
    <div className="flex flex-col gap-2 text-sm">
      {typeof finding.evidence["owasp_category"] === "string" && (
        <p>
          <span className="text-muted-foreground">Catégorie OWASP : </span>
          {finding.evidence["owasp_category"] as string}
        </p>
      )}
      {finding.cwe_id && (
        <p>
          <span className="text-muted-foreground">CWE : </span>
          {finding.cwe_id}
        </p>
      )}
      {typeof finding.evidence["impact"] === "string" && finding.evidence["impact"] && (
        <p>
          <span className="text-muted-foreground">Impact potentiel : </span>
          {finding.evidence["impact"] as string}
        </p>
      )}
      {finding.remediation && (
        <p>
          <span className="text-muted-foreground">Remédiation : </span>
          {finding.remediation}
        </p>
      )}
      {entries.length > 0 && (
        <div className="rounded-md border border-border p-2">
          <p className="mb-1 text-xs text-muted-foreground">Preuves techniques</p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-xs">
            {entries.map(([key, value]) => (
              <React.Fragment key={key}>
                <dt className="text-muted-foreground">{key}</dt>
                <dd className="whitespace-pre-wrap break-all">{renderEvidenceValue(value)}</dd>
              </React.Fragment>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding }: { finding: ScanFindingPublic }) {
  const [expanded, setExpanded] = React.useState(false);
  const method = httpMethod(finding);
  return (
    <>
      <TableRow className="cursor-pointer" onClick={() => setExpanded((v) => !v)}>
        <TableCell>
          <Badge variant={finding.severity}>{SEVERITY_LABELS[finding.severity]}</Badge>
        </TableCell>
        <TableCell className="text-sm">{finding.title}</TableCell>
        <TableCell className="text-sm text-muted-foreground">
          {CATEGORY_LABELS[findingCategory(finding)] ?? findingCategory(finding)}
        </TableCell>
        <TableCell>
          <Badge variant="outline">{CONFIDENCE_LABELS[finding.confidence]}</Badge>
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">{method ?? "—"}</TableCell>
        <TableCell className="max-w-xs truncate text-xs text-muted-foreground">
          {finding.affected_url ?? "—"}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30">
            <div className="flex flex-col gap-2 py-2">
              {finding.description && <p className="text-sm">{finding.description}</p>}
              <FindingEvidence finding={finding} />
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

export function ActiveWebTestingFindingsView({ findings }: { findings: ScanFindingPublic[] }) {
  const [severityFilter, setSeverityFilter] = React.useState<string>("all");
  const [confidenceFilter, setConfidenceFilter] = React.useState<string>("all");
  const [categoryFilter, setCategoryFilter] = React.useState<string>("all");

  const categories = React.useMemo(
    () => Array.from(new Set(findings.map(findingCategory))).sort(),
    [findings],
  );

  const filtered = findings.filter(
    (finding) =>
      (severityFilter === "all" || finding.severity === severityFilter) &&
      (confidenceFilter === "all" || finding.confidence === confidenceFilter) &&
      (categoryFilter === "all" || findingCategory(finding) === categoryFilter),
  );

  const sorted = [...filtered].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  if (findings.length === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="Aucun finding"
        description="Aucun comportement suspect n'a été détecté par les tests actifs de cette analyse."
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <Alert>
        <AlertDescription>
          Ces findings proviennent de <strong>tests actifs</strong> (de vraies requêtes envoyées
          à la cible), contrairement à l&apos;analyse passive ci-dessus. Un comportement suspect
          n&apos;est jamais présenté automatiquement comme une vulnérabilité confirmée : voir le
          niveau de confiance de chaque finding ci-dessous (« Confirmée » n&apos;est jamais
          utilisé par ce module).
        </AlertDescription>
      </Alert>

      <div className="flex flex-wrap gap-2">
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Sévérité" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Toutes sévérités</SelectItem>
            {SEVERITY_ORDER.map((value) => (
              <SelectItem key={value} value={value}>
                {SEVERITY_LABELS[value]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={confidenceFilter} onValueChange={setConfidenceFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Confiance" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Toutes confiances</SelectItem>
            {CONFIDENCE_ORDER.map((value) => (
              <SelectItem key={value} value={value}>
                {CONFIDENCE_LABELS[value]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Catégorie" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Toutes catégories</SelectItem>
            {categories.map((value) => (
              <SelectItem key={value} value={value}>
                {CATEGORY_LABELS[value] ?? value}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {sorted.length === 0 ? (
        <p className="text-sm text-muted-foreground">Aucun finding ne correspond à ces filtres.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Sévérité</TableHead>
              <TableHead>Titre</TableHead>
              <TableHead>Catégorie</TableHead>
              <TableHead>Confiance</TableHead>
              <TableHead>Méthode</TableHead>
              <TableHead>URL concernée</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.map((finding) => (
              <FindingRow key={finding.id} finding={finding} />
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
