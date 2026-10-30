"use client";

import * as React from "react";
import Link from "next/link";
import { toast } from "sonner";
import { ArrowDown, ArrowUp, Loader2, ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/dashboard/empty-state";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { listFindings, updateFindingStatus } from "@/features/findings/api";
import { getApiErrorMessage } from "@/lib/api/error-messages";
import type { FindingListParams, FindingPublic, FindingStatusValue } from "@/types/api";

const PAGE_SIZE = 20;

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
  info: "Info",
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const CONFIDENCE_LABELS: Record<string, string> = {
  confirmed: "Confirmée",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
};
const CONFIDENCE_ORDER = ["confirmed", "high", "medium", "low"];

const STATUS_LABELS: Record<FindingStatusValue, string> = {
  open: "Ouvert",
  in_review: "En revue",
  resolved: "Résolu",
  false_positive: "Faux positif",
};
const STATUS_ORDER: FindingStatusValue[] = ["open", "in_review", "resolved", "false_positive"];

const CATEGORY_LABELS: Record<string, string> = {
  security_headers: "En-têtes de sécurité",
  cookies: "Cookies",
  cors: "CORS",
  info_disclosure: "Divulgation d'informations",
  http_methods: "Méthodes HTTP",
  tls_config: "Configuration TLS/HTTPS",
  injection_surface: "Surface XSS/SQLi",
  api_security: "Sécurité API",
  api_discovery: "Découverte API",
  xss_reflected: "XSS réfléchi (actif)",
  sqli_differential: "SQLi différentiel (actif)",
  http_param_testing: "Tests de paramètres HTTP (actif)",
  api_security_active: "Sécurité API (actif)",
  other: "Autre",
};

function severityBadgeVariant(severity: string): "critical" | "high" | "medium" | "low" | "info" {
  if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low") {
    return severity;
  }
  return "info";
}

function formatDate(value: string): string {
  return new Date(value).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
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

function FindingDetail({ finding }: { finding: FindingPublic }) {
  const entries = Object.entries(finding.evidence).filter(
    ([key]) => key !== "owasp_category" && key !== "impact",
  );
  return (
    <div className="flex flex-col gap-2 py-2 text-sm">
      {finding.description && <p>{finding.description}</p>}
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
          <p className="mb-1 text-xs text-muted-foreground">Preuves techniques (épurées)</p>
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
      <p className="text-xs text-muted-foreground">
        <Link href={`/scans/${finding.scan_id}`} className="hover:underline">
          Voir le scan source
        </Link>
      </p>
    </div>
  );
}

function FindingRow({
  finding,
  onStatusChange,
}: {
  finding: FindingPublic;
  onStatusChange: (findingId: string, status: FindingStatusValue) => void;
}) {
  const [expanded, setExpanded] = React.useState(false);
  const [updating, setUpdating] = React.useState(false);

  async function handleStatusChange(next: string) {
    const status = next as FindingStatusValue;
    setUpdating(true);
    try {
      const updated = await updateFindingStatus(finding.id, { status });
      onStatusChange(finding.id, updated.status);
    } catch (error) {
      toast.error(getApiErrorMessage(error));
    } finally {
      setUpdating(false);
    }
  }

  return (
    <>
      <TableRow className="cursor-pointer" onClick={() => setExpanded((v) => !v)}>
        <TableCell>
          <Badge variant={severityBadgeVariant(finding.severity)}>
            {SEVERITY_LABELS[finding.severity] ?? finding.severity}
          </Badge>
        </TableCell>
        <TableCell className="max-w-xs truncate text-sm">{finding.title}</TableCell>
        <TableCell className="text-sm text-muted-foreground">{finding.target_name}</TableCell>
        <TableCell className="text-sm text-muted-foreground">
          {CATEGORY_LABELS[finding.category] ?? finding.category}
        </TableCell>
        <TableCell>
          <Badge variant="outline">{CONFIDENCE_LABELS[finding.confidence] ?? finding.confidence}</Badge>
        </TableCell>
        <TableCell onClick={(e) => e.stopPropagation()}>
          <Select value={finding.status} onValueChange={handleStatusChange} disabled={updating}>
            <SelectTrigger className="h-8 w-36 text-xs">
              {updating ? <Loader2 className="size-3 animate-spin" /> : <SelectValue />}
            </SelectTrigger>
            <SelectContent>
              {STATUS_ORDER.map((value) => (
                <SelectItem key={value} value={value}>
                  {STATUS_LABELS[value]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </TableCell>
        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
          {formatDate(finding.created_at)}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={7} className="bg-muted/30">
            <FindingDetail finding={finding} />
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

/**
 * Global findings page: filters (severity/confidence/status/category),
 * search, sort, pagination, an expandable detail row and status
 * updates, backed by GET/PATCH /api/v1/findings. "category" options
 * come from the findings loaded so far, since there is no endpoint
 * listing all categories.
 */
export function FindingsListView() {
  const [severity, setSeverity] = React.useState<string>("all");
  const [confidence, setConfidence] = React.useState<string>("all");
  const [status, setStatus] = React.useState<string>("all");
  const [category, setCategory] = React.useState<string>("all");
  const [searchInput, setSearchInput] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [sortBy, setSortBy] = React.useState<FindingListParams["sort_by"]>("created_at");
  const [sortDesc, setSortDesc] = React.useState(true);
  const [page, setPage] = React.useState(1);

  const [findings, setFindings] = React.useState<FindingPublic[] | null>(null);
  const [total, setTotal] = React.useState(0);
  const [error, setError] = React.useState(false);
  const [knownCategories, setKnownCategories] = React.useState<Set<string>>(new Set());

  // Debounce the free-text search box -- avoids firing a request on
  // every keystroke.
  React.useEffect(() => {
    const timeout = setTimeout(() => setSearch(searchInput.trim()), 300);
    return () => clearTimeout(timeout);
  }, [searchInput]);

  // Search resets to page 1 once it actually changes (debounced above)
  // -- otherwise a narrower filter could leave the user stranded on a
  // now-nonexistent page. The other filters reset page 1 directly in
  // their own onValueChange handlers below, rather than reacting to
  // their state in a separate effect.
  const previousSearch = React.useRef(search);
  React.useEffect(() => {
    if (previousSearch.current !== search) {
      previousSearch.current = search;
      setPage(1);
    }
  }, [search]);

  React.useEffect(() => {
    const controller = new AbortController();
    const params: FindingListParams = {
      severity: severity === "all" ? undefined : severity,
      confidence: confidence === "all" ? undefined : confidence,
      status: status === "all" ? undefined : (status as FindingStatusValue),
      category: category === "all" ? undefined : category,
      search: search || undefined,
      sort_by: sortBy,
      sort_desc: sortDesc,
      page,
      page_size: PAGE_SIZE,
    };
    listFindings(params, controller.signal)
      .then((response) => {
        setError(false);
        setFindings(response.items);
        setTotal(response.total);
        setKnownCategories((prev) => {
          const next = new Set(prev);
          response.items.forEach((f) => next.add(f.category));
          return next;
        });
      })
      .catch((err) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(true);
      });
    return () => controller.abort();
  }, [severity, confidence, status, category, search, sortBy, sortDesc, page]);

  function handleStatusChange(findingId: string, newStatus: FindingStatusValue) {
    setFindings((prev) =>
      prev ? prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f)) : prev,
    );
  }

  function toggleSort(field: NonNullable<FindingListParams["sort_by"]>) {
    if (sortBy === field) {
      setSortDesc((v) => !v);
    } else {
      setSortBy(field);
      setSortDesc(true);
    }
    setPage(1);
  }

  function handleFilterChange(setter: (value: string) => void) {
    return (value: string) => {
      setter(value);
      setPage(1);
    };
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const loading = findings === null && !error;

  return (
    <div className="flex flex-col gap-3">
      <Alert>
        <AlertDescription>
          Une observation ou une hypothèse n&apos;est jamais présentée automatiquement comme une
          vulnérabilité confirmée : voir le niveau de confiance de chaque finding ci-dessous (
          « Confirmée » n&apos;est utilisé que lorsque les preuves le justifient réellement).
        </AlertDescription>
      </Alert>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Rechercher (titre, description)..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          className="w-64"
        />

        <Select value={severity} onValueChange={handleFilterChange(setSeverity)}>
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

        <Select value={confidence} onValueChange={handleFilterChange(setConfidence)}>
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

        <Select value={status} onValueChange={handleFilterChange(setStatus)}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Statut" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Tous statuts</SelectItem>
            {STATUS_ORDER.map((value) => (
              <SelectItem key={value} value={value}>
                {STATUS_LABELS[value]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={category} onValueChange={handleFilterChange(setCategory)}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Catégorie" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Toutes catégories</SelectItem>
            {Array.from(knownCategories)
              .sort()
              .map((value) => (
                <SelectItem key={value} value={value}>
                  {CATEGORY_LABELS[value] ?? value}
                </SelectItem>
              ))}
          </SelectContent>
        </Select>

        <div className="ml-auto flex items-center gap-1">
          <Button
            variant={sortBy === "created_at" ? "secondary" : "outline"}
            size="sm"
            onClick={() => toggleSort("created_at")}
          >
            Date
            {sortBy === "created_at" &&
              (sortDesc ? <ArrowDown className="size-3" /> : <ArrowUp className="size-3" />)}
          </Button>
          <Button
            variant={sortBy === "severity" ? "secondary" : "outline"}
            size="sm"
            onClick={() => toggleSort("severity")}
          >
            Sévérité
            {sortBy === "severity" &&
              (sortDesc ? <ArrowDown className="size-3" /> : <ArrowUp className="size-3" />)}
          </Button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" />
          Chargement...
        </div>
      ) : error ? (
        <EmptyState
          icon={ShieldAlert}
          title="Impossible de charger les findings"
          description="Une erreur est survenue lors du chargement. Réessayez."
        />
      ) : findings && findings.length > 0 ? (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Sévérité</TableHead>
                <TableHead>Titre</TableHead>
                <TableHead>Cible</TableHead>
                <TableHead>Catégorie</TableHead>
                <TableHead>Confiance</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Date</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((finding) => (
                <FindingRow key={finding.id} finding={finding} onStatusChange={handleStatusChange} />
              ))}
            </TableBody>
          </Table>

          <div className="flex items-center justify-between pt-2 text-sm text-muted-foreground">
            <span>
              {total} finding{total !== 1 ? "s" : ""} — page {page} / {totalPages}
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Précédent
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Suivant
              </Button>
            </div>
          </div>
        </>
      ) : (
        <EmptyState
          icon={ShieldAlert}
          title="Aucun finding"
          description="Aucune vulnérabilité ou problème de configuration ne correspond à ces filtres pour le moment."
        />
      )}
    </div>
  );
}
