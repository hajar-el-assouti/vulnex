"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type {
  ReconCollectorResultPublic,
  ReconCollectorStatusValue,
  ReconObservation,
  ReconObservationNature,
  ReconPersistedResult,
} from "@/types/api";

/**
 * Shows a completed module run's stored result
 * (build_persisted_result), one tab per collector or check. Values were
 * already redacted and size-capped by the backend before being stored;
 * this component only decides how to display them.
 *
 * Used for recon, advanced_recon, web_vuln_assessment and
 * active_web_testing, which all store the same result shape with
 * different collector slugs. Deep TLS observations (tls_advanced.*) are
 * part of the "tls" collector. Tabs are built from whatever slugs
 * `result.modules` contains, so an unknown slug still shows up, with its
 * raw slug as the label.
 *
 * The visual snapshot collector is disabled by default and never
 * produces an image; its state is shown like any other collector, as a
 * badge and plain text notes.
 *
 * web_vuln_assessment and active_web_testing findings are shown
 * separately (web-vuln-findings-view.tsx,
 * active-web-testing-findings-view.tsx), not in this status table.
 *
 * Values are never rendered as HTML: everything is shown as plain text
 * (see renderValue), even if it looks like markup.
 */

const CATEGORY_LABELS: Record<string, string> = {
  http: "HTTP",
  headers: "En-têtes de sécurité",
  cookies: "Cookies",
  technology: "Technologies",
  metadata: "Métadonnées (robots/sitemap/security.txt)",
  assets: "Ressources externes",
  api_discovery: "Découverte d'API",
  dns: "DNS",
  email_security: "Sécurité email",
  ip_asn: "Infrastructure (IP/ASN)",
  rdap: "RDAP",
  tls: "TLS (incl. analyse approfondie)",
  fingerprint: "Empreinte / Historique",
  // advanced_recon collectors.
  port_scan: "Ports / Services",
  waf_cdn: "WAF / CDN (passif)",
  visual_snapshot: "Capture visuelle (expérimental)",
  // web_vuln_assessment checks. "http", "headers", "cookies",
  // "api_discovery" and "tls" above are shared, no new label needed.
  security_headers: "En-têtes de sécurité (analyse)",
  cors: "CORS",
  info_disclosure: "Divulgation d'informations",
  http_methods: "Méthodes HTTP annoncées",
  tls_config: "Configuration TLS/HTTPS (analyse)",
  injection_surface: "Surface XSS/SQLi (passive)",
  api_security: "Sécurité API (passive)",
  // active_web_testing checks. "http" and "api_discovery" above are
  // shared, no new label needed.
  xss_reflected: "XSS réfléchie (test actif)",
  sqli_differential: "Injection SQL différentielle (test actif)",
  http_param_testing: "Test de paramètres HTTP (actif)",
  api_security_active: "Sécurité API (test actif)",
};

// The order categories are shown in, independent of whatever order the
// backend dict happens to iterate in (Python dict order is insertion
// order, which is stable but not something this UI should depend on).
const CATEGORY_ORDER = [
  "http",
  "headers",
  "cookies",
  "technology",
  "metadata",
  "assets",
  "api_discovery",
  "dns",
  "email_security",
  "ip_asn",
  "rdap",
  "tls",
  // Shown right after "tls" (deep TLS observations are part of it)
  // and before the derived/comparison categories.
  "port_scan",
  "waf_cdn",
  "visual_snapshot",
  "fingerprint",
  // web_vuln_assessment checks, after the shared collectors and before
  // advanced_recon's derived categories. The two modules rarely run
  // together, but one fixed order keeps the tabs from moving around
  // depending on which modules ran.
  "security_headers",
  "cors",
  "info_disclosure",
  "http_methods",
  "tls_config",
  "injection_surface",
  "api_security",
  // active_web_testing checks, after web_vuln_assessment's (its passive
  // counterpart).
  "xss_reflected",
  "sqli_differential",
  "http_param_testing",
  "api_security_active",
];

const COLLECTOR_STATUS_LABELS: Record<ReconCollectorStatusValue, string> = {
  ok: "OK",
  partial: "PARTIEL",
  not_applicable: "NON APPLICABLE",
  error: "ERREUR",
};

const COLLECTOR_STATUS_VARIANTS: Record<
  ReconCollectorStatusValue,
  "success" | "outline" | "secondary" | "destructive"
> = {
  ok: "success",
  partial: "outline",
  not_applicable: "secondary",
  error: "destructive",
};

const NATURE_LABELS: Record<ReconObservationNature, string> = {
  observed: "Observé",
  inferred: "Hypothèse",
  unknown: "Inconnu",
  not_applicable: "N/A",
  error: "Erreur",
};

// Deliberately NEVER "destructive" (red) for any nature -- Recon
// reports observations and hypotheses, never confirmed vulnerabilities
// (see app/engines/recon/schemas.py's own docstring), so nothing here
// should read as an alarm. "error" (collection failed) is the one
// exception worth a slightly stronger outline, but still not red.
const NATURE_VARIANTS: Record<ReconObservationNature, "default" | "outline" | "secondary"> = {
  observed: "default",
  inferred: "outline",
  unknown: "secondary",
  not_applicable: "secondary",
  error: "outline",
};

function renderValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function ObservationRow({ observation }: { observation: ReconObservation }) {
  return (
    <TableRow>
      <TableCell className="font-mono text-xs text-muted-foreground">{observation.key}</TableCell>
      <TableCell className="max-w-md whitespace-pre-wrap break-all text-sm">
        {renderValue(observation.value)}
      </TableCell>
      <TableCell>
        <Badge variant={NATURE_VARIANTS[observation.nature]}>{NATURE_LABELS[observation.nature]}</Badge>
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">{observation.note ?? "—"}</TableCell>
    </TableRow>
  );
}

function CollectorPanel({ result }: { result: ReconCollectorResultPublic }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={COLLECTOR_STATUS_VARIANTS[result.status]}>
          {COLLECTOR_STATUS_LABELS[result.status]}
        </Badge>
        <span className="text-xs text-muted-foreground">
          Confiance : {result.confidence} · {result.duration_ms} ms
        </span>
      </div>

      {result._storage_note && (
        <Alert>
          <AlertDescription>{result._storage_note}</AlertDescription>
        </Alert>
      )}

      {result.errors.length > 0 && (
        <ul className="flex flex-col gap-1 text-sm text-muted-foreground">
          {result.errors.map((err, i) => (
            <li key={i} className="font-mono text-xs">
              {err}
            </li>
          ))}
        </ul>
      )}

      {result.observations.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Clé</TableHead>
              <TableHead>Valeur</TableHead>
              <TableHead>Nature</TableHead>
              <TableHead>Note</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {result.observations.map((obs, i) => (
              <ObservationRow key={`${obs.key}-${i}`} observation={obs} />
            ))}
          </TableBody>
        </Table>
      ) : (
        <p className="text-sm text-muted-foreground">Aucune observation pour cette catégorie.</p>
      )}
    </div>
  );
}

export function ReconResultsView({ result }: { result: ReconPersistedResult }) {
  const slugs = Object.keys(result.modules);
  const ordered = [
    ...CATEGORY_ORDER.filter((slug) => slugs.includes(slug)),
    ...slugs.filter((slug) => !CATEGORY_ORDER.includes(slug)),
  ];

  if (ordered.length === 0) {
    return <p className="text-sm text-muted-foreground">Aucun résultat de reconnaissance disponible.</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      {result.storage_truncated && (
        <Alert>
          <AlertDescription>
            Certaines observations volumineuses ont été omises de l&apos;enregistrement pour
            respecter la limite de taille configurée ({result.truncated_collectors.join(", ")}). Il
            s&apos;agit d&apos;une troncature de stockage, jamais d&apos;un résultat de collecte
            silencieusement incomplet : voir le statut de chaque catégorie ci-dessous.
          </AlertDescription>
        </Alert>
      )}

      <Alert>
        <AlertDescription>
          Ces résultats sont des observations techniques et, le cas échéant, des hypothèses
          (marquées « Hypothèse ») -- jamais des vulnérabilités confirmées. Le moteur Recon ne
          produit aucun finding offensif.
        </AlertDescription>
      </Alert>

      <Tabs defaultValue={ordered[0]}>
        <TabsList className="h-auto flex-wrap">
          {ordered.map((slug) => (
            <TabsTrigger key={slug} value={slug} className="gap-1.5">
              {CATEGORY_LABELS[slug] ?? slug}
              <Badge variant={COLLECTOR_STATUS_VARIANTS[result.modules[slug].status]} className="px-1 py-0 text-[10px]">
                {COLLECTOR_STATUS_LABELS[result.modules[slug].status]}
              </Badge>
            </TabsTrigger>
          ))}
        </TabsList>
        {ordered.map((slug) => (
          <TabsContent key={slug} value={slug} className="pt-3">
            <CollectorPanel result={result.modules[slug]} />
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
