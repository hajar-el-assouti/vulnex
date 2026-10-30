"""Passive XSS / SQL injection surface analysis.

Lists HTTP parameters, forms and entry points, notes their HTML/JS
context, and flags parameter names often tied to data queries. It
never sends a payload, never changes a parameter, and never claims a
confirmed vulnerability.

Three levels are kept separate:
- Confirmed observation (OBSERVED): a parameter, form or value that is
  present in the page or URL.
- Suspicious indicator (INFERRED): something worth a closer look, e.g.
  a query value that appears as-is in the response body.
- Hypothesis (UNKNOWN): a parameter that only looks related to data
  queries by its name ("search", "id"). Never promoted further.

A Finding is only created for suspicious indicators (observed
reflection), at LOW severity and LOW confidence, and its text says
clearly that it is not a confirmed vulnerability. Active verification
is done by the active testing engine.

Uses the stdlib HTMLParser to read tags and attributes only, and
redacts secret-looking strings with collectors/_secrets.py."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from app.engines.recon.collectors._secrets import redact_secrets
from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity
from app.engines.web_vuln.registry import CheckInputs, CheckOutcome

SLUG = "injection_surface"
CATEGORY = "injection_surface"

_OWASP_INJECTION = "A03:2021-Injection"

# Naming heuristic ONLY -- never promoted beyond ObservationNature.UNKNOWN
# ("hypothèse nécessitant vérification") by this check.
_DATA_QUERY_PARAM_NAMES = frozenset(
    {
        "id", "ids", "uid", "user_id", "userid", "account_id", "search", "q", "query",
        "filter", "category", "cat", "sort", "order", "page", "type", "action", "cmd",
        "file", "path", "redirect", "url", "next", "callback", "name", "keyword",
        "term", "lookup", "ref", "product_id", "item_id",
    }
)

_MAX_PARAMETERS_REPORTED = 50
_MIN_REFLECTED_VALUE_LENGTH = 3


class _SurfaceParser(HTMLParser):
    """Extracts forms (action/method/input names) and link query
    parameters -- attribute-level only, never a DOM, never executes or
    interprets anything as markup beyond locating tag/attribute pairs."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[dict] = []
        self.link_params: set[str] = set()
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attr_map.get("action", "")),
                "method": attr_map.get("method", "get").strip().lower() or "get",
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_map.get("name")
            if name:
                self._current_form["inputs"].append(
                    {"name": name, "type": attr_map.get("type", "text" if tag == "input" else tag)}
                )
        elif tag == "a" and attr_map.get("href"):
            full = urljoin(self.base_url, attr_map["href"])
            for key, _ in parse_qsl(urlsplit(full).query, keep_blank_values=True):
                self.link_params.add(key)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


def run(inputs: CheckInputs) -> CheckOutcome:
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)

    if inputs.fetched is None:
        return CheckOutcome(
            collector_result=CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=["no primary response to inspect"],
                source=SLUG,
            )
        )

    body_text = inputs.fetched.body_bytes.decode("utf-8", errors="replace")
    url_query_params = parse_qsl(urlsplit(inputs.fetched.final_url).query, keep_blank_values=True)

    parser = _SurfaceParser(inputs.fetched.final_url)
    try:
        parser.feed(body_text)
    except Exception:  # noqa: BLE001 -- malformed markup must never abort this check
        pass

    # Build the unified parameter inventory: name -> set of source labels.
    inventory: dict[str, set[str]] = {}
    for name, _ in url_query_params:
        inventory.setdefault(name, set()).add("url_query")
    for form in parser.forms:
        label = f"form[{form['method']}]:{redact_secrets(form['action'])}"
        for field in form["inputs"]:
            inventory.setdefault(field["name"], set()).add(label)
    for name in parser.link_params:
        inventory.setdefault(name, set()).add("link_query")

    observations: list[Observation] = []
    findings: list[Finding] = []
    truncated = len(inventory) > _MAX_PARAMETERS_REPORTED

    observations.append(Observation("injection_surface.forms_found", len(parser.forms), ObservationNature.OBSERVED))
    observations.append(
        Observation("injection_surface.parameters_found", len(inventory), ObservationNature.OBSERVED)
    )

    for name, sources in sorted(inventory.items())[:_MAX_PARAMETERS_REPORTED]:
        observations.append(
            Observation(
                f"injection_surface.parameter.{name}",
                {"sources": sorted(sources)},
                ObservationNature.OBSERVED,
            )
        )
        if name.lower() in _DATA_QUERY_PARAM_NAMES:
            observations.append(
                Observation(
                    f"injection_surface.parameter.{name}.data_query_hypothesis",
                    True,
                    ObservationNature.UNKNOWN,
                    note="parameter name suggests it may be used in a data query; not verified -- a naming heuristic only",
                )
            )

    # Suspect-indicator tier: does a value this run actually sent (via
    # the primary URL's own query string) reappear verbatim in the
    # response body? Only evaluated for values we genuinely sent --
    # never for form/link placeholder values we never requested with.
    for name, value in url_query_params:
        if len(value) < _MIN_REFLECTED_VALUE_LENGTH:
            continue
        if value not in body_text:
            continue
        observations.append(
            Observation(
                f"injection_surface.reflection.{name}",
                True,
                ObservationNature.INFERRED,
                note="this parameter's own value reappears verbatim in the response body -- not verified as unescaped or exploitable",
            )
        )
        findings.append(
            Finding(
                check=SLUG,
                title=f"Parameter '{name}' value reflected in response body (unverified)",
                description=(
                    f"The value sent in the '{name}' URL parameter was found reproduced verbatim in "
                    "the response body. This is a POTENTIAL reflection surface worth a closer, "
                    "controlled look -- it is NOT a confirmed cross-site-scripting vulnerability: "
                    "this check never verified whether the value is HTML/JS-escaped, in what context "
                    "it appears, or whether a script-breaking payload would actually execute."
                ),
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.LOW,
                impact="If the reflection turns out to be unescaped and in an executable HTML/JS context, it could be a reflected-XSS surface -- unconfirmed by this passive check.",
                remediation="Context-appropriately encode/escape any request-derived value before it is written into an HTML response (HTML-entity encode in HTML body context, JS-string-escape in inline script context, etc.), and verify with a controlled, authorized active test before treating this as resolved either way.",
                affected_url=inputs.fetched.final_url,
                cwe_id="CWE-79",
                owasp_category=_OWASP_INJECTION,
                evidence={"parameter": name, "value_length": len(value)},
            )
        )

    return CheckOutcome(
        collector_result=CollectorResult(
            collector=SLUG,
            status=CollectorStatus.PARTIAL if truncated else CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"findings_count": len(findings), "parameters_found": len(inventory)},
            errors=[f"stopped reporting individual parameters at {_MAX_PARAMETERS_REPORTED}"] if truncated else [],
            source=SLUG,
            confidence=ConfidenceLevel.MEDIUM,
        ),
        findings=findings,
    )
