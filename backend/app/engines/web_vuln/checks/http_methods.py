"""Advertised HTTP methods check.

Sends one OPTIONS request to the main URL. OPTIONS must not change
server state, so it is the only method this check sends. PUT, DELETE,
PATCH and TRACE are never actually sent, since they could modify the
target's data. A method listed in the `Allow` header is reported as
advertised, not as confirmed exploitable."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.recon.security.request_policy import fetch_target_url
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity
from app.engines.web_vuln.registry import CheckInputs, CheckOutcome

SLUG = "http_methods"
CATEGORY = "http_methods"

_OWASP_MISCONFIG = "A05:2021-Security Misconfiguration"


def _parse_allow(value: str | None) -> list[str]:
    if not value:
        return []
    return [m.strip().upper() for m in value.split(",") if m.strip()]


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
                errors=["no primary response to anchor the OPTIONS probe to"],
                source=SLUG,
            )
        )

    options_response = fetch_target_url(
        inputs.ctx,
        inputs.fetched.final_url,
        max_response_bytes=inputs.settings.web_vuln_max_response_bytes,
        where="web_vuln.http_methods_options",
        method="OPTIONS",
    )
    advertised = _parse_allow(options_response.headers.get("allow"))

    observations = [
        Observation("http_methods.options_status_code", options_response.status_code, ObservationNature.OBSERVED),
        Observation("http_methods.advertised", advertised, ObservationNature.OBSERVED),
    ]

    findings: list[Finding] = []
    of_interest = set(inputs.settings.web_vuln_http_methods_of_interest)
    flagged = sorted(m for m in advertised if m in of_interest)

    if flagged:
        trace_flagged = "TRACE" in flagged
        findings.append(
            Finding(
                check=SLUG,
                title=f"Potentially sensitive HTTP method(s) advertised: {', '.join(flagged)}",
                description=(
                    f"The OPTIONS response for this URL advertises: {', '.join(flagged)} via its "
                    "Allow header. These methods were never actually invoked by this check -- only "
                    "their advertisement was observed."
                ),
                severity=FindingSeverity.MEDIUM if trace_flagged else FindingSeverity.LOW,
                confidence=FindingConfidence.MEDIUM,
                impact=(
                    "TRACE, if actually enabled and reflected, is associated with the long-known "
                    "Cross-Site Tracing (XST) technique; PUT/DELETE/PATCH, if reachable without proper "
                    "authorization, could allow data modification -- this check did not verify either "
                    "condition, only that the method is advertised."
                ),
                remediation=(
                    "Disable TRACE entirely at the web server/proxy. For PUT/DELETE/PATCH, confirm "
                    "they are not reachable without authentication/authorization on this route, and "
                    "remove them from `Allow` if they are not actually implemented here."
                ),
                affected_url=inputs.fetched.final_url,
                cwe_id="CWE-650" if trace_flagged else None,
                owasp_category=_OWASP_MISCONFIG,
                evidence={"advertised_methods": advertised, "flagged": flagged},
            )
        )

    return CheckOutcome(
        collector_result=CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"findings_count": len(findings)},
            source=SLUG,
            confidence=ConfidenceLevel.MEDIUM,
        ),
        findings=findings,
    )
