"""Security headers check.

Uses the header observations already collected by headers_collector.py
(no new request) and creates a Finding when a header is missing or has
a weak value. Each finding quotes the observed value (or "absent") as
evidence.

A missing header is reported as MEDIUM or LOW severity with HIGH
confidence (the absence is directly observed), never CRITICAL: it is a
missing hardening measure, not a confirmed exploitable vulnerability."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity
from app.engines.web_vuln.registry import CheckInputs, CheckOutcome

SLUG = "security_headers"
CATEGORY = "headers"

_OWASP_MISCONFIG = "A05:2021-Security Misconfiguration"

# (observation_key, title, severity, cwe_id, description, remediation)
_MISSING_HEADER_RULES: tuple[tuple[str, str, FindingSeverity, str | None, str, str], ...] = (
    (
        "header.content-security-policy",
        "Content-Security-Policy header absent",
        FindingSeverity.MEDIUM,
        "CWE-693",
        "No Content-Security-Policy header was returned on the primary response. "
        "CSP is the main browser-enforced control against injected/foreign script "
        "execution (XSS impact reduction) and framing-based attacks.",
        "Serve a restrictive Content-Security-Policy (at minimum default-src 'self'; "
        "avoid 'unsafe-inline'/'unsafe-eval') and verify it does not break the "
        "application before enforcing it broadly.",
    ),
    (
        "header.x-content-type-options",
        "X-Content-Type-Options header absent",
        FindingSeverity.LOW,
        "CWE-693",
        "No X-Content-Type-Options: nosniff header was returned, so some browsers "
        "may MIME-sniff the response body and render it as a different content "
        "type than the server declared.",
        "Add 'X-Content-Type-Options: nosniff' to every response.",
    ),
    (
        "header.referrer-policy",
        "Referrer-Policy header absent",
        FindingSeverity.INFO,
        None,
        "No Referrer-Policy header was returned, so the browser's default referrer "
        "behavior applies -- this can leak the full URL (including any sensitive "
        "query parameters) to third-party destinations linked from this page.",
        "Set an explicit Referrer-Policy (e.g. 'strict-origin-when-cross-origin' or "
        "stricter) rather than relying on the browser default.",
    ),
)


def _has_frame_protection(headers_result: CollectorResult) -> bool:
    for obs in headers_result.observations:
        if obs.key == "header.content-security-policy" and obs.value and "frame-ancestors" in str(obs.value):
            return True
    return False


def run(inputs: CheckInputs) -> CheckOutcome:
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    headers_result = inputs.collector_results.get("headers")

    if headers_result is None or headers_result.status == CollectorStatus.NOT_APPLICABLE:
        return CheckOutcome(
            collector_result=CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=["no headers observation available for this run"],
                source=SLUG,
            )
        )

    observed_by_key = {obs.key: obs for obs in headers_result.observations}
    findings: list[Finding] = []
    check_observations = []

    for key, title, severity, cwe_id, description, remediation in _MISSING_HEADER_RULES:
        obs = observed_by_key.get(key)
        if obs is None or obs.nature == ObservationNature.NOT_APPLICABLE:
            # Not applicable for this response (e.g. HSTS evaluated
            # elsewhere) -- nothing to say here, never a fabricated
            # finding against a check that genuinely does not apply.
            continue
        is_present = obs.value is not None and str(obs.value).strip() != ""
        check_observations.append(
            Observation(
                key=f"{SLUG}.{key.split('.', 1)[1]}.present",
                value=is_present,
                nature=ObservationNature.OBSERVED,
            )
        )
        if is_present:
            continue
        findings.append(
            Finding(
                check=SLUG,
                title=title,
                description=description,
                severity=severity,
                confidence=FindingConfidence.HIGH,
                impact=(
                    "Increases the application's reliance on other controls to mitigate the "
                    "class of attack this header addresses; does not by itself confirm an "
                    "exploitable condition."
                ),
                remediation=remediation,
                affected_url=inputs.fetched.final_url if inputs.fetched else None,
                cwe_id=cwe_id,
                owasp_category=_OWASP_MISCONFIG,
                evidence={"header": key.split(".", 1)[1], "observed_value": None},
            )
        )

    # HSTS and X-Frame-Options get their own, slightly more involved
    # rules (HSTS is conditional on HTTPS; X-Frame-Options is only
    # worth flagging when CSP's frame-ancestors doesn't already cover
    # the same protection).
    hsts_obs = observed_by_key.get("header.strict-transport-security")
    if hsts_obs is not None and hsts_obs.nature == ObservationNature.OBSERVED and not hsts_obs.value:
        findings.append(
            Finding(
                check=SLUG,
                title="Strict-Transport-Security header absent on an HTTPS response",
                description=(
                    "The primary response was served over HTTPS but returned no "
                    "Strict-Transport-Security header, so a browser will still accept a "
                    "future plaintext HTTP connection to this host instead of being told "
                    "to always upgrade."
                ),
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                impact="Leaves users exposed to a downgrade/SSL-stripping attempt on a future visit.",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' (and 'preload' once verified site-wide).",
                affected_url=inputs.fetched.final_url if inputs.fetched else None,
                cwe_id="CWE-319",
                owasp_category=_OWASP_MISCONFIG,
                evidence={"header": "strict-transport-security", "observed_value": None, "is_https": True},
            )
        )

    xfo_obs = observed_by_key.get("header.x-frame-options")
    if (
        xfo_obs is not None
        and xfo_obs.nature == ObservationNature.OBSERVED
        and not xfo_obs.value
        and not _has_frame_protection(headers_result)
    ):
        findings.append(
            Finding(
                check=SLUG,
                title="X-Frame-Options header absent with no CSP frame-ancestors fallback",
                description=(
                    "Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors "
                    "directive was found, so the page can be embedded in a third-party "
                    "frame with no browser-level restriction."
                ),
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                impact="A framed page can be a component of a clickjacking attempt; this check cannot confirm one was built.",
                remediation="Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN') and/or a CSP 'frame-ancestors' directive.",
                affected_url=inputs.fetched.final_url if inputs.fetched else None,
                cwe_id="CWE-1021",
                owasp_category=_OWASP_MISCONFIG,
                evidence={"header": "x-frame-options", "observed_value": None},
            )
        )

    return CheckOutcome(
        collector_result=CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=check_observations,
            evidence={"findings_count": len(findings)},
            source=SLUG,
            confidence=ConfidenceLevel.HIGH,
        ),
        findings=findings,
    )
