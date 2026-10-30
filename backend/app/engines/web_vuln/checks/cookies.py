"""Cookie flags check.

Uses the cookie observations already collected and masked by
cookies_collector.py (cookie values are never kept). Flags a missing
Secure or HttpOnly, and a missing or permissive SameSite.

Settings.web_vuln_max_findings_per_check limits the number of findings,
so a site with dozens of cookies doesn't flood the results. When the
limit is hit, a note says so."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, ObservationNature
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity
from app.engines.web_vuln.registry import CheckInputs, CheckOutcome

SLUG = "cookies"
CATEGORY = "cookies"

_OWASP_MISCONFIG = "A05:2021-Security Misconfiguration"


def run(inputs: CheckInputs) -> CheckOutcome:
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    cookies_result = inputs.collector_results.get("cookies")

    if cookies_result is None or cookies_result.status == CollectorStatus.NOT_APPLICABLE:
        return CheckOutcome(
            collector_result=CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=["no cookies observation available for this run"],
                source=SLUG,
            )
        )

    headers_result = inputs.collector_results.get("headers")
    is_https = bool(headers_result.evidence.get("is_https", False)) if headers_result else False
    findings: list[Finding] = []
    max_findings = inputs.settings.web_vuln_max_findings_per_check
    truncated = False

    for obs in cookies_result.observations:
        if not obs.key.startswith("cookie."):
            continue
        if obs.nature != ObservationNature.OBSERVED or not isinstance(obs.value, dict):
            continue
        attrs = obs.value
        name = attrs.get("name", obs.key.removeprefix("cookie."))
        missing_flags = []
        if is_https and not attrs.get("secure"):
            missing_flags.append("Secure")
        if not attrs.get("httponly"):
            missing_flags.append("HttpOnly")
        samesite = (attrs.get("samesite") or "").strip().lower()
        if samesite not in ("strict", "lax"):
            missing_flags.append("SameSite=Strict|Lax")

        if not missing_flags:
            continue

        if len(findings) >= max_findings:
            truncated = True
            break

        findings.append(
            Finding(
                check=SLUG,
                title=f"Cookie '{name}' missing recommended flag(s): {', '.join(missing_flags)}",
                description=(
                    f"The cookie named '{name}' was observed without: {', '.join(missing_flags)}. "
                    "Only the cookie's attributes were inspected -- its value was never read or stored."
                ),
                severity=FindingSeverity.MEDIUM if "HttpOnly" in missing_flags else FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                impact=(
                    "Missing HttpOnly makes the cookie readable by any script that runs on the page "
                    "(including an injected one); missing Secure/SameSite widens the conditions under "
                    "which the cookie is sent. This check does not confirm script injection is possible."
                ),
                remediation=(
                    "Set 'HttpOnly' on every session/auth cookie, 'Secure' on every cookie served over "
                    "HTTPS, and an explicit 'SameSite=Strict' or 'SameSite=Lax' unless cross-site "
                    "delivery is genuinely required."
                ),
                affected_url=inputs.fetched.final_url if inputs.fetched else None,
                cwe_id="CWE-1004" if "HttpOnly" in missing_flags else "CWE-614",
                owasp_category=_OWASP_MISCONFIG,
                evidence={"cookie_name": name, "missing_flags": missing_flags, "is_https": is_https},
            )
        )

    collector_result = CollectorResult(
        collector=SLUG,
        status=CollectorStatus.PARTIAL if truncated else CollectorStatus.OK,
        collected_at=collected_at,
        duration_ms=int((time.monotonic() - started) * 1000),
        observations=[],
        evidence={"findings_count": len(findings)},
        errors=[f"stopped at {max_findings} findings for this check -- more cookies may be affected"]
        if truncated
        else [],
        source=SLUG,
        confidence=ConfidenceLevel.HIGH,
    )
    return CheckOutcome(collector_result=collector_result, findings=findings)
