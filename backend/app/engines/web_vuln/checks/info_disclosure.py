"""Technical information / error message exposure check.

Passive: looks at the already-fetched main response (body and headers)
for things like a version in the Server header, a stack trace or a
debug banner. It never sends a malformed request to trigger an error."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity
from app.engines.web_vuln.registry import CheckInputs, CheckOutcome

SLUG = "info_disclosure"
CATEGORY = "info_disclosure"

_OWASP_MISCONFIG = "A05:2021-Security Misconfiguration"

# (regex, title, description) -- matched against the decoded body,
# case-insensitive, first match only per pattern (a page listing one
# stack trace is one finding, not one per line of it).
_STACK_TRACE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"Exception in thread|java\.lang\.\w+Exception", "Java exception/stack trace"),
    (r"at [\w.$]+\([\w.]+:\d+\)\s*\n\s*at ", "Java/Node.js style stack trace"),
    (r"Warning: \S+\(\): |Fatal error: |Notice: Undefined", "PHP error/warning output"),
    (r"System\.\w+Exception|Microsoft\.\w+\.\w+Exception|Server Error in '/' Application", "ASP.NET error output"),
    (r"django\.core\.exceptions|DEBUG = True|Request Method:\s*\w+\s*\n\s*Request URL:", "Django debug/error page"),
)

# Server/X-Powered-By values that disclose a specific product+version,
# not just a product family -- "nginx" alone is far less useful to an
# attacker than "nginx/1.18.0" or "PHP/7.4.3".
_VERSION_PATTERN = re.compile(r"[/ ]\d+\.\d+")


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

    try:
        body_text = inputs.fetched.body_bytes.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover -- decode(errors="replace") never actually raises
        body_text = ""

    observations: list[Observation] = []
    findings: list[Finding] = []
    max_findings = inputs.settings.web_vuln_max_findings_per_check

    for pattern, label in _STACK_TRACE_PATTERNS:
        match = re.search(pattern, body_text, re.IGNORECASE)
        if not match:
            continue
        observations.append(Observation(f"info_disclosure.body_pattern.{label}", True, ObservationNature.OBSERVED))
        if len(findings) >= max_findings:
            continue
        snippet = body_text[max(0, match.start() - 40) : match.start() + 120]
        findings.append(
            Finding(
                check=SLUG,
                title=f"{label} present in response body",
                description=(
                    f"The response body for this already-authorized page contains what looks like "
                    f"a {label.lower()}. This can reveal internal file paths, framework/library "
                    "versions, or application logic to anyone who requests this page."
                ),
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.MEDIUM,
                impact="Aids an attacker in fingerprinting the stack and crafting further, more targeted requests; does not by itself grant access to anything.",
                remediation="Disable debug/verbose error output in the deployed environment and return a generic error page to clients.",
                affected_url=inputs.fetched.final_url,
                cwe_id="CWE-209",
                owasp_category=_OWASP_MISCONFIG,
                evidence={"pattern_label": label, "snippet": snippet.strip()[:200]},
            )
        )

    for header_name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = inputs.fetched.headers.get(header_name)
        if not value:
            continue
        observations.append(Observation(f"info_disclosure.header.{header_name}", value, ObservationNature.OBSERVED))
        if _VERSION_PATTERN.search(value) and len(findings) < max_findings:
            findings.append(
                Finding(
                    check=SLUG,
                    title=f"'{header_name}' header discloses a specific software version",
                    description=f"The '{header_name}' response header value ('{value}') includes a specific version number.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.HIGH,
                    impact="Lets an attacker target known vulnerabilities for that exact version without further fingerprinting.",
                    remediation=f"Remove or generalize the '{header_name}' header (e.g. via the reverse proxy/server configuration) so it no longer reveals an exact version.",
                    affected_url=inputs.fetched.final_url,
                    cwe_id="CWE-200",
                    owasp_category=_OWASP_MISCONFIG,
                    evidence={"header": header_name, "value": value},
                )
            )

    truncated = len(findings) >= max_findings

    return CheckOutcome(
        collector_result=CollectorResult(
            collector=SLUG,
            status=CollectorStatus.PARTIAL if truncated else CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"findings_count": len(findings), "body_truncated": inputs.fetched.body_truncated},
            errors=[f"stopped at {max_findings} findings for this check"] if truncated else [],
            source=SLUG,
            confidence=ConfidenceLevel.MEDIUM,
        ),
        findings=findings,
    )
