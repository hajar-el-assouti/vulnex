"""Active API security check.

Runs on API endpoints found by api_discovery or from an OpenAPI spec.
For each distinct endpoint, sends up to two non-destructive probes:

1. OPTIONS: reports what the `Allow` header announces, without
   calling those methods (same idea as web_vuln/checks/http_methods.py).
2. GET with an unexpected parameter: looks for a 5xx (bad error
   handling) and for stack traces or framework error messages in
   either response body.

Out of scope: authentication bypass, IDOR, modifying data, brute
force."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.active_web_testing.entrypoints import EntryPoint
from app.engines.active_web_testing.registry import CheckInputs, CheckOutcome
from app.engines.active_web_testing.security.pinned_request import fetch_pinned_url, set_query_param
from app.engines.recon.collectors._secrets import redact_secrets
from app.engines.recon.context import ReconBudgetExceededError, ReconCancelledError
from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity

SLUG = "api_security_active"
CATEGORY = "api_security_active"

_OWASP_MISCONFIG = "A05:2021-Security Misconfiguration"
_UNEXPECTED_PARAM_NAME = "__active_web_testing_unexpected_param__"

# Short, well-known stack-trace/framework-error substrings -- matched
# case-insensitively against a response body this check ALREADY
# fetched for another reason; never a dedicated extra probe.
_ERROR_DISCLOSURE_SIGNATURES = (
    "traceback (most recent call last)",
    "at system.",
    "exception in thread",
    "whitelabel error page",
    "django.core.exceptions",
    "org.springframework",
    "stacktrace",
    "fatal error:",
)


def _api_candidates(entry_points: list[EntryPoint]) -> list[EntryPoint]:
    seen: set[str] = set()
    out: list[EntryPoint] = []
    for ep in entry_points:
        if ep.source not in ("api_discovery", "openapi"):
            continue
        if ep.url in seen:
            continue
        seen.add(ep.url)
        out.append(ep)
    return out


def _check_error_disclosure(body_text: str) -> list[str]:
    lower = body_text.lower()
    return [sig for sig in _ERROR_DISCLOSURE_SIGNATURES if sig in lower]


def run(inputs: CheckInputs) -> CheckOutcome:
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    settings = inputs.settings

    candidates = _api_candidates(inputs.entry_points)
    observations: list[Observation] = []
    findings: list[Finding] = []
    endpoints_tested = 0
    requests_used = 0
    errors: list[str] = []

    observations.append(Observation("api_security_active.candidate_endpoints", len(candidates), ObservationNature.OBSERVED))

    for entry_point in candidates:
        if len(findings) >= settings.active_web_testing_max_findings_per_check:
            break
        if not inputs.request_tracker.allow(entry_point):
            continue

        # --- OPTIONS: announced methods ------------------------------
        try:
            options_response = fetch_pinned_url(
                inputs.ctx, entry_point.url,
                max_response_bytes=settings.active_web_testing_max_response_bytes,
                where="active_web_testing.api_security:options",
                method="OPTIONS",
            )
        except (ReconCancelledError, ReconBudgetExceededError):
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{entry_point.url}: {exc.__class__.__name__}")
            inputs.request_tracker.record(entry_point)
            continue
        inputs.request_tracker.record(entry_point)
        requests_used += 1
        endpoints_tested += 1

        allow_header = options_response.headers.get("allow", "")
        observations.append(
            Observation(
                "api_security_active.announced_methods",
                {"url": redact_secrets(entry_point.url), "allow": allow_header},
                ObservationNature.OBSERVED,
            )
        )

        # --- Unexpected-parameter GET: anomalous behavior + error
        # disclosure -------------------------------------------------
        if inputs.request_tracker.allow(entry_point):
            probe_url = set_query_param(entry_point.url, _UNEXPECTED_PARAM_NAME, "1")
            try:
                probe_response = fetch_pinned_url(
                    inputs.ctx, probe_url,
                    max_response_bytes=settings.active_web_testing_max_response_bytes,
                    where="active_web_testing.api_security:unexpected_param",
                )
            except (ReconCancelledError, ReconBudgetExceededError):
                raise
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{entry_point.url}: {exc.__class__.__name__}")
                inputs.request_tracker.record(entry_point)
                continue
            inputs.request_tracker.record(entry_point)
            requests_used += 1

            body_text = probe_response.body_bytes.decode("utf-8", errors="replace")
            disclosed = _check_error_disclosure(body_text)

            if probe_response.status_code >= 500:
                findings.append(
                    Finding(
                        check=SLUG,
                        title="API endpoint returns a server error on an unexpected parameter",
                        description=(
                            f"Adding a parameter ('{_UNEXPECTED_PARAM_NAME}') never documented or "
                            f"observed for this endpoint produced an HTTP {probe_response.status_code} "
                            "server error instead of being ignored."
                        ),
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.MEDIUM,
                        impact="Improper handling of unexpected API parameters can indicate fragile request parsing; not a confirmed exploit on its own.",
                        remediation="Ensure unrecognized query parameters are ignored by the API rather than causing an unhandled exception.",
                        affected_url=redact_secrets(entry_point.url),
                        http_method="GET",
                        owasp_category=_OWASP_MISCONFIG,
                        evidence={"status_code": probe_response.status_code, "probe": "unexpected_parameter"},
                    )
                )

            if disclosed:
                findings.append(
                    Finding(
                        check=SLUG,
                        title="API endpoint discloses internal error details",
                        description=(
                            "A response from this endpoint contained what looks like a stack trace "
                            "or framework-specific error page, which can reveal internal "
                            "implementation details to any caller."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        confidence=FindingConfidence.MEDIUM,
                        impact="Detailed error output can reveal file paths, framework/library versions, or internal logic useful for further attacks.",
                        remediation="Return a generic error response to callers and log detailed error/stack information server-side only.",
                        affected_url=redact_secrets(entry_point.url),
                        http_method="GET",
                        cwe_id="CWE-209",
                        owasp_category=_OWASP_MISCONFIG,
                        evidence={"matched_signatures": disclosed},
                    )
                )

    return CheckOutcome(
        collector_result=CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK if not errors else CollectorStatus.PARTIAL,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"findings_count": len(findings), "endpoints_tested": endpoints_tested, "requests_used": requests_used},
            errors=errors,
            source=SLUG,
            confidence=ConfidenceLevel.MEDIUM,
        ),
        findings=findings,
    )
