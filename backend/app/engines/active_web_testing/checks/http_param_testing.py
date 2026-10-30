"""HTTP parameter testing check.

For each entry point, sends up to three harmless probes (stops early
if the per-endpoint budget is used up):

1. Type confusion: if the value looks numeric, send a non-numeric
   string. A 5xx is reported as improper error handling.
2. Overlong value: a few KB of repeated characters, to see if long
   input is mishandled. Not a DoS attempt.
3. Unexpected parameter: adds a parameter the target never exposed,
   to see if it changes behavior instead of being ignored.

All values are plain text, no script tags, SQL characters or path
traversal; those are covered by the other checks."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.active_web_testing.entrypoints import EntryPoint
from app.engines.active_web_testing.registry import CheckInputs, CheckOutcome
from app.engines.active_web_testing.security.pinned_request import fetch_pinned_url, set_query_param, split_query_params
from app.engines.recon.collectors._secrets import redact_secrets
from app.engines.recon.context import ReconBudgetExceededError, ReconCancelledError
from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity

SLUG = "http_param_testing"
CATEGORY = "http_param_testing"

_OWASP_VALIDATION = "A03:2021-Injection"  # improper input handling; closest applicable category when no more specific one fits
_OVERLONG_VALUE = "A" * 4000
_UNEXPECTED_PARAM_NAME = "__active_web_testing_unexpected_param__"


def _testable_entry_points(entry_points: list[EntryPoint]) -> list[EntryPoint]:
    return [ep for ep in entry_points if ep.testable and ep.method == "GET" and ep.param_name]


def _looks_numeric(value: str) -> bool:
    return value.strip().lstrip("-").isdigit()


def run(inputs: CheckInputs) -> CheckOutcome:
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    settings = inputs.settings

    candidates = _testable_entry_points(inputs.entry_points)
    observations: list[Observation] = []
    findings: list[Finding] = []
    endpoints_tested = 0
    requests_used = 0
    errors: list[str] = []

    observations.append(Observation("http_param_testing.candidate_entry_points", len(candidates), ObservationNature.OBSERVED))

    for entry_point in candidates:
        if len(findings) >= settings.active_web_testing_max_findings_per_check:
            break

        baseline_value = split_query_params(entry_point.url).get(entry_point.param_name or "", "1")
        tested_this_endpoint = False

        def _probe(url: str, label: str) -> "object | None":
            nonlocal requests_used, tested_this_endpoint
            if not inputs.request_tracker.allow(entry_point):
                return None
            try:
                response = fetch_pinned_url(
                    inputs.ctx, url,
                    max_response_bytes=settings.active_web_testing_max_response_bytes,
                    where=f"active_web_testing.http_param:{entry_point.param_name}:{label}",
                )
            except (ReconCancelledError, ReconBudgetExceededError):
                raise
            except Exception as exc:  # noqa: BLE001 -- one probe's failure must not abort the check
                errors.append(f"{entry_point.param_name}:{label}: {exc.__class__.__name__}")
                inputs.request_tracker.record(entry_point)
                return None
            inputs.request_tracker.record(entry_point)
            requests_used += 1
            tested_this_endpoint = True
            return response

        # --- Type confusion -------------------------------------------
        if _looks_numeric(baseline_value):
            type_url = set_query_param(entry_point.url, entry_point.param_name, "not_a_number_abc")
            response = _probe(type_url, "type_confusion")
            if response is not None and response.status_code >= 500:
                observations.append(
                    Observation(
                        f"http_param_testing.parameter.{entry_point.param_name}.type_confusion_5xx",
                        response.status_code,
                        ObservationNature.OBSERVED,
                        note="replacing a numeric-looking value with a non-numeric string produced a server error",
                    )
                )
                findings.append(
                    Finding(
                        check=SLUG,
                        title=f"Server error on unexpected input type for parameter '{entry_point.param_name}'",
                        description=(
                            f"Replacing the '{entry_point.param_name}' parameter's numeric-looking "
                            f"value with a non-numeric string produced an HTTP {response.status_code} "
                            "server error rather than a graceful 4xx validation response or a "
                            "silently-handled default."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        confidence=FindingConfidence.MEDIUM,
                        impact="An unhandled server error on malformed input can indicate missing input validation, and may expose a stack trace or internal details -- see the info-disclosure checks for that specific risk.",
                        remediation="Validate and reject malformed parameter values with an explicit 4xx response rather than letting them reach code that raises an unhandled exception.",
                        affected_url=redact_secrets(type_url),
                        http_method="GET",
                        owasp_category=_OWASP_VALIDATION,
                        evidence={"parameter": entry_point.param_name, "status_code": response.status_code, "probe": "type_confusion"},
                    )
                )

        if len(findings) >= settings.active_web_testing_max_findings_per_check:
            continue

        # --- Overlong value ---------------------------------------------
        overlong_url = set_query_param(entry_point.url, entry_point.param_name, _OVERLONG_VALUE)
        response = _probe(overlong_url, "overlong_value")
        if response is not None and response.status_code >= 500:
            observations.append(
                Observation(
                    f"http_param_testing.parameter.{entry_point.param_name}.overlong_value_5xx",
                    response.status_code,
                    ObservationNature.OBSERVED,
                    note="an unusually long (but harmless) parameter value produced a server error",
                )
            )
            findings.append(
                Finding(
                    check=SLUG,
                    title=f"Server error on overlong value for parameter '{entry_point.param_name}'",
                    description=(
                        f"Sending an unusually long (4000-character, harmless repeated-character) "
                        f"value for the '{entry_point.param_name}' parameter produced an HTTP "
                        f"{response.status_code} server error."
                    ),
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.MEDIUM,
                    impact="Mishandling of unexpectedly long input can indicate missing length validation; a resource-exhaustion risk is NOT confirmed by this single, bounded probe.",
                    remediation="Enforce an explicit maximum length for this parameter and reject values beyond it with a 4xx response.",
                    affected_url=redact_secrets(overlong_url[:200] + "...(truncated)"),
                    http_method="GET",
                    owasp_category=_OWASP_VALIDATION,
                    evidence={"parameter": entry_point.param_name, "status_code": response.status_code, "probe": "overlong_value", "probe_length": len(_OVERLONG_VALUE)},
                )
            )

        if tested_this_endpoint:
            endpoints_tested += 1

    # --- Unexpected parameter (checked once per distinct base URL, not
    # per parameter, since it is not parameter-specific) -----------------
    seen_urls: set[str] = set()
    for entry_point in candidates:
        if len(findings) >= settings.active_web_testing_max_findings_per_check:
            break
        if entry_point.url in seen_urls:
            continue
        seen_urls.add(entry_point.url)
        if not inputs.request_tracker.allow(entry_point):
            continue
        extra_url = set_query_param(entry_point.url, _UNEXPECTED_PARAM_NAME, "1")
        try:
            response = fetch_pinned_url(
                inputs.ctx, extra_url,
                max_response_bytes=settings.active_web_testing_max_response_bytes,
                where="active_web_testing.http_param:unexpected_param",
            )
        except (ReconCancelledError, ReconBudgetExceededError):
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(f"unexpected_param: {exc.__class__.__name__}")
            inputs.request_tracker.record(entry_point)
            continue
        inputs.request_tracker.record(entry_point)
        requests_used += 1
        if response.status_code >= 500:
            observations.append(
                Observation(
                    "http_param_testing.unexpected_parameter_5xx",
                    response.status_code,
                    ObservationNature.OBSERVED,
                    note="adding a parameter name never advertised anywhere produced a server error",
                )
            )
            findings.append(
                Finding(
                    check=SLUG,
                    title="Server error when an unexpected parameter is present",
                    description=(
                        f"Adding a parameter ('{_UNEXPECTED_PARAM_NAME}') never advertised by this "
                        f"endpoint produced an HTTP {response.status_code} server error instead of "
                        "being silently ignored (the expected, safe behavior for an unrecognized "
                        "parameter)."
                    ),
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.MEDIUM,
                    impact="Improper handling of unexpected parameters can indicate fragile request parsing; not a confirmed exploit on its own.",
                    remediation="Ensure unrecognized parameters are ignored rather than causing an unhandled exception.",
                    affected_url=redact_secrets(entry_point.url),
                    http_method="GET",
                    owasp_category=_OWASP_VALIDATION,
                    evidence={"status_code": response.status_code, "probe": "unexpected_parameter"},
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
