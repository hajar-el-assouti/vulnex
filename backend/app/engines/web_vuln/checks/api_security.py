"""API security check (passive).

- Endpoint discovery reuses the api_discovery collector's result.
- The only new requests are GETs to a short list of common
  OpenAPI/Swagger paths (Settings.web_vuln_openapi_probe_paths), to
  see if an API spec is publicly exposed.
- CORS issues are taken from the cors check's result, which runs
  earlier and shares the same `collector_results` dict. No second
  CORS request.

No authentication bypass, no IDOR testing, no brute force."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.recon.security.request_policy import fetch_target_url
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity
from app.engines.web_vuln.registry import CheckInputs, CheckOutcome

SLUG = "api_security"
CATEGORY = "api_security"

_OWASP_MISCONFIG = "A05:2021-Security Misconfiguration"

_SPEC_MARKERS = ("\"swagger\"", "\"openapi\"", "'swagger'", "'openapi'")


def _looks_like_api_spec(content_type: str, body_text: str) -> bool:
    if "json" not in content_type.lower() and "yaml" not in content_type.lower():
        # Still allow a spec served with a generic content-type, as
        # long as the body itself plainly declares it is one.
        if not any(marker in body_text[:2000].lower() for marker in ("swagger", "openapi")):
            return False
    return any(marker in body_text[:2000].lower() for marker in ("swagger", "openapi"))


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
                errors=["no primary response to anchor this check to"],
                source=SLUG,
            )
        )

    observations: list[Observation] = []
    findings: list[Finding] = []

    api_discovery_result = inputs.collector_results.get("api_discovery")
    candidate_endpoints: list[str] = []
    if api_discovery_result is not None:
        for obs in api_discovery_result.observations:
            if obs.key == "api_discovery.candidate_endpoints" and isinstance(obs.value, list):
                candidate_endpoints = obs.value
    observations.append(
        Observation("api_security.candidate_endpoints_count", len(candidate_endpoints), ObservationNature.OBSERVED)
    )

    exposed_spec_paths: list[str] = []
    for path in inputs.settings.web_vuln_openapi_probe_paths:
        probe_url = f"{inputs.ctx.validated_target.scheme}://{inputs.ctx.validated_target.hostname}"
        if inputs.ctx.validated_target.port:
            probe_url += f":{inputs.ctx.validated_target.port}"
        probe_url += path

        probed = fetch_target_url(
            inputs.ctx,
            probe_url,
            max_response_bytes=inputs.settings.web_vuln_max_response_bytes,
            where=f"web_vuln.openapi_probe:{path}",
        )
        if probed.status_code != 200:
            continue
        body_text = probed.body_bytes.decode("utf-8", errors="replace")
        content_type = probed.headers.get("content-type", "")
        if _looks_like_api_spec(content_type, body_text):
            exposed_spec_paths.append(path)

    observations.append(
        Observation("api_security.openapi_spec_exposed_paths", exposed_spec_paths, ObservationNature.OBSERVED)
    )

    if exposed_spec_paths:
        findings.append(
            Finding(
                check=SLUG,
                title="Publicly accessible OpenAPI/Swagger specification",
                description=(
                    f"The following path(s) returned what looks like a machine-readable API "
                    f"specification document, with no authentication: {', '.join(exposed_spec_paths)}. "
                    "This can enumerate the full API surface (routes, parameters, schemas) for anyone "
                    "who requests it."
                ),
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                impact="Significantly reduces the effort needed to enumerate the API's attack surface; does not by itself expose any data the spec document doesn't itself describe.",
                remediation="Require authentication for the API specification document in any environment beyond local development, or ensure it never documents endpoints/parameters that should not be publicly known.",
                affected_url=f"{probe_url.rsplit('/', 1)[0]}{exposed_spec_paths[0]}" if exposed_spec_paths else None,
                cwe_id="CWE-200",
                owasp_category=_OWASP_MISCONFIG,
                evidence={"exposed_paths": exposed_spec_paths},
            )
        )

    # CORS inconsistency: reuse the "cors" check's already-computed
    # result (shared collector_results dict -- see module docstring)
    # rather than probing again.
    cors_result = inputs.collector_results.get("cors")
    if cors_result is not None and candidate_endpoints:
        cors_findings_count = cors_result.evidence.get("findings_count", 0)
        observations.append(
            Observation(
                "api_security.cors_misconfiguration_also_applies_to_api_surface",
                cors_findings_count > 0,
                ObservationNature.INFERRED if cors_findings_count > 0 else ObservationNature.OBSERVED,
                note=(
                    "the primary origin's own CORS check already flagged a misconfiguration; since "
                    "candidate API endpoints were found served from the same origin, that same "
                    "misconfiguration is inferred to apply to them too -- not independently re-probed"
                )
                if cors_findings_count > 0
                else None,
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
