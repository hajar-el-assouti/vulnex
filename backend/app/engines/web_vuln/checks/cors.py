"""CORS misconfiguration check.

Sends one extra GET with a test `Origin` header, through
request_policy.py::fetch_target_url() (so it gets SSRF validation, the
shared budget and the size limit), and checks whether
Access-Control-Allow-Origin reflects it. No credentials, no attempt to
actually read cross-origin data.

The test Origin (Settings.web_vuln_cors_probe_origin) uses a reserved
TLD (`*.invalid.example`) that no real allowlist would contain. If it
is reflected, the server trusts any Origin, which is the finding.

Exceptions are not caught here: web_vuln/engine.py::_run_check_safely
wraps every check and keeps any Finding already computed."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.recon.security.request_policy import fetch_target_url
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity
from app.engines.web_vuln.registry import CheckInputs, CheckOutcome

SLUG = "cors"
CATEGORY = "cors"

_OWASP_MISCONFIG = "A05:2021-Security Misconfiguration"


def _acao(headers) -> str | None:
    return headers.get("access-control-allow-origin")


def _acac(headers) -> bool:
    return (headers.get("access-control-allow-credentials") or "").strip().lower() == "true"


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
                errors=["no primary response to probe CORS against"],
                source=SLUG,
            )
        )

    primary_acao = _acao(inputs.fetched.headers)
    primary_acac = _acac(inputs.fetched.headers)

    probe_origin = inputs.settings.web_vuln_cors_probe_origin
    probed = fetch_target_url(
        inputs.ctx,
        inputs.fetched.final_url,
        max_response_bytes=inputs.settings.web_vuln_max_response_bytes,
        where="web_vuln.cors_probe",
        method="GET",
        extra_headers={"Origin": probe_origin},
    )
    probed_acao = _acao(probed.headers)
    probed_acac = _acac(probed.headers)
    reflects_arbitrary_origin = probed_acao is not None and probed_acao.strip() == probe_origin

    observations = [
        Observation("cors.primary.access_control_allow_origin", primary_acao, ObservationNature.OBSERVED),
        Observation("cors.primary.access_control_allow_credentials", primary_acac, ObservationNature.OBSERVED),
        Observation("cors.probe.origin_sent", probe_origin, ObservationNature.OBSERVED),
        Observation("cors.probe.access_control_allow_origin", probed_acao, ObservationNature.OBSERVED),
        Observation("cors.probe.access_control_allow_credentials", probed_acac, ObservationNature.OBSERVED),
        Observation("cors.probe.reflects_arbitrary_origin", reflects_arbitrary_origin, ObservationNature.OBSERVED),
    ]

    findings: list[Finding] = []
    evidence = {
        "probe_origin": probe_origin,
        "probe_acao": probed_acao,
        "probe_acac": probed_acac,
        "primary_acao": primary_acao,
        "primary_acac": primary_acac,
    }

    if reflects_arbitrary_origin and probed_acac:
        findings.append(
            Finding(
                check=SLUG,
                title="CORS reflects an arbitrary Origin with credentials allowed",
                description=(
                    f"Requesting with 'Origin: {probe_origin}' (a domain with no legitimate "
                    "relationship to this target) returned that exact value in "
                    "Access-Control-Allow-Origin, together with "
                    "Access-Control-Allow-Credentials: true. A browser would allow any "
                    "attacker-controlled page to read this response with the victim's "
                    "credentials attached."
                ),
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                impact=(
                    "Any site can issue a credentialed cross-origin request on behalf of a "
                    "logged-in victim and read the response -- this check observed the "
                    "permissive headers only, it did not read any actual account data."
                ),
                remediation=(
                    "Allow only an explicit, server-maintained allowlist of trusted origins; "
                    "never echo the request's own Origin header back unconditionally, "
                    "especially alongside Allow-Credentials: true."
                ),
                affected_url=inputs.fetched.final_url,
                cwe_id="CWE-942",
                owasp_category=_OWASP_MISCONFIG,
                evidence=evidence,
            )
        )
    elif reflects_arbitrary_origin:
        findings.append(
            Finding(
                check=SLUG,
                title="CORS reflects an arbitrary Origin",
                description=(
                    f"Requesting with 'Origin: {probe_origin}' returned that exact value in "
                    "Access-Control-Allow-Origin (without Allow-Credentials). No allowlist "
                    "appears to be enforced server-side."
                ),
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                impact="Any site can read this response cross-origin; lower impact than the credentialed case since no session/credentials are attached.",
                remediation="Allow only an explicit, server-maintained allowlist of trusted origins.",
                affected_url=inputs.fetched.final_url,
                cwe_id="CWE-942",
                owasp_category=_OWASP_MISCONFIG,
                evidence=evidence,
            )
        )
    elif primary_acao == "*" and primary_acac:
        # Per the Fetch spec browsers must reject this exact combination
        # outright -- still worth flagging as a misconfiguration SIGNAL
        # (the server is trying to serve an invalid, contradictory
        # policy), never claimed as something a browser would actually
        # honor.
        findings.append(
            Finding(
                check=SLUG,
                title="CORS wildcard Allow-Origin combined with Allow-Credentials",
                description=(
                    "Access-Control-Allow-Origin: '*' was returned together with "
                    "Access-Control-Allow-Credentials: true. Browsers reject this exact "
                    "combination, so it is not directly exploitable as-is, but it signals a "
                    "misconfigured or copy-pasted CORS policy that should be reviewed."
                ),
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                impact="Not directly exploitable in a compliant browser; indicates a CORS configuration that should be reviewed before it is 'fixed' into something that is.",
                remediation="Never pair a wildcard Allow-Origin with Allow-Credentials; use an explicit origin allowlist wherever credentials are involved.",
                affected_url=inputs.fetched.final_url,
                cwe_id="CWE-942",
                owasp_category=_OWASP_MISCONFIG,
                evidence=evidence,
            )
        )

    collector_result = CollectorResult(
        collector=SLUG,
        status=CollectorStatus.OK,
        collected_at=collected_at,
        duration_ms=int((time.monotonic() - started) * 1000),
        observations=observations,
        evidence={"findings_count": len(findings)},
        source=SLUG,
        confidence=ConfidenceLevel.HIGH,
    )
    return CheckOutcome(collector_result=collector_result, findings=findings)
