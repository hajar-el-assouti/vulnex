"""TLS/HTTPS configuration check.

No network connection of its own: it interprets tls_collector.py's
result, which web_vuln/engine.py already collected. Observed TLS facts
in, justified findings out."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, ObservationNature
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity
from app.engines.web_vuln.registry import CheckInputs, CheckOutcome

SLUG = "tls_config"
CATEGORY = "tls"

_OWASP_CRYPTO = "A02:2021-Cryptographic Failures"
_OBSOLETE_VERSIONS = ("TLSv1.0", "TLSv1.1")


def run(inputs: CheckInputs) -> CheckOutcome:
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    tls_result = inputs.collector_results.get("tls")

    if tls_result is None:
        return CheckOutcome(
            collector_result=CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=["no tls observation available for this run"],
                source=SLUG,
            )
        )

    observed_by_key = {obs.key: obs for obs in tls_result.observations}
    findings: list[Finding] = []
    affected_url = inputs.fetched.final_url if inputs.fetched else None

    not_applicable = observed_by_key.get("tls.not_applicable")
    if not_applicable is not None and not_applicable.nature == ObservationNature.NOT_APPLICABLE:
        findings.append(
            Finding(
                check=SLUG,
                title="Target reachable over plain HTTP (no TLS at all)",
                description="The primary target URL uses the http:// scheme -- there is no TLS handshake to evaluate, meaning no transport encryption is in use for this URL at all.",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                impact="Traffic to this URL (including any credentials/session data a client sends) travels unencrypted and can be read or altered in transit by anyone positioned on the network path.",
                remediation="Serve the application over HTTPS and redirect all plain-HTTP requests to it.",
                affected_url=affected_url,
                cwe_id="CWE-319",
                owasp_category=_OWASP_CRYPTO,
                evidence={"scheme": "http"},
            )
        )
        return CheckOutcome(
            collector_result=CollectorResult(
                collector=SLUG,
                status=CollectorStatus.OK,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                evidence={"findings_count": len(findings)},
                source=SLUG,
                confidence=ConfidenceLevel.HIGH,
            ),
            findings=findings,
        )

    cert_valid = observed_by_key.get("tls.certificate_valid")
    if cert_valid is not None and cert_valid.nature == ObservationNature.OBSERVED and cert_valid.value is False:
        findings.append(
            Finding(
                check=SLUG,
                title="TLS certificate failed validation",
                description=f"The TLS handshake completed but certificate verification failed: {cert_valid.note or 'see evidence'}.",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                impact="Clients that do not strictly enforce certificate validation (or that a user has been tricked into overriding a browser warning for) could be connecting to an impersonating server.",
                remediation="Install a certificate signed by a trusted CA for this exact hostname, with a valid chain and validity window.",
                affected_url=affected_url,
                cwe_id="CWE-295",
                owasp_category=_OWASP_CRYPTO,
                evidence={"detail": cert_valid.note or ""},
            )
        )

    protocol = observed_by_key.get("tls.protocol_version")
    if protocol is not None and protocol.value in _OBSOLETE_VERSIONS:
        findings.append(
            Finding(
                check=SLUG,
                title=f"Primary handshake negotiated an obsolete TLS version ({protocol.value})",
                description=f"The primary TLS handshake negotiated {protocol.value}, a deprecated protocol version with known weaknesses.",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.HIGH,
                impact="An obsolete protocol version lacks modern protections and may be vulnerable to known downgrade/cryptographic attacks against that version specifically.",
                remediation="Disable TLS 1.0/1.1 server-side; support TLS 1.2 and 1.3 only.",
                affected_url=affected_url,
                cwe_id="CWE-327",
                owasp_category=_OWASP_CRYPTO,
                evidence={"negotiated_protocol": protocol.value},
            )
        )

    for version in _OBSOLETE_VERSIONS:
        supported_obs = observed_by_key.get(f"tls_advanced.protocol.{version}.supported")
        if supported_obs is not None and supported_obs.value is True:
            findings.append(
                Finding(
                    check=SLUG,
                    title=f"Server still negotiates {version} when a client requests it",
                    description=(
                        f"A dedicated probe (verification disabled, scoped only to protocol "
                        f"negotiation -- see app/engines/recon/collectors/tls_collector.py) "
                        f"found that the server completes a handshake pinned to {version}."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.MEDIUM,
                    impact="A client (or an attacker forcing a downgrade) that negotiates this obsolete version loses the protections modern TLS versions provide.",
                    remediation="Configure the server to refuse TLS versions below 1.2.",
                    affected_url=affected_url,
                    cwe_id="CWE-327",
                    owasp_category=_OWASP_CRYPTO,
                    evidence={"protocol": version, "supported": True},
                )
            )

    return CheckOutcome(
        collector_result=CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            evidence={"findings_count": len(findings)},
            source=SLUG,
            confidence=ConfidenceLevel.HIGH,
        ),
        findings=findings,
    )
