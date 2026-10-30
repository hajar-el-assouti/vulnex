"""IP/ASN/hosting collector: which organization and network own the
target's resolved IP, through RDAP IP lookups on the fixed bootstrap
host (security/external_lookup_policy.py). No paid GeoIP/ASN API, no
scraping.

Unlike the domain collectors, this one still applies to a bare IP
target. But if the IP is private (e.g. 192.168.56.102), no public
registry has a record for it, so the collector returns NOT_APPLICABLE.
That is detected locally, before any RDAP request."""

from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone

from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.context import ReconExecutionContext
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)
from app.engines.recon.security.external_lookup_policy import ExternalLookupError, rdap_get
from app.core.config import get_settings

SLUG = "ip_asn"


def _is_globally_routable(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Deliberately re-implemented here, independent of
    app/security/ssrf.py's own private-address check -- this collector
    is asking a DIFFERENT question (is a public registry record even
    possible for this address) than ssrf.py (is it safe to connect to
    this address), and keeping the two checks separate means a change
    to one is never silently a change to the other's security
    guarantee."""
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def collect(ctx: ReconExecutionContext) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)
        resolved_ips = ctx.validated_target.resolved_ips
        if not resolved_ips:
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.ERROR,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=["no resolved IP address available on the validated target"],
                source="rdap",
            )

        target_ip_str = resolved_ips[0]
        target_ip = ipaddress.ip_address(target_ip_str)

        if not _is_globally_routable(target_ip):
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=[
                    Observation(
                        "ip_asn.not_applicable",
                        True,
                        ObservationNature.NOT_APPLICABLE,
                        note=(
                            f"{target_ip_str} is a private/reserved/non-global address --"
                            " no public RIR registry issues ASN/organization records for"
                            " this range, so an RDAP IP lookup is not a meaningful"
                            " question here (lab target, e.g. OWASP Juice Shop)"
                        ),
                    )
                ],
                evidence={"ip": target_ip_str},
                source="rdap",
                confidence=ConfidenceLevel.HIGH,
            )

        settings = get_settings()
        url = f"{settings.recon_rdap_base_url}/ip/{target_ip_str}"

        try:
            # Same per-hop validation, deadline, and size-cap discipline
            # as rdap_collector.py -- see external_lookup_policy.py.
            response = rdap_get(url, budget=ctx.budget, is_cancelled=ctx.is_cancelled)
        except ExternalLookupError as exc:
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.ERROR,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"{exc.__class__.__name__}: {exc}"],
                source="rdap",
            )

        if response.status_code == 404:
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.OK,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=[
                    Observation(
                        "ip_asn.record_found",
                        False,
                        ObservationNature.OBSERVED,
                        note="RDAP bootstrap reports no record for this IP (confirmed absence, not a lookup failure)",
                    )
                ],
                evidence={"ip": target_ip_str, "url": url, "status_code": 404},
                source="rdap",
                confidence=ConfidenceLevel.HIGH,
            )

        if response.status_code >= 400:
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.ERROR,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"RDAP server returned HTTP {response.status_code}"],
                source="rdap",
            )

        try:
            payload = json.loads(response.body_bytes)
        except ValueError as exc:
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.ERROR,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"malformed RDAP response: {exc}"],
                source="rdap",
            )

        org_name = None
        for entity in payload.get("entities") or []:
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field and field[0] == "fn":
                        org_name = field[-1]
                        break
            if org_name:
                break

        observations = [
            Observation("ip_asn.resolved_ip", target_ip_str, ObservationNature.OBSERVED),
            Observation("ip_asn.record_found", True, ObservationNature.OBSERVED),
            Observation("ip_asn.network_name", payload.get("name"), ObservationNature.OBSERVED if payload.get("name") else ObservationNature.UNKNOWN),
            Observation(
                "ip_asn.network_range",
                {"start": payload.get("startAddress"), "end": payload.get("endAddress")},
                ObservationNature.OBSERVED,
            ),
            Observation("ip_asn.country", payload.get("country"), ObservationNature.OBSERVED if payload.get("country") else ObservationNature.UNKNOWN),
            Observation("ip_asn.organization", org_name, ObservationNature.OBSERVED if org_name else ObservationNature.UNKNOWN),
        ]

        return CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"ip": target_ip_str, "url": url, "status_code": response.status_code},
            source="rdap",
            confidence=ConfidenceLevel.MEDIUM,
        )

    return run_collector_safely(collector_slug=SLUG, source="rdap", fn=_run)
