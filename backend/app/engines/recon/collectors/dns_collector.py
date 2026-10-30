"""DNS collector: A, AAAA, MX, NS, CNAME, SOA, TXT records (with TTL)
for the target's hostname, using dnspython with a fixed resolver list
(security/external_lookup_policy.py), never the target itself.

For a bare IP target (e.g. 192.168.56.102:3000) there is no domain to
query, so the collector returns NOT_APPLICABLE. Same for lab-internal
or reserved names (.local, .lab, .internal, or names in
ctx.lab_hosts): they are never sent to a public resolver."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.collectors._domain_utils import hostname_is_ip_literal, hostname_is_lab_or_reserved
from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.context import ReconExecutionContext
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)
from app.engines.recon.security.external_lookup_policy import build_dns_resolver, query_dns
from app.core.config import get_settings

SLUG = "dns"

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME", "SOA", "TXT")


def collect(ctx: ReconExecutionContext) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)
        hostname = ctx.validated_target.hostname

        if hostname_is_ip_literal(hostname):
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=[
                    Observation(
                        "dns.not_applicable",
                        True,
                        ObservationNature.NOT_APPLICABLE,
                        note=f"target {hostname!r} is a bare IP address, not a domain name -- no DNS records apply",
                    )
                ],
                source="dns",
                confidence=ConfidenceLevel.HIGH,
            )

        if hostname_is_lab_or_reserved(hostname, ctx.lab_hosts):
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=[
                    Observation(
                        "dns.not_applicable",
                        True,
                        ObservationNature.NOT_APPLICABLE,
                        note=f"{hostname!r} is a lab-internal/reserved name, never sent to a public DNS resolver",
                    )
                ],
                source="dns",
                confidence=ConfidenceLevel.HIGH,
            )

        settings = get_settings()
        resolver = build_dns_resolver()
        observations: list[Observation] = []
        errors: list[str] = []
        queries_made = 0

        for record_type in _RECORD_TYPES:
            ctx.raise_if_cancelled(where=f"dns:{record_type}")
            ctx.budget.ensure_not_expired(where=f"dns:{record_type}")
            queries_made += 1
            if queries_made > settings.recon_dns_max_queries:
                errors.append(f"{record_type}: dns query budget exhausted ({settings.recon_dns_max_queries})")
                observations.append(
                    Observation(f"dns.{record_type.lower()}", None, ObservationNature.ERROR, note="dns query budget exhausted")
                )
                continue

            query_timeout = ctx.budget.timeout_for(settings.recon_dns_timeout_seconds)
            result = query_dns(resolver, hostname, record_type, lifetime=query_timeout)
            if result.error:
                errors.append(f"{record_type}: {result.error}")
                observations.append(
                    Observation(f"dns.{record_type.lower()}", None, ObservationNature.ERROR, note=result.error)
                )
                continue

            if not result.found:
                observations.append(
                    Observation(
                        f"dns.{record_type.lower()}",
                        [],
                        ObservationNature.OBSERVED,
                        note="no record of this type (confirmed absence, not a lookup failure)",
                    )
                )
                continue

            observations.append(
                Observation(
                    f"dns.{record_type.lower()}",
                    {"values": list(result.values), "ttl_seconds": result.ttl_seconds},
                    ObservationNature.OBSERVED,
                )
            )

        status = CollectorStatus.PARTIAL if errors else CollectorStatus.OK
        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"hostname": hostname, "record_types_queried": list(_RECORD_TYPES)},
            errors=errors,
            source="dns",
            confidence=ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="dns", fn=_run)
