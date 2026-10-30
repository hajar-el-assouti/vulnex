"""Email security collector: SPF, DMARC, DKIM.

These records are published under a domain name, so for a bare IP
target (or a lab/reserved name) the collector returns NOT_APPLICABLE
and nothing is sent to a public resolver.

For SPF and DMARC, three cases are kept separate:
- OBSERVED absence: the lookup worked and no matching TXT record was
  found (NXDOMAIN/NoAnswer, or no v=spf1 / v=DMARC1 record).
- ERROR: the lookup itself failed (timeout, SERVFAIL...). This says
  nothing about the record and is never reported as an absence.
- UNKNOWN: only used for DKIM.

DKIM selectors are arbitrary names chosen by the domain owner and
can't be listed through DNS. Without a known selector there is
nothing to query, so DKIM is reported UNKNOWN, never absent."""

from __future__ import annotations

import re
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

SLUG = "email_security"

_DMARC_TAG_RE = re.compile(r"\b(p|sp|pct|rua|ruf|adkim|aspf)\s*=\s*([^;]+)")


def _parse_dmarc_tags(record: str) -> dict:
    return {key: value.strip() for key, value in _DMARC_TAG_RE.findall(record)}


def _collect_spf(resolver, hostname: str, errors: list[str], *, lifetime: float) -> Observation:
    result = query_dns(resolver, hostname, "TXT", lifetime=lifetime)
    if result.error:
        errors.append(f"SPF: {result.error}")
        return Observation("email.spf", None, ObservationNature.ERROR, note=result.error)

    spf_records = [v for v in result.values if v.lower().startswith("v=spf1")]
    if not spf_records:
        return Observation(
            "email.spf",
            {"present": False},
            ObservationNature.OBSERVED,
            note="no TXT record starting with v=spf1 (confirmed absence, not a lookup failure)",
        )
    return Observation(
        "email.spf",
        {"present": True, "record": spf_records[0], "additional_records": spf_records[1:] or None},
        ObservationNature.OBSERVED,
    )


def _collect_dmarc(resolver, hostname: str, errors: list[str], *, lifetime: float) -> Observation:
    name = f"_dmarc.{hostname}"
    result = query_dns(resolver, name, "TXT", lifetime=lifetime)
    if result.error:
        errors.append(f"DMARC: {result.error}")
        return Observation("email.dmarc", None, ObservationNature.ERROR, note=result.error)

    dmarc_records = [v for v in result.values if v.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return Observation(
            "email.dmarc",
            {"present": False},
            ObservationNature.OBSERVED,
            note="no TXT record starting with v=DMARC1 at _dmarc.<domain> (confirmed absence, not a lookup failure)",
        )
    tags = _parse_dmarc_tags(dmarc_records[0])
    return Observation(
        "email.dmarc",
        {
            "present": True,
            "record": dmarc_records[0],
            "policy": tags.get("p"),
            "subdomain_policy": tags.get("sp"),
            "percentage": tags.get("pct"),
            "aggregate_reports_to": tags.get("rua"),
            "forensic_reports_to": tags.get("ruf"),
        },
        ObservationNature.OBSERVED,
    )


def _collect_dkim() -> Observation:
    return Observation(
        "email.dkim",
        {"selector_known": False},
        ObservationNature.UNKNOWN,
        note=(
            "DKIM is published per-selector and this collector does not enumerate or"
            " guess selectors -- presence or absence cannot be determined without a"
            " known selector, so this is reported as unknown, never as absent"
        ),
    )


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
                        "email_security.not_applicable",
                        True,
                        ObservationNature.NOT_APPLICABLE,
                        note=(
                            f"target {hostname!r} is a bare IP address, not a domain name --"
                            " SPF/DMARC/DKIM are published under domain names only"
                        ),
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
                        "email_security.not_applicable",
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
        errors: list[str] = []

        ctx.raise_if_cancelled(where="email_security:spf")
        ctx.budget.ensure_not_expired(where="email_security:spf")
        spf_timeout = ctx.budget.timeout_for(settings.recon_dns_timeout_seconds)
        spf_observation = _collect_spf(resolver, hostname, errors, lifetime=spf_timeout)

        ctx.raise_if_cancelled(where="email_security:dmarc")
        ctx.budget.ensure_not_expired(where="email_security:dmarc")
        dmarc_timeout = ctx.budget.timeout_for(settings.recon_dns_timeout_seconds)
        dmarc_observation = _collect_dmarc(resolver, hostname, errors, lifetime=dmarc_timeout)

        dkim_observation = _collect_dkim()  # no network call -- see docstring

        status = CollectorStatus.PARTIAL if errors else CollectorStatus.OK
        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=[spf_observation, dmarc_observation, dkim_observation],
            evidence={"hostname": hostname},
            errors=errors,
            source="dns",
            confidence=ConfidenceLevel.MEDIUM,
        )

    return run_collector_safely(collector_slug=SLUG, source="dns", fn=_run)
