"""Domain RDAP collector: registrar, registration/update/expiry dates,
status codes and nameservers for the target's domain, through the
fixed RDAP bootstrap host (security/external_lookup_policy.py).

Only applies to targets with a domain name. A bare IP has no domain
RDAP record, so it returns NOT_APPLICABLE. (The IP owner lookup is
done by ip_asn_collector.py.)

RDAP fields vary by registry and are often hidden by privacy services.
The collector reports exactly what the registry returned, never
invents a value, and separates "redacted by the registry" from
"missing from the response"."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from urllib.parse import quote

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
from app.engines.recon.security.external_lookup_policy import ExternalLookupError, rdap_get
from app.core.config import get_settings

SLUG = "rdap"

_REDACTED_MARKERS = ("redacted", "data redacted", "not disclosed")


def _is_redacted(value) -> bool:
    return isinstance(value, str) and value.strip().lower() in _REDACTED_MARKERS


def _extract_events(payload: dict) -> dict:
    events = {}
    for event in payload.get("events") or []:
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            events[action] = date
    return events


def _extract_registrar(payload: dict) -> str | None:
    for entity in payload.get("entities") or []:
        roles = entity.get("roles") or []
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field and field[0] == "fn":
                        return field[-1]
            return entity.get("handle")
    return None


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
                        "rdap.not_applicable",
                        True,
                        ObservationNature.NOT_APPLICABLE,
                        note=f"target {hostname!r} is a bare IP address, not a domain name -- no domain RDAP record applies",
                    )
                ],
                source="rdap",
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
                        "rdap.not_applicable",
                        True,
                        ObservationNature.NOT_APPLICABLE,
                        note=f"{hostname!r} is a lab-internal/reserved name -- no public domain RDAP record can exist for it",
                    )
                ],
                source="rdap",
                confidence=ConfidenceLevel.HIGH,
            )

        settings = get_settings()
        url = f"{settings.recon_rdap_base_url}/domain/{quote(hostname, safe='')}"

        try:
            # rdap_get() validates EVERY hop (the bootstrap request and
            # each redirect it issues) against private/loopback/
            # link-local/forbidden-port destinations before connecting,
            # respects the shared global deadline, and enforces a hard
            # response-size cap -- see external_lookup_policy.py.
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
                        "rdap.domain",
                        {"found": False},
                        ObservationNature.OBSERVED,
                        note="RDAP bootstrap reports no record for this domain (confirmed absence, not a lookup failure)",
                    )
                ],
                evidence={"url": url, "status_code": 404},
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

        events = _extract_events(payload)
        registrar = _extract_registrar(payload)
        observations = [
            Observation("rdap.domain_found", True, ObservationNature.OBSERVED),
            Observation(
                "rdap.registrar",
                registrar,
                ObservationNature.OBSERVED if registrar and not _is_redacted(registrar) else ObservationNature.UNKNOWN,
                note="registrar field redacted by registry/registrar privacy service" if _is_redacted(registrar) else None,
            ),
            Observation("rdap.registration_date", events.get("registration"), ObservationNature.OBSERVED if events.get("registration") else ObservationNature.UNKNOWN),
            Observation("rdap.last_changed_date", events.get("last changed"), ObservationNature.OBSERVED if events.get("last changed") else ObservationNature.UNKNOWN),
            Observation("rdap.expiration_date", events.get("expiration"), ObservationNature.OBSERVED if events.get("expiration") else ObservationNature.UNKNOWN),
            Observation("rdap.status", payload.get("status") or [], ObservationNature.OBSERVED),
            Observation(
                "rdap.nameservers",
                [ns.get("ldhName") for ns in (payload.get("nameservers") or []) if ns.get("ldhName")],
                ObservationNature.OBSERVED,
            ),
        ]

        return CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"url": url, "status_code": response.status_code},
            source="rdap",
            confidence=ConfidenceLevel.MEDIUM,
        )

    return run_collector_safely(collector_slug=SLUG, source="rdap", fn=_run)
