"""Recon engine.

Runs every recon collector against one validated target and returns
their CollectorResults, keyed by collector slug:
- target-facing, through request_policy.py: http, headers, cookies,
  technology, metadata;
- DNS/RDAP against fixed public services, through
  external_lookup_policy.py: dns, email_security, rdap, ip_asn
  (plus tls, which connects to the target);
- no network call, parsed from the page already fetched: assets,
  api_discovery;
- fingerprint: compares with this run's other results and the
  previous run, only when a history provider and the run identity are
  given (see run_collectors()).

The engine itself has no Celery or database dependency, so it can be
tested on its own. Results are stored by app/tasks/recon_module.py."""

from __future__ import annotations

from app.engines.recon.collectors import (
    api_discovery_collector,
    assets_collector,
    cookies_collector,
    dns_collector,
    email_security_collector,
    fingerprint_collector,
    headers_collector,
    http_collector,
    ip_asn_collector,
    metadata_collector,
    rdap_collector,
    technology_collector,
    tls_collector,
)
from app.engines.recon.context import ReconBudget, ReconCancelledError, ReconExecutionContext
from app.engines.recon.fingerprint import FingerprintHistoryProvider
from app.engines.recon.schemas import CollectorResult
from app.engines.recon.security.request_policy import FetchedResponse
from app.engines.recon.security.scope_guard import ensure_in_scope
from app.security.ssrf import validate_outbound_url


def build_context(
    *,
    scan_id: str,
    target_base_url: str,
    target_is_authorized: bool,
    budget: ReconBudget,
    allow_private_networks: bool = False,
    lab_hosts: frozenset[str] = frozenset(),
    is_cancelled=lambda: False,
) -> ReconExecutionContext:
    """Re-checks authorization (defense in depth -- see
    security/scope_guard.py) and validates the target once up front
    (SSRF check, so an obviously-out-of-scope target never gets as far
    as building a context at all) before handing back a context every
    collector can use. Every individual request a collector later makes
    still re-validates independently (request_policy.py) -- this
    up-front check does not substitute for that."""
    ensure_in_scope(target_is_authorized=target_is_authorized, target_base_url=target_base_url)
    validated = validate_outbound_url(
        target_base_url, allow_private_networks=allow_private_networks, lab_hosts=lab_hosts
    )
    return ReconExecutionContext(
        scan_id=scan_id,
        target_base_url=target_base_url,
        validated_target=validated,
        budget=budget,
        allow_private_networks=allow_private_networks,
        lab_hosts=lab_hosts,
        is_cancelled=is_cancelled,
    )


def run_collectors(
    ctx: ReconExecutionContext,
    *,
    max_response_bytes: int,
    max_metadata_response_bytes: int,
    history_provider: FingerprintHistoryProvider | None = None,
    target_id: str | None = None,
    module_slug: str = "recon",
    user_id: str | None = None,
    run_id: str | None = None,
) -> dict[str, CollectorResult]:
    """Runs every collector in order, checking for cancellation between
    groups. A collector is never stopped halfway, but its own budget
    and deadline already limit how long it can run.

    `history_provider`/`target_id`/`user_id`/`run_id` are optional.
    If any of them is missing, the fingerprint collector is skipped
    instead of running with a made-up identity, so `results` has no
    "fingerprint" key."""
    results: dict[str, CollectorResult] = {}

    try:
        fetched: FetchedResponse | None = None
        fetch_error: str | None = None
        try:
            fetched = http_collector.fetch_primary(ctx, max_response_bytes=max_response_bytes)
        except ReconCancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 -- recorded below, never escapes
            fetch_error = f"{exc.__class__.__name__}: {exc}"

        results[http_collector.SLUG] = http_collector.collect(ctx, fetched, fetch_error)

        if ctx.is_cancelled():
            return results

        results[headers_collector.SLUG] = headers_collector.collect(ctx, fetched, fetch_error)
        results[cookies_collector.SLUG] = cookies_collector.collect(ctx, fetched, fetch_error)
        results[technology_collector.SLUG] = technology_collector.collect(ctx, fetched, fetch_error)
        results[assets_collector.SLUG] = assets_collector.collect(ctx, fetched, fetch_error)
        results[api_discovery_collector.SLUG] = api_discovery_collector.collect(ctx, fetched, fetch_error)

        if ctx.is_cancelled():
            return results

        results[metadata_collector.SLUG] = metadata_collector.collect(
            ctx, max_metadata_bytes=max_metadata_response_bytes
        )

        if ctx.is_cancelled():
            return results

        # DNS, email security, RDAP and IP/ASN query fixed public services,
        # not the target, so they still run if the page fetch failed. tls
        # connects to the target but validates and connects on its own.
        results[dns_collector.SLUG] = dns_collector.collect(ctx)
        results[email_security_collector.SLUG] = email_security_collector.collect(ctx)
        results[rdap_collector.SLUG] = rdap_collector.collect(ctx)
        results[ip_asn_collector.SLUG] = ip_asn_collector.collect(ctx)
        results[tls_collector.SLUG] = tls_collector.collect(ctx)
    except ReconCancelledError:
        # A cancellation seen inside a collector (checked between its own
        # requests, see ReconExecutionContext.raise_if_cancelled) stops the
        # remaining collectors right away, like the checks between groups.
        # Results from collectors that already finished are kept.
        return results

    if history_provider is not None and target_id is not None and user_id is not None and run_id is not None:
        results[fingerprint_collector.SLUG] = fingerprint_collector.collect(
            results,
            target_id=target_id,
            module_slug=module_slug,
            user_id=user_id,
            run_id=run_id,
            history_provider=history_provider,
        )

    return results
