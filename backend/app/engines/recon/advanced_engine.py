"""Advanced recon engine.

A separate module (`advanced_recon`) from the basic recon engine
(recon/engine.py), so it can be selected on its own.

Since it may run without `recon`, it does its own page fetch and DNS
lookup, reusing the same collectors (http, headers, cookies, dns) to
feed WAF/CDN detection. It also calls tls_collector so deep TLS
analysis works without `recon`.

Collector order: http -> headers/cookies/dns -> tls -> port_scan ->
visual_snapshot -> waf_cdn (no network, uses results already
collected) -> fingerprint (no network). The fingerprint collector
compares with the previous advanced_recon run of the same target, so
a new open port, a changed certificate or a WAF/CDN change shows up
in `fingerprint.changed_keys`. Known limitation: `http.elapsed_ms` is
compared exactly, so normal network jitter also shows as a change.

Cancellation is checked between groups, like recon/engine.py. If a
run is cancelled, it returns what was collected so far, never a
partial waf_cdn/fingerprint result built from incomplete data."""

from __future__ import annotations

from app.engines.recon.collectors import (
    cookies_collector,
    dns_collector,
    fingerprint_collector,
    headers_collector,
    http_collector,
    port_scan_collector,
    tls_collector,
    visual_snapshot_collector,
    waf_cdn_collector,
)
from app.engines.recon.context import ReconCancelledError, ReconExecutionContext
from app.engines.recon.fingerprint import FingerprintHistoryProvider
from app.engines.recon.schemas import CollectorResult
from app.engines.recon.security.request_policy import FetchedResponse

DEFAULT_MODULE_SLUG = "advanced_recon"


def run_advanced_collectors(
    ctx: ReconExecutionContext,
    *,
    allowed_ports: list[int],
    allow_private_network_scan: bool = False,
    network_lab_hosts: frozenset[str] = frozenset(),
    max_response_bytes: int = 2_000_000,
    visual_snapshot_enabled: bool = False,
    history_provider: FingerprintHistoryProvider | None = None,
    target_id: str | None = None,
    module_slug: str = DEFAULT_MODULE_SLUG,
    user_id: str | None = None,
    run_id: str | None = None,
) -> dict[str, CollectorResult]:
    """Runs every advanced collector, stopping immediately (returning
    whatever is already collected) if cancellation is observed --
    same cooperative-cancellation contract as
    app/engines/recon/engine.py::run_collectors()."""
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
        results[dns_collector.SLUG] = dns_collector.collect(ctx)

        if ctx.is_cancelled():
            return results

        results[tls_collector.SLUG] = tls_collector.collect(ctx)

        results[port_scan_collector.SLUG] = port_scan_collector.collect(
            ctx,
            allowed_ports=allowed_ports,
            allow_private_network_scan=allow_private_network_scan,
            network_lab_hosts=network_lab_hosts,
        )

        if ctx.is_cancelled():
            return results

        # Always included, so its disabled state is visible in the results.
        # Doesn't depend on anything above. See visual_snapshot_collector.py
        # for why it is disabled by default.
        results[visual_snapshot_collector.SLUG] = visual_snapshot_collector.collect(
            ctx, enabled=visual_snapshot_enabled
        )
    except ReconCancelledError:
        return results

    results[waf_cdn_collector.SLUG] = waf_cdn_collector.collect(results)

    # Same guard as recon/engine.py: only run the fingerprint collector
    # when a history provider and the full run identity are given. When
    # missing, `results` just has no "fingerprint" key.
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
