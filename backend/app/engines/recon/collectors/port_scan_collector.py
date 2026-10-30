"""Authorized ports/services collector.

A TCP connect check on a small, explicit list of ports on the target's
own host. It is not a general port scanner:

- No IP-range sweep: it only looks at the host in
  `ctx.validated_target`.
- No full port scan: `allowed_ports` is capped at
  Settings.advanced_recon_max_ports_per_scan (see `_clamp_ports`).
- No undeclared port: every port comes from `allowed_ports`
  (Settings.advanced_recon_default_allowed_ports or a per-target
  override, never free text) and is re-validated by
  app/security/network_scan.py. That is a separate authorization from
  the HTTP SSRF allowlist: allowing HTTP on host:3000 never allows
  other ports on that host.
- No firewall bypass, no login attempt: one short TCP connect, an
  optional short passive read, and for a likely plain-HTTP port one
  `HEAD / HTTP/1.0`. No retry or evasion.

Port states (PARTIAL when the budget or a cancellation stopped the
list early):
- "open": the TCP handshake completed.
- "closed": the connection was refused (RST).
- "filtered": no answer within the timeout. Usually means a firewall
  drops the packet (same convention as nmap), but a slow host would
  look the same, so confidence is MEDIUM.
- "unknown": any other connection error (host or network unreachable,
  DNS failure).

A port that network_scan.py refuses (e.g. private host and host:port
not in the network-scan allowlist) is reported as
"authorization_denied", never as closed/filtered/unknown: we didn't
even try, so it isn't a measurement."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

from app.core.config import get_settings
from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.context import ReconBudgetExceededError, ReconExecutionContext
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)
from app.security.network_scan import NetworkScanValidationError, validate_network_scan_target

SLUG = "port_scan"

# No banner read on these ports: they need a TLS handshake, which
# tls_collector.py already does on the main target port.
_TLS_PORTS = frozenset({443, 8443})


@dataclass(frozen=True)
class _PortOutcome:
    port: int
    state: str  # "open" | "closed" | "filtered" | "unknown" | "authorization_denied"
    banner: str | None = None
    service_guess: str | None = None
    detail: str | None = None


def _clamp_ports(allowed_ports: list[int], *, max_ports: int) -> tuple[list[int], bool]:
    """De-duplicates and sorts for a deterministic, reviewable result,
    then hard-caps the list -- this is what makes a misconfigured
    (too-long) `allowed_ports` list fail safe instead of turning into a
    sweep. Returns (ports, was_truncated)."""
    unique_sorted = sorted(set(allowed_ports))
    if len(unique_sorted) > max_ports:
        return unique_sorted[:max_ports], True
    return unique_sorted, False


def _read_banner(sock: socket.socket, *, timeout: float, max_bytes: int) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(max_bytes)
    except (socket.timeout, OSError):
        return b""


def _minimal_http_probe(sock: socket.socket, *, host: str, timeout: float, max_bytes: int) -> bytes:
    """The one "minimal, safe protocol probe" this collector ever
    sends: a bare HEAD for "/" on HTTP/1.0 (no keep-alive, no request
    body, no auth header, no cookie). Only used on a port that is
    plausibly plain HTTP (never 443/8443) and only after a passive
    read produced nothing -- see collect()'s call site."""
    try:
        sock.settimeout(timeout)
        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore"))
        return sock.recv(max_bytes)
    except (socket.timeout, OSError):
        return b""


def _extract_service_guess(banner: bytes) -> str | None:
    text = banner.decode("latin-1", errors="replace")
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if first_line.upper().startswith("HTTP/"):
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
        return "http"
    if first_line.startswith("SSH-"):
        return first_line.strip()
    return None


def _connect(hostname: str, port: int, timeout: float) -> socket.socket:
    """The only socket-creation call in this module, isolated into its
    own function so tests can monkeypatch exactly this (same pattern
    as tls_collector.py's `_perform_tls_handshake`) instead of needing
    a real listening socket."""
    return socket.create_connection((hostname, port), timeout=timeout)


def _check_one_port(
    *,
    hostname: str,
    port: int,
    connect_timeout: float,
    banner_timeout: float,
    banner_max_bytes: int,
    allow_private_network_scan: bool,
    network_lab_hosts: frozenset[str],
) -> _PortOutcome:
    try:
        validate_network_scan_target(
            hostname,
            port,
            allow_private_network_scan=allow_private_network_scan,
            network_lab_hosts=network_lab_hosts,
        )
    except NetworkScanValidationError as exc:
        return _PortOutcome(port=port, state="authorization_denied", detail=str(exc))

    try:
        sock = _connect(hostname, port, connect_timeout)
    except ConnectionRefusedError as exc:
        return _PortOutcome(port=port, state="closed", detail=str(exc))
    except socket.timeout:
        return _PortOutcome(
            port=port,
            state="filtered",
            detail="no response within the connect timeout (conventional interpretation, not certain)",
        )
    except OSError as exc:
        return _PortOutcome(port=port, state="unknown", detail=str(exc))

    try:
        if port in _TLS_PORTS:
            # No TLS handshake here by design -- see module docstring.
            return _PortOutcome(port=port, state="open", detail="TLS port: see TLS Advanced results")

        banner = _read_banner(sock, timeout=banner_timeout, max_bytes=banner_max_bytes)
        if not banner:
            # Nothing spontaneously offered -- try exactly one minimal,
            # safe HTTP probe (never on a port that already looked like
            # something else, and never more than this single probe).
            banner = _minimal_http_probe(
                sock, host=hostname, timeout=banner_timeout, max_bytes=banner_max_bytes
            )
        banner_text = banner.decode("latin-1", errors="replace").strip() if banner else None
        return _PortOutcome(
            port=port,
            state="open",
            banner=banner_text,
            service_guess=_extract_service_guess(banner) if banner else None,
        )
    finally:
        sock.close()


def collect(
    ctx: ReconExecutionContext,
    *,
    allowed_ports: list[int],
    allow_private_network_scan: bool = False,
    network_lab_hosts: frozenset[str] = frozenset(),
) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)
        settings = get_settings()

        hostname = ctx.validated_target.hostname
        ports, truncated = _clamp_ports(
            allowed_ports, max_ports=settings.advanced_recon_max_ports_per_scan
        )

        observations: list[Observation] = []
        errors: list[str] = []
        if truncated:
            errors.append(
                f"allowed_ports list was truncated to the first "
                f"{settings.advanced_recon_max_ports_per_scan} ports (defense in depth "
                f"against a misconfigured sweep-sized list)"
            )

        outcomes: list[_PortOutcome] = []
        connect_timeout = ctx.budget.timeout_for(settings.advanced_recon_port_connect_timeout_seconds)
        concurrency = max(1, min(settings.advanced_recon_port_scan_concurrency, len(ports) or 1))
        stopped_early = False

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {}
            for port in ports:
                ctx.raise_if_cancelled(where=f"port_scan:{port}")
                try:
                    ctx.budget.register_request(where=f"port_scan:{port}")
                except ReconBudgetExceededError as exc:
                    errors.append(f"budget_exceeded before checking port {port}: {exc}")
                    stopped_early = True
                    break
                futures[
                    pool.submit(
                        _check_one_port,
                        hostname=hostname,
                        port=port,
                        connect_timeout=connect_timeout,
                        banner_timeout=ctx.budget.timeout_for(
                            settings.advanced_recon_banner_read_timeout_seconds
                        ),
                        banner_max_bytes=settings.advanced_recon_banner_max_bytes,
                        allow_private_network_scan=allow_private_network_scan,
                        network_lab_hosts=network_lab_hosts,
                    )
                ] = port
            for future in futures:
                outcomes.append(future.result())

        outcomes.sort(key=lambda o: o.port)
        for outcome in outcomes:
            prefix = f"port_scan.port.{outcome.port}"
            observations.append(
                Observation(
                    f"{prefix}.state",
                    outcome.state,
                    ObservationNature.OBSERVED
                    if outcome.state in ("open", "closed")
                    else (
                        ObservationNature.ERROR
                        if outcome.state == "authorization_denied"
                        else ObservationNature.INFERRED
                    ),
                    note=outcome.detail,
                )
            )
            if outcome.banner:
                observations.append(
                    Observation(f"{prefix}.banner", outcome.banner, ObservationNature.OBSERVED)
                )
            if outcome.service_guess:
                observations.append(
                    Observation(
                        f"{prefix}.service_guess", outcome.service_guess, ObservationNature.INFERRED
                    )
                )

        if not ports:
            status = CollectorStatus.NOT_APPLICABLE
        elif stopped_early:
            status = CollectorStatus.PARTIAL
        else:
            status = CollectorStatus.ERROR if not outcomes and errors else CollectorStatus.OK

        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"host": hostname, "ports_checked": [o.port for o in outcomes]},
            errors=errors,
            source="port_scan",
            confidence=ConfidenceLevel.MEDIUM if outcomes else ConfidenceLevel.LOW,
        )

    return run_collector_safely(collector_slug=SLUG, source="port_scan", fn=_run)
