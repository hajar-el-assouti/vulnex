"""SSRF (Server-Side Request Forgery) validation for outbound requests.

What this module doesn't do:
- It makes no request itself. Validation and the request are separate
  steps, so the caller should connect to the validated IP instead of
  resolving the hostname again (that gap is a DNS rebinding window).
  The active testing engine does this with IP pinning
  (active_web_testing/security/pinned_request.py).
- It doesn't replace network isolation. A worker that can reach the
  internal network at the OS/container level is not made safe by an
  application-level check alone.

Lab mode: `allow_private_networks=True` plus a non-empty `lab_hosts`
allowlist, for scanning intentionally vulnerable apps on the same
private network (e.g. OWASP Juice Shop on `192.168.56.102:3000`). It is
a per host:port opt-in, never "trust all private IPs", and must not be
used in a real deployment (Settings.ssrf_lab_allowlist is empty by
default).

`lab_hosts` entries are `"host:port"` strings, matched on both the
host and the port. Otherwise an allowlisted host would be exempt on
every port, and a scan could reach an admin panel or a database on
the same machine. A bare hostname entry is not accepted.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Ports that are almost never a legitimate HTTP(S) target and are common
# pivot targets (SMTP, internal RPC, databases, etc.). Not exhaustive --
# defense in depth on top of the private-IP rejection below, not a
# replacement for it.
_SUSPICIOUS_PORTS = frozenset({25, 587, 465, 22, 23, 3306, 5432, 6379, 11211, 2375, 2376})


class SSRFValidationError(ValueError):
    """Raised for any URL/target this module refuses to let an engine
    connect to. The message is safe to log and to surface in a
    ScanEvent -- it never echoes back more than the rejected host."""


@dataclass(frozen=True)
class ValidatedTarget:
    """Result of a passed validation. `resolved_ips` is what a future
    engine must connect to (IP pinning) -- re-resolving the hostname
    again right before connecting reopens the DNS-rebinding window this
    validation is meant to close."""

    hostname: str
    port: int
    scheme: str
    resolved_ips: tuple[str, ...]


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        # IPv4-mapped IPv6 (::ffff:10.0.0.1) must be unwrapped and
        # re-checked, not waved through just because it's technically a
        # "public-looking" IPv6 literal.
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None
            and _is_disallowed_ip(ip.ipv4_mapped))
    )


def _resolve_all(hostname: str) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFValidationError(f"Could not resolve host: {hostname!r}") from exc
    ips = {info[4][0] for info in infos}
    if not ips:
        raise SSRFValidationError(f"Host resolved to no addresses: {hostname!r}")
    return tuple(sorted(ips))


def _is_lab_exempt(hostname: str, port: int, *, allow_private_networks: bool, lab_hosts: frozenset[str]) -> bool:
    """Matches `"host:port"`, never a bare host, so allowlisting the lab
    target doesn't exempt other ports on the same host.
    `allow_private_networks` must also be True: neither setting is
    enough on its own."""
    if not allow_private_networks:
        return False
    normalized_entries = {entry.lower() for entry in lab_hosts}
    return f"{hostname.lower()}:{port}" in normalized_entries


def validate_outbound_url(
    url: str,
    *,
    allow_private_networks: bool = False,
    lab_hosts: frozenset[str] = frozenset(),
) -> ValidatedTarget:
    """Raises SSRFValidationError unless `url` is safe to request.

    Checks, in order: scheme allowlist, hostname presence, DNS resolution,
    and that every resolved address is a public, non-reserved IP -- unless
    this exact `"host:port"` is in `lab_hosts` AND `allow_private_networks`
    is explicitly True (see module docstring and _is_lab_exempt(): an
    explicit per-host:port opt-in, never a blanket private-network
    allowance, and never exempt on a port the lab target doesn't
    actually listen on).
    """
    parts = urlsplit(url)

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFValidationError(f"Unsupported scheme: {parts.scheme!r}")

    hostname = parts.hostname
    if not hostname:
        raise SSRFValidationError("URL has no hostname")

    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    if port in _SUSPICIOUS_PORTS:
        raise SSRFValidationError(f"Port {port} is not a permitted HTTP(S) target port")

    lab_exempt = _is_lab_exempt(
        hostname, port, allow_private_networks=allow_private_networks, lab_hosts=lab_hosts
    )

    resolved_ips = _resolve_all(hostname)

    if not lab_exempt:
        for raw_ip in resolved_ips:
            ip = ipaddress.ip_address(raw_ip)
            if _is_disallowed_ip(ip):
                raise SSRFValidationError(
                    f"Host {hostname!r} resolves to a non-public address ({raw_ip}); refusing"
                )

    return ValidatedTarget(
        hostname=hostname, port=port, scheme=parts.scheme.lower(), resolved_ips=resolved_ips
    )


def validate_redirect_hop(
    redirect_url: str,
    *,
    allow_private_networks: bool = False,
    lab_hosts: frozenset[str] = frozenset(),
) -> ValidatedTarget:
    """Re-runs full validation on a redirect target. A future engine MUST
    disable its HTTP client's automatic redirect-following and call this
    (capping total hops, e.g. 5) before issuing the next request --
    letting a client silently follow a redirect from a validated public
    URL to an internal one is the single most common way an SSRF guard
    like this one gets bypassed in practice."""
    return validate_outbound_url(
        redirect_url, allow_private_networks=allow_private_networks, lab_hosts=lab_hosts
    )
