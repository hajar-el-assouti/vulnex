"""Network-scan authorization, kept separate from app/security/ssrf.py.

Allowing HTTP on `192.168.56.102:3000` must never allow scanning other
ports on that host. So this module:
- has its own allowlist (Settings.advanced_recon_network_lab_allowlist),
  never Settings.ssrf_lab_allowlist;
- has its own private-network opt-in
  (Settings.advanced_recon_allow_private_network_scan), never
  Settings.ssrf_allow_private_networks;
- is checked for each (host, port) the port scanner tries, not once
  per host. Allowing port 3000 says nothing about 22, 80, 443, 8080
  or 8443; each must be listed.

_is_disallowed_ip below duplicates ssrf.py's check on purpose instead
of importing its private helper, so the two authorization rules can
change independently. It is only a few standard ipaddress properties
(private, loopback, link-local, multicast, reserved, unspecified).

Limits:
- DNS is resolved here once, and the collector connects to those IPs.
  This narrows the DNS rebinding window but doesn't remove it.
- This doesn't replace network or Docker isolation: a worker that
  already has access to an internal network is not made safe by an
  application-level check alone.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


class NetworkScanValidationError(ValueError):
    """Raised for any (host, port) pair this module refuses to let the
    port-scan collector connect to. Safe to log/surface in a result --
    never echoes back more than the rejected host and port."""


@dataclass(frozen=True)
class NetworkScanValidatedTarget:
    hostname: str
    port: int
    resolved_ips: tuple[str, ...]


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Intentionally duplicated from app/security/ssrf.py -- see this
    module's docstring for why."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (
            isinstance(ip, ipaddress.IPv6Address)
            and ip.ipv4_mapped is not None
            and _is_disallowed_ip(ip.ipv4_mapped)
        )
    )


def _resolve_all(hostname: str) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise NetworkScanValidationError(f"Could not resolve host: {hostname!r}") from exc
    ips = {info[4][0] for info in infos}
    if not ips:
        raise NetworkScanValidationError(f"Host resolved to no addresses: {hostname!r}")
    return tuple(sorted(ips))


def is_network_scan_lab_exempt(
    hostname: str, port: int, *, allow_private_network_scan: bool, network_lab_hosts: frozenset[str]
) -> bool:
    """Per (host, port) match against this module's OWN allowlist --
    never Settings.ssrf_lab_allowlist, and never a bare-host match (see
    module docstring). Both the flag AND the exact host:port entry are
    required, exactly like app/security/ssrf.py's own two-factor
    design for the HTTP case -- but these are two entirely separate
    pairs of switches."""
    if not allow_private_network_scan:
        return False
    normalized = {entry.lower() for entry in network_lab_hosts}
    return f"{hostname.lower()}:{port}" in normalized


def validate_network_scan_target(
    hostname: str,
    port: int,
    *,
    allow_private_network_scan: bool = False,
    network_lab_hosts: frozenset[str] = frozenset(),
) -> NetworkScanValidatedTarget:
    """Raises NetworkScanValidationError unless this exact (host, port)
    pair is safe to open a raw TCP connection to: resolves the hostname
    and requires every resolved address to be a public, non-reserved
    IP, UNLESS this exact "host:port" is in `network_lab_hosts` AND
    `allow_private_network_scan` is True (see
    is_network_scan_lab_exempt)."""
    resolved_ips = _resolve_all(hostname)

    if not is_network_scan_lab_exempt(
        hostname,
        port,
        allow_private_network_scan=allow_private_network_scan,
        network_lab_hosts=network_lab_hosts,
    ):
        for raw_ip in resolved_ips:
            ip = ipaddress.ip_address(raw_ip)
            if _is_disallowed_ip(ip):
                raise NetworkScanValidationError(
                    f"Host {hostname!r} resolves to a non-public address ({raw_ip}); "
                    f"refusing to open a network connection to port {port}"
                )

    return NetworkScanValidatedTarget(hostname=hostname, port=port, resolved_ips=resolved_ips)
