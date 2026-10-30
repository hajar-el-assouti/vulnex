"""Network policy for the DNS, email security and RDAP collectors.
Kept separate from request_policy.py on purpose.

request_policy.py is the only way to reach the scan target, which is
attacker-influenced (it controls its redirects, headers and body). The
collectors here never contact the target; they only talk to a short,
fixed list of public services:

- DNS: resolvers from Settings.recon_dns_resolvers (1.1.1.1 / 9.9.9.9
  by default, configurable). The domain name comes from the target,
  but the resolver is fixed configuration. Lab-internal or reserved
  names (see collectors/_domain_utils.py) are never sent to them, to
  avoid leaking internal names to a third party.
- RDAP: a single fixed bootstrap host (Settings.recon_rdap_base_url,
  https://rdap.org by default). The domain/IP only goes into a
  percent-encoded path segment, never into a hostname. The bootstrap
  host redirects to the registry's RDAP server, which we can't know in
  advance, so rdap_get() validates every hop: https only, no forbidden
  ports, and the resolved IPs must be public. A spoofed RDAP response
  can't be used to reach the internal network.

  Same caveat as request_policy.py: the IP is checked at validation
  time and httpx resolves again when connecting. There is no IP
  pinning here, so the window is narrowed, not removed.

Nothing built from the target's response data (HTML, headers) is ever
used as a URL or host here.

This module doesn't use app/security/ssrf.py: its private-IP check is
implemented separately so the two policies never share a single point
of failure."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver
import httpx

from app.core.config import get_settings

# Module-level test-only seams, mirroring request_policy.py's pattern --
# used exclusively by tests/engines/recon/conftest.py. Never touched by
# any production code path.
_TEST_HTTP_TRANSPORT: httpx.BaseTransport | None = None
_TEST_RESOLVER: "dns.resolver.Resolver | None" = None


def _set_test_http_transport(transport: httpx.BaseTransport | None) -> None:
    global _TEST_HTTP_TRANSPORT
    _TEST_HTTP_TRANSPORT = transport


def _set_test_resolver(resolver: "dns.resolver.Resolver | None") -> None:
    global _TEST_RESOLVER
    _TEST_RESOLVER = resolver


class ExternalLookupError(RuntimeError):
    """Base for every failure talking to the fixed DNS/RDAP
    infrastructure (timeout, SERVFAIL, malformed RDAP response, a
    rejected redirect destination, ...). Collectors catch this (and its
    subclasses) and turn it into a well-formed ERROR observation -- it
    never escapes to crash a whole scan."""


class RdapDestinationRejectedError(ExternalLookupError):
    """A specific RDAP hop (the initial bootstrap request or one of its
    redirects) failed validation: non-https scheme, a forbidden port, or
    an address that is not publicly routable. Distinct from a generic
    network failure -- this is a policy decision, not a connectivity
    problem."""


class RdapResponseTooLargeError(ExternalLookupError):
    """The RDAP response body exceeded Settings.recon_rdap_max_response_
    bytes. Raised immediately once the cap is crossed while streaming --
    never buffered first and checked after, and never truncated-and-
    returned the way request_policy.py handles an oversized HTML body:
    a JSON document cut off mid-stream cannot be parsed at all, so
    there is no meaningful "partial" RDAP result to salvage."""


class TooManyRdapRedirectsError(ExternalLookupError):
    """RDAP's redirect chain exceeded Settings.recon_rdap_max_redirects
    without reaching a final, non-redirect response."""


# Ports that are never a legitimate RDAP (HTTPS) endpoint -- the same
# category of defense-in-depth as app/security/ssrf.py's own
# _SUSPICIOUS_PORTS, deliberately reimplemented here rather than
# imported, so the two policies stay independent.
_FORBIDDEN_RDAP_PORTS = frozenset({22, 23, 25, 587, 465, 3306, 5432, 6379, 11211, 2375, 2376})

_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Independently reimplemented from app/security/ssrf.py's
    identically-named check -- same category of address (private,
    loopback, link-local -- which is what a cloud metadata endpoint
    like 169.254.169.254 is, multicast, reserved, unspecified, and
    IPv4-mapped IPv6 unwrapped before re-checking), but kept as a
    separate implementation on purpose: this module's job is "is this a
    legitimate public RDAP server", not "is this safe to scan as a
    target", and those two checks must never be allowed to silently
    become the same code path."""
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


def _validate_rdap_destination(url: str) -> None:
    """Re-run before every single RDAP hop (see module docstring) --
    raises RdapDestinationRejectedError rather than returning a bool, so
    a caller can never accidentally forget to check a return value."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise RdapDestinationRejectedError(f"RDAP destination must use https, got {parts.scheme!r}")

    hostname = parts.hostname
    if not hostname:
        raise RdapDestinationRejectedError("RDAP destination URL has no hostname")

    port = parts.port or 443
    if port in _FORBIDDEN_RDAP_PORTS:
        raise RdapDestinationRejectedError(f"RDAP destination port {port} is not permitted")

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise RdapDestinationRejectedError(f"Could not resolve RDAP destination host: {hostname!r}") from exc

    resolved_ips = {info[4][0] for info in infos}
    if not resolved_ips:
        raise RdapDestinationRejectedError(f"RDAP destination host resolved to no addresses: {hostname!r}")

    for raw_ip in resolved_ips:
        ip = ipaddress.ip_address(raw_ip)
        if _is_disallowed_ip(ip):
            raise RdapDestinationRejectedError(
                f"RDAP destination {hostname!r} resolves to a non-public address ({raw_ip}); refusing"
            )


@dataclass(frozen=True)
class RdapResponse:
    """The final (non-redirect) response from an rdap_get() call: just
    enough to let a collector decide OK/absence/error without ever
    touching httpx's own Response object (which would otherwise make it
    easy to accidentally call .json()/.content again after the stream
    that produced it has already been consumed)."""

    status_code: int
    headers: dict[str, str]
    body_bytes: bytes


def rdap_get(url: str, *, budget, is_cancelled=lambda: False) -> RdapResponse:
    """GETs `url`, manually following up to Settings.recon_rdap_max_
    redirects redirects -- never httpx's own automatic
    follow_redirects, precisely so every hop can be validated first (see
    module docstring). Every hop also respects the shared global
    deadline (`budget.ensure_not_expired`) and uses a per-hop timeout
    clamped to whatever time is actually left
    (`budget.timeout_for(...)`), exactly like request_policy.py does for
    the scan target. The response body is read via streaming with a
    hard size cap (Settings.recon_rdap_max_response_bytes) that raises
    RdapResponseTooLargeError the moment it is crossed, rather than
    buffering an unbounded body first.

    `is_cancelled`, when supplied by the caller (rdap_collector.py /
    ip_asn_collector.py pass `ctx.is_cancelled`), is checked before
    every hop alongside the budget check -- raising
    app.engines.recon.context.ReconCancelledError, deliberately NOT one
    of this module's own ExternalLookupError subclasses, so a collector
    that catches ExternalLookupError around this call does not
    accidentally swallow a cancellation the same way it would swallow a
    real RDAP failure (see collectors/base.py::run_collector_safely,
    which re-raises ReconCancelledError instead of converting it to a
    CollectorStatus.ERROR)."""
    from app.engines.recon.context import ReconCancelledError  # local import: avoids a cycle (context.py does not import this module)

    settings = get_settings()
    current = url

    for _hop in range(settings.recon_rdap_max_redirects + 1):
        if is_cancelled():
            raise ReconCancelledError("RDAP lookup cancelled")
        budget.ensure_not_expired(where="rdap")
        _validate_rdap_destination(current)
        timeout = budget.timeout_for(settings.recon_rdap_timeout_seconds)

        with httpx.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
            verify=True,
            headers={"User-Agent": "vulnex-recon/1.0 (+lab use only)"},
            transport=_TEST_HTTP_TRANSPORT,
        ) as client:
            with client.stream("GET", current) as response:
                if response.status_code in _REDIRECT_STATUS_CODES:
                    location = response.headers.get("location")
                    if not location:
                        raise RdapDestinationRejectedError("RDAP redirect response had no Location header")
                    current = urljoin(current, location)
                    continue

                chunks: list[bytes] = []
                total = 0
                max_bytes = settings.recon_rdap_max_response_bytes
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise RdapResponseTooLargeError(
                            f"RDAP response from {current!r} exceeded {max_bytes} bytes"
                        )
                    chunks.append(chunk)

                return RdapResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body_bytes=b"".join(chunks),
                )

    raise TooManyRdapRedirectsError(f"RDAP request exceeded {settings.recon_rdap_max_redirects} redirects")


def build_dns_resolver() -> "dns.resolver.Resolver":
    """A dnspython Resolver pinned to Settings.recon_dns_resolvers --
    NEVER the system/container's own /etc/resolv.conf, so this
    collector's behavior doesn't depend on (or leak through) whatever
    DNS the deployment happens to have configured for itself. The
    resolver list is ordinary Settings configuration: 1.1.1.1 / 9.9.9.9
    are only the shipped DEFAULT for environments where reaching them is
    allowed -- a deployment overrides Settings.recon_dns_resolvers to
    whatever resolver(s) its own egress policy permits."""
    if _TEST_RESOLVER is not None:
        return _TEST_RESOLVER
    settings = get_settings()
    if not settings.recon_dns_resolvers:
        raise ExternalLookupError("Settings.recon_dns_resolvers is empty -- no DNS resolver configured")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(settings.recon_dns_resolvers)
    resolver.timeout = settings.recon_dns_timeout_seconds
    resolver.lifetime = settings.recon_dns_timeout_seconds
    return resolver


@dataclass(frozen=True)
class DnsQueryResult:
    """Uniform shape for a single record-type query: either records were
    found, the name genuinely has none of this type (NXDOMAIN/NoAnswer --
    a real, meaningful absence), or the lookup itself failed (timeout,
    SERVFAIL, malformed response -- an ERROR, never confused with a real
    absence). `ttl_seconds` is captured from the SAME answer that
    produced `values` -- callers never need a second query just to read
    the TTL."""

    record_type: str
    found: bool
    values: tuple[str, ...]
    ttl_seconds: int | None = None
    error: str | None = None


def query_dns(
    resolver: "dns.resolver.Resolver",
    name: str,
    record_type: str,
    *,
    lifetime: float | None = None,
) -> DnsQueryResult:
    """One query, one record type, never raises -- every outcome
    (records found / genuinely absent / lookup failed, including a
    connectivity failure to every configured resolver) is encoded in the
    returned DnsQueryResult so callers can distinguish absence from
    error without their own try/except around dnspython's exception
    hierarchy.

    `lifetime`, when given, overrides the resolver's own configured
    timeout for just this call -- used by callers to clamp every
    individual query to whatever is left on the shared global deadline
    (ReconBudget.timeout_for), since the resolver object itself is built
    once per collector run while the deadline keeps shrinking across
    several queries."""
    try:
        kwargs = {"lifetime": lifetime} if lifetime is not None else {}
        answer = resolver.resolve(name, record_type, **kwargs)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # A genuine, confirmed absence: the name exists (or doesn't) and
        # authoritatively has no record of this type. This is an
        # OBSERVED absence, never an error.
        return DnsQueryResult(record_type=record_type, found=False, values=())
    except dns.exception.DNSException as exc:
        # Timeout, SERVFAIL, malformed response, every configured
        # resolver unreachable, etc. -- the lookup itself did not
        # complete, so this says NOTHING about whether the record
        # exists. Must never be reported as if it were an absence.
        return DnsQueryResult(record_type=record_type, found=False, values=(), error=f"{exc.__class__.__name__}: {exc}")

    values = tuple(str(item).strip('"') for item in answer)
    ttl = int(answer.rrset.ttl) if answer.rrset is not None else None
    return DnsQueryResult(record_type=record_type, found=True, values=values, ttl_seconds=ttl)
