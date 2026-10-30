"""Network policy for the active web testing engine.

Stricter than app/engines/recon/security/request_policy.py, and kept
separate from it.

## Why a separate policy

request_policy.py validates the resolved IP right before connecting
(app/security/ssrf.py::validate_outbound_url()), but httpx then
resolves the hostname again when it opens the TCP connection. That
leaves a small DNS rebinding window. It is accepted for the passive
engines, which only read public information.

It is not acceptable when sending test payloads: an attacker who
controls the target's DNS could pass validation with a public IP and
then point the real connection to an internal host. Here, the client
connects to the exact IP that was validated.

## How pinning works

No monkeypatching and no shared state, everything is per request:

1. The validated IP is written into the request URL
   (`_build_pinned_url()`), so there is no hostname left to resolve.
2. The `Host` header is set to the original hostname, so virtual
   hosting on the target still works.
3. TLS SNI and certificate validation use the original hostname,
   through httpcore's `sni_hostname` request extension.

Since nothing is shared between requests, threads or workers,
parallel tasks can't interfere with each other.

## Limits

- Redirects are never followed automatically: each hop is validated
  and pinned separately.
- Only GET, HEAD and OPTIONS are allowed (enforced by an assertion).
- An attacker who wins the race against our own DNS lookup is still
  possible in theory, but there is no longer a second, unchecked
  resolution done later by httpx.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.engines.recon.context import ReconExecutionContext
from app.security.ssrf import SSRFValidationError, ValidatedTarget, validate_outbound_url, validate_redirect_hop

DEFAULT_USER_AGENT = "PentestSaaS-ActiveWebTestingEngine/1.0 (+authorized-lab-scan; active-testing-confirmed)"

# GET/HEAD plus OPTIONS -- OPTIONS is the one HTTP-spec-guaranteed-safe
# method (it must never change server state), the exact same exception
# app/engines/web_vuln/checks/http_methods.py already relies on for its
# own "announced methods" check. No other method is ever permitted.
_ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Test-only seam, exactly like request_policy.py's own -- a unit test
# installs an httpx.MockTransport here so no test in this engine's
# suite ever makes a real network call or a real DNS lookup.
_TEST_TRANSPORT: httpx.BaseTransport | None = None


def _set_test_transport(transport: httpx.BaseTransport | None) -> None:
    global _TEST_TRANSPORT
    _TEST_TRANSPORT = transport


class ResponseTooLargeError(RuntimeError):
    pass


class TooManyRedirectsError(RuntimeError):
    pass


@dataclass(frozen=True)
class FetchedResponse:
    final_url: str
    status_code: int
    headers: httpx.Headers
    url_chain: list[str]
    body_bytes: bytes
    body_truncated: bool
    elapsed_ms: int


def _build_pinned_url(url: str, pinned_ip: str) -> str:
    """Returns `url` with its authority's host replaced by the literal
    pinned IP address -- scheme, port, path, query and fragment all
    unchanged. This is the entire pinning mechanism (see module
    docstring): httpcore dials whatever host appears in the request
    URL, so putting the validated IP there directly means there is no
    hostname left for any resolver, global or otherwise, to answer for
    this connection.

    An IPv6 literal gets RFC 3986 §3.2.2 bracket syntax
    (`[2001:db8::1]`), since a bare `:` in a netloc would otherwise be
    parsed as a port separator."""
    parts = urlsplit(url)
    host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    if parts.username:
        # Never expected in this engine's own URLs, but preserved
        # rather than silently dropped if it ever occurs.
        userinfo = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _client(timeout_seconds: float) -> httpx.Client:
    return httpx.Client(
        trust_env=False,
        follow_redirects=False,
        timeout=timeout_seconds,
        verify=True,
        headers={"User-Agent": DEFAULT_USER_AGENT},
        transport=_TEST_TRANSPORT,
    )


def _read_capped(response: httpx.Response, *, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    for chunk in response.iter_bytes():
        if total + len(chunk) > max_bytes:
            chunks.append(chunk[: max_bytes - total])
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), truncated


def fetch_pinned_url(
    ctx: ReconExecutionContext,
    url: str,
    *,
    max_response_bytes: int,
    where: str,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
) -> FetchedResponse:
    """The only function the active testing engine may use to reach a
    target.

    Same budget, cancellation, size cap and per-hop redirect validation
    as request_policy.py::fetch_target_url(), but every connection
    (first request and each redirect hop) is pinned to the IP that
    hop's SSRF validation approved. Each hop builds its own pinned URL
    and client.

    `method` must be "GET", "HEAD" or "OPTIONS". This is enforced here
    so no check can ever send a state-changing request, even by
    mistake. Anything else raises AssertionError.

    `follow_redirects` defaults to True. When False, a redirect response
    is returned as-is from the first hop and the Location header is
    never followed. This sends fewer requests, never an unvalidated
    one. Used by discovery_fuzzing, which only needs the status code
    and Location header."""
    assert method.upper() in _ALLOWED_METHODS, (
        f"active_web_testing may only ever send GET/HEAD/OPTIONS, never {method!r} -- "
        "this is a structural guarantee against non-idempotent requests, not a caller choice"
    )

    budget = ctx.budget
    url_chain: list[str] = []
    current = url

    for hop in range(budget.max_redirects + 1):
        ctx.raise_if_cancelled(where=f"{where} (hop {hop})")
        budget.register_request(where=f"{where} (hop {hop})")

        if hop == 0:
            validated: ValidatedTarget = validate_outbound_url(
                current,
                allow_private_networks=ctx.allow_private_networks,
                lab_hosts=ctx.lab_hosts,
            )
        else:
            validated = validate_redirect_hop(
                current,
                allow_private_networks=ctx.allow_private_networks,
                lab_hosts=ctx.lab_hosts,
            )
        url_chain.append(current)

        # Pin to the FIRST resolved IP, deterministically -- a target
        # with multiple A/AAAA records still gets exactly one, stable
        # destination for this request, rather than this module
        # (or httpx) picking a potentially different one than what was
        # just validated.
        pinned_ip = validated.resolved_ips[0]
        pinned_url = _build_pinned_url(current, pinned_ip)

        # Host header + SNI explicitly set to the ORIGINAL hostname --
        # see module docstring points 2/3. extra_headers is never
        # allowed to supply its own Host; this module's own pin always
        # wins, so a caller can't accidentally (or a future bug can't
        # silently) defeat the pin by also setting Host.
        headers = {**(extra_headers or {}), "Host": validated.hostname}

        timeout = budget.per_request_timeout()
        request_started = time.monotonic()
        with _client(timeout) as client:
            request = client.build_request(
                method,
                pinned_url,
                headers=headers,
                extensions={"sni_hostname": validated.hostname},
            )
            response = client.send(request, stream=True)
            try:
                if response.is_redirect:
                    if not follow_redirects:
                        body, truncated = _read_capped(response, max_bytes=max_response_bytes)
                        elapsed_ms = int((time.monotonic() - request_started) * 1000)
                        return FetchedResponse(
                            final_url=current,
                            status_code=response.status_code,
                            headers=response.headers,
                            url_chain=url_chain,
                            body_bytes=body,
                            body_truncated=truncated,
                            elapsed_ms=elapsed_ms,
                        )
                    location = response.headers.get("location")
                    response.close()
                    if not location:
                        raise SSRFValidationError("Redirect response without a Location header")
                    current = urljoin(current, location)
                    continue

                body, truncated = _read_capped(response, max_bytes=max_response_bytes)
                elapsed_ms = int((time.monotonic() - request_started) * 1000)
                return FetchedResponse(
                    final_url=current,
                    status_code=response.status_code,
                    headers=response.headers,
                    url_chain=url_chain,
                    body_bytes=body,
                    body_truncated=truncated,
                    elapsed_ms=elapsed_ms,
                )
            finally:
                response.close()

    raise TooManyRedirectsError(f"Exceeded {budget.max_redirects} redirects while fetching {url!r}")


def split_query_params(url: str) -> dict[str, str]:
    """Small helper shared by this engine's checks: the first value of
    each query-string parameter on `url`, decoded. Kept here (not
    duplicated per-check) since every active check needs the same
    parse. Deliberately uses urllib's own parser, never a hand-rolled
    split, to avoid a subtly wrong edge case (encoded '&'/'=', repeated
    keys) silently mis-identifying a parameter."""
    from urllib.parse import parse_qsl

    query = urlsplit(url).query
    pairs = parse_qsl(query, keep_blank_values=True)
    out: dict[str, str] = {}
    for key, value in pairs:
        if key not in out:
            out[key] = value
    return out


def set_query_param(url: str, key: str, value: str) -> str:
    """Returns `url` with query parameter `key` set to `value` (added if
    absent, replaced if present), every other parameter and the path
    left untouched. Used by every active check to build its test
    requests from a baseline URL."""
    from urllib.parse import parse_qsl, urlencode, urlunsplit

    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    new_pairs = []
    for existing_key, existing_value in pairs:
        if existing_key == key:
            new_pairs.append((key, value))
            replaced = True
        else:
            new_pairs.append((existing_key, existing_value))
    if not replaced:
        new_pairs.append((key, value))
    new_query = urlencode(new_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
