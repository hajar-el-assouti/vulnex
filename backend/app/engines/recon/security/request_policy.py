"""Network policy for recon collectors reaching a scan target.

The only place a recon collector may create an HTTP client or follow a
redirect to a target. The DNS/RDAP collectors use a separate policy
(external_lookup_policy.py) and must never use this one.

What it does against SSRF and DNS rebinding, and what it doesn't:

- `trust_env=False` on every httpx client: proxy environment variables
  are ignored, so they can't redirect scan traffic.
- `follow_redirects=False`: every redirect hop is validated by our own
  loop through app/security/ssrf.py, not by httpx.
- Every request, including each redirect hop, is validated right
  before connecting, not once at the start of the scan.
- This is not IP pinning, and it doesn't fully prevent DNS rebinding:
  httpx resolves the hostname again a few milliseconds after our
  check, so an attacker controlling the target's DNS could in theory
  win that race. Accepted for these passive, read-only collectors.
  The active testing engine uses real IP pinning
  (active_web_testing/security/pinned_request.py).
- Bodies are read in chunks (`iter_bytes`) and the stream is closed as
  soon as the size limit is reached, so a target can't exhaust memory.
- The main page and the metadata files (robots.txt, sitemap.xml,
  security.txt) use separate size limits passed by the caller.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from app.engines.recon.context import ReconExecutionContext
from app.security.ssrf import SSRFValidationError, validate_outbound_url, validate_redirect_hop

DEFAULT_USER_AGENT = "PentestSaaS-ReconEngine/1.0 (+authorized-lab-scan)"

# Test-only seam: a unit test installs an httpx.MockTransport here so no
# collector test ever makes a real network call. None in production
# means "let httpx build its real transport" -- this must never be set
# outside tests. See tests/engines/recon/conftest.py.
_TEST_TRANSPORT: httpx.BaseTransport | None = None


def _set_test_transport(transport: httpx.BaseTransport | None) -> None:
    global _TEST_TRANSPORT
    _TEST_TRANSPORT = transport


class ResponseTooLargeError(RuntimeError):
    """Raised when a target response exceeds the configured size cap --
    caught by the calling collector, never propagated as a crash."""


class TooManyRedirectsError(RuntimeError):
    """Raised once budget.max_redirects hops have all been followed
    without reaching a non-redirect response."""


@dataclass(frozen=True)
class FetchedResponse:
    """What fetch_target_url() hands back: the final response plus the
    full, re-validated redirect chain that got there. `body_truncated`
    says whether the configured size cap was hit -- the calling
    collector must treat a truncated body as partial evidence, never as
    the complete page."""

    final_url: str
    status_code: int
    headers: httpx.Headers
    url_chain: list[str]
    body_bytes: bytes
    body_truncated: bool
    elapsed_ms: int


def _client(timeout_seconds: float) -> httpx.Client:
    # verify=True is never disabled, even for a lab target. A bad
    # certificate is something the TLS collector reports, not a reason
    # to skip verification here.
    return httpx.Client(
        trust_env=False,
        follow_redirects=False,
        timeout=timeout_seconds,
        verify=True,
        headers={"User-Agent": DEFAULT_USER_AGENT},
        transport=_TEST_TRANSPORT,
    )


def _read_capped(response: httpx.Response, *, max_bytes: int) -> tuple[bytes, bool]:
    """Streams the body in chunks, stopping (without raising) the
    moment max_bytes would be exceeded. Returns (body_bytes_up_to_the_
    cap, was_truncated)."""
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


def fetch_target_url(
    ctx: ReconExecutionContext,
    url: str,
    *,
    max_response_bytes: int,
    where: str,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
) -> FetchedResponse:
    """The only function a recon collector may use to reach a target.

    Validates `url` and every redirect hop with app/security/ssrf.py
    right before connecting, enforces the shared scan budget (deadline
    and request count), and caps the body at `max_response_bytes`.

    Raises SSRFValidationError, ResponseTooLargeError (not raised
    today, _read_capped truncates instead), TooManyRedirectsError,
    httpx.HTTPError or ReconBudgetExceededError. Collectors handle
    these through collectors/base.py::run_collector_safely.

    `method`/`extra_headers` are used by the web_vuln CORS check (GET
    with a test `Origin` header) and HTTP methods check (OPTIONS).
    Other callers use the default GET."""
    budget = ctx.budget
    url_chain: list[str] = []
    current = url

    for hop in range(budget.max_redirects + 1):
        # Live cancellation checkpoint, alongside (never instead of) the
        # budget check below -- see ReconExecutionContext.raise_if_cancelled's
        # own docstring. Checked before every hop, not just the first, so
        # a cancellation requested mid-redirect-chain stops this fetch
        # immediately rather than waiting for the chain to resolve.
        ctx.raise_if_cancelled(where=f"{where} (hop {hop})")
        budget.register_request(where=f"{where} (hop {hop})")

        # Re-validate THIS hop right now, not once at the top of the
        # scan -- see module docstring for exactly what this does and
        # does not close off.
        if hop == 0:
            validate_outbound_url(
                current,
                allow_private_networks=ctx.allow_private_networks,
                lab_hosts=ctx.lab_hosts,
            )
        else:
            validate_redirect_hop(
                current,
                allow_private_networks=ctx.allow_private_networks,
                lab_hosts=ctx.lab_hosts,
            )
        url_chain.append(current)

        timeout = budget.per_request_timeout()
        request_started = time.monotonic()
        with _client(timeout) as client:
            request = client.build_request(method, current, headers=extra_headers)
            response = client.send(request, stream=True)
            try:
                if response.is_redirect:
                    location = response.headers.get("location")
                    response.close()
                    if not location:
                        raise SSRFValidationError("Redirect response without a Location header")
                    current = urljoin(current, location)
                    continue

                body, truncated = _read_capped(response, max_bytes=max_response_bytes)
                # Measured manually (time.monotonic() around the full
                # send-and-read), not via httpx's own Response.elapsed --
                # that attribute is only reliably populated once a
                # streamed response has been fully read AND closed in
                # every httpx version this project might run on, so
                # relying on it here would be fragile.
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
