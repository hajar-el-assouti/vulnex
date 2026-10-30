/**
 * BFF proxy: the browser only talks to this Next.js origin. This route
 * forwards everything under /api/v1/* to the FastAPI backend
 * server-to-server and relays cookies both ways.
 *
 * Why: the backend's session cookie is `SameSite=Lax`. A fetch() from
 * http://localhost:3000 to http://localhost:8001 is cross-site, and Lax
 * cookies aren't sent on cross-site fetch/POST requests. Login would
 * seem to work, but every following request would be unauthenticated.
 * Going through this same-origin proxy means the browser only sees
 * first-party cookies. FastAPI is still the only place that issues
 * sessions, checks passwords and checks CSRF; this file only relays
 * bytes and headers.
 */
import { NextRequest, NextResponse } from "next/server";

// Server-only: no NEXT_PUBLIC_ prefix, so it never ends up in client
// JavaScript. Defaults to local development, where FastAPI runs with
// `uvicorn ... --port 8001` (see .env.example). Docker Compose maps the
// backend to host port 8000 instead; set BACKEND_INTERNAL_URL when
// running that way.
const BACKEND_URL = process.env.BACKEND_INTERNAL_URL ?? "http://localhost:8001";

// Headers that must NOT be forwarded as-is in either direction: Host/
// Connection are connection-specific (forwarding the browser's Host to
// FastAPI would be wrong), and content-length is recomputed by fetch
// itself from the actual body.
const REQUEST_HEADERS_TO_DROP = new Set(["host", "connection", "content-length"]);
const RESPONSE_HEADERS_TO_DROP = new Set([
  "content-encoding", // the body we re-send is already decoded
  "content-length",
  "connection",
  "transfer-encoding",
]);

/**
 * Client-address and forwarding headers. Next.js's App Router gives route
 * handlers no API to read the raw TCP peer address (`NextRequest.ip` was
 * removed in Next 15 -- see the "Version History" note on the NextRequest
 * doc), so there is no way for this proxy to independently verify that an
 * incoming `X-Forwarded-For` / `X-Real-IP` / `Forwarded` header actually
 * came from something trustworthy rather than from whoever is holding the
 * TCP connection. Any of the three is fully attacker-controlled on a
 * request that reaches this route directly (a raw HTTP client, not
 * necessarily a browser).
 *
 * The backend mirrors this exact concern on its own side
 * (`_client_ip()` in app/api/v1/endpoints/auth.py / `trust_x_forwarded_for`
 * + `trusted_proxies` in app/core/config.py): it only trusts
 * X-Forwarded-For when the immediate TCP peer connecting to it is itself
 * a configured trusted proxy. In this architecture that immediate peer is
 * always *this* Next.js server, so FastAPI's trust setting is really a
 * decision about whether to trust what this file forwards. Forwarding an
 * unverified, client-supplied value here -- as the previous revision did
 * unconditionally -- defeats that protection entirely: an attacker could
 * set a fresh X-Forwarded-For on every request straight to this route and
 * dodge the backend's per-IP rate limiting (and forge the `ip_address`
 * recorded on sessions) if an operator had also flipped on
 * trust_x_forwarded_for/trusted_proxies for this server's address,
 * reasonably expecting "my own BFF" to behave like a well-behaved reverse
 * proxy that only ever reports what it actually observed.
 *
 * Secure default (TRUST_UPSTREAM_PROXY_HEADERS unset/false, matching the
 * backend's own default-closed posture): never forward any of these --
 * strip them unconditionally. FastAPI then falls back to the TCP peer it
 * actually sees (this Next.js server's own address) for every request;
 * rate limiting becomes coarser (shared across all visitors behind this
 * BFF) rather than wrong, which is the safe failure mode.
 *
 * Opt-in (TRUST_UPSTREAM_PROXY_HEADERS=true): set this ONLY when this
 * Next.js instance itself sits behind a real reverse proxy / load
 * balancer that is not reachable by anyone except through that proxy,
 * and that proxy itself sets/overwrites (not merely appends to) these
 * headers from its own observed connection before anything reaches this
 * app -- the same precondition the backend's own `trusted_proxies`
 * assumes about its immediate peer. With that precondition true, the
 * value arriving here is trustworthy and passed through unmodified;
 * FastAPI's TRUSTED_PROXIES must then include this frontend server's own
 * address (not the original reverse proxy's), since this server is
 * FastAPI's immediate peer. Flipping this on WITHOUT such a proxy in
 * front of this app re-opens the exact spoofing hole described above.
 */
const CLIENT_ADDRESS_HEADERS = new Set(["x-forwarded-for", "x-real-ip", "forwarded"]);

// No legitimate use for these reaches the backend in this architecture
// (nothing here or in FastAPI reads them) -- dropped unconditionally,
// regardless of TRUST_UPSTREAM_PROXY_HEADERS, as opposed to the three
// address headers above which the trust flag can opt back in.
const RESERVED_FORWARDING_HEADERS = new Set([
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
]);

const TRUST_UPSTREAM_PROXY_HEADERS = process.env.TRUST_UPSTREAM_PROXY_HEADERS === "true";

/**
 * Pure and exported so the security-sensitive stripping rules above can
 * be unit-tested directly (see
 * src/app/api/v1/[...path]/forwarded-headers.test.ts) without spinning up
 * a full Next.js request/response cycle.
 */
export function buildForwardedRequestHeaders(
  incoming: Headers,
  options: { trustUpstreamProxyHeaders: boolean } = {
    trustUpstreamProxyHeaders: TRUST_UPSTREAM_PROXY_HEADERS,
  },
): Headers {
  const headers = new Headers();
  for (const [key, value] of incoming.entries()) {
    const lower = key.toLowerCase();
    if (REQUEST_HEADERS_TO_DROP.has(lower)) continue;
    if (RESERVED_FORWARDING_HEADERS.has(lower)) continue;
    if (CLIENT_ADDRESS_HEADERS.has(lower) && !options.trustUpstreamProxyHeaders) continue;
    headers.set(key, value);
  }
  return headers;
}

async function proxy(request: NextRequest, path: string[]): Promise<NextResponse> {
  const targetUrl = new URL(`/api/v1/${path.join("/")}`, BACKEND_URL);
  targetUrl.search = request.nextUrl.search;

  const headers = buildForwardedRequestHeaders(request.headers);

  const hasBody = !["GET", "HEAD"].includes(request.method);

  const backendResponse = await fetch(targetUrl, {
    method: request.method,
    headers,
    body: hasBody ? await request.arrayBuffer() : undefined,
    redirect: "manual",
    cache: "no-store",
  });

  const responseHeaders = new Headers();
  for (const [key, value] of backendResponse.headers.entries()) {
    if (!RESPONSE_HEADERS_TO_DROP.has(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  }

  // `Headers.get("set-cookie")` would merge multiple Set-Cookie headers
  // into one invalid comma-joined string -- the backend sets TWO
  // (session_id and csrf_token) on login. getSetCookie() (Node/undici,
  // available here) returns them as a proper array, and NextResponse
  // supports appending each one individually.
  responseHeaders.delete("set-cookie");
  const body = await backendResponse.arrayBuffer();
  const response = new NextResponse(body, {
    status: backendResponse.status,
    headers: responseHeaders,
  });
  for (const cookie of backendResponse.headers.getSetCookie()) {
    response.headers.append("set-cookie", cookie);
  }

  return response;
}

type RouteParams = { params: Promise<{ path: string[] }> };

async function handler(request: NextRequest, { params }: RouteParams) {
  const { path } = await params;
  return proxy(request, path);
}

export {
  handler as GET,
  handler as POST,
  handler as PUT,
  handler as PATCH,
  handler as DELETE,
};
