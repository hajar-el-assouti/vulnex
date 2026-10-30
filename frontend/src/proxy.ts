import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Adds security headers to every response, including a nonce-based
 * Content-Security-Policy, following the documented Next.js pattern:
 * the middleware creates a nonce per request and puts it in the CSP
 * header, and the App Router scripts (and next-themes' theme script,
 * see src/app/layout.tsx) use it. So `script-src` never needs
 * 'unsafe-inline'.
 *
 * `'unsafe-eval'` is only added when NODE_ENV !== "production": the dev
 * server's hot reload uses eval(). A production build never gets it.
 *
 * No Strict-Transport-Security header here: the lab runs over plain
 * HTTP, where HSTS would lock users out. HSTS belongs on the HTTPS
 * reverse proxy in front of a real deployment.
 */
export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV !== "production";

  const scriptSrc = isDev
    ? `'self' 'nonce-${nonce}' 'unsafe-eval'`
    : `'self' 'nonce-${nonce}'`;

  const csp = [
    `default-src 'self'`,
    `script-src ${scriptSrc}`,
    // Tailwind compiles to an external stylesheet (covered by style-src
    // 'self'). 'unsafe-inline' is kept for now because Radix UI sets
    // inline `style` attributes for popover/tooltip positioning. Nonces
    // only cover <style> elements, not style attributes, so there is no
    // narrower option without hashing every dynamic style.
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `form-action 'self'`,
    `base-uri 'self'`,
    // Clickjacking protection: no page here should be framed, not even
    // by the same origin.
    `frame-ancestors 'none'`,
    `object-src 'none'`,
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");

  return response;
}

export const config = {
  // Every route except static assets and Next's own internals -- those
  // are served with their own immutable caching and don't need (and
  // for _next/static, shouldn't have middleware overhead added to) a
  // per-request CSP nonce.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
