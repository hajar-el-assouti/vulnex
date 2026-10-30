import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */

  // DEV-MODE ONLY (next start / production has no such check at all --
  // see README "Dépannage: interface non interactive via IP LAN").
  // Next.js blocks cross-origin requests to dev-only assets and endpoints
  // (the HMR WebSocket, Server Actions, the dev overlay) unless the
  // request's Origin/Referer hostname is localhost, a localhost
  // subdomain, or the hostname `next dev` itself was started with. A
  // browser reaching the dev server through a different hostname --
  // such as a LAN IP, which is exactly how this app is accessed in this
  // project's deployment (see README "Environnement de développement sur
  // IP LAN") -- gets refused, and that refusal on the HMR socket surfaces
  // in Chrome as "ERR_INVALID_HTTP_RESPONSE" / "WebSocket connection
  // failed": the handshake's HTTP upgrade response is Next's dev-origin
  // guard rejecting it, not a malformed server. This is Next's own
  // documented, sanctioned way to allowlist a known dev origin --
  // listing the exact host here is not disabling the protection, it is
  // correctly configuring it for a host that is expected to reach this
  // dev server (see allowedDevOrigins in
  // node_modules/next/dist/docs/01-app/03-api-reference/05-config/01-next-config-js/allowedDevOrigins.md).
  // Only the Origin header's hostname is matched (no scheme, no port),
  // so the frontend VM's bare IP is listed once, covering every port.
  allowedDevOrigins: ["192.168.56.102"],

  // Cache Components (and the Partial Prefetching it enables) require every
  // route that reads the session to be split behind <Suspense> boundaries
  // using `use cache: private`. This app is a session-gated SaaS dashboard:
  // virtually every route (both the (auth) and (dashboard) layouts) reads
  // the session cookie, so there is no meaningful static shell to prerender
  // here. Adopting that pattern app-wide would add real complexity for no
  // practical benefit, so standard dynamic rendering is used instead.
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
