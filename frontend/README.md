# VULNEX — Frontend

Next.js (App Router) dashboard for VULNEX. Authentication, sessions and
CSRF protection are handled by the FastAPI backend: this app never
duplicates that logic and never stores a token of its own.

## Stack

- Next.js 16 (App Router, Turbopack), React 19, TypeScript (strict)
- Tailwind CSS v4, shadcn/ui-style components built on Radix UI, Lucide icons
- next-themes (dark/light), Geist Sans/Mono
- react-hook-form + Zod for client-side validation
- Vitest + React Testing Library

## Architecture: a same-origin BFF

The backend issues `SameSite=Lax` session cookies (`session_id`,
HttpOnly) and a readable CSRF cookie (`csrf_token`). A cross-origin
`fetch` from `localhost:3000` to `localhost:8001` can't carry them
reliably. Instead of relaxing the cookie policy or switching to JWTs,
every `/api/v1/*` call goes through a Route Handler
(`src/app/api/v1/[...path]/route.ts`), so the browser only talks to its
own origin:

```
Browser --same-origin--> Next.js BFF route --forwards--> FastAPI backend
```

- CSRF uses the double-submit pattern expected by the backend: the
  `csrf_token` cookie is read in `src/lib/api/csrf.ts` and sent in the
  `X-CSRF-Token` header on every mutating request (`src/lib/api/client.ts`).
- Server Components that need the current user (layout auth guards,
  Settings page) call the backend directly with `cookies()` from
  `next/headers` (`src/lib/api/server.ts`), deduplicated per request with
  React's `cache()`.
- The BFF route only forwards method, body and headers (including each
  `Set-Cookie` separately, via `Headers.getSetCookie()`). No business
  logic, authorization or session handling lives here.
- Client-supplied address headers are not blindly relayed (see below).

## Getting started

```bash
npm install
cp .env.example .env.local   # BACKEND_INTERNAL_URL, defaults to http://localhost:8001
npm run dev                  # http://localhost:3000
```

The backend must be running at that URL, with Postgres and Redis up and
migrations applied (`alembic upgrade head`). There is no mock backend.
For local (non-Docker) development, run it on port 8001:

```bash
cd ../backend && source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

With Docker Compose (`backend/docker-compose.yml`), the backend is on
host port 8000: set `BACKEND_INTERNAL_URL=http://localhost:8000` in
`.env.local`.

## X-Forwarded-For handling

Next.js route handlers can't read the real TCP peer address, so the BFF
can't tell a genuine `X-Forwarded-For` from a forged one. The backend
only trusts this header when the connecting peer is a configured
trusted proxy, and here that peer is always this Next.js server. Blindly
forwarding the header would let a client spoof its IP and bypass the
backend's IP-based rate limiting.

Controlled by `TRUST_UPSTREAM_PROXY_HEADERS` (`.env.example`):

- **Default (false):** `X-Forwarded-For`, `X-Real-IP` and `Forwarded`
  are never forwarded. The backend sees this server's address for every
  request, so rate limiting is coarser but never wrong.
  `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Forwarded-Port` are
  always stripped.
- **`true`:** only when this app runs behind its own reverse proxy that
  sets these headers itself and is the only way in. The backend's
  `TRUSTED_PROXIES` must then include this server's address.

## Troubleshooting: UI not interactive when opened through a LAN IP

In development mode, Next.js blocks cross-origin requests to its dev
endpoints (HMR WebSocket, dev overlay) unless the host is `localhost` or
the host `next dev` was started with. Opening the dev server through
`http://192.168.56.102:3001` made the HMR WebSocket fail
(`ERR_INVALID_HTTP_RESPONSE`), and the page never became interactive.

- `next.config.ts` declares `allowedDevOrigins: ["192.168.56.102"]`, the
  official way to allow a development host.
- The login and register forms use `method="post"`, so if hydration ever
  fails, a native submit never puts the password in the URL.

For long-running remote access, use production mode instead:

```bash
npm run build
npm run start -- -p 3001
```

## Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Dev server with Turbopack |
| `npm run build` | Production build |
| `npm run start` | Serve the production build |
| `npm run lint` | ESLint |
| `npm run typecheck` | `tsc --noEmit` (strict) |
| `npm run test` | Unit/component tests (Vitest) |
| `npm run test:watch` | Same, in watch mode |

## Project structure

```
src/
  app/                   App Router routes; (auth) and (dashboard) groups,
                         each with its own server-side auth guard layout
  components/            ui/ (primitives), layout/ (shell, nav, topbar),
                         dashboard/ (cards, badges, empty states)
  features/auth/         Login/register forms, Zod schemas, API calls
  features/targets/      Target create/authorize forms and list
  features/scans/        New scan form, scan list/detail, module results,
                         findings views, rerun
  features/findings/     Global findings page
  features/dashboard/    Dashboard stats
  features/scan-profiles/ Saved scan profiles
  lib/api/               Browser client, server-side caller, CSRF helper,
                         error messages
  lib/hooks/             Client hooks (theme, sidebar, scan status polling)
  types/api.ts           Hand-written types mirroring the backend schemas
```

## Security

- The session stays in an HttpOnly cookie; this app never reads it or
  stores anything in `localStorage`.
- CSRF uses the double-submit header expected by the backend (logout is
  rejected with `403` without it).
- Every page under `(dashboard)` is protected server-side by a layout
  that redirects unauthenticated users to `/login` before rendering.
- `BACKEND_INTERNAL_URL` is server-only (no `NEXT_PUBLIC_` prefix).
- A nonce-based Content-Security-Policy and other security headers are
  set in `src/proxy.ts`.
- Data coming from scanned targets (evidence, reflected values) is always
  rendered as plain text, never as HTML.

## Known items

- `npm audit` reports high-severity advisories in a dev-only chain
  (`eslint-config-next` → `fast-glob`/`micromatch`/`braces`, a ReDoS in
  `braces`). It is lint tooling only and doesn't ship to production.
  `npm audit fix --force` would downgrade `eslint-config-next` to a
  version incompatible with Next 16, so it wasn't applied.
- The `components/ui/*` files were written by hand from the Radix UI
  primitives instead of being generated by the shadcn/ui CLI.
