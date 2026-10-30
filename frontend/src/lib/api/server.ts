/**
 * Server-side auth check, for Server Components only (the protected
 * route group's layout). Calls FastAPI directly rather than bouncing
 * through this app's own /api/v1 proxy route -- we're already on the
 * server, so there is no SameSite/CORS concern to work around here,
 * only the need to forward the incoming request's session cookie by
 * hand (a server-side fetch has no cookie jar of its own).
 */
import { cache } from "react";
import { cookies } from "next/headers";

import type { UserPublic } from "@/types/api";

// See the matching constant in src/app/api/v1/[...path]/route.ts for why
// 8001 (local non-Docker dev convention) is the fallback here too.
const BACKEND_URL = process.env.BACKEND_INTERNAL_URL ?? "http://localhost:8001";

/**
 * Returns the authenticated user, or `null` if there is no valid
 * session (401) -- the only outcome page/layout guards are expected to
 * act on by redirecting to /login. Any other failure (503 from a Redis
 * outage, a network error reaching the backend) is thrown, not
 * swallowed into `null`, so a real outage surfaces as an error rather
 * than looking identical to "not logged in".
 *
 * Wrapped in React's `cache()` so a layout and the page it renders
 * both calling this in the same request only hit the backend once.
 */
export const getCurrentUser = cache(async (): Promise<UserPublic | null> => {
  const cookieStore = await cookies();
  const cookieHeader = cookieStore
    .getAll()
    .map((c) => `${c.name}=${c.value}`)
    .join("; ");

  const response = await fetch(`${BACKEND_URL}/api/v1/auth/me`, {
    headers: cookieHeader ? { cookie: cookieHeader } : undefined,
    cache: "no-store",
  });

  if (response.status === 401) {
    return null;
  }

  if (!response.ok) {
    throw new Error(`GET /api/v1/auth/me failed with status ${response.status}`);
  }

  return (await response.json()) as UserPublic;
});
