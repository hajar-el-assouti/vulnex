/**
 * Reads the backend's double-submit CSRF cookie (app/core/config.py:
 * `csrf_cookie_name`, "csrf_token" by default) directly from
 * document.cookie. This is exactly what the backend's design expects:
 * the CSRF cookie is deliberately NOT HttpOnly for precisely this
 * reason (see app/api/v1/endpoints/auth.py `_set_session_cookies`) --
 * the whole point of the double-submit pattern is that client-side JS
 * reads the cookie and echoes it back in a header, which only
 * same-origin JS could do, defeating a cross-site forged request.
 *
 * Client-side only (document.cookie) -- never used from a Server
 * Component; see lib/api/server.ts for the server-side equivalent via
 * next/headers.
 */
const CSRF_COOKIE_NAME = "csrf_token";
export const CSRF_HEADER_NAME = "X-CSRF-Token";

export function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null;

  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${CSRF_COOKIE_NAME}=`));

  if (!match) return null;
  return decodeURIComponent(match.slice(CSRF_COOKIE_NAME.length + 1));
}
