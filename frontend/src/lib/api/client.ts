/**
 * Client-side API wrapper. Every call is a same-origin request to this
 * Next.js app's own /api/v1/* route, which the BFF proxy
 * (src/app/api/v1/[...path]/route.ts) forwards to FastAPI. Components
 * never construct a cross-origin URL to the backend themselves -- see
 * that file's docstring for why (SameSite=Lax cookies).
 */
import { ApiError, type ApiErrorBody } from "@/types/api";
import { CSRF_HEADER_NAME, readCsrfCookie } from "@/lib/api/csrf";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export interface ApiFetchOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
}

/**
 * Calls `/api/v1${path}` and returns the parsed JSON body as `T` on a
 * 2xx response, or throws `ApiError` (status + the backend's own error
 * body) otherwise. Does not assume the response shape -- callers decide
 * what `T` is per endpoint, matching the hand-written types in
 * types/api.ts rather than anything inferred.
 */
export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers = new Headers();

  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }

  if (MUTATING_METHODS.has(method)) {
    const csrfToken = readCsrfCookie();
    if (csrfToken) {
      headers.set(CSRF_HEADER_NAME, csrfToken);
    }
  }

  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    signal: options.signal,
  });

  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? await response.json().catch(() => null)
    : null;

  if (!response.ok) {
    const retryAfterHeader = response.headers.get("retry-after");
    throw new ApiError(
      response.status,
      payload as ApiErrorBody | null,
      retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : null,
    );
  }

  return payload as T;
}
