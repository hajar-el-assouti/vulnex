import { ApiError } from "@/types/api";

/**
 * Turns an ApiError into a message the user can act on. Handles 401,
 * 403, 409, 422, 429 and 503, plus a generic fallback. Never claims a
 * more specific cause than what the backend returned.
 */
export function getApiErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return "Une erreur réseau est survenue. Vérifiez votre connexion et réessayez.";
  }

  switch (error.status) {
    case 401:
      return error.body?.detail ?? "Email ou mot de passe incorrect.";
    case 403: {
      // The backend's double-submit CSRF guard (app/api/deps.py
      // ::require_csrf) always sends the same literal detail, in
      // English, on a CSRF failure -- translate that one case, but
      // pass through any other 403 detail verbatim (e.g. "This target
      // is not authorized for scanning" from POST /scans), rather than
      // mislabeling every 403 as a CSRF problem.
      if (!error.body?.detail || error.body.detail === "CSRF validation failed") {
        return "Action refusée (jeton de sécurité invalide). Rechargez la page et réessayez.";
      }
      return error.body.detail;
    }
    case 409:
      return error.body?.detail ?? "Cet email est déjà utilisé.";
    case 422: {
      if (error.body && "errors" in error.body && error.body.errors?.length) {
        return error.body.errors.map((e) => e.msg).join(" ");
      }
      return "Certaines informations saisies ne sont pas valides.";
    }
    case 429: {
      const retry = error.retryAfterSeconds;
      return retry
        ? `Trop de tentatives. Réessayez dans ${retry} seconde${retry > 1 ? "s" : ""}.`
        : "Trop de tentatives. Réessayez plus tard.";
    }
    case 503:
      return "Le service est temporairement indisponible. Réessayez dans quelques instants.";
    default:
      return error.body?.detail ?? "Une erreur est survenue. Réessayez.";
  }
}
