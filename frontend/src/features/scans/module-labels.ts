/**
 * Display labels for scan module slugs, shared between the
 * scan-creation module picker (new-scan-form.tsx) and the scan detail
 * view's module table (scan-detail-view.tsx), so the two never drift
 * apart. Falls back to the raw slug for a module not listed here (a
 * future module seeded but not yet given a friendly label).
 */
export const MODULE_LABELS: Record<string, string> = {
  recon: "Recon (reconnaissance web)",
  diagnostic: "Diagnostic (auto-test d'orchestration)",
  // Separate module, selectable on its own.
  advanced_recon: "Recon avancée (ports, TLS approfondi, WAF/CDN)",
  // Independent of "recon" and "advanced_recon".
  web_vuln_assessment: "Analyse de vulnérabilités web",
  // Sends active test requests to the target. Disabled by default on
  // the server and requires an explicit per-scan confirmation in
  // new-scan-form.tsx.
  active_web_testing: "Tests actifs de vulnérabilités (XSS, SQLi, API)",
  // Also active (sends GET requests for paths the user didn't name).
  // Disabled by default on the server and requires the same per-scan
  // confirmation as active_web_testing.
  discovery_fuzzing: "Découverte de chemins et fichiers (Quick Scan)",
};

export const MODULE_DESCRIPTIONS: Record<string, string> = {
  recon:
    "Reconnaissance web passive : HTTP, en-têtes, cookies, technologies, métadonnées, DNS, " +
    "sécurité email, infrastructure IP/ASN, RDAP, TLS, ressources externes et découverte d'API.",
  diagnostic:
    "Auto-test interne de l'orchestration (aucune requête réseau, aucun résultat de sécurité).",
  advanced_recon:
    "Vérification d'une liste explicite et limitée de ports autorisés, analyse TLS approfondie " +
    "et détection passive de WAF/CDN. Aucun balayage, aucune authentification, aucune " +
    "exploitation. Portée réseau strictement séparée de l'autorisation HTTP.",
  web_vuln_assessment:
    "Analyse passive et non destructive : en-têtes de sécurité, cookies, CORS, configuration " +
    "TLS/HTTPS, méthodes HTTP annoncées, divulgation d'informations, surface XSS/SQLi passive " +
    "et contrôles de sécurité API. Aucune exploitation, aucun payload offensif, aucune " +
    "modification des données de la cible.",
  active_web_testing:
    "Envoie de vraies requêtes de test (marqueurs XSS inoffensifs, sondes SQLi différentielles " +
    "non destructives, paramètres HTTP inattendus, vérifications actives d'API) à la cible " +
    "autorisée. Aucune opération destructive, aucune extraction de données, aucun contournement " +
    "d'authentification. Un résultat n'est jamais présenté comme une vulnérabilité confirmée " +
    "automatiquement. Nécessite votre confirmation explicite ci-dessous.",
  discovery_fuzzing:
    "Teste jusqu'à 50 chemins (Quick Scan) d'une liste de mots issue de SecLists (licence MIT) " +
    "contre la cible, en GET uniquement, sans jamais suivre de redirection. Détecte les cas où " +
    "le serveur répond toujours 200 (faux positifs \"soft 404\"). Un chemin découvert n'est " +
    "jamais enregistré automatiquement comme une vulnérabilité -- par exemple, /admin répondant " +
    "403 est une observation technique, pas une preuve d'accès non autorisé. Nécessite votre " +
    "confirmation explicite ci-dessous.",
};
