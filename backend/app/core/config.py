"""Application configuration.

Settings are loaded from environment variables (and an optional .env file).
See .env.example for the full list of supported variables.
"""

from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

from pydantic_settings import BaseSettings, SettingsConfigDict


def _with_redis_db(redis_url: str, db: int) -> str:
    """Swaps the path (database index) of a redis:// URL, keeping
    scheme/auth/host/port/query untouched. Used to derive the Celery
    broker/result-backend URLs from REDIS_URL without hand-building a
    new URL string and risking dropping a password or query param."""
    parts = urlsplit(redis_url)
    return urlunsplit((parts.scheme, parts.netloc, f"/{db}", parts.query, parts.fragment))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- General ---
    environment: str = "development"
    debug: bool = False
    project_name: str = "VULNEX"
    api_v1_prefix: str = "/api/v1"

    # --- Database ---
    # No defaults on purpose: nothing here is a guessable fallback
    # credential. These are Optional at the *settings* level only so that
    # importing the app (building routes, running non-DB tests) doesn't
    # itself require Postgres config -- but `database_url` below raises
    # loudly the moment anything actually tries to use it without either
    # a full postgres_user/password/db trio or an explicit override.
    postgres_user: str | None = None
    postgres_password: str | None = None
    postgres_db: str | None = None
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # Overrides the assembled URL above when set directly (e.g. in tests,
    # or to point at SQLite for a throwaway Alembic autogenerate run).
    database_url_override: str | None = None

    # --- CORS ---
    cors_origins: list[str] = ["http://localhost:3000"]

    # --- Auth / sessions ---
    # No default, same reasoning as the DB credentials: a guessable or
    # checked-in secret used for CSRF-token HMACs would defeat the point.
    # Generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))"
    secret_key: str | None = None

    session_cookie_name: str = "session_id"
    csrf_cookie_name: str = "csrf_token"
    csrf_header_name: str = "X-CSRF-Token"

    # Absolute session lifetime and idle timeout -- see sessions table /
    # app/services/auth.py docstrings for the full policy.
    session_ttl_hours: int = 12
    session_idle_timeout_minutes: int = 30

    # Login rate limiting (per email and per IP; see
    # app/core/rate_limit.py). Shared across replicas via Redis as of
    # this revision -- see "Redis / rate limiting" below.
    login_rate_limit_max_attempts: int = 5
    login_rate_limit_window_seconds: int = 15 * 60

    # Registration rate limiting (per IP only -- there's no "this email
    # already has a session" equivalent to reset against for register,
    # and the goal here is throttling mass-account-creation / probing,
    # not protecting one specific account).
    register_rate_limit_max_attempts: int = 10
    register_rate_limit_window_seconds: int = 60 * 60

    # --- Redis / rate limiting ---
    # No default, same reasoning as SECRET_KEY / the Postgres credentials:
    # nothing here is a guessable fallback. Optional at the settings
    # level so importing the app or running the SQLite-only unit suite
    # never requires Redis -- require_redis_url() raises loudly the
    # moment a rate-limited endpoint is actually hit without it.
    redis_url: str | None = None

    # Short on purpose: a rate-limit check runs on every login/register
    # request, so a slow/unreachable Redis must fail fast (see
    # rate_limit_fail_open below) rather than hang the request.
    redis_timeout_seconds: float = 0.3

    # Fail closed by default: if Redis is unreachable, login and
    # registration return 503 instead of allowing unlimited attempts.
    # Set to True to keep auth available during a Redis outage, at the
    # cost of no brute-force protection for that time.
    rate_limit_fail_open: bool = False

    # --- Reverse proxy trust (X-Forwarded-For) ---
    # SECURE DEFAULT: do not trust X-Forwarded-For at all. A client can
    # set any value for this header; trusting it blindly lets an
    # attacker spoof the IP used for rate limiting and session
    # ip_address logging, and dodge or frame another user's bucket at
    # will. Only flip this on, and only in combination with
    # trusted_proxies below, once a real reverse proxy that itself
    # sets/overwrites the header sits in front of this app.
    trust_x_forwarded_for: bool = False

    # CIDR ranges (JSON array, same style as CORS_ORIGINS) of the
    # reverse proxies allowed to be trusted for X-Forwarded-For. Only
    # the immediate TCP peer (what the ASGI server reports as the
    # connecting address) is checked against this list -- see
    # _client_ip() in app/api/v1/endpoints/auth.py for why that, and not
    # the header's own content, is what must be verified.
    trusted_proxies: list[str] = []

    # --- Celery / scan orchestration ----------------------------------
    # Uses a different Redis DB index than REDIS_URL, which holds the
    # rate limiter keys, so a FLUSHDB or key collision can't break both.
    # Defaults reuse redis_url with another DB index, and can be pointed
    # at a separate Redis instance.
    celery_broker_url_override: str | None = None
    celery_result_backend_url_override: str | None = None
    celery_broker_db: int = 1
    celery_result_backend_db: int = 2

    # A scan or module run is considered stuck after this many seconds
    # (worker crash, or a dispatch that never happened) and gets
    # reconciled. Kept short for development; size it to the real module
    # timeout in production.
    scan_dispatch_stuck_after_seconds: int = 30
    scan_cancellation_grace_seconds: int = 30
    scan_dispatch_max_attempts: int = 5

    # Hard ceiling on how long a single module run may execute before the
    # worker itself kills it (Celery soft/hard time limits) -- belt and
    # suspenders against a hung or misbehaving module, real or future.
    scan_module_run_timeout_seconds: int = 300

    # --- SSRF (app/security/ssrf.py) ------------------------------------
    # Empty by default: no host is exempt from the public-IP-only rule.
    # Only used together with allow_private_networks=True, for lab targets
    # on the same private network (e.g. OWASP Juice Shop at
    # "192.168.56.102:3000").
    #
    # Entries are "host:port", not a bare host, so only the lab target's
    # web port is exempt, not every port on that machine.
    ssrf_lab_allowlist: list[str] = []
    # False by default. Controls whether app/tasks/recon_module.py may
    # pass allow_private_networks=True to the recon engine. On its own it
    # does nothing: the host must also be listed in ssrf_lab_allowlist.
    # Set both only for a lab target like OWASP Juice Shop.
    ssrf_allow_private_networks: bool = False

    # --- Recon engine: stored result -----------------------------------
    # Max size of the JSONB result stored in ScanModuleRun.result. If a
    # result is bigger, the largest collector outputs are dropped and the
    # run is flagged storage_truncated (see app/engines/recon/persistence.py).
    recon_result_max_persisted_bytes: int = 200_000

    # --- Recon engine: live cancellation -------------------------------
    # How often the background poller in app/tasks/scan_tasks.py re-reads
    # the scan status while a module runs. Collectors only check an
    # in-memory flag, so this is the only DB cost. 1 second keeps it low
    # while cancellation still feels immediate.
    recon_cancellation_poll_interval_seconds: float = 1.0

    # --- Recon engine: execution budgets --------------------------------
    # Conservative limits: a lab scan against one target finishes in a few
    # seconds. The DNS/RDAP collectors have their own timeouts and network
    # policy (see app/engines/recon/security/request_policy.py).
    recon_total_timeout_seconds: float = 45.0
    recon_request_timeout_seconds: float = 8.0
    recon_max_requests: int = 20
    recon_max_redirects: int = 5
    # Primary page fetch and "other" target requests (robots.txt /
    # sitemap.xml / security.txt) are capped independently on purpose --
    # tightening one must never silently tighten the other.
    recon_max_response_bytes: int = 2_000_000
    recon_max_metadata_response_bytes: int = 512_000

    # --- Recon engine: DNS/RDAP/TLS ----------------------------------------
    # These collectors don't use request_policy.py: they query a fixed DNS
    # resolver, the already-validated target (TLS), or a short hardcoded
    # list of public services that is never built from user input (see
    # app/engines/recon/security/external_lookup_policy.py).
    #
    # Fixed public DNS resolvers, never derived from the target. Two
    # different providers so one being unreachable doesn't break every
    # DNS collector.
    recon_dns_resolvers: list[str] = ["1.1.1.1", "9.9.9.9"]
    recon_dns_timeout_seconds: float = 5.0
    recon_dns_max_queries: int = 20
    # RDAP bootstrap: a single, fixed, well-known host. rdap.org issues
    # the actual redirect to whichever registry/registrar RDAP server
    # holds the record for a given domain or IP -- that final host is
    # not known in advance, which is why the RDAP client (unlike
    # request_policy.py's target client) is allowed to follow a small,
    # capped number of redirects: every hop in that chain is still
    # RDAP-protocol public registry infrastructure, never the scan
    # target or anything scan-target-influenced.
    recon_rdap_base_url: str = "https://rdap.org"
    recon_rdap_timeout_seconds: float = 6.0
    recon_rdap_max_redirects: int = 4
    # RDAP responses are small, structured JSON -- unlike
    # request_policy.py's HTML handling, a response over this cap is a
    # hard ERROR (RdapResponseTooLargeError), never a silent truncate:
    # a JSON document cut off mid-stream is not parseable data, so
    # "partial JSON" is not a usable partial result the way a partial
    # HTML page is.
    recon_rdap_max_response_bytes: int = 262_144
    recon_tls_timeout_seconds: float = 6.0

    # --- Advanced recon: ports/services -----------------------------------
    # Explicit, limited port allowlist: no IP-range sweep and no full
    # 65535-port scan. Port 22 is left out by default; add it only when
    # it is explicitly in the authorized scope.
    advanced_recon_default_allowed_ports: list[int] = [80, 443, 8080, 8443]
    # Defense in depth, independent of how long the configured list
    # above is: even a misconfigured list can never turn this collector
    # into a de facto sweep. The collector itself also rejects any
    # caller-supplied list longer than this (see port_scan_collector.py).
    advanced_recon_max_ports_per_scan: int = 12
    # Short on purpose: a single TCP connect attempt per port.
    advanced_recon_port_connect_timeout_seconds: float = 2.0
    # "Concurrence contrôlée" -- a small, fixed worker pool, never
    # "as many sockets as there are ports".
    advanced_recon_port_scan_concurrency: int = 4
    # Passive/minimal-probe banner read: a short extra read on an
    # already-open socket, never a second connection and never any
    # authentication exchange.
    advanced_recon_banner_read_timeout_seconds: float = 2.0
    advanced_recon_banner_max_bytes: int = 256

    # host:port entries the port scanner may connect to on a private
    # network. Kept separate from ssrf_lab_allowlist on purpose: allowing
    # HTTP to "192.168.56.102:3000" must not also allow raw TCP connections
    # to other ports on that host. Each port must be listed explicitly
    # (see app/security/network_scan.py). Empty by default.
    advanced_recon_network_lab_allowlist: list[str] = []
    # Mirrors ssrf_allow_private_networks's own "two-factor opt-in"
    # design (see that field's docstring) but as an entirely separate
    # switch: flipping ssrf_allow_private_networks on for the HTTP
    # recon module does NOT, by itself, allow the port-scanner to touch
    # any private address -- this flag must also be explicitly set.
    advanced_recon_allow_private_network_scan: bool = False

    # --- Advanced recon: deep TLS ------------------------------------------
    # Separate from recon_tls_timeout_seconds because the deep TLS collector
    # does one handshake per TLS version, and each must stay short.
    advanced_recon_tls_probe_timeout_seconds: float = 4.0

    # --- Advanced recon: visual snapshot -----------------------------------
    # Experimental and off by default: browser isolation could not be
    # verified reliably on a 6 GB RAM VM. Only enable it after checking
    # the isolation on your own deployment.
    advanced_recon_visual_snapshot_enabled: bool = False

    # --- Web vulnerability assessment engine -------------------------------
    # Separate module ("web_vuln_assessment"). Reuses the recon budget and
    # cancellation classes from app/engines/recon/context.py, but has its
    # own budget settings so it never shares limits with a recon run.
    web_vuln_total_timeout_seconds: float = 45.0
    web_vuln_request_timeout_seconds: float = 8.0
    web_vuln_max_requests: int = 20
    web_vuln_max_redirects: int = 5
    web_vuln_max_response_bytes: int = 2_000_000
    web_vuln_result_max_persisted_bytes: int = 200_000

    # CORS check: one extra GET with a test Origin header. Counts against
    # web_vuln_max_requests like every other request.
    web_vuln_cors_probe_origin: str = "https://cors-probe.invalid.example"

    # HTTP methods check: sends a single OPTIONS request, the only method
    # guaranteed not to change server state. PUT/DELETE/PATCH are never
    # actually sent, since they could modify the target's data. The check
    # only reports what the server announces in its `Allow` header.
    web_vuln_http_methods_of_interest: list[str] = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]

    # Findings-per-check ceiling: a pathological target (e.g. hundreds of
    # cookies, each missing every flag) must never let one check flood
    # scan_findings with near-duplicate rows -- each check in
    # app/engines/web_vuln/checks/ enforces this on itself, reporting an
    # explicit note (never silently) when it stops short.
    web_vuln_max_findings_per_check: int = 25

    # API security check: a short list of common OpenAPI/Swagger paths,
    # fetched with GET to see if an API spec is publicly exposed. Not a
    # brute-force path list.
    web_vuln_openapi_probe_paths: list[str] = [
        "/openapi.json",
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/v2/api-docs",
    ]

    # --- Active web testing engine ---------------------------------------
    # Separate module ("active_web_testing"). Unlike the other engines it
    # sends test payloads (XSS marker, SQLi probes). They are never
    # destructive, but this is no longer passive, so the module is behind
    # five independent gates, all checked before any request is sent
    # (see app/tasks/active_web_testing_module.py):
    #
    #   1. The seeded ScanModule row has is_enabled=False: an operator must
    #      enable it in the database first.
    #   2. active_web_testing_enabled below: a deployment-level kill switch,
    #      re-checked at run time.
    #   3. ScanCreateRequest.active_testing_confirmed: the user must confirm
    #      active testing for each scan (enforced in services/scans.py).
    #   4. active_web_testing_lab_allowlist below: its own host:port
    #      allowlist, never shared with the recon or port-scan allowlists.
    #   5. SSRF validation and IP pinning on every request
    #      (app/engines/active_web_testing/security/pinned_request.py).
    #      The passive engines validate the resolved IP but httpx resolves
    #      the hostname again when connecting, which leaves a small DNS
    #      rebinding window. That is acceptable for passive reads, not for
    #      sending payloads, so this engine connects to the exact IP that
    #      was validated.
    #
    # False by default. Enabling it alone does nothing: gates 1 and 4 must
    # also be set.
    active_web_testing_enabled: bool = False
    # Empty by default -- host:port strings, e.g. ["192.168.56.102:3000"].
    # Deliberately NOT ssrf_lab_allowlist and NOT
    # advanced_recon_network_lab_allowlist -- see the gate #4 note above.
    active_web_testing_lab_allowlist: list[str] = []

    active_web_testing_total_timeout_seconds: float = 60.0
    active_web_testing_request_timeout_seconds: float = 8.0
    # Overall budget for the whole module run, across every collector.
    active_web_testing_max_requests: int = 40
    # Per entry point cap, separate from the overall budget, so a target
    # with many entry points still only gets a few test requests on each
    # one. Set to 10 to fit the SQLi check's worst case (9 requests).
    # Enforced by app/engines/active_web_testing/registry.py::EndpointRequestTracker.
    active_web_testing_max_requests_per_endpoint: int = 10
    # Limited concurrency: 1, strictly sequential. IP pinning no longer
    # depends on it (pinning is request-scoped, see pinned_request.py), but
    # sequential requests are gentler on the target and keep per-endpoint
    # budgets simple.
    active_web_testing_max_concurrency: int = 1
    active_web_testing_max_redirects: int = 5
    active_web_testing_max_response_bytes: int = 2_000_000
    active_web_testing_result_max_persisted_bytes: int = 200_000

    # Reflected XSS check: the marker is a unique, harmless string with
    # HTML metacharacters around it. Never a real <script> tag, never an
    # event handler, never an out-of-band callback. There is no browser:
    # detection only checks whether the marker comes back in the response,
    # and whether it is HTML-escaped. A unique suffix per request avoids
    # confusing it with another test or with existing page content.
    active_web_testing_xss_marker_prefix: str = "xsstestmarker"

    # SQLi check: minimal, non-destructive probes only. A quote
    # (error-based) and a boolean true/false pair, compared against an
    # untouched baseline request. No UNION, no time-based payloads
    # (SLEEP/WAITFOR), no stacked queries, nothing that writes.
    active_web_testing_sqli_error_probe: str = "'"
    active_web_testing_sqli_boolean_true_probe: str = "' OR '1'='1"
    active_web_testing_sqli_boolean_false_probe: str = "' OR '1'='2"
    # A short, well-known set of substrings that a target's own error
    # page tends to include verbatim when a SQL driver raises -- matched
    # case-insensitively against the (already size-capped) response body.
    # Not exhaustive by design: a false negative here just means "no
    # finding", never a crash; a true positive is still only ever
    # reported at LOW/MEDIUM confidence, never CONFIRMED, without a
    # second, independent differential signal agreeing with it (see
    # app/engines/active_web_testing/checks/sqli_differential.py).
    active_web_testing_sql_error_signatures: list[str] = [
        "sql syntax",
        "mysql_fetch",
        "you have an error in your sql syntax",
        "ora-01756",
        "ora-00933",
        "sqlite3::",
        "sqlite3.operationalerror",
        "pg_query",
        "unterminated quoted string",
        "unclosed quotation mark",
        "sqlstate",
        "odbc sql server driver",
        "npgsql.",
        "psycopg2.",
    ]

    # Findings-per-check ceiling, mirroring web_vuln_max_findings_per_check.
    active_web_testing_max_findings_per_check: int = 15

    # --- SQLi check: syntax probe ---------------------------------------
    # Every probe is still a single read-only GET (catalog in
    # app/engines/active_web_testing/checks/sqli_payloads.py).
    #
    # A bare semicolon, sent in addition to the quote: a badly built query
    # may fail differently on an unexpected statement separator than on a
    # stray quote, so testing both catches more cases.
    active_web_testing_sqli_syntax_probe: str = ";"
    # A syntax anomaly (status change or length change beyond the measured
    # noise) is recorded as an Observation, but never produces a Finding on
    # its own: an HTTP 500 alone does not prove SQL injection.
    #
    # Reproducibility: when round 1 finds a candidate signal, the probe is
    # re-sent to confirm it. This is lazy, so a clean endpoint still costs
    # 6 requests (2 baseline + 1 error + 1 syntax + 2 boolean); a
    # suspicious one costs up to 3 more.
    active_web_testing_sqli_require_error_reproduction: bool = True
    active_web_testing_sqli_require_boolean_reproduction: bool = True
    # Worst case per endpoint is 9 requests (2 baseline + 1 error +
    # 1 syntax + 2 boolean + 1 error confirm + 2 boolean confirm), which is
    # why active_web_testing_max_requests_per_endpoint is 10.
    #
    # Substrings that mean the response is a WAF block page rather than the
    # application. Only checked on the baseline: if the baseline is already
    # a block page, every probe would hit it too, so SQLi analysis is
    # skipped and an Observation is recorded.
    active_web_testing_sqli_waf_signatures: list[str] = [
        "access denied",
        "request blocked",
        "406 not acceptable",
        "mod_security",
        "modsecurity",
        "web application firewall",
        "incapsula",
        "cloudflare",
        "akamai",
        "blocked by",
    ]
    # Maps part of a matched SQL error signature to the database engine it
    # usually comes from. Only adds information to the finding's evidence;
    # it never changes whether a finding is created.
    active_web_testing_sql_error_engine_hints: dict[str, str] = {
        "mysql_fetch": "MySQL/MariaDB",
        "you have an error in your sql syntax": "MySQL/MariaDB",
        "ora-01756": "Oracle",
        "ora-00933": "Oracle",
        "sqlite3::": "SQLite",
        "sqlite3.operationalerror": "SQLite",
        "pg_query": "PostgreSQL",
        "unterminated quoted string": "PostgreSQL",
        "npgsql.": "PostgreSQL (.NET driver)",
        "psycopg2.": "PostgreSQL (Python driver)",
        "odbc sql server driver": "Microsoft SQL Server",
        "unclosed quotation mark": "Microsoft SQL Server",
    }

    # --- Discovery & fuzzing engine ---------------------------------------
    # Path discovery with a SecLists-based wordlist
    # (app/engines/discovery_fuzzing/wordlists/common.txt). It only sends
    # GET requests, but it requests paths the user never named and shows up
    # in the target's logs, so it is treated as active testing and gets the
    # same five gates as active_web_testing, independently:
    #   1. Seeded ScanModule row with is_enabled=False.
    #   2. discovery_fuzzing_enabled below, re-checked at run time by
    #      app/tasks/discovery_fuzzing_module.py. Enabling one active module
    #      never enables the other.
    #   3. active_testing_confirmed on the scan (the module has
    #      requires_active_confirmation=True).
    #   4. discovery_fuzzing_lab_allowlist below: its own host:port list,
    #      never shared with the other allowlists.
    #   5. SSRF validation and IP pinning on every request, reusing
    #      active_web_testing/security/pinned_request.py.
    discovery_fuzzing_enabled: bool = False
    # Empty by default -- host:port strings, e.g. ["192.168.56.102:3000"].
    discovery_fuzzing_lab_allowlist: list[str] = []

    # Three modes, each a maximum number of wordlist entries to test.
    # Always the first N entries of the cleaned, deterministically ordered
    # wordlist (app/engines/discovery_fuzzing/wordlist.py), so the same mode
    # always tests the same paths in the same order. Quick is a prefix of
    # Standard, which is a prefix of Deep.
    discovery_fuzzing_quick_max_paths: int = 50
    # Prepared but not selectable yet: only "quick" is accepted for now
    # (see app/tasks/discovery_fuzzing_module.py).
    discovery_fuzzing_standard_max_paths: int = 300
    discovery_fuzzing_deep_max_paths: int = 1000

    # Budget sized for Quick (50 paths) plus a few soft-404 baseline
    # probes (app/engines/discovery_fuzzing/baseline.py) and some headroom.
    # Standard/Deep will need a larger budget once they are enabled.
    discovery_fuzzing_total_timeout_seconds: float = 90.0
    discovery_fuzzing_request_timeout_seconds: float = 6.0
    discovery_fuzzing_max_requests: int = 60
    # "Concurrence limitée" -- sequential, exactly like
    # active_web_testing_max_concurrency, for the same reason (gentler
    # on a lab target, trivial per-request budget accounting). No
    # concurrency primitive exists in this engine; this setting
    # documents the deliberate choice rather than controlling anything
    # yet.
    discovery_fuzzing_max_concurrency: int = 1
    # Never chases a redirect at all (pinned_request.fetch_pinned_url's
    # new follow_redirects=False path) -- a discovered path's own 3xx
    # status and Location header are the observation; this module never
    # issues the second request that "suivre la redirection" would
    # require, so there is no destination left to "vérifier" and no
    # window for a redirect-to-localhost (or anywhere else) to ever
    # reach this module's own transport. Kept here only for parity with
    # every other engine's settings shape; not actually consulted by
    # this module's own request path.
    discovery_fuzzing_max_redirects: int = 0
    discovery_fuzzing_max_response_bytes: int = 200_000
    discovery_fuzzing_result_max_persisted_bytes: int = 200_000
    # Soft-404 baseline: how many deterministic, scan-unique,
    # guaranteed-nonexistent paths are probed BEFORE any real wordlist
    # entry, to detect a target that answers 200 for everything (see
    # app/engines/discovery_fuzzing/baseline.py). 2 independent probes,
    # not 1, so a target that happens to 200 on one specific accidental
    # collision is not mistaken for "always 200".
    discovery_fuzzing_soft_404_probe_count: int = 2
    # A later 200 response is classified as "likely_soft_404" (never
    # "accessible") when its body length is within this many bytes of
    # the baseline probes' own (already-capped) body length -- never an
    # exact-byte-count requirement, since many soft-404 pages include a
    # dynamic element (a timestamp, a request id) that varies slightly
    # run to run while still being, substantively, the same page.
    discovery_fuzzing_soft_404_body_length_tolerance: int = 32

    # --- Report generation ------------------------------------------------
    # Directory where generated PDF/HTML reports are stored.
    # Report.storage_path is relative to it, never an absolute path a
    # client could influence. Not served as static files: reports are only
    # downloaded through GET /reports/{id}/download, which checks
    # ownership. Point it at a persistent, backed-up volume in production.
    report_storage_dir: str = "data/reports"

    @property
    def celery_broker_url(self) -> str:
        if self.celery_broker_url_override:
            return self.celery_broker_url_override
        return _with_redis_db(self.require_redis_url(), self.celery_broker_db)

    @property
    def celery_result_backend_url(self) -> str:
        if self.celery_result_backend_url_override:
            return self.celery_result_backend_url_override
        return _with_redis_db(self.require_redis_url(), self.celery_result_backend_db)

    @property
    def cookie_secure(self) -> bool:
        """Secure flag for session/CSRF cookies. False only in explicit
        local development, so a plain-HTTP dev server still works; any
        other environment name defaults to secure-by-default."""
        return self.environment != "development"

    def require_secret_key(self) -> str:
        if not self.secret_key:
            raise RuntimeError(
                "SECRET_KEY is not configured (see .env.example). Refusing to "
                "sign CSRF tokens with a default/empty key."
            )
        return self.secret_key

    def require_redis_url(self) -> str:
        if not self.redis_url:
            raise RuntimeError(
                "REDIS_URL is not configured (see .env.example). Login/"
                "registration rate limiting requires Redis as of this "
                "revision -- it is no longer in-process memory."
            )
        return self.redis_url

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            return self.database_url_override
        if not (self.postgres_user and self.postgres_password and self.postgres_db):
            raise RuntimeError(
                "Database is not configured: set POSTGRES_USER, POSTGRES_PASSWORD "
                "and POSTGRES_DB (see .env.example), or DATABASE_URL_OVERRIDE. "
                "Refusing to fall back to a default credential."
            )
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
