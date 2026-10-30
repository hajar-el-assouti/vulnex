"""Entry-point discovery for the active web testing engine.

Builds the list every active check (XSS, SQLi, HTTP parameters, API)
tests against: GET query parameters, HTML form fields, API endpoints
found passively, and query parameters from a public OpenAPI/Swagger
spec. Each entry point records its source, URL, HTTP method and a
confidence level.

Reuses:
- `_SurfaceParser` from web_vuln/checks/injection_surface.py for
  forms and links;
- the endpoints already found by api_discovery_collector;
- `redact_secrets()` on every URL before it is logged or stored.

## Testable entry points

An entry point is testable only if:
- its method is GET (pinned_request.py only allows GET/HEAD/OPTIONS),
  and
- it has a parameter to change.

Forms using POST, PUT... are still listed (so the user sees the full
surface) but never tested, to avoid any non-idempotent action.

## OpenAPI limitation

Query parameters are only taken from paths without a `{...}` segment.
Testing `/products/{id}` would mean guessing an ID, which could hit a
real record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urljoin, urlsplit

from app.engines.recon.collectors._secrets import redact_secrets
from app.engines.recon.context import ReconExecutionContext
from app.engines.recon.schemas import CollectorResult
from app.engines.recon.security.request_policy import FetchedResponse

# Import order matters here. `app.engines.web_vuln.registry` MUST
# finish building its own CHECK_REGISTRY (which imports every check
# submodule, injection_surface included, for the first time) before
# this module imports `injection_surface` directly -- otherwise, if
# THIS import is the very first thing to ever touch injection_surface,
# Python inserts it into sys.modules and starts executing it; its own
# top-level `from app.engines.web_vuln.registry import ...` then
# imports registry.py for the first time, whose _build_registry() in
# turn re-imports injection_surface from sys.modules while it is still
# mid-initialization (SLUG/CATEGORY/run not yet defined on it), and the
# SecurityCheck Protocol isinstance check inside register_checks()
# fails. Importing `registry` first (a cheap, idempotent no-op once
# any other engine has already triggered it, which is normal in this
# app's own startup/scan-task import graph, but not guaranteed in an
# isolated unit test) makes this module's own import order correct on
# its own, rather than depending on something else importing web_vuln
# first by luck.
import app.engines.web_vuln.registry  # noqa: F401
from app.engines.web_vuln.checks.injection_surface import _SurfaceParser

_MAX_ENTRY_POINTS = 60


@dataclass(frozen=True)
class EntryPoint:
    source: str  # "url_query" | "form" | "link_query" | "api_discovery" | "openapi"
    url: str
    method: str  # upper-cased
    param_name: str | None
    confidence: str  # "low" | "medium" | "high"
    testable: bool


def _dedupe(entry_points: list[EntryPoint]) -> list[EntryPoint]:
    seen: set[tuple[str, str, str | None]] = set()
    out: list[EntryPoint] = []
    for ep in entry_points:
        key = (ep.url, ep.method, ep.param_name)
        if key in seen:
            continue
        seen.add(key)
        out.append(ep)
    return out


def _from_url_query(fetched: FetchedResponse) -> list[EntryPoint]:
    params = parse_qsl(urlsplit(fetched.final_url).query, keep_blank_values=True)
    return [
        EntryPoint(
            source="url_query",
            url=fetched.final_url,
            method="GET",
            param_name=name,
            confidence="high",
            testable=True,
        )
        for name, _ in params
    ]


def _from_html(fetched: FetchedResponse) -> list[EntryPoint]:
    body_text = fetched.body_bytes.decode("utf-8", errors="replace")
    parser = _SurfaceParser(fetched.final_url)
    try:
        parser.feed(body_text)
    except Exception:  # noqa: BLE001 -- malformed markup must never abort discovery
        pass

    entry_points: list[EntryPoint] = []
    for form in parser.forms:
        method = form["method"].upper()
        action = redact_secrets(form["action"])
        for field in form["inputs"]:
            entry_points.append(
                EntryPoint(
                    source="form",
                    url=action,
                    method=method,
                    param_name=field["name"],
                    confidence="high",
                    testable=(method == "GET"),
                )
            )
    for name in parser.link_params:
        entry_points.append(
            EntryPoint(
                source="link_query",
                url=fetched.final_url,
                method="GET",
                param_name=name,
                confidence="medium",
                testable=True,
            )
        )
    return entry_points


def _from_api_discovery(collector_results: dict[str, CollectorResult]) -> list[EntryPoint]:
    api_discovery_result = collector_results.get("api_discovery")
    if api_discovery_result is None:
        return []
    candidates: list[str] = []
    for obs in api_discovery_result.observations:
        if obs.key == "api_discovery.candidate_endpoints" and isinstance(obs.value, list):
            candidates = obs.value
    return [
        EntryPoint(source="api_discovery", url=endpoint, method="GET", param_name=None, confidence="low", testable=False)
        for endpoint in candidates
    ]


def _openapi_query_params(spec: dict) -> list[tuple[str, str]]:
    """Returns (path, param_name) pairs for every GET operation's
    query-string parameter on a path with no `{...}` template
    segment -- see module docstring for why templated paths are
    skipped entirely."""
    out: list[tuple[str, str]] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return out
    for path, operations in paths.items():
        if not isinstance(path, str) or "{" in path:
            continue
        if not isinstance(operations, dict):
            continue
        get_op = operations.get("get")
        if not isinstance(get_op, dict):
            continue
        for param in get_op.get("parameters", []) or []:
            if not isinstance(param, dict):
                continue
            if param.get("in") == "query" and isinstance(param.get("name"), str):
                out.append((path, param["name"]))
    return out


def discover_entry_points(
    *,
    ctx: ReconExecutionContext,
    fetched: FetchedResponse | None,
    collector_results: dict[str, CollectorResult],
    openapi_probe_paths: list[str],
    max_response_bytes: int,
) -> list[EntryPoint]:
    """Builds the full, deduplicated entry-point inventory. Never
    raises: a failure fetching/parsing any one source is swallowed and
    simply contributes nothing from that source, exactly like every
    collector in this platform's "never let one bad source take down
    the whole run" discipline."""
    from app.engines.active_web_testing.security.pinned_request import fetch_pinned_url

    entry_points: list[EntryPoint] = []

    if fetched is not None:
        entry_points.extend(_from_url_query(fetched))
        entry_points.extend(_from_html(fetched))

    entry_points.extend(_from_api_discovery(collector_results))

    if ctx.validated_target is not None:
        base = f"{ctx.validated_target.scheme}://{ctx.validated_target.hostname}"
        if ctx.validated_target.port:
            base += f":{ctx.validated_target.port}"
        for probe_path in openapi_probe_paths:
            try:
                probed = fetch_pinned_url(
                    ctx,
                    base + probe_path,
                    max_response_bytes=max_response_bytes,
                    where=f"active_web_testing.openapi_probe:{probe_path}",
                )
            except Exception:  # noqa: BLE001 -- see function docstring
                continue
            if probed.status_code != 200:
                continue
            try:
                spec = json.loads(probed.body_bytes.decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(spec, dict):
                continue
            for path, param_name in _openapi_query_params(spec):
                entry_points.append(
                    EntryPoint(
                        source="openapi",
                        url=urljoin(base + "/", path.lstrip("/")),
                        method="GET",
                        param_name=param_name,
                        confidence="medium",
                        testable=True,
                    )
                )

    return _dedupe(entry_points)[:_MAX_ENTRY_POINTS]
