"""Check registry for the web vulnerability assessment engine.

A check receives everything collected in this run (`CheckInputs`) and
returns a `CollectorResult` (observations) plus zero or more
`Finding`s.

No dynamic plugin loading: `CHECK_REGISTRY` is an explicit, ordered
tuple. Adding a check is a one-line change, reviewed like any other
code, and nothing unlisted ever runs.

A check that needs its own request (CORS, HTTP methods) must go
through request_policy.py::fetch_target_url(), to get SSRF validation,
redirect handling, the size limit and the shared budget. Never raw
httpx/requests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from app.engines.recon.context import ReconExecutionContext
from app.engines.recon.schemas import CollectorResult
from app.engines.web_vuln.findings import Finding

if TYPE_CHECKING:
    from app.core.config import Settings
    from app.engines.recon.security.request_policy import FetchedResponse


@dataclass(frozen=True)
class CheckInputs:
    """Everything a check may read. `collector_results` holds whatever
    this engine's own run_checks() already collected before dispatching
    checks (http/headers/cookies/tls today -- see engine.py), keyed by
    the SAME collector slugs app/engines/recon/collectors/ uses, so a
    check reading `collector_results["headers"]` gets the identical
    shape Recon's own headers_collector produces. A check must never
    mutate this dict or any CollectorResult inside it."""

    ctx: ReconExecutionContext
    fetched: "FetchedResponse | None"
    fetch_error: str | None
    collector_results: dict[str, CollectorResult]
    settings: "Settings"


@dataclass(frozen=True)
class CheckOutcome:
    """What a check hands back: its own observation-shaped
    CollectorResult (collector=slug, exactly like any Recon collector)
    plus whatever Findings it could justify with real evidence from
    this run. `findings` is empty, never omitted, when a check finds
    nothing to report -- "ran successfully, nothing to flag" is itself
    useful information, carried in collector_result.status/observations,
    never silently indistinguishable from "didn't run"."""

    collector_result: CollectorResult
    findings: list[Finding] = field(default_factory=list)


@runtime_checkable
class SecurityCheck(Protocol):
    """A check module's public shape -- app/engines/web_vuln/checks/*.py
    each define SLUG, CATEGORY, and a module-level `run()` matching
    this signature, exactly like app/engines/recon/collectors/*.py's
    own SLUG + collect() convention."""

    SLUG: str
    CATEGORY: str

    def run(self, inputs: CheckInputs) -> CheckOutcome: ...


# Order is the order checks run in and the order their tabs/sections
# appear in the frontend -- see
# features/scans/web-vuln-results-view.tsx's own CATEGORY_ORDER, which
# must be extended whenever a slug is added here. Imported lazily
# inside _build_registry() (not at module top level) purely to avoid a
# long import chain at module-import time for anything that only needs
# CheckInputs/CheckOutcome/SecurityCheck from this module without
# wanting every check's own dependencies pulled in immediately (e.g. a
# unit test of one single check module).


def register_checks(*modules: Any) -> tuple[Any, ...]:
    """Validates every module against the SecurityCheck Protocol at
    import time (never silently accepting a mistyped check module) and
    returns them as the final, ordered registry tuple."""
    for module in modules:
        if not isinstance(module, SecurityCheck):
            raise TypeError(
                f"{module!r} does not satisfy the SecurityCheck protocol "
                "(missing SLUG/CATEGORY/run) -- fix the check module, "
                "never relax this check"
            )
    slugs = [module.SLUG for module in modules]
    if len(slugs) != len(set(slugs)):
        raise ValueError(f"duplicate check SLUGs in CHECK_REGISTRY: {slugs!r}")
    return tuple(modules)


def _build_registry() -> tuple[Any, ...]:
    from app.engines.web_vuln.checks import (
        api_security,
        cookies,
        cors,
        http_methods,
        info_disclosure,
        injection_surface,
        security_headers,
        tls_config,
    )

    return register_checks(
        security_headers,
        cookies,
        cors,
        info_disclosure,
        http_methods,
        tls_config,
        injection_surface,
        api_security,
    )


CHECK_REGISTRY: tuple[Any, ...] = _build_registry()
