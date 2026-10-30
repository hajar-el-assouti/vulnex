"""Check registry for the active web testing engine.

Same design as web_vuln/registry.py (explicit, ordered CHECK_REGISTRY
tuple, same SecurityCheck protocol). `CheckInputs` also carries the
entry-point list and a shared `EndpointRequestTracker`, so
Settings.active_web_testing_max_requests_per_endpoint applies to all
checks together: four checks probing the same parameter share one
budget."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from app.engines.active_web_testing.entrypoints import EntryPoint
from app.engines.recon.context import ReconExecutionContext
from app.engines.recon.schemas import CollectorResult
from app.engines.web_vuln.findings import Finding

if TYPE_CHECKING:
    from app.core.config import Settings
    from app.engines.recon.security.request_policy import FetchedResponse


class EndpointRequestTracker:
    """Shared, per-run counter of test requests already sent to each
    entry point (keyed by (url, method, param_name)) -- see module
    docstring. `allow()` must be checked by a check BEFORE sending a
    test request for that entry point, and `record()` called after
    actually sending one; a check that never calls `record()` for a
    request it made would silently let every other check overspend the
    endpoint's shared budget."""

    def __init__(self, max_requests_per_endpoint: int) -> None:
        self._max = max_requests_per_endpoint
        self._counts: dict[tuple[str, str, str | None], int] = {}

    def allow(self, entry_point: EntryPoint) -> bool:
        key = (entry_point.url, entry_point.method, entry_point.param_name)
        return self._counts.get(key, 0) < self._max

    def record(self, entry_point: EntryPoint) -> None:
        key = (entry_point.url, entry_point.method, entry_point.param_name)
        self._counts[key] = self._counts.get(key, 0) + 1


@dataclass(frozen=True)
class CheckInputs:
    ctx: ReconExecutionContext
    fetched: "FetchedResponse | None"
    entry_points: list[EntryPoint]
    settings: "Settings"
    request_tracker: EndpointRequestTracker


@dataclass(frozen=True)
class CheckOutcome:
    collector_result: CollectorResult
    findings: list[Finding] = field(default_factory=list)


@runtime_checkable
class SecurityCheck(Protocol):
    SLUG: str
    CATEGORY: str

    def run(self, inputs: CheckInputs) -> CheckOutcome: ...


def register_checks(*modules: Any) -> tuple[Any, ...]:
    for module in modules:
        if not isinstance(module, SecurityCheck):
            raise TypeError(
                f"{module!r} does not satisfy the SecurityCheck protocol "
                "(missing SLUG/CATEGORY/run) -- fix the check module, never relax this check"
            )
    slugs = [module.SLUG for module in modules]
    if len(slugs) != len(set(slugs)):
        raise ValueError(f"duplicate check SLUGs in CHECK_REGISTRY: {slugs!r}")
    return tuple(modules)


def _build_registry() -> tuple[Any, ...]:
    from app.engines.active_web_testing.checks import (
        api_security_active,
        http_param_testing,
        sqli_differential,
        xss_reflected,
    )

    return register_checks(
        xss_reflected,
        sqli_differential,
        http_param_testing,
        api_security_active,
    )


CHECK_REGISTRY: tuple[Any, ...] = _build_registry()
