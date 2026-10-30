"""Execution budget and per-scan context for the Recon engine.

Separate from app/engines/contracts.py's ScanContext (orchestration-level,
Celery/DB-facing, not yet touched in this checkpoint) -- this is
engine-internal: the shared execution budget and the SSRF-validated
target, passed by reference into every collector within one scan run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.security.ssrf import ValidatedTarget


class ReconBudgetExceededError(RuntimeError):
    """Raised by budget checks; the collector harness
    (collectors/base.py::run_collector_safely) catches this at collector
    boundaries and records it as a collector-level CollectorStatus.ERROR,
    never lets it escape as an unhandled exception that would abort the
    whole scan or leave it in an inconsistent state."""


class ReconCancelledError(RuntimeError):
    """Raised by ReconExecutionContext.raise_if_cancelled() -- unlike
    ReconBudgetExceededError, this is deliberately NOT caught at the
    collector boundary (collectors/base.py::run_collector_safely
    re-raises it) so it propagates all the way up to
    app/engines/recon/engine.py::run_collectors(), which stops
    dispatching any further collector rather than recording this one
    collector as ERROR and moving on to the next. A cancelled scan
    should stop, not fail one collector and keep going."""


@dataclass
class ReconBudget:
    """One instance per scan run, shared by reference across every
    collector the engine invokes, so "20 requests total for this scan"
    is actually enforced across collectors, not per-collector.

    `time.monotonic()` is used throughout -- never wall-clock
    datetime.now() -- specifically because it cannot jump backwards or
    forwards due to a system clock adjustment (NTP correction, manual
    change) mid-scan. A deadline built from wall-clock time could be
    invalidated by such a jump; monotonic time cannot."""

    deadline_monotonic: float
    request_timeout_seconds: float
    max_requests: int
    max_response_bytes: int
    max_metadata_response_bytes: int
    max_redirects: int
    requests_made: int = field(default=0, init=False)

    @classmethod
    def start_now(
        cls,
        *,
        total_timeout_seconds: float,
        request_timeout_seconds: float,
        max_requests: int,
        max_response_bytes: int,
        max_metadata_response_bytes: int,
        max_redirects: int,
    ) -> "ReconBudget":
        return cls(
            deadline_monotonic=time.monotonic() + total_timeout_seconds,
            request_timeout_seconds=request_timeout_seconds,
            max_requests=max_requests,
            max_response_bytes=max_response_bytes,
            max_metadata_response_bytes=max_metadata_response_bytes,
            max_redirects=max_redirects,
        )

    def remaining_seconds(self) -> float:
        return self.deadline_monotonic - time.monotonic()

    def ensure_not_expired(self, *, where: str) -> None:
        if self.remaining_seconds() <= 0:
            raise ReconBudgetExceededError(f"Recon scan deadline exceeded ({where})")

    def per_request_timeout(self) -> float:
        """Never waits longer than what's actually left on the global
        deadline, even if that's shorter than the configured per-request
        timeout -- a request started with 2s left on the clock must not
        be given the full configured timeout (e.g. 8s)."""
        return self.timeout_for(self.request_timeout_seconds)

    def timeout_for(self, configured_timeout_seconds: float) -> float:
        """Same clamping as per_request_timeout(), but for an operation
        type with its OWN configured timeout (DNS, RDAP, TLS -- each
        has a distinct Settings.recon_*_timeout_seconds, deliberately
        separate from the HTTP target's recon_request_timeout_seconds).
        Every network operation this engine makes, regardless of which
        collector or which fixed/target host it talks to, is bounded by
        BOTH its own configured timeout AND whatever is left on this
        one shared global deadline -- never just the former."""
        return max(0.01, min(configured_timeout_seconds, self.remaining_seconds()))

    def register_request(self, *, where: str) -> None:
        """Must be called immediately before every single network
        request (including each redirect hop) -- checks the deadline
        AND the request-count ceiling, and raises before a request is
        ever attempted if either is already exhausted."""
        self.ensure_not_expired(where=where)
        if self.requests_made >= self.max_requests:
            raise ReconBudgetExceededError(
                f"Recon scan request budget exhausted "
                f"({self.requests_made}/{self.max_requests}, {where})"
            )
        self.requests_made += 1


@runtime_checkable
class CancellationCheckLike(Protocol):
    def __call__(self) -> bool: ...


@dataclass
class ReconExecutionContext:
    """What every collector receives.

    `validated_target` is the SSRF-checked snapshot of the target as of
    when this context was built -- a collector must still re-validate
    on every individual request/redirect (see
    security/request_policy.py) because this snapshot can go stale
    (DNS rebinding) between context construction and the moment a given
    collector actually connects. This context never claims to make that
    gap zero; see request_policy.py's module docstring for the
    documented residual risk."""

    scan_id: str
    target_base_url: str
    validated_target: ValidatedTarget
    budget: ReconBudget
    allow_private_networks: bool
    lab_hosts: frozenset[str]
    is_cancelled: CancellationCheckLike

    def raise_if_cancelled(self, *, where: str) -> None:
        """The per-request cancellation checkpoint -- called alongside
        (never instead of) budget.ensure_not_expired()/register_request()
        at every individual HTTP/DNS/RDAP/TLS operation, in addition to
        the existing between-collector checks in run_collectors(). Costs
        exactly one call to `is_cancelled()`, which is itself a cheap,
        non-blocking read (a threading.Event.is_set() in production via
        app/tasks/scan_tasks.py's live poller, or a frozen bool in a
        context that never updates) -- never a DB query by itself, which
        is what keeps this check "léger" however many requests a
        collector makes."""
        if self.is_cancelled():
            raise ReconCancelledError(f"Recon scan cancelled ({where})")
