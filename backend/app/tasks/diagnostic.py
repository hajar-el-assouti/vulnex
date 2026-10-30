"""Diagnostic module, used to test the orchestration.

Not a security engine and never presented as one. It goes through
the whole orchestration contract (app/engines/contracts.py): receives
a ScanContext, honors cancellation, reports progress, returns a
ModuleExecutionResult. It makes no network call and always returns
zero findings.
"""

from __future__ import annotations

import time

from app.engines.contracts import (
    CancellationContext,
    ModuleExecutionResult,
    ModuleExecutionStatus,
    ScanContext,
)

SLUG = "diagnostic"

# A few short, labelled steps so the scan's event feed shows real
# progress instead of a single "running" state. Kept short so tests
# don't need long sleeps.
_STEPS = (
    "Validating orchestration context",
    "Simulating target reachability check",
    "Simulating module execution",
    "Finalizing diagnostic run",
)


class DiagnosticModule:
    """Implements the ScanModule protocol (structurally -- see
    app/engines/contracts.py's @runtime_checkable ScanModule)."""

    slug = SLUG

    def run(self, context: ScanContext) -> ModuleExecutionResult:
        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled before the diagnostic module started",
            )

        for step in _STEPS:
            # Deliberately inert: no request is made, nothing is
            # scanned. This sleep only simulates work taking time, so
            # the orchestration's progress/cancellation plumbing has
            # something real to exercise.
            time.sleep(0.05)
            if context.cancellation.check():
                return ModuleExecutionResult(
                    status=ModuleExecutionStatus.CANCELLED,
                    summary=f"Cancelled during step: {step}",
                )

        return ModuleExecutionResult(
            status=ModuleExecutionStatus.COMPLETED,
            findings=[],  # always empty -- see module docstring
            summary="Diagnostic run completed; orchestration path verified end to end",
        )


def build_cancellation_context(is_cancelled_now: bool) -> CancellationContext:
    """The diagnostic module checks cancellation at its own step
    boundaries (see DiagnosticModule.run above), not via a live DB
    poll mid-call -- it has no long-running internal work to poll
    during. A real, longer-running engine must instead pass a
    CancellationContext whose is_cancelled() re-checks the database (or
    a cheap in-memory cache of it) on every call, so a request made
    *after* cancellation was recorded still observes it."""
    return CancellationContext(is_cancelled=lambda: is_cancelled_now)
