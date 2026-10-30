"""Visual snapshot collector.

**Experimental, disabled by default, and not implemented yet.**

## Why

Taking a screenshot safely requires all of these at once:
1. Never run the browser inside the FastAPI process.
2. No heavy new dependency on a 6 GB RAM VM.
3. Block every secondary request the page makes: the browser may only
   load the one authorized URL, nothing it links to or embeds.
4. Never reach an internal service.
5. Never pass platform cookies or credentials to the browser.
6. Can be disabled, and is limited in time, memory and size.

Point 3 is the blocker. Blocking requests needs an automation API with
request interception (Playwright's `page.route()`), which means adding
Playwright and Chromium, with no verified memory figure for the VM.
Running a bare `chromium --headless --screenshot` can't block
individual requests at all.

## Current state

- `Settings.advanced_recon_visual_snapshot_enabled` (default False)
  gates the feature.
- The collector is wired into advanced_engine.py so the section exists
  end to end, but it returns NOT_APPLICABLE by default, and an explicit
  ERROR if the flag is forced on, since the capture itself is not
  implemented. It never returns a fake screenshot.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.context import ReconExecutionContext
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)

SLUG = "visual_snapshot"

_BLOCKER_NOTE = (
    "Visual Snapshot is experimental and not implemented yet: no "
    "verified way to block every secondary/out-of-scope request "
    "was confirmed in this development environment without adding "
    "an unverified-footprint browser automation stack under the deployment VM's "
    "6 GB RAM constraint. See visual_snapshot_collector.py's module docstring "
    "for the full blocker. This collector never takes a screenshot, with or "
    "without the feature flag, until that isolation is verified and this "
    "docstring is updated to say so."
)


def collect(ctx: ReconExecutionContext, *, enabled: bool) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)

        if not enabled:
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=[
                    Observation(
                        "visual_snapshot.enabled",
                        False,
                        ObservationNature.NOT_APPLICABLE,
                        note="disabled by default (advanced_recon_visual_snapshot_enabled=False)",
                    )
                ],
                source="visual_snapshot",
                confidence=ConfidenceLevel.HIGH,
            )

        # Even with the flag forced on, the capture itself is not
        # implemented -- see this module's docstring. Reported as an
        # explicit ERROR with the precise blocker, never a fabricated
        # or partially-isolated screenshot.
        return CollectorResult(
            collector=SLUG,
            status=CollectorStatus.ERROR,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=[
                Observation(
                    "visual_snapshot.enabled",
                    True,
                    ObservationNature.ERROR,
                    note=_BLOCKER_NOTE,
                )
            ],
            errors=[_BLOCKER_NOTE],
            source="visual_snapshot",
            confidence=ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="visual_snapshot", fn=_run)
