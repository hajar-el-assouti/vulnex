"""Soft-404 detection for the discovery & fuzzing engine.

Some targets answer every unknown path with 200 (an SPA catch-all
route, a custom error page without a 404 status). Without handling
this, every tested path would look "accessible" and the results would
be full of false positives. A status code alone doesn't prove a
resource exists.

Before testing the wordlist, we request a few paths that can't exist
(built from the scan id). If they all return non-2xx, there is no
soft-404 behavior. If some return 2xx, their status and body length
become a baseline signature: a later 200 with almost the same length
is reported as `likely_soft_404`, not `accessible`.

This module makes no HTTP calls itself; engine.py does them and
passes the results in, which keeps it easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProbeOutcome:
    """One soft-404 baseline probe's result, as observed by the
    engine's own fetch call."""

    path: str
    status_code: int | None  # None if the probe itself errored (timeout, etc.)
    body_length: int | None


@dataclass(frozen=True)
class BaselineSignature:
    """What a subsequent real path's own 200 response is compared
    against. `detected` is False whenever not a single baseline probe
    came back 2xx -- the normal, expected case for a target with real
    404 handling; `reference_body_length` is then meaningless and
    unused."""

    detected: bool
    reference_body_length: int | None = None


def build_probe_paths(scan_id: str, *, count: int) -> list[str]:
    """Deterministic, scan-unique, guaranteed-nonexistent path
    segments. Deterministic (not random) so a re-run of the exact same
    scan probes the exact same paths -- consistent with the module's
    own "ordre de sélection déterministe" requirement for the real
    wordlist entries, extended here to the baseline probes too.
    Scan-unique (keyed by `scan_id`, not a fixed literal) so no
    conceivable real target resource could ever coincidentally share
    one of these names across two different scans."""
    return [f"__discovery-probe-{scan_id}-{i}__" for i in range(count)]


def compute_signature(
    probe_outcomes: list[ProbeOutcome], *, body_length_tolerance: int
) -> BaselineSignature:
    """Soft-404 is declared the moment ANY probe comes back 2xx -- a
    target that is soft-404-prone on even one of a handful of
    guaranteed-nonexistent paths is treated as soft-404-prone outright,
    never averaged away by the other probes also happening to 404
    correctly. `reference_body_length` is the SMALLEST body length
    among the 2xx probes (the most conservative choice: using the
    smallest, rather than the largest or an average, means a real
    wordlist entry's response has to be at least that small to be
    misclassified as `likely_soft_404` -- a real, meaningfully larger
    page is never swept into the soft-404 bucket just because it also
    happens to return 200)."""
    successful_lengths = [
        outcome.body_length
        for outcome in probe_outcomes
        if outcome.status_code is not None and 200 <= outcome.status_code < 300 and outcome.body_length is not None
    ]
    if not successful_lengths:
        return BaselineSignature(detected=False)
    return BaselineSignature(detected=True, reference_body_length=min(successful_lengths))


def matches_soft_404(
    signature: BaselineSignature, *, status_code: int, body_length: int, body_length_tolerance: int
) -> bool:
    """True iff `status_code`/`body_length` (a REAL wordlist entry's
    own 200 response) should be reported as `likely_soft_404` rather
    than `accessible`. Only ever called when `status_code` is itself
    2xx -- a 404/403/etc. response is never reclassified by this
    function at all, since the soft-404 problem is specifically about
    2xx responses that lie about a resource's existence."""
    if not signature.detected or signature.reference_body_length is None:
        return False
    return abs(body_length - signature.reference_body_length) <= body_length_tolerance
