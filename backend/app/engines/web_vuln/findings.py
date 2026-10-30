"""Finding model for the web vulnerability assessment engine.

Recon produces Observations (technical facts). A Finding is a
justified security claim that someone would act on, and is what ends
up in the `scan_findings` table.

No database code here, like the rest of app/engines/*.
FindingSeverity/FindingConfidence use the same values as the ORM's
Severity/Confidence. Finding.to_dict() is converted into a ScanFinding
row in one place only: app/services/findings.py.

Every Finding must point to real evidence collected in this run (a
header value, cookie flags, a body snippet). `evidence` can't be empty
when confidence is HIGH or CONFIRMED (see validate()).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class FindingValidationError(ValueError):
    """Raised by Finding.__post_init__ -- a check that would produce an
    invalid Finding is a bug in that check, caught here rather than
    allowed to reach app/services/findings.py and silently become a
    malformed scan_findings row."""


@dataclass(frozen=True)
class Finding:
    """One justified security claim. `check` is the registry slug that
    produced it. It isn't a scan_findings column, but deduplication
    relies on it, so it is stored in `evidence["check"]`.

    `owasp_category` (e.g. "A05:2021-Security Misconfiguration") and
    `cwe_id` are optional. `impact` is kept separate from
    `description` so the potential impact can be reviewed on its own,
    without overstating it."""

    check: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: FindingConfidence
    impact: str
    remediation: str
    affected_url: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Optional HTTP method used by the test request (e.g. "GET"), set by
    # the active checks. Stored in evidence["_http_method"] by to_dict(),
    # like `check` in evidence["_check"], so no new column is needed.
    http_method: str | None = None

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise FindingValidationError("Finding.title must not be empty")
        if not self.evidence:
            raise FindingValidationError(
                f"Finding {self.check!r}/{self.title!r} has no evidence -- "
                "every finding must point at something actually observed this run"
            )
        if self.confidence in (FindingConfidence.HIGH, FindingConfidence.CONFIRMED) and len(
            self.evidence
        ) == 0:
            # Redundant with the check above today (empty evidence is
            # already rejected unconditionally), kept as its own named
            # branch so a future relaxation of the first check (e.g.
            # allowing a documented-absence evidence shape) cannot
            # accidentally also relax this HIGH/CONFIRMED-specific bar
            # without a reviewer noticing.
            raise FindingValidationError(
                f"Finding {self.check!r}/{self.title!r} claims {self.confidence.value} "
                "confidence with no evidence"
            )

    def dedup_key(self) -> str:
        """Stable across a re-run of the exact same check against the
        exact same URL with the exact same title -- used both to drop
        intra-run duplicates (two checks independently flagging the
        same thing) and, by app/services/findings.py, to recognize an
        already-recorded finding on a later run of the same scan
        module without creating a second row for it. Deliberately NOT a
        hash of `evidence` -- the evidence for the "same" finding is
        expected to vary run to run (a fresh timestamp, a refreshed
        header capture) without that making it a different finding."""
        raw = f"{self.check}\x1f{self.title}\x1f{self.affected_url or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Shaped exactly like app/engines/contracts.py::
        ModuleExecutionResult.findings expects: a plain dict mirroring
        ScanFinding's own fields, plus `_check`/`_dedup_key`/`_impact`
        (underscore-prefixed: never literal ScanFinding columns,
        consumed only by app/services/findings.py before the real
        columns are written, exactly like ReconCollectorResultPublic's
        own `_storage_note` convention in recon-results-view.tsx)."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "affected_url": self.affected_url,
            "cwe_id": self.cwe_id,
            "evidence": {
                **self.evidence,
                "owasp_category": self.owasp_category,
                "impact": self.impact,
                **({"_http_method": self.http_method} if self.http_method else {}),
            },
            "remediation": self.remediation,
            "_check": self.check,
            "_dedup_key": self.dedup_key(),
            "_detected_at": self.detected_at.isoformat(),
        }


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drops intra-run duplicates (same dedup_key()) keeping the first
    occurrence -- two checks independently noticing "no HSTS header"
    for the same URL must produce one finding, not two."""
    seen: set[str] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = finding.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
