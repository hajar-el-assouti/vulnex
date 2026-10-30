"""Common result format returned by every recon collector.

Each collector returns one CollectorResult. Recon produces
observations, not vulnerability findings: findings come from the
web_vuln and active testing engines.

Every fact is one Observation, tagged with how it was determined
(`nature`), never defaulting to "observed":

- OBSERVED: read directly from the response (a header value, a cookie
  flag, the status code).
- INFERRED: deduced from indirect evidence (e.g. "probably Next.js"
  from a marker in the body).
- UNKNOWN: can't be determined from the data (e.g. no known signature
  matched; no signature is not proof of absence).
- NOT_APPLICABLE: the check doesn't apply to this target (e.g. HSTS on
  a response not served over HTTPS).
- ERROR: collecting this data point failed (timeout, refused,
  malformed response). Different from UNKNOWN: "we couldn't try" vs
  "we tried and still don't know".

CollectorStatus.OK means collection worked, not that the target has no
vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ObservationNature(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class CollectorStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Observation:
    """One fact. `value` is a plain JSON-serializable type, since it is
    stored in scan_module_runs.result and displayed by the frontend. It
    must never be treated as HTML. Raw page content and raw cookie
    values are never stored here, only derived facts."""

    key: str
    value: Any
    nature: ObservationNature
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "value": self.value, "nature": self.nature.value, "note": self.note}


@dataclass(frozen=True)
class CollectorResult:
    """Collector, Status, Collected_at, Duration_ms, Observations,
    Evidence, Errors, Source, Confidence."""

    collector: str
    status: CollectorStatus
    collected_at: datetime
    duration_ms: int
    observations: list[Observation] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    source: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.LOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector": self.collector,
            "status": self.status.value,
            "collected_at": self.collected_at.isoformat(),
            "duration_ms": self.duration_ms,
            "observations": [o.to_dict() for o in self.observations],
            "evidence": self.evidence,
            "errors": self.errors,
            "source": self.source,
            "confidence": self.confidence.value,
        }

    @classmethod
    def error(
        cls,
        *,
        collector: str,
        source: str,
        collected_at: datetime,
        duration_ms: int,
        errors: list[str],
    ) -> "CollectorResult":
        return cls(
            collector=collector,
            status=CollectorStatus.ERROR,
            collected_at=collected_at,
            duration_ms=duration_ms,
            observations=[],
            evidence={},
            errors=errors,
            source=source,
            confidence=ConfidenceLevel.LOW,
        )
