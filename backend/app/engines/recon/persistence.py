"""Sanitization and size limiting of a recon run's CollectorResults
before they are saved to `scan_module_runs.result` or sent in a
ScanEvent payload.

Collectors already avoid storing secrets at the source: cookie values
are never stored (cookies_collector.py), only a sha256 of the body is
kept (http_collector.py), and redact_secrets() is applied to strings
taken from page markup.

This module is a second layer at the storage boundary, so a future
collector that forgets one of those rules can't leak a secret into the
database. Every value is treated as untrusted and redacted again.

No database access here; the write happens in
app/tasks/recon_module.py."""

from __future__ import annotations

import json
from typing import Any

from app.engines.recon.collectors._secrets import redact_secrets
from app.engines.recon.fingerprint import compute_fingerprint
from app.engines.recon.schemas import CollectorResult

# Keys that are never stored, whatever their value: cookie values,
# credentials, tokens, full response bodies. Matched as a
# case-insensitive substring against every dict key.
_FORBIDDEN_KEY_SUBSTRINGS = (
    "cookie_value",
    "raw_body",
    "full_html",
    "full_body",
    "set_cookie_raw",
    "password",
    "credential",
)


def _redact_value(value: Any) -> Any:
    """Recursively redacts every string in `value` (nested dicts and
    lists included) with redact_secrets(), and drops any key matching
    _FORBIDDEN_KEY_SUBSTRINGS completely. Some fields (a cookie value,
    a raw body) must not be stored at all, even redacted."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {
            key: _redact_value(val)
            for key, val in value.items()
            if not any(forbidden in key.lower() for forbidden in _FORBIDDEN_KEY_SUBSTRINGS)
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


def _sanitize_result_dict(result_dict: dict) -> dict:
    sanitized = dict(result_dict)
    sanitized["observations"] = [
        {**obs, "value": _redact_value(obs.get("value"))} for obs in result_dict.get("observations", [])
    ]
    sanitized["evidence"] = _redact_value(result_dict.get("evidence", {}))
    sanitized["errors"] = [redact_secrets(e) for e in result_dict.get("errors", [])]
    return sanitized


def _payload_size_bytes(payload: dict) -> int:
    return len(json.dumps(payload, default=str).encode("utf-8"))


def build_persisted_result(
    results: dict[str, CollectorResult],
    *,
    max_bytes: int,
) -> dict:
    """Returns the exact dict that becomes `ScanModuleRun.result`:

    - "modules": one sanitized `CollectorResult.to_dict()` per collector
      slug, every string value passed through `redact_secrets()` again
      (defense in depth) and every forbidden-shaped key dropped.
    - "fingerprint_snapshot": `compute_fingerprint()`'s own output,
      computed from the REAL (pre-sanitization) results -- this is what
      a FUTURE run's history provider
      (app/services/recon_history.py::fetch_previous_recon_run) reads to
      build a `HistoryEntry` for comparison, so a later run never has
      to re-derive a fingerprint from an already-truncated storage
      payload. Safe to store as-is: `compute_fingerprint()` only pulls
      `Observation.value` for OBSERVED/INFERRED observations, which the
      collectors already produce redacted at the source, and this
      module's own `modules` sanitization pass does not change that.
    - "storage_truncated" / "truncated_collectors": set only when the
      sanitized payload still exceeds `max_bytes` and one or more
      collectors' `observations` arrays had to be dropped (replaced
      with an explicit `_storage_note`) to fit under the cap. This is
      NEVER silent -- a result truncated for storage is always
      distinguishable from one whose collectors genuinely found
      nothing, and distinct from the collector-level PARTIAL/ERROR
      statuses the engine itself already reports.
    """
    # compute_fingerprint() reads Observation.value directly and does no
    # redaction itself, so it is redacted here like `modules` below: this
    # snapshot is stored too. If two different secrets in the same field
    # both become "[REDACTED]", that field looks unchanged between runs.
    # That is an accepted trade-off: never storing secrets comes first.
    fingerprint_snapshot = _redact_value(compute_fingerprint(results))
    modules = {slug: _sanitize_result_dict(result.to_dict()) for slug, result in results.items()}

    payload: dict[str, Any] = {
        "modules": modules,
        "fingerprint_snapshot": fingerprint_snapshot,
        "storage_truncated": False,
        "truncated_collectors": [],
    }

    if _payload_size_bytes(payload) <= max_bytes:
        return payload

    # Truncate the largest collectors first -- keep status/evidence/
    # errors (small, high-signal) and drop only the (potentially large)
    # observations array, replacing it with an explicit note.
    truncated: list[str] = []
    order = sorted(modules.keys(), key=lambda slug: len(json.dumps(modules[slug], default=str)), reverse=True)
    for slug in order:
        if _payload_size_bytes(payload) <= max_bytes:
            break
        modules[slug]["observations"] = []
        modules[slug]["_storage_note"] = (
            "observations omitted: the persisted result exceeded the configured "
            "storage size limit (recon_result_max_persisted_bytes)"
        )
        truncated.append(slug)

    payload["storage_truncated"] = bool(truncated)
    payload["truncated_collectors"] = sorted(truncated)
    return payload
