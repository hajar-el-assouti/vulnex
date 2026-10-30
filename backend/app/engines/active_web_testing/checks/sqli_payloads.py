"""SQL injection test catalog.

A small, declarative list of `SqliTestDefinition` entries instead of
probe strings hardcoded in sqli_differential.py. Each entry has an id,
a detection family, the parameter types it applies to, its objective,
its risk level, its execution limits and how to interpret the result.

The probes were picked by hand from a public SQL injection cheat
sheet. The list is never imported as-is. Most families were rejected
because they don't fit this engine's rules (GET only, nothing
destructive, predictable timing, no data extraction):
- Time-based (SLEEP/BENCHMARK/WAITFOR/pg_sleep): rejected. A real
  delay would just look like a timeout and make scans unpredictable.
- UNION-based: rejected, it is data extraction.
- Authentication bypass payloads (`admin' --` ...): rejected. The
  `' OR '1'='1` / `' OR '1'='2` pair is only used as a true/false
  differential on an arbitrary parameter, never against a login form.
- ORDER BY / GROUP BY schema probing: rejected, it is enumeration and
  would need many requests per parameter.

Kept: the boolean true/false pair, and from the generic syntax
characters only `;` in addition to the existing quote probe.

Keeping the catalog as a reviewed tuple in the repo, instead of
loading a payload file at runtime, means what the scanner sends never
depends on a text file dropped next to it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SqliTestFamily(str, Enum):
    BASELINE = "baseline"          # not a probe -- the untouched reference value
    SYNTAX = "syntax"              # 5.B: bare syntax/comment character
    ERROR = "error"                # 5.C: a probe read against known SQL-driver error signatures
    BOOLEAN_TRUE = "boolean_true"  # 5.D: tautology probe
    BOOLEAN_FALSE = "boolean_false"  # 5.D: contradiction probe


class SqliRiskLevel(str, Enum):
    # Every entry in this catalog is "none": a single, idempotent GET
    # request with no destructive side effect, no data extraction, no
    # unpredictable timing. There is deliberately no "low"/"medium"
    # tier above this -- a test that needed one would not belong in
    # this catalog at all (see module docstring on what was rejected).
    NONE = "none"


@dataclass(frozen=True)
class SqliTestDefinition:
    id: str
    family: SqliTestFamily
    compatible_param_types: tuple[str, ...]
    objective: str
    risk_level: SqliRiskLevel
    execution_limit: str
    interpretation_rule: str
    db_engine_hint: str | None = None


# `payload_from` tells sqli_differential.py which Settings field holds
# the actual probe string. The catalog documents what each test is and
# why; Settings keeps the live value.
SQLI_TEST_DEFINITIONS: tuple[SqliTestDefinition, ...] = (
    SqliTestDefinition(
        id="sqli.baseline.untouched",
        family=SqliTestFamily.BASELINE,
        compatible_param_types=("string", "numeric"),
        objective="Capture the parameter's own existing/default value, completely untouched, as the comparison reference.",
        risk_level=SqliRiskLevel.NONE,
        execution_limit="Sent twice (baseline_1, baseline_2) to measure natural response noise before any probe is judged against it.",
        interpretation_rule="Never itself a signal. The length/status difference BETWEEN baseline_1 and baseline_2 sets the noise threshold every later probe is compared against.",
    ),
    SqliTestDefinition(
        id="sqli.syntax.quote",
        family=SqliTestFamily.SYNTAX,
        compatible_param_types=("string",),
        objective="Append a single quote to the baseline value; if the backend concatenates it unescaped into a string-delimited SQL literal, the query may become malformed.",
        risk_level=SqliRiskLevel.NONE,
        execution_limit="One request; this is also the error-based probe (active_web_testing_sqli_error_probe) -- the same request serves both the syntax-level and the error-signature-level interpretation, never sent twice for two purposes.",
        interpretation_rule="A status-code or response-length anomaly alone is NEVER a Finding ('ne jamais conclure à partir d'un simple HTTP 500') -- it is read against known SQL-driver error signatures (see sqli.error.* below) and otherwise only ever recorded as a corroborating Observation.",
    ),
    SqliTestDefinition(
        id="sqli.syntax.semicolon",
        family=SqliTestFamily.SYNTAX,
        compatible_param_types=("string", "numeric"),
        objective="Append a bare statement-separator character to the baseline value -- a different malformation shape than a stray quote (catches a driver that tolerates an unterminated string but chokes on an unexpected second statement, or vice versa).",
        risk_level=SqliRiskLevel.NONE,
        execution_limit="One request (active_web_testing_sqli_syntax_probe). Never followed by an actual second statement -- this is a bare separator, nothing is appended after it.",
        interpretation_rule="Same rule as sqli.syntax.quote: a status/length anomaly here is recorded as a corroborating 'syntax_anomaly' Observation and can never by itself produce a Finding.",
    ),
    SqliTestDefinition(
        id="sqli.error.signature_match",
        family=SqliTestFamily.ERROR,
        compatible_param_types=("string", "numeric"),
        objective="Check the quote-probe's response body for a known SQL-driver error-message substring that was absent from both baseline responses.",
        risk_level=SqliRiskLevel.NONE,
        execution_limit="Reuses sqli.syntax.quote's single request; if a signature matches, exactly ONE additional confirmation request re-sends the same probe (active_web_testing_sqli_require_error_reproduction) before a Finding is produced.",
        interpretation_rule="A signature match is a Finding-worthy signal ONLY if it (a) was absent from both baseline responses and (b) reproduces on the confirmation request. A one-off, non-reproducing match is recorded as a suspect/non-concluant Observation instead.",
        db_engine_hint="looked up at match time from Settings.active_web_testing_sql_error_engine_hints -- purely informational, never changes whether a Finding is produced",
    ),
    SqliTestDefinition(
        id="sqli.boolean.tautology_pair",
        family=SqliTestFamily.BOOLEAN_TRUE,
        compatible_param_types=("string",),
        objective="Send a TRUE tautology (\"' OR '1'='1\") and a FALSE contradiction (\"' OR '1'='2\") and compare both against the baseline: a genuine boolean-based injection should make the TRUE probe look like baseline while the FALSE probe looks different.",
        risk_level=SqliRiskLevel.NONE,
        execution_limit="Two requests for round 1 (one TRUE, one FALSE); if asymmetric, exactly TWO additional confirmation requests (active_web_testing_sqli_require_boolean_reproduction) re-send the same pair before a Finding is produced.",
        interpretation_rule="An asymmetry (TRUE within noise of baseline, FALSE beyond noise AND beyond the TRUE probe) is a Finding-worthy signal ONLY if it reproduces identically on the confirmation round. An asymmetry that does not reproduce is recorded as a suspect/non-concluant 'boolean_asymmetry_not_reproducible' Observation instead -- never a Finding.",
    ),
)


def definitions_by_family(family: SqliTestFamily) -> tuple[SqliTestDefinition, ...]:
    return tuple(d for d in SQLI_TEST_DEFINITIONS if d.family == family)


def lookup_engine_hint(matched_signature: str, hints: dict[str, str]) -> str | None:
    """Looks up a human-readable database-engine name for an
    already-matched error signature. Pure, no I/O; `hints` is always
    Settings.active_web_testing_sql_error_engine_hints, passed in
    rather than imported, so this module stays settings-free (every
    other check module in this engine follows the same convention --
    see sqli_differential.py's own `settings = inputs.settings`)."""
    return hints.get(matched_signature.lower())
