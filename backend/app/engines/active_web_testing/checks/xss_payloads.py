"""Catalog of the reflected XSS tests this engine sends.

The tests were designed after reviewing a large public XSS cheat sheet
(about 1000 unique payloads). None of those payloads is imported here.
Each one either:
- needs real JavaScript execution to mean anything (there is no
  browser in this project),
- targets an old browser quirk (IE conditional comments, VBScript,
  UTF-7...) that can't be verified on the target,
- steals cookies, exfiltrates data, loads external resources or
  redirects to a third party (out of scope),
- is a fragment, not a standalone test, or
- is a variant of another entry.

What matters for detection is not the exact exploit string, but:
(a) whether the value is reflected at all, (b) where in the document
it lands, and (c) whether the characters that matter there come back
unescaped. `checks/xss_reflected.py` tests exactly that with two
harmless probes:

1. A baseline request with the parameter's original value, to check
   the response is stable and skip endpoints that can't be analyzed
   (WAF block page, 5xx, redirect).
2. One marker probe: a unique token wrapped in `"`, `'`, `<` and `>`.
   No script, no event handler. If a raw reflection is found, the same
   probe is sent once more to confirm it; a result that doesn't
   reproduce stays an Observation.

Stored XSS, DOM XSS and the other families are out of scope: they
would require executing JavaScript."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class XssTestFamily(str, Enum):
    BASELINE = "baseline"
    STRUCTURAL_MARKER = "structural_marker"


class XssRiskLevel(str, Enum):
    """Deliberately only one tier exists -- every test this catalog
    defines is a single, idempotent, read-only GET probe using an
    inert marker that never executes anything. See sqli_payloads.py's
    identical design choice for the SQLi catalog; this mirrors it."""

    NONE = "none"


@dataclass(frozen=True)
class XssTestDefinition:
    id: str
    family: XssTestFamily
    target_context: str
    objective: str
    risk_level: XssRiskLevel
    execution_limit: str
    interpretation_rule: str


XSS_TEST_DEFINITIONS: tuple[XssTestDefinition, ...] = (
    XssTestDefinition(
        id="xss.baseline",
        family=XssTestFamily.BASELINE,
        target_context="n/a -- pre-probe stability check",
        objective=(
            "Fetch the entry point with its own existing/default parameter "
            "value, untouched, to measure a stable reference response and "
            "screen out an endpoint this check cannot usefully read."
        ),
        risk_level=XssRiskLevel.NONE,
        execution_limit="max 1 request per endpoint, sent once",
        interpretation_rule=(
            "If the baseline matches a known WAF/block-page signature, is "
            "itself >=500, or is itself a redirect, no further XSS probing "
            "is attempted for this parameter -- recorded as an Observation, "
            "never a Finding."
        ),
    ),
    XssTestDefinition(
        id="xss.structural_marker",
        family=XssTestFamily.STRUCTURAL_MARKER,
        target_context="unknown until the response is parsed",
        objective=(
            "Inject one unique, inert alphanumeric token wrapped in the "
            "four metacharacters that determine escaping behavior across "
            "every XSS family in the reviewed corpus (double quote, single "
            "quote, '<', '>') into the GET parameter, then: (1) detect "
            "whether/where the bare token is reflected at all, (2) classify "
            "the real document context at that location (HTML text node, "
            "quoted/unquoted attribute value, script content, style "
            "content, HTML comment, or needs-further-analysis), and (3) "
            "determine whether each wrapping metacharacter survived raw, "
            "was HTML-entity-encoded, was returned as a literal percent- "
            "encoded or double-percent-encoded string, or was stripped."
        ),
        risk_level=XssRiskLevel.NONE,
        execution_limit=(
            "max 1 request per endpoint for the initial probe, plus 1 "
            "LAZY confirmation request only if a raw/partially-raw "
            "candidate is found -- max 2 requests total, never sent if the "
            "baseline guard above already skipped this parameter"
        ),
        interpretation_rule=(
            "No Finding when: the token is not reflected; every wrapping "
            "metacharacter is HTML-entity-encoded, URL-encoded, or double-"
            "encoded as a literal string; the reflection lands in an HTML "
            "comment or a context this check could not confidently "
            "classify; or a raw/partial candidate does not reproduce on "
            "the confirmation request. A Finding is raised only for a "
            "reproducing raw/partially-raw reflection in a recognized, "
            "interpretable context -- always at LOW confidence, never "
            "CONFIRMED, because this check never executes JavaScript and "
            "so can never prove a real exploit would actually run."
        ),
    ),
)


def definitions_by_family(family: XssTestFamily) -> tuple[XssTestDefinition, ...]:
    return tuple(d for d in XSS_TEST_DEFINITIONS if d.family == family)
