"""Reflected XSS check.

Probe definitions are in xss_payloads.py.

## Steps, for each testable entry point

1. Baseline: the parameter's original value, sent once. If it looks
   like a WAF block page, is a 5xx or a redirect, stop here
   (Observation only). Uses `fetch_pinned_url` with
   `follow_redirects=False`, since a redirected response can't be
   compared to the baseline.
2. Marker probe: one request with a unique token wrapped in `"'<`
   and `>`, the four characters that decide XSS risk. No real
   `<script>`, nothing that executes. If the token isn't in the
   response, there is nothing to analyze.
3. If the token is found:
   - `_classify_context` finds where it landed: HTML text, quoted or
     unquoted attribute, script, style, HTML comment, or
     "needs_further_analysis" when the parser isn't sure;
   - `_encoding_treatment` checks whether the characters came back
     raw, HTML-entity encoded, URL encoded as literal text, or were
     stripped.
4. Only a "raw" or "partial_raw" result in a context we can interpret
   is a candidate (never an HTML comment or "needs_further_analysis").
5. Content-Type: only responses declared as HTML are analyzed as
   markup. This trusts the declared header and does not sniff the
   body, so a server that mislabels its responses can fool it.
6. `_plausible_structural_break()` checks that the specific
   character that matters in that context survived raw. For example,
   a raw quote without a raw `<` in an HTML text node can't open a new
   tag. A plausible candidate is re-probed once; only a reproducing
   result becomes a Finding.

Findings always stay at LOW confidence: without a browser, the check
can't tell "this character is unescaped" from "a browser would
actually run something here".

## Non-HTML responses

JSON, XML, JavaScript and plain text responses get a separate, more
limited analysis (`_non_html_reflection_classification()`):
- "simple_marker_reflection": reflected, nothing more;
- "escaped_string_reflection": reflected inside a string, with the
  important character correctly escaped for that format;
- "potentially_executable_context": that character came back raw.

Only JavaScript responses (e.g. JSONP) can produce a Finding this way,
after the same reproduction check: a browser loading them with
`<script src>` really executes them. JSON is never executed on its
own, generic XML usually isn't either, and plain text never is, so
those are Observation only. Other types (images, PDF, CSS...) are not
probed at all."""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime, timezone

from app.engines.active_web_testing.entrypoints import EntryPoint
from app.engines.active_web_testing.registry import CheckInputs, CheckOutcome
from app.engines.active_web_testing.security.pinned_request import FetchedResponse, fetch_pinned_url, set_query_param, split_query_params
from app.engines.recon.collectors._secrets import redact_secrets
from app.engines.recon.context import ReconBudgetExceededError, ReconCancelledError
from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity

SLUG = "xss_reflected"
CATEGORY = "xss_reflected"

_OWASP_XSS = "A03:2021-Injection"
_DEFAULT_BASELINE_VALUE = "1"

# The four metacharacters whose escaping behavior determines XSS risk
# across every family in the reviewed corpus -- see xss_payloads.py.
# Prepended/appended around the unique marker so a single probe can
# answer "is it reflected", "where", and "is each of these escaped" at
# once, without sending four separate requests.
_STRUCTURAL_PREFIX = "\"'<"
_STRUCTURAL_SUFFIX = ">"

_RAW_PREFIX = re.compile(re.escape(_STRUCTURAL_PREFIX) + r"$")
_RAW_SUFFIX = re.compile(r"^" + re.escape(_STRUCTURAL_SUFFIX))
_ENTITY_PREFIX = re.compile(r"(&quot;|&#34;|&#x22;)(&#39;|&#x27;|&apos;)(&lt;|&#60;|&#x3c;)\s*$", re.IGNORECASE)
_ENTITY_SUFFIX = re.compile(r"^\s*(&gt;|&#62;|&#x3e;)", re.IGNORECASE)
_URLENC_PREFIX = re.compile(r"%22%27%3c$", re.IGNORECASE)
_URLENC_SUFFIX = re.compile(r"^%3e", re.IGNORECASE)
_DBLENC_PREFIX = re.compile(r"%2522%2527%253c$", re.IGNORECASE)
_DBLENC_SUFFIX = re.compile(r"^%253e", re.IGNORECASE)

_TAG_NAME_RE = re.compile(r"<\s*(/?)\s*([a-zA-Z][a-zA-Z0-9]*)")

# --- Content-Type gating ---------------------------------------------
# Only responses declared as HTML (or XHTML) are treated as markup.
# Anything else, including a missing or invalid header, never produces
# a Finding. Based on the declared type only, not the body.
_HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_NON_HTML_MEDIA_TYPES = frozenset(
    {
        "application/json", "application/javascript", "text/javascript",
        "application/xml", "text/xml", "application/octet-stream",
        "application/pdf", "application/zip", "multipart/form-data",
        "text/plain", "text/css", "text/csv",
    }
)
_NON_HTML_MEDIA_PREFIXES = ("image/", "audio/", "video/", "font/")


def _content_type_category(response: "FetchedResponse") -> tuple[str, str | None, str | None]:
    """Returns (category, raw_header_value, media_type).

    category is "html", "non_html" or "ambiguous". media_type is the
    declared type without parameters, lower-cased, or None if it can't
    be parsed (category is then "ambiguous"). Only the header is
    inspected, never the body."""
    raw = response.headers.get("content-type")
    if not raw or not raw.strip():
        return "ambiguous", raw, None
    media_type = raw.split(";", 1)[0].strip().lower()
    if not media_type or "/" not in media_type:
        return "ambiguous", raw, None
    if media_type in _HTML_MEDIA_TYPES:
        return "html", raw, media_type
    if media_type in _NON_HTML_MEDIA_TYPES or media_type.startswith(_NON_HTML_MEDIA_PREFIXES):
        return "non_html", raw, media_type
    if media_type.startswith("text/"):
        # An unrecognized text/* subtype (text/markdown, text/x-foo,
        # ...) is not HTML rendering either -- conservative default.
        return "non_html", raw, media_type
    # An unrecognized, non-text media type (a custom vendor type, a
    # typo, etc.) -- cannot be assumed to render as HTML.
    return "ambiguous", raw, media_type


# --- Non-HTML responses ------------------------------------------------
# Maps a "non_html" category to one of the four kinds we can analyze
# (json, xml, javascript, plain_text) and classifies the reflection.
# Does not touch the HTML functions above.
def _non_html_kind(media_type: str | None) -> str:
    """Maps a "non_html"-category media type to one of the four kinds
    this check analyzes further: "json", "xml", "javascript",
    "plain_text". Everything else -- images, audio, video, fonts,
    application/octet-stream, application/pdf, application/zip,
    multipart/form-data, text/css, text/csv, or an unrecognized text/*
    subtype -- maps to "other", which gets no secondary analysis at
    all (see the docstring: none of those formats has a documented
    in-browser execution pathway for a reflected string)."""
    if not media_type:
        return "other"
    mt = media_type.lower()
    if mt == "application/json" or mt.endswith("+json"):
        return "json"
    if mt in ("application/xml", "text/xml") or mt.endswith("+xml"):
        return "xml"
    if mt in ("application/javascript", "text/javascript"):
        return "javascript"
    if mt == "text/plain":
        return "plain_text"
    return "other"


def _locate_marker(body_text: str, marker: str) -> tuple[bool, str, str]:
    """Finds our injected marker in a non-HTML body and returns the same
    (reflected, prefix_window, suffix_window) shape the HTML path's own
    `interpret()` closure builds, without any HTML-specific context
    lookup (there is no tag/attribute/script structure to classify in
    JSON/XML/JavaScript/plain text)."""
    idx = body_text.find(marker)
    if idx == -1:
        return False, "", ""
    prefix_window = body_text[max(0, idx - 64) : idx]
    suffix_window = body_text[idx + len(marker) : idx + len(marker) + 64]
    return True, prefix_window, suffix_window


def _string_escape_tail_match(window: str, raw_char: str) -> tuple[str, str]:
    """Like `_strip_tail_match` above, but for JSON/JavaScript
    backslash-escaping instead of HTML-entity/URL-encoding: a
    backslash-escaped occurrence of `raw_char` at the tail of `window`
    is "escaped" (safe -- stays inside its string literal), a bare
    occurrence is "raw" (potentially breaks out of it), and anything
    else leaves `window` untouched as "absent". Checked BEFORE the bare
    case specifically so a backslash-escaped quote (two characters,
    "\\\"") is never misread as a raw one just because it also ends
    with the quote character."""
    if window.endswith("\\" + raw_char):
        return "escaped", window[: -(1 + len(raw_char))]
    if window.endswith(raw_char):
        return "raw", window[: -len(raw_char)]
    return "absent", window


def _json_or_js_char_states(prefix_window: str) -> dict[str, str]:
    """Peels our own injected prefix (`"'<`) off `prefix_window` from
    the tail inward, in the exact order it was injected (`<` last,
    then `'`, then `"` first) -- mirroring `_char_states`' own
    tail-adjacency reasoning above (never a bare substring/containment
    check, for the identical reason: a coincidental quote elsewhere in
    the window must never be mistaken for our own), but checking
    JSON/JavaScript backslash-escaping at each step instead of
    HTML-entity/URL-encoding. Without this peeling, a check that only
    looked at the window's literal last character would find `<` (our
    suffix-most injected character) immediately before the marker and
    never even reach the `"`/`'` characters that actually matter for
    JSON/JavaScript string breakout, however they came back."""
    lt_state, remainder = _string_escape_tail_match(prefix_window, "<")
    squote_state, remainder = _string_escape_tail_match(remainder, "'")
    dquote_state, _ = _string_escape_tail_match(remainder, '"')
    return {"lt": lt_state, "single_quote": squote_state, "double_quote": dquote_state}


def _non_html_reflection_classification(kind: str, prefix_window: str, suffix_window: str) -> str:
    """Classifies a confirmed non-HTML reflection into one of
    "simple_marker_reflection", "escaped_string_reflection",
    "raw_breaks_string" (JSON only -- see below), or
    "potentially_executable_context" -- see the module docstring's new
    section for which kinds can ever reach the last one. Reuses
    `_char_states` for XML (XML escapes "<" the same way HTML does,
    with "&lt;") rather than reinventing HTML-entity detection."""
    if kind in ("json", "javascript"):
        states = _json_or_js_char_states(prefix_window)
        double_quote, single_quote = states["double_quote"], states["single_quote"]
        if double_quote == "raw" or (kind == "javascript" and single_quote == "raw"):
            # JSON never reaches "potentially_executable_context" --
            # the caller only ever treats "javascript" as actionable; a
            # raw-breaking JSON reflection is still reported, just as
            # "raw_breaks_string", never escalated to a Finding.
            return "potentially_executable_context" if kind == "javascript" else "raw_breaks_string"
        if double_quote == "escaped" or (kind == "javascript" and single_quote == "escaped"):
            return "escaped_string_reflection"
        return "simple_marker_reflection"
    if kind == "xml":
        char_states = _char_states(prefix_window, suffix_window)
        if char_states["lt"] == "raw":
            return "potentially_executable_context"
        if char_states["lt"] == "encoded":
            return "escaped_string_reflection"
        return "simple_marker_reflection"
    # "plain_text": inert by construction -- a browser never executes
    # text/plain as markup or script, however the metacharacters come
    # back, so this is always the most conservative classification.
    return "simple_marker_reflection"


# --- Per-character check ----------------------------------------------
# Looks at each of the four injected characters separately, so the
# decision can require the specific character that matters in a given
# context, not just "something was raw nearby".
#
# Not a simple `raw_char in window` check: the page itself can contain
# the same character close by (e.g. a real `<p>` tag), which would look
# like our '<' survived. Each character is checked right next to where
# our injected sequence ends, in the order it was injected (prefix:
# dquote, squote, lt before the marker; suffix: gt right after).
def _strip_tail_match(window: str, raw_char: str, entities: tuple[str, ...], url_enc: str, double_enc: str) -> tuple[str, str]:
    if window.endswith(raw_char):
        return "raw", window[: -len(raw_char)]
    low = window.lower()
    for entity in entities:
        if low.endswith(entity.lower()):
            return "encoded", window[: -len(entity)]
    if low.endswith(url_enc.lower()):
        return "url_encoded", window[: -len(url_enc)]
    if low.endswith(double_enc.lower()):
        return "double_encoded", window[: -len(double_enc)]
    return "absent", window


def _char_states(prefix_window: str, suffix_window: str) -> dict[str, str]:
    lt_state, remainder = _strip_tail_match(prefix_window, "<", ("&lt;", "&#60;", "&#x3c;"), "%3c", "%253c")
    squote_state, remainder = _strip_tail_match(remainder, "'", ("&#39;", "&#x27;", "&apos;"), "%27", "%2527")
    dquote_state, _remainder = _strip_tail_match(remainder, '"', ("&quot;", "&#34;", "&#x22;"), "%22", "%2522")
    gt_state, _ = _strip_tail_match_from_start(suffix_window, ">", ("&gt;", "&#62;", "&#x3e;"), "%3e", "%253e")
    return {"double_quote": dquote_state, "single_quote": squote_state, "lt": lt_state, "gt": gt_state}


def _strip_tail_match_from_start(window: str, raw_char: str, entities: tuple[str, ...], url_enc: str, double_enc: str) -> tuple[str, str]:
    if window.startswith(raw_char):
        return "raw", window[len(raw_char) :]
    low = window.lower()
    for entity in entities:
        if low.startswith(entity.lower()):
            return "encoded", window[len(entity) :]
    if low.startswith(url_enc.lower()):
        return "url_encoded", window[len(url_enc) :]
    if low.startswith(double_enc.lower()):
        return "double_encoded", window[len(double_enc) :]
    return "absent", window


def _plausible_structural_break(context: str, char_states: dict[str, str]) -> bool:
    """Decides whether the metacharacters that actually survived raw
    could plausibly alter the HTML/JS structure AT THIS SPECIFIC
    context -- not just "some special character was reflected
    unescaped somewhere nearby". A raw quote sitting in plain HTML
    text is inert (nothing in HTML text is quote-delimited); a raw
    angle bracket sitting inside an already-quoted attribute value
    does nothing until the quote itself is closed. Each context below
    requires exactly the character(s) whose escaping is what a secure
    application actually needs to get right there."""
    if context == "html_text":
        # Only a raw '<' can open a new tag in plain text; raw quotes
        # are inert here.
        return char_states["lt"] == "raw"
    if context == "attribute_double_quoted":
        return char_states["double_quote"] == "raw"
    if context == "attribute_single_quoted":
        return char_states["single_quote"] == "raw"
    if context == "attribute_unquoted":
        # Either a raw '>' (ends the tag early) or a raw '<' (starts a
        # new one) breaks an unquoted attribute value; no quote is
        # delimiting it, so quotes surviving raw here are inert.
        return char_states["gt"] == "raw" or char_states["lt"] == "raw"
    if context == "script_content":
        # What matters inside a <script> block is breaking out of the
        # enclosing JS string literal -- a raw quote (whichever the
        # application itself used). Raw angle brackets alone are inert
        # to a JavaScript parser.
        return char_states["double_quote"] == "raw" or char_states["single_quote"] == "raw"
    if context == "style_content":
        # This probe carries no "</style>" sequence, so it cannot
        # plausibly break out of a CSS block regardless of which
        # metacharacters survived raw -- deliberately conservative.
        return False
    return False


def _testable_entry_points(entry_points: list[EntryPoint]) -> list[EntryPoint]:
    return [ep for ep in entry_points if ep.testable and ep.method == "GET" and ep.param_name]


def _baseline_value(entry_point: EntryPoint) -> str:
    existing = split_query_params(entry_point.url).get(entry_point.param_name or "")
    return existing if existing else _DEFAULT_BASELINE_VALUE


def _fetch(ctx, url: str, *, settings, where: str) -> "FetchedResponse":
    # follow_redirects=False, same reason as in sqli_differential.py.
    return fetch_pinned_url(
        ctx, url, max_response_bytes=settings.active_web_testing_max_response_bytes, where=where,
        follow_redirects=False,
    )


def _is_redirect(response: "FetchedResponse") -> bool:
    return 300 <= response.status_code < 400


def _body_text(response: "FetchedResponse") -> str:
    return response.body_bytes.decode("utf-8", errors="replace")


class _EndpointBudgetExhausted(Exception):
    """Internal signal: the shared per-endpoint tracker refused a
    request this function wanted to send. Caught one call up, never
    allowed to look like an endpoint-level fetch failure."""


def _probe(entry_point: EntryPoint, label: str, value: str, *, inputs: CheckInputs, settings) -> "FetchedResponse":
    if not inputs.request_tracker.allow(entry_point):
        raise _EndpointBudgetExhausted(label)
    test_url = set_query_param(entry_point.url, entry_point.param_name, value)
    response = _fetch(inputs.ctx, test_url, settings=settings, where=f"active_web_testing.xss:{entry_point.param_name}:{label}")
    inputs.request_tracker.record(entry_point)
    return response


def _classify_context(body_text: str, index: int) -> str:
    """Single-pass context classification with a small state machine.

    Not a full DOM parse, but it follows real tag, attribute, script,
    style and comment boundaries instead of a plain substring search.

    Returns one of: "html_text", "attribute_double_quoted",
    "attribute_single_quoted", "attribute_unquoted", "script_content",
    "style_content", "html_comment", "needs_further_analysis"."""
    pos = 0
    in_comment = False
    in_script = False
    in_style = False
    in_tag = False
    quote_char: str | None = None
    after_equals = False
    pending_tag_name: str | None = None
    n = min(index, len(body_text))

    while pos < n:
        if in_comment:
            close = body_text.find("-->", pos, n + 3)
            if close == -1 or close >= n:
                pos = n
                break
            pos = close + 3
            in_comment = False
            continue

        if in_script or in_style:
            close_tag = "</script" if in_script else "</style"
            idx = body_text.lower().find(close_tag, pos, n + len(close_tag))
            if idx == -1 or idx >= n:
                pos = n
                break
            end = body_text.find(">", idx, n + 1)
            pos = (end + 1) if (end != -1 and end < n) else n
            in_script = False
            in_style = False
            continue

        if in_tag:
            ch = body_text[pos]
            if quote_char:
                if ch == quote_char:
                    quote_char = None
                pos += 1
                continue
            if ch in ('"', "'"):
                quote_char = ch
                after_equals = False
                pos += 1
                continue
            if ch == ">":
                in_tag = False
                if pending_tag_name == "script":
                    in_script = True
                elif pending_tag_name == "style":
                    in_style = True
                pending_tag_name = None
                after_equals = False
                pos += 1
                continue
            if ch == "=":
                after_equals = True
                pos += 1
                continue
            if ch.isspace():
                after_equals = False
                pos += 1
                continue
            pos += 1
            continue

        # Not currently inside a tag/script/style/comment.
        if body_text.startswith("<!--", pos):
            in_comment = True
            pos += 4
            continue
        if body_text[pos] == "<":
            m = _TAG_NAME_RE.match(body_text, pos)
            is_closing = bool(m and m.group(1) == "/")
            tag_name = m.group(2).lower() if m else None
            in_tag = True
            after_equals = False
            pending_tag_name = tag_name if (tag_name and not is_closing) else None
            pos += 1
            continue
        pos += 1

    if in_comment:
        return "html_comment"
    if in_script:
        return "script_content"
    if in_style:
        return "style_content"
    if in_tag:
        if quote_char == '"':
            return "attribute_double_quoted"
        if quote_char == "'":
            return "attribute_single_quoted"
        if after_equals:
            return "attribute_unquoted"
        return "needs_further_analysis"
    return "html_text"


def _encoding_treatment(prefix_window: str, suffix_window: str) -> str:
    """Compares what surrounds the reflected marker with the four injected
    characters: raw, HTML-entity encoded, URL encoded or double encoded.

    Order matters: fully raw is checked first, then fully HTML encoded,
    then URL encoded text. URL encoded output is treated as safe: a
    literal "%3C" in HTML is just text, not a "<"."""
    if _RAW_PREFIX.search(prefix_window) and _RAW_SUFFIX.match(suffix_window):
        return "raw"
    if _ENTITY_PREFIX.search(prefix_window) and _ENTITY_SUFFIX.match(suffix_window):
        return "html_entity_encoded"
    if _URLENC_PREFIX.search(prefix_window) and _URLENC_SUFFIX.match(suffix_window):
        return "url_encoded_literal"
    if _DBLENC_PREFIX.search(prefix_window) and _DBLENC_SUFFIX.match(suffix_window):
        return "double_encoded_literal"
    if _RAW_PREFIX.search(prefix_window) or _RAW_SUFFIX.match(suffix_window):
        return "partial_raw"
    return "neutralized_or_stripped"


# Contexts where a Finding can be raised. A comment can't be broken by
# this probe (it has no "-->"), and "needs_further_analysis" means the
# parser wasn't sure, so both stay non-conclusive.
_INTERPRETABLE_CONTEXTS = frozenset(
    {
        "html_text",
        "attribute_double_quoted",
        "attribute_single_quoted",
        "attribute_unquoted",
        "script_content",
        "style_content",
    }
)
_RAW_TREATMENTS = frozenset({"raw", "partial_raw"})


def run(inputs: CheckInputs) -> CheckOutcome:
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    settings = inputs.settings

    candidates = _testable_entry_points(inputs.entry_points)
    observations: list[Observation] = []
    findings: list[Finding] = []
    endpoints_tested = 0
    requests_used = 0
    errors: list[str] = []

    observations.append(Observation("xss_reflected.candidate_entry_points", len(candidates), ObservationNature.OBSERVED))

    for entry_point in candidates:
        if len(findings) >= settings.active_web_testing_max_findings_per_check:
            break

        param = entry_point.param_name
        baseline_value = _baseline_value(entry_point)

        def obs(suffix: str, value, nature: ObservationNature = ObservationNature.OBSERVED, note: str | None = None) -> None:
            observations.append(Observation(f"xss_reflected.parameter.{param}.{suffix}", value, nature, note=note))

        try:
            baseline = _probe(entry_point, "baseline", baseline_value, inputs=inputs, settings=settings)
            requests_used += 1
        except _EndpointBudgetExhausted:
            continue
        except (ReconCancelledError, ReconBudgetExceededError):
            raise
        except Exception as exc:  # noqa: BLE001 -- one endpoint's failure must not abort the check
            errors.append(f"{param}: {exc.__class__.__name__}")
            continue

        endpoints_tested += 1
        baseline_text = _body_text(baseline)

        # --- Short-circuit guards (never spend further probe budget on
        # an endpoint this check cannot usefully read).
        waf_hit = next((sig for sig in settings.active_web_testing_sqli_waf_signatures if sig in baseline_text.lower()), None)
        if waf_hit:
            obs("waf_suspected", waf_hit, ObservationNature.OBSERVED, note="baseline response matches a known WAF/block-page signature -- no reflection probing attempted for this parameter")
            continue
        if baseline.status_code >= 500:
            obs("baseline_already_erroring", baseline.status_code, ObservationNature.OBSERVED, note="baseline itself returns a server error -- no stable reference to interpret a reflection against")
            continue
        if _is_redirect(baseline):
            obs("baseline_is_redirect", baseline.status_code, ObservationNature.OBSERVED, note="baseline itself redirects -- not a meaningful comparison surface for this check")
            continue

        # --- Content-Type gate (baseline). "ambiguous" and other non-HTML
        # types (images, pdf, css, zip...) are skipped: a reflected string
        # can't execute there. "html" goes through the normal analysis
        # below. json/xml/javascript/plain_text set `non_html_kind` and go
        # through the limited non-HTML path.
        baseline_ct_category, baseline_ct_raw, baseline_media_type = _content_type_category(baseline)
        non_html_kind: str | None = None
        if baseline_ct_category == "ambiguous":
            obs(
                "content_type_ambiguous",
                {"content_type": baseline_ct_raw},
                ObservationNature.OBSERVED,
                note=(
                    "baseline response's declared Content-Type is missing, malformed, or "
                    "unrecognized -- skipping reflection probing for this parameter; this is a "
                    "static, header-trusting check and cannot detect a server that mislabels its "
                    "own response"
                ),
            )
            continue
        if baseline_ct_category == "non_html":
            non_html_kind = _non_html_kind(baseline_media_type)
            if non_html_kind == "other":
                obs(
                    "content_type_not_html",
                    {"content_type": baseline_ct_raw, "non_html_kind": non_html_kind},
                    ObservationNature.OBSERVED,
                    note=(
                        "baseline response's declared Content-Type is not HTML and not one of the "
                        "non-HTML kinds this check analyzes further (json/xml/javascript/plain_text) "
                        "-- skipping reflection probing entirely for this parameter"
                    ),
                )
                continue
            obs(
                "content_type_not_html",
                {"content_type": baseline_ct_raw, "non_html_kind": non_html_kind},
                ObservationNature.OBSERVED,
                note=(
                    "baseline response's declared Content-Type is not HTML -- this check's "
                    "contextual HTML analysis (tag/attribute/script/style parsing) does not apply; "
                    "a separate, more limited reflection analysis for this content type runs below "
                    "instead"
                ),
            )

        marker = f"{settings.active_web_testing_xss_marker_prefix}{uuid.uuid4().hex[:8]}"
        probe_value = f"{_STRUCTURAL_PREFIX}{marker}{_STRUCTURAL_SUFFIX}"

        def interpret(body_text: str) -> tuple[bool, str | None, str | None, str, str]:
            """Returns (reflected, context, treatment, prefix_window,
            suffix_window). context/treatment are None when the marker
            is not reflected at all; the windows are always returned
            (empty strings when not reflected) so callers can run
            per-character plausibility analysis without re-deriving
            them."""
            idx = body_text.find(marker)
            if idx == -1:
                return False, None, None, "", ""
            prefix_window = body_text[max(0, idx - 64) : idx]
            suffix_window = body_text[idx + len(marker) : idx + len(marker) + 64]
            treatment = _encoding_treatment(prefix_window, suffix_window)
            # If our own injected prefix survived fully raw, the parser
            # must be asked about the state BEFORE those injected
            # characters -- otherwise the attacker's own raw '<' would
            # be mistaken for a tag genuinely present in the target's
            # original markup, hiding exactly the finding-worthy case
            # (see module docstring).
            context_index = idx - len(_STRUCTURAL_PREFIX) if _RAW_PREFIX.search(prefix_window) else idx
            context = _classify_context(body_text, max(0, context_index))
            return True, context, treatment, prefix_window, suffix_window

        try:
            probe_response = _probe(entry_point, "structural_marker", probe_value, inputs=inputs, settings=settings)
            requests_used += 1
        except _EndpointBudgetExhausted:
            obs("probe_skipped_budget_exhausted", True, ObservationNature.OBSERVED, note="the per-endpoint request budget was exhausted before the structural-marker probe could be sent")
            continue
        except (ReconCancelledError, ReconBudgetExceededError):
            raise
        except Exception as exc:  # noqa: BLE001 -- one endpoint's failure must not abort the check
            errors.append(f"{param}: {exc.__class__.__name__}")
            continue

        if _is_redirect(probe_response):
            obs("probe_redirected", True, ObservationNature.OBSERVED, note="the structural-marker probe itself produced a redirect -- excluded as an unreliable comparison")
            continue

        probe_waf_hit = next((sig for sig in settings.active_web_testing_sqli_waf_signatures if sig in _body_text(probe_response).lower()), None)
        if probe_waf_hit and probe_waf_hit not in baseline_text.lower():
            obs("probe_waf_suspected", probe_waf_hit, ObservationNature.OBSERVED, note="the probe response (not the baseline) matches a known WAF/block-page signature -- treated as non-concluant, no Finding raised")
            continue

        if non_html_kind is not None:
            # --- Non-HTML analysis path, separate from the HTML path below.
            probe_ct_category, probe_ct_raw, probe_media_type = _content_type_category(probe_response)
            probe_non_html_kind = (
                _non_html_kind(probe_media_type) if probe_ct_category == "non_html" else probe_ct_category
            )
            if probe_non_html_kind != non_html_kind:
                obs(
                    "non_html_probe_content_type_changed",
                    {"baseline_non_html_kind": non_html_kind, "probe_content_type": probe_ct_raw},
                    ObservationNature.OBSERVED,
                    note=(
                        "the probe response's declared Content-Type no longer matches the baseline's "
                        "non-HTML kind -- defense in depth, same as the HTML path's own probe-side "
                        "gate; treated as non-concluant, no Finding raised"
                    ),
                )
                continue

            reflected, prefix_window, suffix_window = _locate_marker(_body_text(probe_response), marker)
            if not reflected:
                obs(
                    "non_html_reflected", False, ObservationNature.OBSERVED,
                    note=f"marker not found in a {non_html_kind} response -- analysis limited by content type, nothing further to classify",
                )
                continue

            classification = _non_html_reflection_classification(non_html_kind, prefix_window, suffix_window)

            if non_html_kind != "javascript" or classification != "potentially_executable_context":
                obs(
                    "non_html_reflection_classification",
                    {"non_html_kind": non_html_kind, "classification": classification},
                    ObservationNature.OBSERVED,
                    note=(
                        f"reflection analyzed as a {non_html_kind} response (analysis limited by "
                        f"content type, not this check's full HTML context/encoding/plausibility "
                        f"pipeline): classified as {classification}. "
                        + (
                            "a JSON response is never executed as script by a browser on its own, so "
                            "this is never escalated to a Finding here, however its metacharacters "
                            "come back -- see the module docstring's own closing note on this."
                            if non_html_kind == "json"
                            else "an XML response's embedded-markup execution pathway is not reliably "
                            "true for a generic application/xml or text/xml response (unlike actual "
                            "SVG/XHTML, already classified as HTML above) -- Observation only, no "
                            "Finding raised."
                            if non_html_kind == "xml"
                            else "a text/plain response is never rendered as markup or executed as "
                            "script by a browser, however its metacharacters come back -- Observation "
                            "only, no Finding raised."
                            if non_html_kind == "plain_text"
                            else "no raw-breaking string-literal escape was found, or this isn't the "
                            "one non-HTML kind (javascript) this check can ever raise a Finding for -- "
                            "Observation only, no Finding raised."
                        )
                    ),
                )
                continue

            # --- Only "javascript" + "potentially_executable_context"
            # reaches here: a raw, unescaped quote came back adjacent to
            # our injected marker in a response declared as executable
            # JavaScript (e.g. a JSONP-style API) -- analogous to the
            # HTML path's own `script_content` context. Same lazy
            # reproduction gate as the HTML path: a one-off reflection
            # is never enough.
            try:
                confirm_response = _probe(entry_point, "non_html_structural_marker_confirm", probe_value, inputs=inputs, settings=settings)
                requests_used += 1
            except _EndpointBudgetExhausted:
                obs(
                    "non_html_candidate_unconfirmed", {"non_html_kind": non_html_kind, "classification": classification}, ObservationNature.INFERRED,
                    note="a candidate potentially-executable JavaScript reflection was found but the per-endpoint request budget was exhausted before it could be re-confirmed -- treated as unconfirmed, no Finding raised",
                )
                continue
            except (ReconCancelledError, ReconBudgetExceededError):
                raise
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{param}: {exc.__class__.__name__}")
                continue

            if _is_redirect(confirm_response):
                obs("non_html_candidate_unconfirmed", {"non_html_kind": non_html_kind, "classification": classification}, ObservationNature.INFERRED, note="confirmation request redirected -- treated as unconfirmed, no Finding raised")
                continue

            confirm_ct_category, _confirm_ct_raw, confirm_media_type = _content_type_category(confirm_response)
            confirm_non_html_kind = (
                _non_html_kind(confirm_media_type) if confirm_ct_category == "non_html" else confirm_ct_category
            )
            confirmed_reflected, confirm_prefix, confirm_suffix = _locate_marker(_body_text(confirm_response), marker)
            confirmed_classification = (
                _non_html_reflection_classification(non_html_kind, confirm_prefix, confirm_suffix)
                if confirmed_reflected
                else None
            )
            reproduced = confirm_non_html_kind == non_html_kind and confirmed_classification == classification

            if not reproduced:
                obs(
                    "non_html_reflection_not_reproducible", {"non_html_kind": non_html_kind, "classification": classification}, ObservationNature.INFERRED,
                    note="a candidate potentially-executable JavaScript reflection did not reproduce identically on a confirmation request -- treated as suspect/non-concluant, no Finding raised",
                )
                continue

            obs(
                "non_html_reflected_potentially_executable", {"non_html_kind": non_html_kind, "classification": classification}, ObservationNature.INFERRED,
                note="a unique, inert marker's raw quote survived adjacent to it in a response declared as executable JavaScript, and this reproduced on an independent confirmation request -- a suspect indicator, not a confirmed XSS",
            )
            findings.append(
                Finding(
                    check=SLUG,
                    title=f"Unescaped reflection of parameter '{param}' in a JavaScript response (unconfirmed XSS indicator)",
                    description=(
                        f"A unique, inert test marker, sent in the '{param}' parameter, was found "
                        f"reproduced in a response declared as {probe_media_type or 'application/javascript'}, "
                        "with a raw, unescaped quote immediately adjacent to it -- potentially breaking "
                        "out of a JavaScript string literal if this response is loaded as a script "
                        "(e.g. a JSONP-style <script src=\"...\"> inclusion), and this reproduced on an "
                        "independent confirmation request. This is a suspect indicator only -- this "
                        "check never executed any script and never rendered the response in a browser; "
                        "it is NOT a confirmed cross-site-scripting vulnerability."
                    ),
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.LOW,
                    impact="If this response is genuinely consumed as executable JavaScript by a browser (e.g. via <script src>), attacker-controlled script execution could result -- unconfirmed by this check, which performs no real JavaScript execution.",
                    remediation="Correctly escape this parameter's value for a JavaScript string literal (backslash-escape quotes and backslashes) before writing it into a response served as JavaScript, then re-verify with a controlled, separately-authorized active test.",
                    affected_url=redact_secrets(entry_point.url),
                    http_method="GET",
                    cwe_id="CWE-79",
                    owasp_category=_OWASP_XSS,
                    evidence={
                        "parameter": param,
                        "source": entry_point.source,
                        "non_html_kind": non_html_kind,
                        "classification": classification,
                        "content_type": baseline_ct_raw,
                        "reproduced": True,
                    },
                )
            )
            continue

        # --- Content-Type gate (probe). Re-checked in case the probe
        # response has a different Content-Type than the baseline.
        probe_ct_category, probe_ct_raw, probe_media_type = _content_type_category(probe_response)
        if probe_ct_category != "html":
            obs(
                "probe_content_type_not_html" if probe_ct_category == "non_html" else "probe_content_type_ambiguous",
                {"content_type": probe_ct_raw},
                ObservationNature.OBSERVED,
                note="the probe response's declared Content-Type differs from the baseline and is not confirmed HTML -- treated as non-concluant, no Finding raised",
            )
            continue

        reflected, context, treatment, prefix_window, suffix_window = interpret(_body_text(probe_response))

        if not reflected:
            obs("reflected", False, ObservationNature.OBSERVED)
            continue

        if treatment not in _RAW_TREATMENTS or context not in _INTERPRETABLE_CONTEXTS:
            obs(
                "reflected_non_actionable",
                {"context": context, "treatment": treatment},
                ObservationNature.OBSERVED,
                note="marker reflected but either safely encoded, or in a context/encoding combination this check does not raise a Finding for (HTML comment, unclassifiable context, or fully encoded/stripped metacharacters) -- documented as non-concluant",
            )
            continue

        # --- Plausibility check: a raw result isn't enough, the specific
        # character that matters in this context must be the one that
        # came back raw (see _plausible_structural_break).
        char_states = _char_states(prefix_window, suffix_window)
        if not _plausible_structural_break(context, char_states):
            obs(
                "reflected_raw_but_not_structurally_plausible",
                {"context": context, "treatment": treatment, "char_states": char_states},
                ObservationNature.OBSERVED,
                note=(
                    "a metacharacter survived raw/partially-raw, but not the specific one(s) that "
                    "could actually alter the HTML/JS structure in this context -- an inert "
                    "indicator, not a plausible structural break; no Finding raised"
                ),
            )
            continue

        # --- Candidate found: confirm it with a second identical probe
        # before creating a Finding. A one-off reflection is not enough.
        try:
            confirm_response = _probe(entry_point, "structural_marker_confirm", probe_value, inputs=inputs, settings=settings)
            requests_used += 1
        except _EndpointBudgetExhausted:
            obs(
                "candidate_unconfirmed", {"context": context, "treatment": treatment}, ObservationNature.INFERRED,
                note="a candidate raw/partially-raw reflection was found but the per-endpoint request budget was exhausted before it could be re-confirmed -- treated as unconfirmed, no Finding raised",
            )
            continue
        except (ReconCancelledError, ReconBudgetExceededError):
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{param}: {exc.__class__.__name__}")
            continue

        if _is_redirect(confirm_response):
            obs("candidate_unconfirmed", {"context": context, "treatment": treatment}, ObservationNature.INFERRED, note="confirmation request redirected -- treated as unconfirmed, no Finding raised")
            continue

        confirm_ct_category, _confirm_ct_raw, confirm_media_type = _content_type_category(confirm_response)
        confirmed_reflected, confirmed_context, confirmed_treatment, confirm_prefix, confirm_suffix = interpret(_body_text(confirm_response))
        confirmed_plausible = confirmed_reflected and _plausible_structural_break(
            confirmed_context, _char_states(confirm_prefix, confirm_suffix)
        )
        reproduced = (
            confirm_ct_category == "html"
            and confirmed_reflected
            and confirmed_context == context
            and confirmed_treatment == treatment
            and confirmed_plausible
        )

        if not reproduced:
            obs(
                "reflection_not_reproducible", {"context": context, "treatment": treatment}, ObservationNature.INFERRED,
                note="a candidate raw/partially-raw reflection did not reproduce identically on a confirmation request -- treated as suspect/non-concluant, no Finding raised",
            )
            continue

        obs(
            "reflected_unescaped", {"context": context, "treatment": treatment}, ObservationNature.INFERRED,
            note="a unique, inert structural marker was reflected with its metacharacters raw/partially-raw, in an interpretable context, and this reproduced on an independent confirmation request -- a suspect indicator, not a confirmed XSS",
        )
        severity = FindingSeverity.HIGH if context == "script_content" and treatment == "raw" else FindingSeverity.MEDIUM
        findings.append(
            Finding(
                check=SLUG,
                title=f"Unescaped reflection of parameter '{param}' (unconfirmed XSS indicator)",
                description=(
                    f"A unique, inert test marker wrapped in HTML/attribute metacharacters, sent in "
                    f"the '{param}' parameter, was found reproduced in the response body with its "
                    f"metacharacters {treatment.replace('_', ' ')}, in what this check's context "
                    f"analysis classifies as a {context.replace('_', ' ')} context, and this "
                    "reproduced on an independent confirmation request. This is a suspect indicator "
                    "only -- this check never executed any script and never rendered the response in "
                    "a browser; it is NOT a confirmed cross-site-scripting vulnerability. A raw, "
                    "unescaped metacharacter in a potentially dangerous context is necessary but not "
                    "sufficient for real exploitation -- the surrounding markup, the target's actual "
                    "parser/browser behavior, and any client-side script that would need to run are "
                    "all unverified by this check."
                ),
                severity=severity,
                confidence=FindingConfidence.LOW,
                impact="If this reflection is genuinely unescaped and reachable in a browser-rendered context, it could allow attacker-controlled script execution -- unconfirmed by this check, which performs no real JavaScript execution.",
                remediation="Context-appropriately encode/escape this parameter's value before writing it into the response (HTML-entity encode in body/attribute context, JS-string-escape in script context, CSS-escape in style context), then re-verify with a controlled, separately-authorized active test.",
                affected_url=redact_secrets(entry_point.url),
                http_method="GET",
                cwe_id="CWE-79",
                owasp_category=_OWASP_XSS,
                evidence={
                    "parameter": param,
                    "source": entry_point.source,
                    "context": context,
                    "encoding_treatment": treatment,
                    "content_type": baseline_ct_raw,
                    "structural_break_basis": {k: v for k, v in char_states.items() if v == "raw"},
                    "reproduced": True,
                },
            )
        )

    return CheckOutcome(
        collector_result=CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK if not errors else CollectorStatus.PARTIAL,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={
                "findings_count": len(findings),
                "endpoints_tested": endpoints_tested,
                "requests_used": requests_used,
            },
            errors=errors,
            source=SLUG,
            confidence=ConfidenceLevel.MEDIUM,
        ),
        findings=findings,
    )
