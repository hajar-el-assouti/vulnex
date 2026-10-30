"""SQL injection check, differential and non-destructive.

For each entry point, sends a short sequence of GET requests, limited
by Settings.active_web_testing_max_requests_per_endpoint (shared with
the other checks). Probe definitions are in sqli_payloads.py.

Skipped before sending anything (recorded as an Observation):
- the baseline looks like a WAF block page;
- the baseline is already a 5xx;
- the baseline is a redirect.

Round 1:
1. Baseline, sent twice, to measure the normal noise of the response.
2. Quote probe: a single quote appended to the value. Checked for a
   known SQL error message not present in the baseline, and for a
   status/length anomaly (Observation only, never a Finding).
3. Semicolon probe: same anomaly check with a different malformation.
4. Boolean probes: `' OR '1'='1` and `' OR '1'='2`. Candidate only if
   the TRUE response looks like the baseline while the FALSE response
   differs from both by more than the noise.

Round 2 (only if round 1 found a candidate): the same probes are
re-sent. The signal must reproduce, otherwise it stays a suspect
Observation. If the budget runs out before confirmation, the signal
is treated as unconfirmed.

The boolean comparison uses both response length and content
similarity (token-level Jaccard, cheaper than a full diff on large
bodies). If TRUE and FALSE return the same content but both differ
from the baseline, the endpoint is probably just ignoring a malformed
query, so it is flagged as non-conclusive. The same type of signal
(length or content) must reproduce in round 2.

No UNION, no time-based payloads, no stacked queries, nothing that
writes. Findings are capped at MEDIUM confidence, never CONFIRMED:
they are indicators that need a manual, authorized follow-up."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.active_web_testing.checks.sqli_payloads import lookup_engine_hint
from app.engines.active_web_testing.entrypoints import EntryPoint
from app.engines.active_web_testing.registry import CheckInputs, CheckOutcome
from app.engines.active_web_testing.security.pinned_request import FetchedResponse, fetch_pinned_url, set_query_param, split_query_params
from app.engines.recon.collectors._secrets import redact_secrets
from app.engines.recon.context import ReconBudgetExceededError, ReconCancelledError
from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.engines.web_vuln.findings import Finding, FindingConfidence, FindingSeverity

SLUG = "sqli_differential"
CATEGORY = "sqli_differential"

_OWASP_SQLI = "A03:2021-Injection"
_DEFAULT_BASELINE_VALUE = "1"
# A response-length difference smaller than this many bytes beyond the
# measured baseline-vs-baseline noise is never treated as a signal --
# avoids a one-byte timestamp drift being mistaken for a boolean
# divergence.
_MIN_MEANINGFUL_LENGTH_DELTA = 8

# How similar two normalized bodies must be (token-level Jaccard,
# 0.0-1.0) to count as the same content. Kept close to 1.0 so normal
# noise (a timestamp, a request id) doesn't look like an asymmetry.
_CONTENT_SIMILARITY_MATCH_THRESHOLD = 0.92
# Caps the cost of the token-level comparison below for a very large
# response body -- a corroborating Observation never needs to inspect
# more than this many tokens to be useful.
_MAX_COMPARED_TOKENS = 5000


def _normalize_text(text: str) -> str:
    """Collapses whitespace runs to a single space and strips leading/
    trailing whitespace -- the minimum normalization needed so that a
    purely cosmetic formatting difference (indentation, a trailing
    newline, one extra blank line) never registers as a genuine
    content difference below."""
    return " ".join(text.split())


def _content_similarity(text_a: str, text_b: str) -> float:
    """A cheap (linear, never full sequence alignment), token-level
    Jaccard similarity between two normalized response bodies: the
    fraction of distinct tokens they share. 1.0 means identical token
    sets, 0.0 means no shared tokens at all. See the module docstring's
    new section for why this is deliberately NOT
    difflib.SequenceMatcher (worst-case quadratic) -- a bounded-cost
    approximate signal is the right trade-off for a corroborating
    Observation, never the sole basis for a Finding by itself."""
    tokens_a = set(_normalize_text(text_a).split(" ")[:_MAX_COMPARED_TOKENS])
    tokens_b = set(_normalize_text(text_b).split(" ")[:_MAX_COMPARED_TOKENS])
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def _boolean_signal(true_text: str, false_text: str, baseline_text: str, threshold: int) -> dict:
    """Computes the length and content metrics for one round of
    TRUE/FALSE probes. Used for both round 1 and the confirmation
    round, so the same formula decides a candidate and its
    reproduction."""
    true_delta = abs(len(true_text) - len(baseline_text))
    false_delta = abs(len(false_text) - len(baseline_text))
    true_vs_false_delta = abs(len(true_text) - len(false_text))
    length_asymmetric = true_delta <= threshold and false_delta > threshold and true_vs_false_delta > threshold

    true_vs_baseline_similarity = _content_similarity(true_text, baseline_text)
    false_vs_baseline_similarity = _content_similarity(false_text, baseline_text)
    true_vs_false_similarity = _content_similarity(true_text, false_text)
    content_asymmetric = (
        true_vs_baseline_similarity >= _CONTENT_SIMILARITY_MATCH_THRESHOLD
        and false_vs_baseline_similarity < _CONTENT_SIMILARITY_MATCH_THRESHOLD
        and true_vs_false_similarity < _CONTENT_SIMILARITY_MATCH_THRESHOLD
    )

    # TRUE and FALSE return near-identical content, and both differ from
    # the baseline. Both probes behaved the same way, which points to the
    # endpoint's normal handling of a malformed query (e.g. falling back to
    # an unfiltered list), not to SQLi. Flagged as non-conclusive.
    non_conclusive_same_fallback = (
        not length_asymmetric
        and not content_asymmetric
        and true_vs_baseline_similarity < _CONTENT_SIMILARITY_MATCH_THRESHOLD
        and false_vs_baseline_similarity < _CONTENT_SIMILARITY_MATCH_THRESHOLD
        and true_vs_false_similarity >= _CONTENT_SIMILARITY_MATCH_THRESHOLD
    )

    return {
        "asymmetric": length_asymmetric or content_asymmetric,
        "length_asymmetric": length_asymmetric,
        "content_asymmetric": content_asymmetric,
        "non_conclusive_same_fallback": non_conclusive_same_fallback,
        "true_delta": true_delta,
        "false_delta": false_delta,
        "true_vs_false_delta": true_vs_false_delta,
        "true_vs_baseline_similarity": round(true_vs_baseline_similarity, 4),
        "false_vs_baseline_similarity": round(false_vs_baseline_similarity, 4),
        "true_vs_false_similarity": round(true_vs_false_similarity, 4),
    }


def _testable_entry_points(entry_points: list[EntryPoint]) -> list[EntryPoint]:
    return [ep for ep in entry_points if ep.testable and ep.method == "GET" and ep.param_name]


def _baseline_value(entry_point: EntryPoint) -> str:
    existing = split_query_params(entry_point.url).get(entry_point.param_name or "")
    return existing if existing else _DEFAULT_BASELINE_VALUE


def _fetch(ctx, url: str, *, settings, where: str):
    # follow_redirects=False: if a probe gets redirected, following it
    # would compare a different page than the baseline and spend extra
    # requests. Returning the redirect itself lets the check detect it and
    # exclude it (see _is_redirect()).
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


def _probe(
    entry_point: EntryPoint, label: str, value: str, *, inputs: CheckInputs, settings
) -> "FetchedResponse":
    if not inputs.request_tracker.allow(entry_point):
        raise _EndpointBudgetExhausted(label)
    test_url = set_query_param(entry_point.url, entry_point.param_name, value)
    response = _fetch(
        inputs.ctx, test_url, settings=settings,
        where=f"active_web_testing.sqli:{entry_point.param_name}:{label}",
    )
    inputs.request_tracker.record(entry_point)
    return response


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

    observations.append(Observation("sqli_differential.candidate_entry_points", len(candidates), ObservationNature.OBSERVED))

    for entry_point in candidates:
        if len(findings) >= settings.active_web_testing_max_findings_per_check:
            break

        param = entry_point.param_name
        baseline_value = _baseline_value(entry_point)

        def obs(suffix: str, value, nature: ObservationNature = ObservationNature.OBSERVED, note: str | None = None) -> None:
            observations.append(Observation(f"sqli_differential.parameter.{param}.{suffix}", value, nature, note=note))

        try:
            baseline_1 = _probe(entry_point, "baseline_1", baseline_value, inputs=inputs, settings=settings)
            requests_used += 1
            baseline_2 = _probe(entry_point, "baseline_2", baseline_value, inputs=inputs, settings=settings)
            requests_used += 1
        except _EndpointBudgetExhausted:
            continue
        except (ReconCancelledError, ReconBudgetExceededError):
            raise
        except Exception as exc:  # noqa: BLE001 -- one endpoint's failure must not abort the check
            errors.append(f"{param}: {exc.__class__.__name__}")
            continue

        endpoints_tested += 1
        baseline_1_text = _body_text(baseline_1)
        baseline_2_text = _body_text(baseline_2)
        noise = abs(len(baseline_1_text) - len(baseline_2_text))
        threshold = max(noise, _MIN_MEANINGFUL_LENGTH_DELTA)

        # --- Short-circuit guards (never spend the probe budget past
        # this point for an endpoint this check cannot usefully read).
        waf_hit = next(
            (
                sig for sig in settings.active_web_testing_sqli_waf_signatures
                if sig in baseline_1_text.lower() or sig in baseline_2_text.lower()
            ),
            None,
        )
        if waf_hit:
            obs("waf_suspected", waf_hit, ObservationNature.OBSERVED, note="baseline response matches a known WAF/block-page signature -- no further SQLi probing attempted for this parameter")
            continue
        if baseline_1.status_code >= 500 or baseline_2.status_code >= 500:
            obs("baseline_already_erroring", {"baseline_1": baseline_1.status_code, "baseline_2": baseline_2.status_code}, ObservationNature.OBSERVED, note="baseline itself returns a server error -- no stable reference to diff probes against")
            continue
        if _is_redirect(baseline_1) or _is_redirect(baseline_2):
            obs("baseline_is_redirect", {"baseline_1": baseline_1.status_code, "baseline_2": baseline_2.status_code}, ObservationNature.OBSERVED, note="baseline itself redirects -- not a meaningful comparison surface for this check")
            continue

        # --- Round 1 probes: error/syntax(quote), syntax(semicolon), boolean true/false.
        try:
            error_probe_value = baseline_value + settings.active_web_testing_sqli_error_probe
            error_resp = _probe(entry_point, "error", error_probe_value, inputs=inputs, settings=settings)
            requests_used += 1
            syntax_probe_value = baseline_value + settings.active_web_testing_sqli_syntax_probe
            syntax_resp = _probe(entry_point, "syntax", syntax_probe_value, inputs=inputs, settings=settings)
            requests_used += 1
            true_resp = _probe(entry_point, "bool_true", settings.active_web_testing_sqli_boolean_true_probe, inputs=inputs, settings=settings)
            requests_used += 1
            false_resp = _probe(entry_point, "bool_false", settings.active_web_testing_sqli_boolean_false_probe, inputs=inputs, settings=settings)
            requests_used += 1
        except _EndpointBudgetExhausted:
            continue
        except (ReconCancelledError, ReconBudgetExceededError):
            raise
        except Exception as exc:  # noqa: BLE001 -- one endpoint's failure must not abort the check
            errors.append(f"{param}: {exc.__class__.__name__}")
            continue

        error_text = _body_text(error_resp)
        syntax_text = _body_text(syntax_resp)
        true_text = _body_text(true_resp)
        false_text = _body_text(false_resp)

        # --- Ignored-parameter guard (purely informational -- nothing
        # below would fire anyway when every probe is byte-identical,
        # but an explicit Observation is clearer for an operator than
        # silence).
        if len({baseline_1_text, baseline_2_text, error_text, syntax_text, true_text, false_text}) == 1:
            obs("parameter_appears_ignored", True, ObservationNature.OBSERVED, note="every probe produced a byte-identical response to the baseline -- the application does not appear to use this parameter's value")

        # --- Error-based signal -----------------------------------------
        baseline_signatures = {
            sig for sig in settings.active_web_testing_sql_error_signatures
            if sig in baseline_1_text.lower() or sig in baseline_2_text.lower()
        }
        round1_matched = (
            []
            if _is_redirect(error_resp)
            else [
                sig for sig in settings.active_web_testing_sql_error_signatures
                if sig in error_text.lower() and sig not in baseline_signatures
            ]
        )
        if _is_redirect(error_resp):
            obs("error_probe_redirected", True, ObservationNature.OBSERVED, note="the error probe itself produced a redirect -- excluded from error-signature analysis as an unreliable comparison")

        confirmed_signatures: list[str] = []
        if round1_matched:
            if settings.active_web_testing_sqli_require_error_reproduction:
                try:
                    confirm_resp = _probe(entry_point, "error_confirm", error_probe_value, inputs=inputs, settings=settings)
                    requests_used += 1
                    confirm_text = _body_text(confirm_resp)
                    confirmed_signatures = [sig for sig in round1_matched if sig in confirm_text.lower()]
                except _EndpointBudgetExhausted:
                    confirmed_signatures = []
                    obs("error_signature_unconfirmed", round1_matched, ObservationNature.INFERRED, note="a candidate error signature was found but the per-endpoint request budget was exhausted before it could be re-confirmed -- treated as unconfirmed, no Finding raised")
                except (ReconCancelledError, ReconBudgetExceededError):
                    raise
                except Exception:  # noqa: BLE001 -- confirmation failing must never abort the endpoint
                    confirmed_signatures = []
            else:
                confirmed_signatures = round1_matched

        if confirmed_signatures:
            engine_hints = {
                sig: lookup_engine_hint(sig, settings.active_web_testing_sql_error_engine_hints)
                for sig in confirmed_signatures
            }
            likely_engine = next((v for v in engine_hints.values() if v), None)
            obs(
                "error_signature", confirmed_signatures, ObservationNature.INFERRED,
                note="a SQL-driver error signature appeared only after the error probe (never in either baseline response) and reproduced on a confirmation request",
            )
            findings.append(
                Finding(
                    check=SLUG,
                    title=f"Possible error-based SQL injection indicator on parameter '{param}'",
                    description=(
                        f"Appending a single quote to the '{param}' parameter's "
                        "value produced a response containing a database-driver error signature "
                        "that was absent from two otherwise-identical baseline requests, and the "
                        "same signature reproduced on an independent confirmation request. This is "
                        "a differential signal, not a confirmed SQL injection -- no data was "
                        "extracted, no schema was enumerated, and no further exploitation was "
                        "attempted."
                        + (f" The signature is characteristic of {likely_engine}." if likely_engine else "")
                    ),
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.MEDIUM,
                    impact="If a real SQL injection exists here, it could allow unauthorized data access or manipulation -- unconfirmed by this check, which only observes error-message signatures.",
                    remediation="Use parameterized queries / prepared statements for this parameter, verify with a controlled, separately-authorized follow-up, and ensure database error details are never shown directly to users.",
                    affected_url=redact_secrets(entry_point.url),
                    http_method="GET",
                    cwe_id="CWE-89",
                    owasp_category=_OWASP_SQLI,
                    evidence={
                        "parameter": param,
                        "source": entry_point.source,
                        "matched_signatures": confirmed_signatures,
                        "likely_db_engine": likely_engine,
                        "reproduced": True,
                    },
                )
            )
        elif round1_matched:
            obs(
                "error_signature_not_reproducible", round1_matched, ObservationNature.INFERRED,
                note="a candidate error signature appeared once but did not reproduce on a confirmation request -- treated as suspect/non-concluant, no Finding raised",
            )
        else:
            obs("error_signature", False, ObservationNature.OBSERVED)

        # --- Syntax-based anomaly (semicolon probe) -- corroborating
        # Observation ONLY, never a Finding by itself ("ne jamais
        # conclure à une SQL injection à partir d'un simple HTTP 500").
        syntax_anomaly = False
        if _is_redirect(syntax_resp):
            obs("syntax_probe_redirected", True, ObservationNature.OBSERVED, note="the syntax probe itself produced a redirect -- excluded from anomaly analysis as an unreliable comparison")
        else:
            status_flip = syntax_resp.status_code != baseline_1.status_code and (syntax_resp.status_code >= 500 or baseline_1.status_code >= 500)
            length_delta = abs(len(syntax_text) - len(baseline_1_text))
            syntax_anomaly = status_flip or length_delta > threshold
            if syntax_anomaly:
                obs(
                    "syntax_anomaly",
                    {"status_code": syntax_resp.status_code, "baseline_status_code": baseline_1.status_code, "length_delta": length_delta, "noise_threshold": threshold},
                    ObservationNature.INFERRED,
                    note="a bare syntax character produced a status or length anomaly versus baseline -- a corroborating indicator only, never sufficient on its own to conclude SQL injection",
                )
            else:
                obs("syntax_anomaly", False, ObservationNature.OBSERVED)

        # --- Boolean-based signal: length + normalized content comparison
        if _is_redirect(true_resp) or _is_redirect(false_resp):
            obs("boolean_probe_redirected", True, ObservationNature.OBSERVED, note="a boolean probe produced a redirect -- excluded from boolean-asymmetry analysis as an unreliable comparison")
            signal1 = None
            asymmetric1 = False
        else:
            signal1 = _boolean_signal(true_text, false_text, baseline_1_text, threshold)
            asymmetric1 = signal1["asymmetric"]
            # Always record a diagnostic of the TRUE/FALSE comparison, so the
            # user can see why this parameter was or wasn't flagged.
            obs(
                "boolean_diagnostic",
                {k: v for k, v in signal1.items() if k != "asymmetric"},
                ObservationNature.OBSERVED,
                note="diagnostic comparison of the TRUE/FALSE boolean probes against baseline, by both response length and normalized (whitespace-collapsed, token-level) content similarity",
            )
            if signal1["non_conclusive_same_fallback"]:
                obs(
                    "boolean_probe_non_conclusive_same_fallback", True, ObservationNature.INFERRED,
                    note="the TRUE and FALSE probes produced near-identical (or byte-identical) content that both diverge from baseline -- there is nothing asymmetric about this, and it is far more consistent with the endpoint's own natural behavior on an unrecognized/malformed query (e.g. falling back to an unfiltered listing) than with a boolean SQLi signal; explicitly non-concluant, no Finding raised",
                )

        boolean_confirmed = False
        signal2 = None
        if asymmetric1 and not round1_matched:
            if settings.active_web_testing_sqli_require_boolean_reproduction:
                try:
                    true_resp_2 = _probe(entry_point, "bool_true_confirm", settings.active_web_testing_sqli_boolean_true_probe, inputs=inputs, settings=settings)
                    requests_used += 1
                    false_resp_2 = _probe(entry_point, "bool_false_confirm", settings.active_web_testing_sqli_boolean_false_probe, inputs=inputs, settings=settings)
                    requests_used += 1
                    if not (_is_redirect(true_resp_2) or _is_redirect(false_resp_2)):
                        true_text_2 = _body_text(true_resp_2)
                        false_text_2 = _body_text(false_resp_2)
                        signal2 = _boolean_signal(true_text_2, false_text_2, baseline_1_text, threshold)
                        # Each signal type must reproduce on its own: a round-1 candidate
                        # based on length can't be "confirmed" by a content difference, and
                        # vice versa.
                        boolean_confirmed = (
                            (signal1["length_asymmetric"] and signal2["length_asymmetric"])
                            or (signal1["content_asymmetric"] and signal2["content_asymmetric"])
                        )
                except _EndpointBudgetExhausted:
                    boolean_confirmed = False
                    obs("boolean_asymmetry_unconfirmed", True, ObservationNature.INFERRED, note="a candidate boolean asymmetry was found but the per-endpoint request budget was exhausted before it could be re-confirmed -- treated as unconfirmed, no Finding raised")
                except (ReconCancelledError, ReconBudgetExceededError):
                    raise
                except Exception:  # noqa: BLE001 -- confirmation failing must never abort the endpoint
                    boolean_confirmed = False
            else:
                boolean_confirmed = True

        if boolean_confirmed:
            signal_basis = "length_and_content" if signal1["length_asymmetric"] and signal1["content_asymmetric"] else ("length" if signal1["length_asymmetric"] else "content")
            obs(
                "boolean_asymmetry", {**{k: v for k, v in signal1.items() if k != "asymmetric"}, "signal_basis": signal_basis},
                ObservationNature.INFERRED,
                note="the TRUE boolean probe resembled baseline (by length and/or normalized content) while the FALSE probe diverged, reproducibly across two independent rounds -- a suspect indicator, not a confirmed blind SQL injection",
            )
            findings.append(
                Finding(
                    check=SLUG,
                    title=f"Possible boolean-based blind SQL injection indicator on parameter '{param}'",
                    description=(
                        f"A tautology ('{settings.active_web_testing_sqli_boolean_true_probe}') sent "
                        f"in the '{param}' parameter produced a response resembling "
                        f"the baseline ({signal_basis.replace('_', ' ')}-wise, within measured noise), "
                        f"while a contradiction "
                        f"('{settings.active_web_testing_sqli_boolean_false_probe}') produced a "
                        "meaningfully different response -- and this asymmetry reproduced "
                        "identically on an independent confirmation round. This is a "
                        "differential signal only -- not a confirmed SQL injection, and no data "
                        "was extracted."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.MEDIUM,
                    impact="If this asymmetry reflects a real, exploitable SQL injection, an attacker could infer data a boolean condition at a time -- unconfirmed by this check.",
                    remediation="Use parameterized queries / prepared statements for this parameter, and verify with a controlled, separately-authorized follow-up before treating this as resolved either way.",
                    affected_url=redact_secrets(entry_point.url),
                    http_method="GET",
                    cwe_id="CWE-89",
                    owasp_category=_OWASP_SQLI,
                    evidence={
                        "parameter": param,
                        "source": entry_point.source,
                        "true_delta": signal1["true_delta"],
                        "false_delta": signal1["false_delta"],
                        "signal_basis": signal_basis,
                        "reproduced": True,
                        "corroborating_syntax_anomaly": syntax_anomaly,
                    },
                )
            )
        elif asymmetric1 and round1_matched:
            # Already explained by (and reported as) the error-based
            # signal above -- mirrors the pre-3.1A check's own mutual-
            # exclusivity rule: don't double-report the same underlying
            # issue as two separate findings.
            obs("boolean_asymmetry", False, ObservationNature.OBSERVED)
        elif asymmetric1 and not boolean_confirmed:
            # asymmetric1 is only ever True in the non-redirect branch
            # above, where signal1 was already computed.
            obs(
                "boolean_asymmetry_not_reproducible",
                {"true_delta": signal1["true_delta"], "false_delta": signal1["false_delta"]},
                ObservationNature.INFERRED,
                note="a candidate boolean asymmetry appeared once but did not reproduce (by the same signal type) on a confirmation round -- treated as suspect/non-concluant, no Finding raised",
            )
        else:
            obs("boolean_asymmetry", False, ObservationNature.OBSERVED)

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
