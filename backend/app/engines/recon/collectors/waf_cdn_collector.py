"""Passive WAF/CDN detection.

No network call of its own: it only uses data already collected in
the same run: response headers, cookie names (never values) and the
DNS CNAME chain. It never sends anything designed to trigger a WAF.

Each detection has a confidence level and the list of signals behind
it. A single signature is never treated as proof. Confidence depends
on how many independent signal types (header / cookie name / CNAME)
agree:
- HIGH: 2 or more types matched.
- MEDIUM: 1 type matched, on a provider-specific signal.
- No match: the provider is not listed.

It only detects that a provider is present; it never tests whether
the WAF would block something."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone

from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)

SLUG = "waf_cdn"


@dataclass(frozen=True)
class _Signature:
    name: str
    # Exact header NAME -> expected substring in its value (case-
    # insensitive), or None to mean "presence of this header at all is
    # itself the signal" (e.g. cf-ray has no fixed value to match).
    headers: dict[str, str | None]
    # Cookie NAME substrings (never values).
    cookie_name_substrings: tuple[str, ...]
    # Substrings expected in a CNAME target.
    cname_substrings: tuple[str, ...]


_SIGNATURES: tuple[_Signature, ...] = (
    _Signature(
        name="Cloudflare",
        headers={"cf-ray": None, "cf-cache-status": None, "server": "cloudflare"},
        cookie_name_substrings=("__cfduid", "__cf_bm", "cf_clearance"),
        cname_substrings=("cloudflare.net",),
    ),
    _Signature(
        name="Akamai",
        headers={"server": "akamaighost", "x-akamai-transformed": None, "akamai-origin-hop": None},
        cookie_name_substrings=("akacd_", "aka_a2"),
        cname_substrings=("akamaiedge.net", "akamai.net", "akamaitechnologies.com"),
    ),
    _Signature(
        name="AWS CloudFront / AWS WAF",
        headers={"x-amz-cf-id": None, "x-amz-cf-pop": None, "via": "cloudfront"},
        cookie_name_substrings=(),
        cname_substrings=("cloudfront.net",),
    ),
    _Signature(
        name="Imperva",
        headers={"x-iinfo": None, "x-cdn": "incapsula"},
        cookie_name_substrings=("incap_ses_", "visid_incap_"),
        cname_substrings=("incapdns.net", "imperva"),
    ),
    _Signature(
        name="Fastly",
        headers={"x-served-by": None, "x-fastly-request-id": None},
        cookie_name_substrings=(),
        cname_substrings=("fastly.net",),
    ),
    _Signature(
        name="Sucuri",
        headers={"server": "sucuri/cloudproxy", "x-sucuri-id": None, "x-sucuri-cache": None},
        cookie_name_substrings=(),
        cname_substrings=("sucuri.net",),
    ),
    _Signature(
        name="Azure Front Door / Azure WAF",
        headers={"x-azure-ref": None},
        cookie_name_substrings=(),
        cname_substrings=("azurefd.net", "azure-dns"),
    ),
)


def _extract_headers(results: dict[str, CollectorResult]) -> dict[str, str]:
    """Reads the already-collected `header.*`/`server_header` keys from
    the `headers` collector's own result -- never a raw response
    object, and never a new fetch."""
    headers_result = results.get("headers")
    extracted: dict[str, str] = {}
    if headers_result is None:
        return extracted
    for obs in headers_result.observations:
        if obs.value is None:
            continue
        if obs.key == "server_header":
            extracted["server"] = str(obs.value)
        elif obs.key.startswith("header."):
            extracted[obs.key[len("header.") :]] = str(obs.value)
    return extracted


def _extract_cookie_names(results: dict[str, CollectorResult]) -> list[str]:
    cookies_result = results.get("cookies")
    if cookies_result is None:
        return []
    names = []
    for obs in cookies_result.observations:
        if obs.key.startswith("cookie."):
            names.append(obs.key[len("cookie.") :])
    return names


def _extract_cname_values(results: dict[str, CollectorResult]) -> list[str]:
    dns_result = results.get("dns")
    if dns_result is None:
        return []
    for obs in dns_result.observations:
        if obs.key == "dns.cname" and isinstance(obs.value, dict):
            return [str(v) for v in obs.value.get("values", [])]
    return []


def _match_signature(
    sig: _Signature, *, headers: dict[str, str], cookie_names: list[str], cnames: list[str]
) -> tuple[bool, ConfidenceLevel, list[str]] | None:
    evidence: list[str] = []
    matched_categories = 0

    header_matched = False
    for header_name, expected_substring in sig.headers.items():
        actual = headers.get(header_name)
        if actual is None:
            continue
        if expected_substring is None or expected_substring in actual.lower():
            evidence.append(f"header '{header_name}': {actual!r}")
            header_matched = True
    if header_matched:
        matched_categories += 1

    cookie_matched = False
    for cookie_name in cookie_names:
        lowered = cookie_name.lower()
        if any(substr in lowered for substr in sig.cookie_name_substrings):
            evidence.append(f"cookie name: {cookie_name!r}")
            cookie_matched = True
    if cookie_matched:
        matched_categories += 1

    cname_matched = False
    for cname in cnames:
        lowered = cname.lower()
        if any(substr in lowered for substr in sig.cname_substrings):
            evidence.append(f"CNAME target: {cname!r}")
            cname_matched = True
    if cname_matched:
        matched_categories += 1

    if matched_categories == 0:
        return None
    confidence = ConfidenceLevel.HIGH if matched_categories >= 2 else ConfidenceLevel.MEDIUM
    return True, confidence, evidence


def collect(results: dict[str, "CollectorResult"]) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)

        headers = {k.lower(): v for k, v in _extract_headers(results).items()}
        cookie_names = _extract_cookie_names(results)
        cnames = _extract_cname_values(results)

        observations: list[Observation] = []
        detected_any = False

        if not headers and not cookie_names and not cnames:
            observations.append(
                Observation(
                    "waf_cdn.not_applicable",
                    True,
                    ObservationNature.NOT_APPLICABLE,
                    note="no headers/cookies/DNS data available from this run to inspect "
                    "(the primary fetch and/or DNS lookup did not produce usable results)",
                )
            )
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=observations,
                source="waf_cdn",
                confidence=ConfidenceLevel.LOW,
            )

        for sig in _SIGNATURES:
            match = _match_signature(sig, headers=headers, cookie_names=cookie_names, cnames=cnames)
            if match is None:
                continue
            _, confidence, evidence = match
            detected_any = True
            prefix = f"waf_cdn.{sig.name.lower().replace(' ', '_').replace('/', '_')}"
            observations.append(
                Observation(
                    f"{prefix}.detected",
                    True,
                    ObservationNature.INFERRED,
                    note="a single signature is never certain proof -- see evidence and confidence",
                )
            )
            observations.append(Observation(f"{prefix}.evidence", evidence, ObservationNature.OBSERVED))
            observations.append(
                Observation(f"{prefix}.confidence", confidence.value, ObservationNature.OBSERVED)
            )

        if not detected_any:
            observations.append(
                Observation(
                    "waf_cdn.none_detected",
                    True,
                    ObservationNature.UNKNOWN,
                    note="no known WAF/CDN signature matched -- absence of a signature is not "
                    "proof the target has no such protection (it may use one with no public "
                    "signature, or one not yet in this collector's signature list)",
                )
            )

        return CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={
                "headers_inspected": sorted(headers.keys()),
                "cookie_count": len(cookie_names),
                "cname_count": len(cnames),
            },
            source="waf_cdn",
            confidence=ConfidenceLevel.MEDIUM,
        )

    return run_collector_safely(collector_slug=SLUG, source="waf_cdn", fn=_run)
