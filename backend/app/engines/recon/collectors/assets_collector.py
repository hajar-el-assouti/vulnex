"""External assets: external scripts, stylesheets and frames referenced
by the page, and whether they declare Subresource Integrity
(`integrity`) and `crossorigin`.

No extra network call: parses `fetched.body_bytes` from
http_collector. External resources are referenced, never downloaded.

Uses the stdlib HTMLParser only to read tags and attributes; page
content is never treated as executable.

"External" means a different scheme, host or port than the page's
final URL. Every URL goes through redact_secrets() before being
stored."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.engines.recon.collectors._secrets import redact_secrets
from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.context import ReconExecutionContext
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)
from app.engines.recon.security.request_policy import FetchedResponse

SLUG = "assets"

# tag -> attribute that carries the resource URL this tag loads.
_RESOURCE_TAGS: dict[str, str] = {
    "script": "src",
    "link": "href",
    "img": "src",
    "iframe": "src",
}

_MAX_RESOURCES_REPORTED = 100


class _ExternalResourceExtractor(HTMLParser):
    """Collects (tag, url, integrity, crossorigin) for every tag in
    _RESOURCE_TAGS, from raw markup only -- never executes or renders
    anything. `<link>` tags are kept regardless of `rel` at parse time;
    the caller decides which `rel` values count as a resource (style
    sheets) versus noise (e.g. rel="canonical")."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _RESOURCE_TAGS:
            return
        attr_dict = {k.lower(): v for k, v in attrs}
        url_attr = _RESOURCE_TAGS[tag]
        url = attr_dict.get(url_attr)
        if not url:
            return
        if tag == "link" and (attr_dict.get("rel") or "").lower() not in ("stylesheet", "preload", "modulepreload"):
            return
        self.found.append(
            {
                "tag": tag,
                "url": url,
                "integrity": attr_dict.get("integrity"),
                "crossorigin": attr_dict.get("crossorigin"),
            }
        )


def _is_external(resource_url: str, final_url: str) -> bool:
    resource_parts = urlsplit(urljoin(final_url, resource_url))
    page_parts = urlsplit(final_url)
    return (resource_parts.scheme, resource_parts.netloc) != (page_parts.scheme, page_parts.netloc)


def collect(
    ctx: ReconExecutionContext,
    fetched: FetchedResponse | None,
    fetch_error: str | None,
) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)

        if fetched is None:
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"no primary response to inspect: {fetch_error or 'unknown'}"],
                source="direct_http+html",
            )

        body_text = fetched.body_bytes.decode("utf-8", errors="replace")
        extractor = _ExternalResourceExtractor()
        extractor.feed(body_text)

        external = [item for item in extractor.found if _is_external(item["url"], fetched.final_url)]

        observations: list[Observation] = []
        reported = external[:_MAX_RESOURCES_REPORTED]
        for item in reported:
            sanitized_url = redact_secrets(urljoin(fetched.final_url, item["url"]))
            observations.append(
                Observation(
                    "assets.external_resource",
                    {
                        "tag": item["tag"],
                        "url": sanitized_url,
                        "has_sri": item["integrity"] is not None,
                        "has_crossorigin": item["crossorigin"] is not None,
                        "crossorigin_value": item["crossorigin"],
                    },
                    ObservationNature.OBSERVED,
                )
            )

        observations.append(
            Observation(
                "assets.external_resource_count",
                len(external),
                ObservationNature.OBSERVED,
                note=(
                    f"only the first {_MAX_RESOURCES_REPORTED} are reported individually above"
                    if len(external) > _MAX_RESOURCES_REPORTED
                    else None
                ),
            )
        )

        if fetched.body_truncated:
            observations.append(
                Observation(
                    "assets.body_scan_truncated",
                    True,
                    ObservationNature.OBSERVED,
                    note=(
                        "the body was truncated before this collector scanned it -- a resource"
                        " reference below the truncation point would not be found; this result"
                        " is potentially incomplete, not a confirmed full inventory"
                    ),
                )
            )

        status = CollectorStatus.PARTIAL if fetched.body_truncated else CollectorStatus.OK
        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"total_external_resources": len(external), "body_truncated": fetched.body_truncated},
            source="direct_http+html",
            confidence=ConfidenceLevel.LOW if fetched.body_truncated else ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="direct_http+html", fn=_run)
