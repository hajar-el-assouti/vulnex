"""Standard metadata files only: robots.txt, sitemap.xml,
/.well-known/security.txt (and the old /security.txt). Each fixed path
is fetched once, through the same SSRF-validated policy as
http_collector. URLs found inside robots.txt or sitemap.xml are never
followed (no crawling).

Uses its own, smaller size limit
(Settings.recon_max_metadata_response_bytes).

sitemap.xml is parsed with xml.etree.ElementTree, which does not
expand external entities. Only the size-capped bytes are parsed, and
an ET.ParseError is reported as "could not parse", never a crash."""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urljoin

import httpx

from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.context import ReconBudgetExceededError, ReconExecutionContext
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)
from app.engines.recon.security.request_policy import (
    ResponseTooLargeError,
    TooManyRedirectsError,
    fetch_target_url,
)
from app.security.ssrf import SSRFValidationError

SLUG = "metadata"

_WELL_KNOWN_PATHS = ("robots.txt", "sitemap.xml", ".well-known/security.txt", "security.txt")


def _fetch_one(ctx: ReconExecutionContext, path: str, *, max_bytes: int) -> dict:
    url = urljoin(ctx.target_base_url.rstrip("/") + "/", path)
    try:
        fetched = fetch_target_url(ctx, url, max_response_bytes=max_bytes, where=f"metadata:{path}")
        return {
            "path": path,
            "url": url,
            "present": fetched.status_code < 400,
            "status_code": fetched.status_code,
            "content_type": fetched.headers.get("content-type"),
            "size_bytes": len(fetched.body_bytes),
            "truncated": fetched.body_truncated,
            "body_bytes": fetched.body_bytes,
        }
    except (
        SSRFValidationError,
        ResponseTooLargeError,
        TooManyRedirectsError,
        ReconBudgetExceededError,
        httpx.HTTPError,
    ) as exc:
        # Network errors are caught per path, so one of the four paths
        # failing doesn't prevent the others from being reported.
        #
        # ReconBudgetExceededError is caught too: the request budget is
        # shared with every other collector in the scan, so running out
        # halfway through is expected. Catching it per path gives a PARTIAL
        # result (paths already fetched keep their data, the rest are
        # reported as errors) instead of losing everything behind one
        # collector-wide ERROR.
        return {"path": path, "url": url, "error": f"{exc.__class__.__name__}: {exc}"}


def _summarize_robots(body_bytes: bytes) -> dict:
    text = body_bytes.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    disallow = sum(1 for line in lines if line.lower().startswith("disallow:"))
    allow = sum(1 for line in lines if line.lower().startswith("allow:"))
    # Referenced sitemap URLs are recorded as plain strings only -- they
    # are never fetched by this collector (no recursive crawl).
    sitemaps = [line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("sitemap:")]
    return {
        "directive_lines": len(lines),
        "disallow_count": disallow,
        "allow_count": allow,
        "referenced_sitemaps": sitemaps,
    }


def _summarize_sitemap(body_bytes: bytes) -> dict:
    try:
        root = ET.fromstring(body_bytes)
    except ET.ParseError as exc:
        return {"parse_error": str(exc)}

    def _local_tag(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    url_count = sum(1 for el in root.iter() if _local_tag(el.tag) == "url")
    return {"root_tag": _local_tag(root.tag), "url_entry_count": url_count}


def collect(ctx: ReconExecutionContext, *, max_metadata_bytes: int) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)
        observations: list[Observation] = []
        errors: list[str] = []
        any_truncated = False

        for path in _WELL_KNOWN_PATHS:
            result = _fetch_one(ctx, path, max_bytes=max_metadata_bytes)
            if "error" in result:
                errors.append(f"{path}: {result['error']}")
                observations.append(
                    Observation(f"metadata.{path}", {"present": False}, ObservationNature.ERROR, note=result["error"])
                )
                continue
            if not result["present"]:
                observations.append(
                    Observation(
                        f"metadata.{path}",
                        {"present": False, "status_code": result["status_code"]},
                        ObservationNature.OBSERVED,
                    )
                )
                continue

            if result["truncated"]:
                any_truncated = True

            summary: dict = {
                "present": True,
                "status_code": result["status_code"],
                "content_type": result["content_type"],
                "size_bytes": result["size_bytes"],
                "truncated": result["truncated"],
            }
            # A truncated body makes any derived summary below
            # (disallow/allow counts, sitemap URL-entry count) a count
            # over a partial document -- e.g. a sitemap cut off mid-<url>
            # would under-count entries. Flag it on the summary itself,
            # not only on the raw truncated boolean, so a reader of this
            # one observation doesn't have to cross-reference it.
            if result["truncated"]:
                summary["note"] = "response truncated before this summary was computed; counts below may be incomplete"
            if path == "robots.txt":
                summary["robots"] = _summarize_robots(result["body_bytes"])
            elif path == "sitemap.xml":
                summary["sitemap"] = _summarize_sitemap(result["body_bytes"])
            observations.append(Observation(f"metadata.{path}", summary, ObservationNature.OBSERVED))

        status = CollectorStatus.PARTIAL if (errors or any_truncated) else CollectorStatus.OK
        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"paths_checked": list(_WELL_KNOWN_PATHS), "any_truncated": any_truncated},
            errors=errors,
            source="direct_http",
            confidence=ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="direct_http", fn=_run)
