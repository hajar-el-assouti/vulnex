"""Loading, deterministic selection and safe URL building for the
discovery & fuzzing wordlist.

`wordlists/common.txt` is already cleaned (see `wordlists/README.md`):
no empty lines, no duplicates, no absolute URL, no leading `/`, no
`..`, no backslash, no control characters, max 256 characters.
`load_wordlist()` still re-checks every line on each load, so a
corrupted or hand-edited file is caught. A wordlist supplied by the
user goes through the same validation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

_WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"
_DEFAULT_WORDLIST_PATH = _WORDLIST_DIR / "common.txt"

_MAX_LINE_LEN = 256
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# The three modes. Each value is the Settings attribute holding that
# mode's limit, so app/core/config.py stays the single source of truth.
# "standard" and "deep" are listed so the logic handles all three the
# same way, but only "quick" is accepted for now (see
# app/tasks/discovery_fuzzing_module.py).
MODE_SETTING_ATTR = {
    "quick": "discovery_fuzzing_quick_max_paths",
    "standard": "discovery_fuzzing_standard_max_paths",
    "deep": "discovery_fuzzing_deep_max_paths",
}


class WordlistValidationError(ValueError):
    """Raised for a wordlist file (vendored or caller-supplied) that
    fails cleaning validation -- never silently repaired or partially
    loaded; see module docstring."""


def _validate_and_clean_lines(raw_text: str) -> list[str]:
    seen: set[str] = set()
    cleaned: list[str] = []
    for line in raw_text.splitlines():
        entry = line.strip()
        if not entry:
            continue
        if len(entry) > _MAX_LINE_LEN:
            raise WordlistValidationError(f"wordlist entry too long ({len(entry)} chars): {entry[:40]!r}...")
        if _CONTROL_CHARS.search(entry):
            raise WordlistValidationError(f"wordlist entry contains a control character: {entry!r}")
        if "://" in entry:
            raise WordlistValidationError(f"wordlist entry embeds an absolute URL: {entry!r}")
        if entry.startswith("/"):
            raise WordlistValidationError(f"wordlist entry has a leading '/': {entry!r}")
        if ".." in entry:
            raise WordlistValidationError(f"wordlist entry contains a path-traversal sequence: {entry!r}")
        if "\\" in entry:
            raise WordlistValidationError(f"wordlist entry contains a backslash: {entry!r}")
        if entry in seen:
            continue  # exact duplicate -- dropped, first occurrence already kept
        seen.add(entry)
        cleaned.append(entry)
    return cleaned


@lru_cache(maxsize=8)
def _load_wordlist_cached(path_str: str) -> tuple[str, ...]:
    path = Path(path_str)
    raw_text = path.read_text(encoding="utf-8")
    return tuple(_validate_and_clean_lines(raw_text))


def load_wordlist(path: Path | None = None) -> list[str]:
    """Returns the cleaned wordlist entries, in their on-disk order --
    that order is the entire determinism guarantee `select_paths()`
    relies on. Cached per distinct path (the vendored file never
    changes at runtime; a caller-supplied path is cached too, which is
    safe because this process never mutates a wordlist file it reads).
    """
    target_path = path if path is not None else _DEFAULT_WORDLIST_PATH
    return list(_load_wordlist_cached(str(target_path)))


def select_paths(entries: list[str], *, max_paths: int) -> list[str]:
    """Returns the first `max_paths` entries, in order. Never random,
    never reordered. `max_paths` is a maximum: a shorter wordlist
    returns all its entries."""
    if max_paths < 0:
        raise ValueError("max_paths must not be negative")
    return entries[:max_paths]


@dataclass(frozen=True)
class BuiltRequestUrl:
    entry: str
    url: str


def build_request_url(base_url: str, entry: str) -> str:
    """Joins one wordlist entry onto `base_url` as a path segment,
    percent-encoding whatever the entry itself cannot safely carry
    unencoded in a URL path (a literal space in "Program Files", for
    instance) -- entries are never rejected for containing such
    characters (see wordlists/README.md); they are encoded here
    instead, at the one place a request URL is actually built.

    A small number of upstream SecLists entries carry their own
    embedded query string (e.g. "dns-query?name=google.com&type=A") --
    split on the first literal '?' and encode the path portion and the
    query portion separately, so '?'/'='/'&' inside a genuine query
    string are preserved as query syntax rather than being escaped into
    an inert literal string that would change what's actually being
    requested."""
    path_part, _, query_part = entry.partition("?")
    encoded_path = quote(path_part, safe="/")
    base = base_url if base_url.endswith("/") else base_url + "/"
    url = base + encoded_path
    if query_part:
        encoded_query = quote(query_part, safe="=&")
        url = f"{url}?{encoded_query}"
    return url
