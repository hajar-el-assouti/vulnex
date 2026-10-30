# Wordlist attribution and provenance

This directory vendors **exactly one file** from the
[SecLists](https://github.com/danielmiessler/SecLists) project, not a clone of
the repository:

- Source: `Discovery/Web-Content/common.txt`
- Upstream license: **MIT**, Copyright (c) 2018 Daniel Miessler — the full
  license text is kept verbatim in `LICENSE_SECLISTS.txt` in this same
  directory, per the MIT license's own requirement that the copyright notice
  and permission notice be preserved in any copy of the software.
- Fetched via a direct HTTPS request to
  `https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt`
  on 2026-10-25 (see `common.manifest.json` for the exact timestamp, the
  upstream file's SHA-256, this vendored file's own SHA-256, and the full,
  itemized list of entries this project's cleaning step removed and why).

## Why this file, and why cleaned

`common.txt` is SecLists' standard general-purpose content-discovery
wordlist — the same one most DAST/fuzzing tools ship as their default. It was
cleaned (not used verbatim) before being committed here:

- Blank lines dropped.
- Exact duplicates dropped (first occurrence kept — the file's own ordering,
  otherwise untouched, is what makes path *selection* deterministic; see
  `app/engines/discovery_fuzzing/wordlist.py`).
- Any entry containing an embedded absolute URL (`://`), a leading `/`, a
  `..` traversal sequence, a backslash, a NUL byte, another disallowed
  control character, or longer than 256 characters is rejected outright,
  never silently kept or rewritten. Exactly 2 entries were rejected for
  this file (see `common.manifest.json`'s `rejected_entries`); every other
  entry was kept unchanged.
- An entry containing a literal space (e.g. `Program Files`) is **kept**,
  not rejected — it is percent-encoded at request-build time by
  `app/engines/discovery_fuzzing/wordlist.py`, exactly like any other
  character a URL path segment cannot contain unencoded.

## Reproducibility

`common.manifest.json` is this vendored file's version record: the exact
source URL, the upstream raw file's own SHA-256, this cleaned file's SHA-256,
and the full list of what the cleaning step removed. Re-running the cleaning
script against the same upstream commit reproduces the exact same
`common.txt` and the exact same SHA-256 recorded here.

## Scope

Nothing else from SecLists is vendored. Adding another SecLists
wordlist means repeating this same process (fetch one file,
clean it the same way, record a manifest) rather than adding a broader
dependency on the SecLists repository as a whole.
