"""Small shared helper: is the target's hostname a domain name or an
IP address?

A bare IP has no domain DNS records, no SPF/DMARC/DKIM and no domain
RDAP record. That is not an error or an unknown, the question just
doesn't apply, so these collectors return NOT_APPLICABLE (e.g. for
Juice Shop on a private IP)."""

from __future__ import annotations

import ipaddress

# IANA special-use / reserved domain suffixes (RFC 6761) plus common ad
# hoc lab conventions. A hostname under any of these has no business
# being sent to a PUBLIC DNS resolver: either it is defined to never
# resolve on the public internet (.local, .onion, .localhost) or it is
# this project's own lab convention for "this name is internal, not a
# real registered domain" (.lab, .internal). Checked independently of
# hostname_is_ip_literal: a lab target can be named rather than
# addressed by bare IP.
#
# Deliberately NOT included here: ".example"/".invalid"/".test" (also
# RFC 2606/6761 reserved). This whole test suite's own fixture
# convention (tests/engines/recon/conftest.py's ctx_factory default:
# "recon-test.example") and these collectors' own test files use those
# suffixes as ordinary-looking placeholder domains for a target that is
# NOT meant to trigger not_applicable -- adding them here would make
# the fixture collide with this exact check. A deployment whose actual
# lab target is named under one of those suffixes is still covered by
# explicitly listing it in ctx.lab_hosts (checked first, below).
_RESERVED_OR_LAB_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lab",
    ".onion",
)


def hostname_is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def hostname_is_lab_or_reserved(hostname: str, lab_hosts: frozenset[str] = frozenset()) -> bool:
    """True when `hostname` is explicitly one of this scan's own
    lab-allowlisted hosts (ReconExecutionContext.lab_hosts -- the same
    per-host opt-in app/security/ssrf.py uses), or ends in one of the
    reserved/lab-convention suffixes above. Either case means: this is
    not a real, publicly-registered domain name, so it must never be
    queried against a public DNS resolver (Settings.recon_dns_
    resolvers) -- doing so would leak this lab's internal naming to a
    third-party resolver for no useful answer (these names were never
    going to resolve there) and, more importantly, is simply the wrong
    operation for a name that was never meant to be public."""
    lowered = hostname.lower()
    # ssrf.py's lab_hosts entries are "host:port" (e.g.
    # "192.168.56.102:3000"). Here the question is different ("should
    # this name be sent to a public DNS resolver?"), and the port doesn't
    # matter, so strip ":<port>" before comparing.
    lab_hostnames = {entry.lower().rsplit(":", 1)[0] for entry in lab_hosts}
    if lowered in lab_hostnames:
        return True
    return any(lowered.endswith(suffix) for suffix in _RESERVED_OR_LAB_SUFFIXES)
