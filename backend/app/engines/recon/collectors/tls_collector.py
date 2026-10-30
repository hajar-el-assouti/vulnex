"""TLS/certificate collector: certificate subject, issuer, validity,
SAN, and the negotiated protocol and cipher, using only the stdlib
ssl/socket modules.

Unlike the DNS/RDAP collectors, this one connects to the target, so it
re-validates through app/security/ssrf.py right before connecting,
like request_policy.py (same DNS rebinding caveat, see that module).

Not applicable on plain HTTP: there is no handshake at all, which is
different from a failed handshake.

Certificate verification is never disabled to get an answer. A
verification failure (expired, wrong hostname, self-signed) is
reported as data (tls.certificate_valid = False, with the reason).

Four failure cases are kept separate:
- invalid or untrusted certificate after a completed handshake: real
  data about the target, status stays OK;
- handshake failure (protocol mismatch, no shared cipher, non-TLS
  service): no certificate was seen;
- connection timeout: says nothing about TLS, only reachability;
- certificate not retrieved for another connection reason (refused,
  no route, DNS failure).
Each one sets `tls.failure_kind`, and none of them invents certificate
fields for a certificate that was never received."""

from __future__ import annotations

import socket
import ssl
import time
import warnings
from datetime import datetime, timezone

from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.context import ReconBudgetExceededError, ReconExecutionContext
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)
from app.security.ssrf import SSRFValidationError, validate_outbound_url
from app.core.config import get_settings

SLUG = "tls"

# ---------------------------------------------------------------------
# Deep TLS analysis.
#
# Adds extra observations to the same "tls" collector. Only runs after
# the main, fully verified handshake above has succeeded.
#
# Two extra probes, neither of which is used to decide
# tls.certificate_valid:
#
# 1. _probe_protocol_version(): one connection per TLS version (1.0,
#    1.1, 1.2, 1.3), pinned with min == max, with verification disabled.
#    This is the only place verification is turned off, and every
#    observation says so. It is fine here because the question is only
#    "can this version be negotiated", not "who is the server". A failed
#    probe is reported as `unsupported_by_client_or_server`, since one
#    failed handshake can't tell which side lacks support.
#
# 2. _perform_chain_probe(): a second connection with normal
#    verification, only to get the certificate chain in DER form
#    (getpeercert()'s dict has no signature algorithm or key size). If
#    it fails, the error is recorded and the status becomes PARTIAL; the
#    main certificate data is kept.
#
# Both probes use the shared recon budget and cancellation.
# ---------------------------------------------------------------------

_OBSOLETE_PROTOCOL_VERSIONS = frozenset({"TLSv1.0", "TLSv1.1"})


def _tls_version_constants() -> tuple[tuple[str, "ssl.TLSVersion"], ...]:
    """ssl.TLSVersion.TLSv1 / TLSv1_1 are deprecated names in recent
    Python (the protocols are obsolete, which is why we test for them).
    The DeprecationWarning is suppressed only around this access."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return (
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        )


def _probe_protocol_version(host: str, port: int, version: "ssl.TLSVersion", timeout: float):
    """Isolated into its own function so tests can monkeypatch exactly
    this (same pattern as _perform_tls_handshake above). Verification
    is deliberately disabled -- see this section's module-level
    docstring for exactly why that is safe and never silent."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Pinning min==max to an obsolete version (TLSv1.0/1.1) itself
    # raises a DeprecationWarning in modern Python, separate from the
    # attribute-access warning _tls_version_constants() already
    # suppresses -- same justification, same narrow scope: this is the
    # whole point of testing for an obsolete protocol's negotiability.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = version
        ctx.maximum_version = version
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            return tls_sock.version(), tls_sock.cipher()


def _perform_chain_probe(
    host: str, port: int, timeout: float, *, context: ssl.SSLContext | None = None
) -> list[bytes]:
    """A second, separate connection using the same real verification
    as _perform_tls_handshake (ssl.create_default_context() -- never
    weakened -- unless a test explicitly injects its own `context`,
    e.g. one that trusts a local test CA; production code never passes
    this parameter, so production behaviour is unchanged). Returns the
    verified chain as a list of DER-encoded certificates (leaf first),
    or an empty list if the running Python's ssl module has no
    get_verified_chain() (added in Python 3.13) -- reported as
    `chain_unavailable`, never fabricated, by the caller."""
    ctx = context or ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            get_chain = getattr(tls_sock, "get_verified_chain", None)
            if get_chain is None:
                return []
            try:
                chain = get_chain()
            except ssl.SSLError:
                return []
            return [
                der.public_bytes(_der_encoding()) if hasattr(der, "public_bytes") else der
                for der in (chain or [])
            ]


def _der_encoding():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def _describe_certificate(der_bytes: bytes) -> dict:
    """Parses one DER certificate with `cryptography` to get fields that
    ssl.getpeercert() doesn't provide. `key_size` is left out for an
    unknown key type, and `signature_algorithm` is None when the
    signature has no single hash (e.g. Ed25519/Ed448)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

    cert = x509.load_der_x509_certificate(der_bytes)
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type, key_size = "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type, key_size = f"EC ({public_key.curve.name})", public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_type, key_size = "DSA", public_key.key_size
    else:
        key_type, key_size = public_key.__class__.__name__, None

    sig_hash = cert.signature_hash_algorithm
    return {
        "subject": cert.subject.rfc4514_string(),
        "signature_algorithm": sig_hash.name if sig_hash is not None else None,
        "key_type": key_type,
        "key_size": key_size,
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
    }


def _collect_advanced_tls_observations(
    ctx: ReconExecutionContext, *, host: str, port: int
) -> tuple[list[Observation], list[str]]:
    """Runs the Checkpoint-C protocol-version and chain probes,
    bounded by the same shared budget/cancellation as every other
    network operation. Never raises for an individual probe's own
    network failure -- each is caught and reported as an Observation/
    error, so one obsolete-protocol probe failing (the expected
    outcome on a modern target) never prevents the others from
    running. ReconCancelledError and ReconBudgetExceededError are
    deliberately NOT caught here: like every other collector, a
    cancellation must propagate to stop the whole scan, and a budget
    exhaustion must propagate to run_collector_safely (which reports
    it); neither should produce a fabricated advanced-TLS result."""
    settings = get_settings()
    observations: list[Observation] = []
    errors: list[str] = []

    for version_name, version_const in _tls_version_constants():
        ctx.raise_if_cancelled(where=f"tls:version_probe:{version_name}")
        ctx.budget.register_request(where=f"tls:version_probe:{version_name}")
        timeout = ctx.budget.timeout_for(settings.advanced_recon_tls_probe_timeout_seconds)
        prefix = f"tls_advanced.protocol.{version_name}"
        try:
            negotiated_protocol, cipher = _probe_protocol_version(host, port, version_const, timeout)
        except ssl.SSLError as exc:
            observations.append(
                Observation(
                    f"{prefix}.supported",
                    False,
                    ObservationNature.OBSERVED,
                    note=(
                        "handshake pinned to this exact version did not complete "
                        f"({exc}) -- this client cannot distinguish 'server does not "
                        "support it' from 'this client's own OpenSSL build refuses to "
                        "offer it' (a common outcome for TLS 1.0/1.1 under OpenSSL "
                        "3.x's default security policy); never presented as certain"
                    ),
                )
            )
            continue
        except (socket.timeout, OSError) as exc:
            observations.append(
                Observation(
                    f"{prefix}.supported",
                    None,
                    ObservationNature.UNKNOWN,
                    note=f"connection-level failure during version probe, not a TLS-layer answer: {exc}",
                )
            )
            continue

        observations.append(Observation(f"{prefix}.supported", True, ObservationNature.OBSERVED))
        if version_name in _OBSOLETE_PROTOCOL_VERSIONS:
            observations.append(
                Observation(
                    f"{prefix}.obsolete",
                    True,
                    ObservationNature.OBSERVED,
                    note="TLS 1.0/1.1 are obsolete protocol versions",
                )
            )
        if cipher:
            observations.append(
                Observation(f"{prefix}.cipher_suite", cipher[0], ObservationNature.OBSERVED)
            )

    client_cipher_count = len(ssl.create_default_context().get_ciphers() or [])
    observations.append(
        Observation(
            "tls_advanced.client_available_cipher_count",
            client_cipher_count,
            ObservationNature.OBSERVED,
            note=(
                "how many cipher suites THIS client's OpenSSL build can offer -- "
                "a library capability, never a claim about what the target accepts"
            ),
        )
    )

    ctx.raise_if_cancelled(where="tls:chain_probe")
    ctx.budget.register_request(where="tls:chain_probe")
    chain_timeout = ctx.budget.timeout_for(settings.advanced_recon_tls_probe_timeout_seconds)
    try:
        chain_der = _perform_chain_probe(host, port, chain_timeout)
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        errors.append(f"chain_probe_failed: {exc.__class__.__name__}: {exc}")
        return observations, errors

    if not chain_der:
        observations.append(
            Observation(
                "tls_advanced.chain.available",
                False,
                ObservationNature.UNKNOWN,
                note="verified certificate chain unavailable (requires Python 3.13+'s "
                "SSLSocket.get_verified_chain(), or the chain probe found nothing to report)",
            )
        )
        return observations, errors

    observations.append(
        Observation("tls_advanced.chain.length", len(chain_der), ObservationNature.OBSERVED)
    )
    for index, der in enumerate(chain_der[:10]):  # bounded -- never an unbounded chain dump
        try:
            described = _describe_certificate(der)
        except Exception as exc:  # noqa: BLE001 -- a parse failure is reported, never fatal
            errors.append(f"chain_cert_{index}_parse_failed: {exc.__class__.__name__}: {exc}")
            continue
        chain_prefix = f"tls_advanced.chain.{index}"
        observations.append(
            Observation(f"{chain_prefix}.subject", described["subject"], ObservationNature.OBSERVED)
        )
        observations.append(
            Observation(
                f"{chain_prefix}.signature_algorithm",
                described["signature_algorithm"],
                ObservationNature.OBSERVED if described["signature_algorithm"] else ObservationNature.UNKNOWN,
            )
        )
        observations.append(
            Observation(f"{chain_prefix}.key_type", described["key_type"], ObservationNature.OBSERVED)
        )
        observations.append(
            Observation(
                f"{chain_prefix}.key_size",
                described["key_size"],
                ObservationNature.OBSERVED if described["key_size"] else ObservationNature.UNKNOWN,
            )
        )
        observations.append(
            Observation(
                f"{chain_prefix}.not_valid_after", described["not_valid_after"], ObservationNature.OBSERVED
            )
        )

    return observations, errors


def _perform_tls_handshake(host: str, port: int, timeout: float):
    """The only network I/O in this collector, isolated into its own
    function so tests can monkeypatch exactly this call (the same
    pattern used throughout this test suite for socket.getaddrinfo)
    instead of needing a fake raw socket/TLS stack. Returns
    (cert_dict, negotiated_protocol, cipher_tuple); raises
    ssl.SSLCertVerificationError / socket.timeout / OSError / ssl.SSLError
    exactly like the real stdlib calls it wraps -- the caller is what
    tells these apart into distinct failure kinds, this function itself
    adds no interpretation."""
    ssl_context = ssl.create_default_context()  # real verification, never weakened
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ssl_context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            return tls_sock.getpeercert(), tls_sock.version(), tls_sock.cipher()


def _flatten_name(name_tuples) -> dict[str, str]:
    flat: dict[str, str] = {}
    for rdn in name_tuples or ():
        for key, value in rdn:
            flat[key] = value
    return flat


def _failure_result(
    *,
    collected_at,
    started: float,
    failure_kind: str,
    detail: str,
) -> CollectorResult:
    """Shared shape for every 'the handshake never completed, so no
    certificate was ever observed' outcome -- a single ERROR observation
    carrying `failure_kind`, never any certificate field."""
    return CollectorResult(
        collector=SLUG,
        status=CollectorStatus.ERROR,
        collected_at=collected_at,
        duration_ms=int((time.monotonic() - started) * 1000),
        observations=[
            Observation(
                "tls.failure_kind",
                failure_kind,
                ObservationNature.ERROR,
                note=detail,
            )
        ],
        errors=[f"{failure_kind}: {detail}"],
        source="tls",
    )


def collect(ctx: ReconExecutionContext) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)

        if ctx.validated_target.scheme != "https":
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=[
                    Observation(
                        "tls.not_applicable",
                        True,
                        ObservationNature.NOT_APPLICABLE,
                        note=f"target scheme is {ctx.validated_target.scheme!r}, not https -- there is no TLS handshake to inspect",
                    )
                ],
                source="tls",
                confidence=ConfidenceLevel.HIGH,
            )

        ctx.raise_if_cancelled(where="tls:connect")
        ctx.budget.ensure_not_expired(where="tls:connect")
        try:
            validate_outbound_url(
                ctx.target_base_url,
                allow_private_networks=ctx.allow_private_networks,
                lab_hosts=ctx.lab_hosts,
            )
        except SSRFValidationError as exc:
            return CollectorResult.error(
                collector=SLUG,
                source="tls",
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"ssrf_rejected: {exc}"],
            )

        host = ctx.validated_target.hostname
        port = ctx.validated_target.port
        settings = get_settings()
        # recon_tls_timeout_seconds (TLS's own configured timeout),
        # clamped to whatever is actually left on the shared global
        # deadline -- never the HTTP target's recon_request_timeout_
        # seconds, which is a different operation type with its own
        # budget (Checkpoint-C validation adjustment #4).
        timeout = ctx.budget.timeout_for(settings.recon_tls_timeout_seconds)

        try:
            cert, negotiated_protocol, cipher = _perform_tls_handshake(host, port, timeout)
        except ssl.SSLCertVerificationError as exc:
            # The handshake COMPLETED -- a real certificate was really
            # presented and really failed verification. This is
            # observed data about the target, not a collection failure:
            # status stays OK, the certificate is confirmed invalid.
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.OK,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=[
                    Observation(
                        "tls.certificate_valid",
                        False,
                        ObservationNature.OBSERVED,
                        note=f"certificate verification failed: {exc}",
                    ),
                    Observation("tls.failure_kind", "certificate_invalid", ObservationNature.OBSERVED),
                ],
                evidence={"host": host, "port": port},
                source="tls",
                confidence=ConfidenceLevel.HIGH,
            )
        except socket.timeout as exc:
            # socket.timeout (an alias of TimeoutError, itself an
            # OSError subclass) must be checked BEFORE the generic
            # OSError branch below -- this says nothing about TLS at
            # all, only that the connection did not complete within the
            # allotted time. Never conflated with a handshake failure.
            return _failure_result(
                collected_at=collected_at, started=started, failure_kind="timeout", detail=str(exc)
            )
        except ssl.SSLError as exc:
            # Any OTHER TLS-layer failure (protocol mismatch, no shared
            # cipher, a non-TLS service answering on this port, ...) --
            # the handshake itself never completed, so no certificate
            # was ever observed. Distinct from SSLCertVerificationError
            # above (a completed handshake whose cert failed checks)
            # and from a plain connection failure below (never even
            # reached the TLS layer).
            return _failure_result(
                collected_at=collected_at, started=started, failure_kind="handshake_failed", detail=str(exc)
            )
        except OSError as exc:
            # Connection refused, no route, DNS failure at connect
            # time, etc. -- never reached far enough to say anything
            # about TLS or a certificate.
            return _failure_result(
                collected_at=collected_at, started=started, failure_kind="connection_failed", detail=str(exc)
            )

        if not cert:
            # A handshake that completed but returned an empty/None
            # peer certificate dict (can happen with certain contexts
            # or servers) -- this is NOT the same as "no certificate
            # fields to report", and must never be papered over by
            # emitting a full set of None-valued fields that would look
            # like a confirmed absence. Reported as UNKNOWN, with
            # nothing fabricated.
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.OK,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=[
                    Observation(
                        "tls.certificate_valid",
                        None,
                        ObservationNature.UNKNOWN,
                        note="TLS handshake completed but no peer certificate details were returned",
                    ),
                    Observation("tls.failure_kind", "certificate_unavailable", ObservationNature.UNKNOWN),
                ],
                evidence={"host": host, "port": port},
                source="tls",
                confidence=ConfidenceLevel.LOW,
            )

        subject = _flatten_name(cert.get("subject"))
        issuer = _flatten_name(cert.get("issuer"))
        san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]

        observations = [
            Observation("tls.certificate_valid", True, ObservationNature.OBSERVED),
            Observation("tls.subject_common_name", subject.get("commonName"), ObservationNature.OBSERVED),
            Observation("tls.issuer_common_name", issuer.get("commonName"), ObservationNature.OBSERVED),
            Observation(
                "tls.issuer_organization",
                issuer.get("organizationName"),
                ObservationNature.OBSERVED if issuer.get("organizationName") else ObservationNature.UNKNOWN,
            ),
            Observation("tls.not_before", cert.get("notBefore"), ObservationNature.OBSERVED),
            Observation("tls.not_after", cert.get("notAfter"), ObservationNature.OBSERVED),
            Observation("tls.subject_alt_names", san, ObservationNature.OBSERVED),
            Observation("tls.protocol_version", negotiated_protocol, ObservationNature.OBSERVED),
            Observation(
                "tls.cipher_suite",
                cipher[0] if cipher else None,
                ObservationNature.OBSERVED if cipher else ObservationNature.UNKNOWN,
            ),
        ]

        # Add the deep TLS analysis to this successful result. If the
        # budget runs out, the result becomes PARTIAL but the main
        # certificate data is kept. ReconCancelledError is not caught: it
        # must propagate like in every other collector.
        status = CollectorStatus.OK
        errors: list[str] = []
        try:
            advanced_observations, advanced_errors = _collect_advanced_tls_observations(
                ctx, host=host, port=port
            )
            observations.extend(advanced_observations)
            if advanced_errors:
                errors.extend(advanced_errors)
                status = CollectorStatus.PARTIAL
        except ReconBudgetExceededError as exc:
            errors.append(f"advanced_tls_budget_exceeded: {exc}")
            status = CollectorStatus.PARTIAL

        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"host": host, "port": port},
            errors=errors,
            source="tls",
            confidence=ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="tls", fn=_run)
