"""Defense-in-depth re-check before a Recon context is ever built.

By the time a ReconExecutionContext exists, the central authorization
check (app/services/targets.py::ensure_target_is_authorized) has already
run once, before this engine is ever invoked -- see
app/engines/contracts.py's ScanContext docstring: the orchestration
layer only ever hands an engine an already-validated, already-authorized
target. This module exists so that a future refactor of the calling
Celery task that accidentally skips that central check still gets
caught here, one layer closer to the actual network call -- not because
this engine distrusts its caller, but because a network-reaching module
is exactly the place where "someone forgot to call the authorization
check" has real consequences.
"""

from __future__ import annotations


class ReconScopeError(RuntimeError):
    """Raised if a ReconExecutionContext is ever about to be built for
    something that was not already validated as an authorized, owned
    target with a real base URL."""


def ensure_in_scope(*, target_is_authorized: bool, target_base_url: str) -> None:
    if not target_is_authorized:
        raise ReconScopeError(
            f"Refusing to build a Recon context for an unauthorized target ({target_base_url!r})"
        )
    if not target_base_url:
        raise ReconScopeError("Refusing to build a Recon context with no target_base_url")
