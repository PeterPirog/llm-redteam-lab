"""Asynchronous leased-target close boundary before synchronous infrastructure teardown.

A disposable target may own asynchronous client state even when its surrounding Docker,
network and filesystem supervisors use synchronous lifecycle APIs.  Campaign code must
close the target first and prove that close completed before the lease provider reports
infrastructure cleanup.
"""

from __future__ import annotations

import inspect

from pydantic import Field

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .target_trial_isolation import TargetTrialLease

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class TargetTrialCloseObservation(StrictModel):
    """Hash-safe evidence that target-level async resources were closed."""

    version: int = Field(ge=1, default=1)
    lease_id_hash: str = Field(pattern=_HASH_PATTERN)
    close_kind: str = Field(min_length=1)
    close_completed: bool
    proof_sha256: str = Field(pattern=_HASH_PATTERN)


async def close_target_trial(lease: TargetTrialLease) -> TargetTrialCloseObservation:
    """Close an optional sync/async target hook without starting a nested event loop."""

    target = lease.target
    closer = getattr(target, "aclose", None)
    if closer is None:
        return _observation(
            lease_id_hash=lease.attestation.lease_id_hash,
            close_kind="no_target_close_hook",
        )
    if not callable(closer):
        raise RuntimeError("target aclose attribute is not callable")

    result = closer()
    if not inspect.isawaitable(result):
        raise RuntimeError("target aclose hook must return an awaitable")
    await result
    return _observation(
        lease_id_hash=lease.attestation.lease_id_hash,
        close_kind="awaited_aclose",
    )


def _observation(*, lease_id_hash: str, close_kind: str) -> TargetTrialCloseObservation:
    proof = canonical_json_hash(
        {
            "version": 1,
            "lease_id_hash": lease_id_hash,
            "close_kind": close_kind,
            "close_completed": True,
        }
    )
    return TargetTrialCloseObservation(
        lease_id_hash=lease_id_hash,
        close_kind=close_kind,
        close_completed=True,
        proof_sha256=proof,
    )
