"""Async-compatible target-trial teardown without breaking synchronous providers.

Disposable AGENT targets can own asynchronous HTTP transport state while older isolation
providers expose synchronous teardown. Campaign code therefore releases every lease through
one async boundary that prefers a provider-native ``release_async`` implementation and
falls back to the established synchronous ``release`` contract.
"""

from __future__ import annotations

import inspect
from typing import Protocol, runtime_checkable

from .target_trial_isolation import (
    TargetTrialIsolationRelease,
    TargetTrialLease,
    TargetTrialLeaseProvider,
)


@runtime_checkable
class AsyncTargetTrialLeaseProvider(Protocol):
    """Optional extension for providers whose complete teardown must be awaited."""

    async def release_async(
        self,
        lease: TargetTrialLease,
    ) -> TargetTrialIsolationRelease: ...


async def release_target_trial_lease(
    provider: TargetTrialLeaseProvider,
    lease: TargetTrialLease,
) -> TargetTrialIsolationRelease:
    """Release one lease without nesting event loops or weakening existing providers."""

    async_release = getattr(provider, "release_async", None)
    if async_release is not None:
        if not callable(async_release):
            raise RuntimeError("target isolation provider release_async is not callable")
        result = async_release(lease)
        if not inspect.isawaitable(result):
            raise RuntimeError("target isolation provider release_async must return awaitable")
        release = await result
    else:
        release = provider.release(lease)

    if not isinstance(release, TargetTrialIsolationRelease):
        raise RuntimeError("target isolation provider returned invalid release evidence")
    if release.lease_id_hash != lease.attestation.lease_id_hash:
        raise RuntimeError("target isolation release does not bind the acquired lease")
    return release
