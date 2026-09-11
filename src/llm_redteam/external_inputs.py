"""Generic contract for security-significant external inputs used by Blue targets."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .domain import AttackCase
from .evaluation_sets import EvaluationDependencyFingerprint


@runtime_checkable
class EvaluationDependencyProvider(Protocol):
    """Expose immutable external-input identities required for held-out evaluation.

    Providers return hashes only. Raw retrieval documents, repository paths, tool output,
    MCP data and other attacker-controlled bytes remain owned by their concrete runtime.
    """

    def evaluation_dependencies(
        self,
        case: AttackCase,
    ) -> tuple[EvaluationDependencyFingerprint, ...]: ...


def evaluation_dependencies_for_target(
    target: object,
    case: AttackCase,
) -> tuple[EvaluationDependencyFingerprint, ...]:
    """Return target-provided dependencies without making an inference call."""

    if not isinstance(target, EvaluationDependencyProvider):
        return ()
    dependencies = tuple(target.evaluation_dependencies(case))
    identities = [(item.kind, item.reference_hash) for item in dependencies]
    if len(identities) != len(set(identities)):
        raise ValueError("target returned duplicate external dependency identities")
    return tuple(
        sorted(
            dependencies,
            key=lambda item: (item.kind, item.reference_hash, item.content_hash),
        )
    )
