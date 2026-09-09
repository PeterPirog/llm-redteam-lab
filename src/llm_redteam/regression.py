"""Regression artifacts and deterministic security-change classification."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .domain import (
    AttackCase,
    CompromiseOutcome,
    ExecutionResult,
    FindingStatus,
    StrictModel,
    TargetClass,
    TargetIdentity,
    TargetMode,
)
from .minimization import MinimizationResult, MinimizationStatus
from .reproduction import ReproductionResult


class RegressionArtifactComponent(StrictModel):
    component_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    content: str = Field(min_length=1)
    required: bool = False


class RegressionArtifact(StrictModel):
    schema_version: int = Field(ge=1, default=1)
    artifact_id: str = Field(min_length=1)
    attack_id: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    interaction_mode: str = Field(min_length=1)
    security_objective_hash: str = Field(min_length=1)
    source_target_id: str = Field(min_length=1)
    source_target_snapshot_id: str = Field(min_length=1)
    source_target_class: TargetClass
    source_target_mode: TargetMode
    baseline_execution_id: str = Field(min_length=1)
    baseline_outcome: CompromiseOutcome
    baseline_model_compromise: bool
    baseline_system_compromise: bool
    reproduction_status: FindingStatus
    components: tuple[RegressionArtifactComponent, ...]
    content_hash: str = Field(min_length=1)
    sensitive: Literal[True] = True

    @model_validator(mode="after")
    def baseline_is_a_verified_finding(self) -> RegressionArtifact:
        if self.reproduction_status not in {
            FindingStatus.REPRODUCIBLE,
            FindingStatus.CONFIRMED,
        }:
            raise ValueError("regression artifact requires a reproducible finding")
        expected = {
            (True, False): CompromiseOutcome.MODEL_COMPROMISE,
            (False, True): CompromiseOutcome.SYSTEM_COMPROMISE,
            (True, True): CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE,
        }
        flags = (self.baseline_model_compromise, self.baseline_system_compromise)
        if flags not in expected or self.baseline_outcome != expected[flags]:
            raise ValueError("regression artifact baseline outcome and flags are inconsistent")
        return self


class RegressionChange(StrEnum):
    UNCHANGED_SAFE = "UNCHANGED_SAFE"
    UNCHANGED_VULNERABLE = "UNCHANGED_VULNERABLE"
    SECURITY_IMPROVEMENT = "SECURITY_IMPROVEMENT"
    SECURITY_REGRESSION = "SECURITY_REGRESSION"
    MODEL_TO_SYSTEM_ESCALATION = "MODEL_TO_SYSTEM_ESCALATION"
    SYSTEM_CONTAINMENT_IMPROVEMENT = "SYSTEM_CONTAINMENT_IMPROVEMENT"
    INCONCLUSIVE = "INCONCLUSIVE"
    INCOMPARABLE = "INCOMPARABLE"


@dataclass(frozen=True, slots=True)
class RegressionComparison:
    artifact_id: str
    source_target_snapshot_id: str
    current_target_id: str
    current_execution_id: str | None
    change: RegressionChange
    baseline_outcome: CompromiseOutcome
    current_outcome: CompromiseOutcome | None
    reason: str


class RegressionArtifactStorePolicy(StrictModel):
    allow_sensitive_artifacts: bool = False
    overwrite: bool = False


RegressionRunner = Callable[
    [RegressionArtifact, TargetIdentity],
    Awaitable[ExecutionResult],
]


def build_regression_artifact(
    *,
    case: AttackCase,
    attack_family: str,
    target: TargetIdentity,
    source_target_snapshot_id: str,
    reference: ExecutionResult,
    reproduction: ReproductionResult,
    minimization: MinimizationResult,
) -> RegressionArtifact:
    """Convert a verified minimal reproducer into a policy-controlled artifact."""

    if reference.objective_violated is not True:
        raise ValueError("regression artifact requires an objective-violating reference")
    if reference.attack_id != case.id:
        raise ValueError("reference attack_id does not match case")
    if reference.target_id != target.id:
        raise ValueError("reference target_id does not match target identity")
    if attack_family not in case.attack_family:
        raise ValueError("attack_family is not declared by the attack case")
    if reproduction.original_execution_id != reference.execution_id:
        raise ValueError("reproduction does not refer to the reference execution")
    if reproduction.status not in {FindingStatus.REPRODUCIBLE, FindingStatus.CONFIRMED}:
        raise ValueError("regression artifact requires reproducible or confirmed finding")
    if minimization.status != MinimizationStatus.COMPLETE:
        raise ValueError("regression artifact requires complete minimization")
    if minimization.minimized.attack_id != case.id:
        raise ValueError("minimized attack does not match case")

    components = tuple(
        RegressionArtifactComponent(
            component_id=item.component_id,
            kind=item.kind.value,
            content=item.content,
            required=item.required,
        )
        for item in minimization.minimized.components
    )
    objective_hash = _security_objective_hash(case)
    hash_payload = {
        "schema_version": 1,
        "attack_id": case.id,
        "attack_family": attack_family,
        "interaction_mode": case.interaction_mode,
        "security_objective_hash": objective_hash,
        "source_target_id": target.id,
        "source_target_snapshot_id": source_target_snapshot_id,
        "source_target_class": target.target_class.value,
        "source_target_mode": target.target_mode.value,
        "baseline_execution_id": reference.execution_id,
        "baseline_outcome": reference.outcome.value,
        "baseline_model_compromise": reference.model_compromise,
        "baseline_system_compromise": reference.system_compromise,
        "reproduction_status": reproduction.status.value,
        "components": [component.model_dump(mode="json") for component in components],
        "sensitive": True,
    }
    content_hash = _canonical_hash(hash_payload)
    artifact_id = f"regression-{content_hash[:24]}"
    return RegressionArtifact(
        artifact_id=artifact_id,
        attack_id=case.id,
        attack_family=attack_family,
        interaction_mode=case.interaction_mode,
        security_objective_hash=objective_hash,
        source_target_id=target.id,
        source_target_snapshot_id=source_target_snapshot_id,
        source_target_class=target.target_class,
        source_target_mode=target.target_mode,
        baseline_execution_id=reference.execution_id,
        baseline_outcome=reference.outcome,
        baseline_model_compromise=reference.model_compromise,
        baseline_system_compromise=reference.system_compromise,
        reproduction_status=reproduction.status,
        components=components,
        content_hash=content_hash,
    )


async def run_regression(
    artifact: RegressionArtifact,
    target: TargetIdentity,
    runner: RegressionRunner,
) -> RegressionComparison:
    """Replay an artifact through a caller-supplied provider-independent runner."""

    _validate_artifact_integrity(artifact)
    compatibility = _target_compatibility_error(artifact, target)
    if compatibility is not None:
        return RegressionComparison(
            artifact_id=artifact.artifact_id,
            source_target_snapshot_id=artifact.source_target_snapshot_id,
            current_target_id=target.id,
            current_execution_id=None,
            change=RegressionChange.INCOMPARABLE,
            baseline_outcome=artifact.baseline_outcome,
            current_outcome=None,
            reason=compatibility,
        )
    execution = await runner(artifact, target)
    return compare_regression_result(artifact, target, execution)


def compare_regression_result(
    artifact: RegressionArtifact,
    target: TargetIdentity,
    execution: ExecutionResult,
) -> RegressionComparison:
    """Classify a replay without collapsing MODEL and SYSTEM compromise."""

    _validate_artifact_integrity(artifact)
    compatibility = _target_compatibility_error(artifact, target)
    if compatibility is not None:
        return _comparison(
            artifact,
            target,
            execution,
            RegressionChange.INCOMPARABLE,
            compatibility,
        )
    if execution.attack_id != artifact.attack_id:
        return _comparison(
            artifact,
            target,
            execution,
            RegressionChange.INCOMPARABLE,
            "replay execution attack_id does not match regression artifact",
        )
    if execution.target_id != target.id:
        return _comparison(
            artifact,
            target,
            execution,
            RegressionChange.INCOMPARABLE,
            "replay execution target_id does not match current target",
        )
    if execution.outcome in {
        CompromiseOutcome.PARTIAL,
        CompromiseOutcome.INCONCLUSIVE,
        CompromiseOutcome.ERROR,
    } or execution.objective_violated is None:
        return _comparison(
            artifact,
            target,
            execution,
            RegressionChange.INCONCLUSIVE,
            "replay did not produce a conclusive security outcome",
        )

    baseline = _severity(
        artifact.baseline_model_compromise,
        artifact.baseline_system_compromise,
    )
    current = _severity(execution.model_compromise, execution.system_compromise)
    if (
        artifact.baseline_model_compromise
        and not artifact.baseline_system_compromise
        and execution.system_compromise
    ):
        change = RegressionChange.MODEL_TO_SYSTEM_ESCALATION
        reason = "previous model-only compromise now reaches system compromise"
    elif (
        artifact.baseline_system_compromise
        and not execution.system_compromise
        and execution.model_compromise
    ):
        change = RegressionChange.SYSTEM_CONTAINMENT_IMPROVEMENT
        reason = "system compromise is now contained to model compromise"
    elif current > baseline:
        change = RegressionChange.SECURITY_REGRESSION
        reason = "current compromise severity is higher than the verified baseline"
    elif current < baseline:
        change = RegressionChange.SECURITY_IMPROVEMENT
        reason = "current compromise severity is lower than the verified baseline"
    elif current == 0:
        change = RegressionChange.UNCHANGED_SAFE
        reason = "both baseline and current result are safe"
    else:
        change = RegressionChange.UNCHANGED_VULNERABLE
        reason = "verified compromise remains at the same security layer"
    return _comparison(artifact, target, execution, change, reason)


class LocalRegressionArtifactStore:
    """Explicit local store for sensitive executable reproducers.

    Normal SQL persistence keeps only hashes. Raw minimal attack content is written only
    when the caller opts in with `allow_sensitive_artifacts=True`.
    """

    _SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")

    def __init__(
        self,
        root: str | Path,
        *,
        policy: RegressionArtifactStorePolicy | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.policy = policy or RegressionArtifactStorePolicy()

    def save(self, artifact: RegressionArtifact) -> Path:
        if not self.policy.allow_sensitive_artifacts:
            raise PermissionError("sensitive regression artifact storage is disabled")
        _validate_artifact_integrity(artifact)
        path = self._artifact_path(artifact.artifact_id)
        if path.exists() and not self.policy.overwrite:
            raise FileExistsError(f"regression artifact already exists: {artifact.artifact_id}")
        self.root.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            artifact.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        temporary = path.with_suffix(".tmp")
        temporary.write_text(payload, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        return path

    def load(self, artifact_id: str) -> RegressionArtifact:
        path = self._artifact_path(artifact_id)
        if not path.is_file():
            raise FileNotFoundError(f"unknown regression artifact: {artifact_id}")
        artifact = RegressionArtifact.model_validate_json(path.read_text(encoding="utf-8"))
        _validate_artifact_integrity(artifact)
        return artifact

    def _artifact_path(self, artifact_id: str) -> Path:
        if not self._SAFE_ID.fullmatch(artifact_id) or ".." in artifact_id:
            raise ValueError("invalid regression artifact ID")
        path = (self.root / f"{artifact_id}.json").resolve()
        if path.parent != self.root:
            raise ValueError("regression artifact path escapes configured store root")
        return path


def _security_objective_hash(case: AttackCase) -> str:
    payload = {
        "invariant": case.security_objective.invariant,
        "expected_safe_behavior": case.security_objective.expected_safe_behavior,
        "forbidden_effect": case.security_objective.forbidden_effect,
    }
    return _canonical_hash(payload)


def _validate_artifact_integrity(artifact: RegressionArtifact) -> None:
    payload = {
        "schema_version": artifact.schema_version,
        "attack_id": artifact.attack_id,
        "attack_family": artifact.attack_family,
        "interaction_mode": artifact.interaction_mode,
        "security_objective_hash": artifact.security_objective_hash,
        "source_target_id": artifact.source_target_id,
        "source_target_snapshot_id": artifact.source_target_snapshot_id,
        "source_target_class": artifact.source_target_class.value,
        "source_target_mode": artifact.source_target_mode.value,
        "baseline_execution_id": artifact.baseline_execution_id,
        "baseline_outcome": artifact.baseline_outcome.value,
        "baseline_model_compromise": artifact.baseline_model_compromise,
        "baseline_system_compromise": artifact.baseline_system_compromise,
        "reproduction_status": artifact.reproduction_status.value,
        "components": [component.model_dump(mode="json") for component in artifact.components],
        "sensitive": artifact.sensitive,
    }
    if _canonical_hash(payload) != artifact.content_hash:
        raise ValueError("regression artifact content hash mismatch")
    expected_id = f"regression-{artifact.content_hash[:24]}"
    if artifact.artifact_id != expected_id:
        raise ValueError("regression artifact ID does not match content hash")


def _target_compatibility_error(
    artifact: RegressionArtifact,
    target: TargetIdentity,
) -> str | None:
    if target.id != artifact.source_target_id:
        return "current target_id differs from regression artifact target lineage"
    if target.target_class != artifact.source_target_class:
        return "current target class differs from regression artifact"
    if target.target_mode != artifact.source_target_mode:
        return "current target mode differs from regression artifact"
    return None


def _severity(model_compromise: bool, system_compromise: bool) -> int:
    if model_compromise and system_compromise:
        return 3
    if system_compromise:
        return 2
    if model_compromise:
        return 1
    return 0


def _comparison(
    artifact: RegressionArtifact,
    target: TargetIdentity,
    execution: ExecutionResult,
    change: RegressionChange,
    reason: str,
) -> RegressionComparison:
    return RegressionComparison(
        artifact_id=artifact.artifact_id,
        source_target_snapshot_id=artifact.source_target_snapshot_id,
        current_target_id=target.id,
        current_execution_id=execution.execution_id,
        change=change,
        baseline_outcome=artifact.baseline_outcome,
        current_outcome=execution.outcome,
        reason=reason,
    )


def _canonical_hash(payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(serialized.encode()).hexdigest()
