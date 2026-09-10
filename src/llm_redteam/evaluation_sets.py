"""Hash-bound discovery/evaluation partitions for auditable security measurement.

The manifest separates adaptive vulnerability discovery from comparative Blue
measurement. It never stores raw attack payloads or external-input locators; it stores
case identifiers, canonical case fingerprints and (schema v2) hash-only identities of
external attack inputs. Evaluation content must not be exposed to the Red policy during
discovery. A SEQUESTERED manifest additionally declares that the case definitions live
outside the discovery runtime/repository view.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from enum import StrEnum
from hashlib import sha256

from pydantic import Field, model_validator

from .domain import AttackCase, StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_MANIFEST_SCHEMA_V1 = 1
_MANIFEST_SCHEMA_V2 = 2


class EvaluationSetExposure(StrEnum):
    """How strongly evaluation content is isolated from adaptive discovery."""

    INTERNAL_HELD_OUT = "INTERNAL_HELD_OUT"
    SEQUESTERED = "SEQUESTERED"


class EvaluationDependencyFingerprint(StrictModel):
    """Hash-only identity of attack input bytes stored outside the AttackCase."""

    kind: str = Field(min_length=1)
    reference_hash: str = Field(pattern=_HASH_PATTERN)
    content_hash: str = Field(pattern=_HASH_PATTERN)


class EvaluationCaseFingerprint(StrictModel):
    """Content identity for one attack case without retaining its raw payload."""

    case_id: str = Field(min_length=1)
    content_hash: str = Field(pattern=_HASH_PATTERN)
    dependencies: tuple[EvaluationDependencyFingerprint, ...] = ()

    @model_validator(mode="after")
    def dependencies_are_canonical(self) -> EvaluationCaseFingerprint:
        keys = [(item.kind, item.reference_hash) for item in self.dependencies]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate evaluation dependency identities are not allowed")
        if self.dependencies != _sorted_dependencies(self.dependencies):
            raise ValueError("evaluation dependencies must use canonical sorted order")
        return self


class HeldOutEvaluationManifest(StrictModel):
    """Immutable partition declaration used to gate comparative Blue metrics."""

    schema_version: int = Field(ge=_MANIFEST_SCHEMA_V1, le=_MANIFEST_SCHEMA_V2, default=1)
    manifest_id: str = Field(min_length=1)
    exposure: EvaluationSetExposure
    split_strategy: str = Field(min_length=1)
    corpus_snapshot_hash: str = Field(pattern=_HASH_PATTERN)
    red_can_access_evaluation_content: bool = False
    sequestered_source_id: str | None = None
    discovery_cases: tuple[EvaluationCaseFingerprint, ...]
    evaluation_cases: tuple[EvaluationCaseFingerprint, ...]
    discovery_case_set_hash: str = Field(pattern=_HASH_PATTERN)
    evaluation_case_set_hash: str = Field(pattern=_HASH_PATTERN)
    content_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def partition_is_valid(self) -> HeldOutEvaluationManifest:
        if not self.evaluation_cases:
            raise ValueError("held-out manifest requires at least one evaluation case")
        if self.red_can_access_evaluation_content:
            raise ValueError("held-out evaluation content must not be accessible to Red")
        if self.exposure == EvaluationSetExposure.SEQUESTERED and not self.sequestered_source_id:
            raise ValueError("SEQUESTERED evaluation requires sequestered_source_id")
        if self.schema_version == _MANIFEST_SCHEMA_V1 and any(
            item.dependencies for item in self.discovery_cases + self.evaluation_cases
        ):
            raise ValueError("schema v1 held-out manifests cannot bind external dependencies")

        discovery_ids = [item.case_id for item in self.discovery_cases]
        evaluation_ids = [item.case_id for item in self.evaluation_cases]
        if len(discovery_ids) != len(set(discovery_ids)):
            raise ValueError("duplicate discovery case IDs are not allowed")
        if len(evaluation_ids) != len(set(evaluation_ids)):
            raise ValueError("duplicate evaluation case IDs are not allowed")
        if set(discovery_ids) & set(evaluation_ids):
            raise ValueError("discovery and evaluation case IDs must be disjoint")

        discovery_hashes = {item.content_hash for item in self.discovery_cases}
        evaluation_hashes = {item.content_hash for item in self.evaluation_cases}
        if discovery_hashes & evaluation_hashes:
            raise ValueError("discovery and evaluation case content must be disjoint")

        expected_discovery_hash = fingerprint_case_fingerprints(
            self.discovery_cases,
            schema_version=self.schema_version,
        )
        expected_evaluation_hash = fingerprint_case_fingerprints(
            self.evaluation_cases,
            schema_version=self.schema_version,
        )
        if self.discovery_case_set_hash != expected_discovery_hash:
            raise ValueError("discovery_case_set_hash does not match manifest cases")
        if self.evaluation_case_set_hash != expected_evaluation_hash:
            raise ValueError("evaluation_case_set_hash does not match manifest cases")
        if self.content_hash != _canonical_hash(self._hash_payload()):
            raise ValueError("held-out manifest content_hash does not match manifest content")
        return self

    def _hash_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "exposure": self.exposure.value,
            "split_strategy": self.split_strategy,
            "corpus_snapshot_hash": self.corpus_snapshot_hash,
            "red_can_access_evaluation_content": self.red_can_access_evaluation_content,
            "sequestered_source_id": self.sequestered_source_id,
            "discovery_cases": [
                _case_fingerprint_payload(item, schema_version=self.schema_version)
                for item in self.discovery_cases
            ],
            "evaluation_cases": [
                _case_fingerprint_payload(item, schema_version=self.schema_version)
                for item in self.evaluation_cases
            ],
            "discovery_case_set_hash": self.discovery_case_set_hash,
            "evaluation_case_set_hash": self.evaluation_case_set_hash,
        }


def fingerprint_external_dependency(
    *,
    kind: str,
    reference: str,
    content_hash: str,
) -> EvaluationDependencyFingerprint:
    """Create a hash-only dependency identity without retaining its raw locator."""

    return EvaluationDependencyFingerprint(
        kind=kind,
        reference_hash=sha256(reference.encode()).hexdigest(),
        content_hash=content_hash,
    )


def fingerprint_attack_case(
    case: AttackCase,
    *,
    dependencies: Iterable[EvaluationDependencyFingerprint] = (),
) -> EvaluationCaseFingerprint:
    """Fingerprint normalized case content independently from its external case ID."""

    normalized = case.model_dump(mode="json")
    normalized.pop("id", None)
    return EvaluationCaseFingerprint(
        case_id=case.id,
        content_hash=_canonical_hash(normalized),
        dependencies=_sorted_dependencies(tuple(dependencies)),
    )


def fingerprint_case_fingerprints(
    cases: Iterable[EvaluationCaseFingerprint],
    *,
    schema_version: int = _MANIFEST_SCHEMA_V1,
) -> str:
    """Order-independent hash of case IDs and exact normalized attack inputs."""

    normalized = sorted(
        (
            _case_fingerprint_payload(item, schema_version=schema_version)
            for item in cases
        ),
        key=lambda item: (str(item["case_id"]), str(item["content_hash"])),
    )
    return _canonical_hash(normalized)


def build_held_out_evaluation_manifest(
    *,
    manifest_id: str,
    discovery_cases: Iterable[AttackCase],
    evaluation_cases: Iterable[AttackCase],
    corpus_snapshot_hash: str,
    split_strategy: str,
    exposure: EvaluationSetExposure = EvaluationSetExposure.INTERNAL_HELD_OUT,
    sequestered_source_id: str | None = None,
    dependency_fingerprints: Mapping[
        str, Iterable[EvaluationDependencyFingerprint]
    ] | None = None,
) -> HeldOutEvaluationManifest:
    """Build a canonical immutable split manifest from normalized attack inputs."""

    discovery_cases = tuple(discovery_cases)
    evaluation_cases = tuple(evaluation_cases)
    all_case_ids = {case.id for case in discovery_cases + evaluation_cases}
    dependency_map = {
        case_id: _sorted_dependencies(tuple(items))
        for case_id, items in (dependency_fingerprints or {}).items()
    }
    unknown_dependency_cases = sorted(set(dependency_map) - all_case_ids)
    if unknown_dependency_cases:
        raise ValueError(
            "dependency fingerprints reference unknown case IDs: "
            f"{unknown_dependency_cases}"
        )
    schema_version = (
        _MANIFEST_SCHEMA_V2 if dependency_fingerprints is not None else _MANIFEST_SCHEMA_V1
    )

    discovery = tuple(
        fingerprint_attack_case(case, dependencies=dependency_map.get(case.id, ()))
        for case in discovery_cases
    )
    evaluation = tuple(
        fingerprint_attack_case(case, dependencies=dependency_map.get(case.id, ()))
        for case in evaluation_cases
    )
    discovery_hash = fingerprint_case_fingerprints(
        discovery,
        schema_version=schema_version,
    )
    evaluation_hash = fingerprint_case_fingerprints(
        evaluation,
        schema_version=schema_version,
    )
    payload = {
        "schema_version": schema_version,
        "manifest_id": manifest_id,
        "exposure": exposure.value,
        "split_strategy": split_strategy,
        "corpus_snapshot_hash": corpus_snapshot_hash,
        "red_can_access_evaluation_content": False,
        "sequestered_source_id": sequestered_source_id,
        "discovery_cases": [
            _case_fingerprint_payload(item, schema_version=schema_version) for item in discovery
        ],
        "evaluation_cases": [
            _case_fingerprint_payload(item, schema_version=schema_version) for item in evaluation
        ],
        "discovery_case_set_hash": discovery_hash,
        "evaluation_case_set_hash": evaluation_hash,
    }
    return HeldOutEvaluationManifest(
        **payload,
        content_hash=_canonical_hash(payload),
    )


def select_manifest_cases(
    cases: Iterable[AttackCase],
    *,
    manifest: HeldOutEvaluationManifest,
    evaluation: bool,
) -> tuple[AttackCase, ...]:
    """Select one partition and fail if any normalized case content differs."""

    expected = manifest.evaluation_cases if evaluation else manifest.discovery_cases
    expected_by_id = {item.case_id: item.content_hash for item in expected}
    available = {case.id: case for case in cases}
    missing = sorted(set(expected_by_id) - set(available))
    if missing:
        raise ValueError(f"manifest cases are missing from supplied corpus: {missing}")

    selected: list[AttackCase] = []
    for case_id in sorted(expected_by_id):
        case = available[case_id]
        observed = fingerprint_attack_case(case).content_hash
        if observed != expected_by_id[case_id]:
            raise ValueError(f"case content hash mismatch for {case_id}")
        selected.append(case)
    return tuple(selected)


def validate_manifest_case_dependencies(
    manifest: HeldOutEvaluationManifest,
    *,
    case_id: str,
    observed_dependencies: Iterable[EvaluationDependencyFingerprint],
    evaluation: bool,
) -> None:
    """Fail closed unless external attack inputs exactly match a v2 manifest binding."""

    if manifest.schema_version < _MANIFEST_SCHEMA_V2:
        raise ValueError(
            "held-out manifest schema v2 is required to bind external attack dependencies"
        )
    partition = manifest.evaluation_cases if evaluation else manifest.discovery_cases
    expected_by_id = {item.case_id: item.dependencies for item in partition}
    if case_id not in expected_by_id:
        raise ValueError(f"case {case_id} is not present in the selected manifest partition")
    observed = _sorted_dependencies(tuple(observed_dependencies))
    if observed != expected_by_id[case_id]:
        raise ValueError(f"external attack dependency mismatch for {case_id}")


def _case_fingerprint_payload(
    item: EvaluationCaseFingerprint,
    *,
    schema_version: int,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "case_id": item.case_id,
        "content_hash": item.content_hash,
    }
    if schema_version >= _MANIFEST_SCHEMA_V2:
        payload["dependencies"] = [
            dependency.model_dump(mode="json") for dependency in item.dependencies
        ]
    return payload


def _sorted_dependencies(
    dependencies: tuple[EvaluationDependencyFingerprint, ...],
) -> tuple[EvaluationDependencyFingerprint, ...]:
    return tuple(
        sorted(
            dependencies,
            key=lambda item: (item.kind, item.reference_hash, item.content_hash),
        )
    )


def _canonical_hash(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(raw.encode()).hexdigest()
