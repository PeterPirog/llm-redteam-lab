"""Hash-bound discovery/evaluation partitions for auditable security measurement.

The manifest separates adaptive vulnerability discovery from comparative Blue
measurement. It never stores raw attack payloads; it stores case identifiers and
canonical content fingerprints. Evaluation content must not be exposed to the Red
policy during discovery. A SEQUESTERED manifest additionally declares that the case
definitions live outside the discovery runtime/repository view.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from enum import StrEnum
from hashlib import sha256

from pydantic import Field, model_validator

from .domain import AttackCase, StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class EvaluationSetExposure(StrEnum):
    """How strongly evaluation content is isolated from adaptive discovery."""

    INTERNAL_HELD_OUT = "INTERNAL_HELD_OUT"
    SEQUESTERED = "SEQUESTERED"


class EvaluationCaseFingerprint(StrictModel):
    """Content identity for one attack case without retaining its raw payload."""

    case_id: str = Field(min_length=1)
    content_hash: str = Field(pattern=_HASH_PATTERN)


class HeldOutEvaluationManifest(StrictModel):
    """Immutable partition declaration used to gate comparative Blue metrics."""

    schema_version: int = Field(ge=1, default=1)
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

        discovery_ids = [item.case_id for item in self.discovery_cases]
        evaluation_ids = [item.case_id for item in self.evaluation_cases]
        if len(discovery_ids) != len(set(discovery_ids)):
            raise ValueError("duplicate discovery case IDs are not allowed")
        if len(evaluation_ids) != len(set(evaluation_ids)):
            raise ValueError("duplicate evaluation case IDs are not allowed")

        id_overlap = set(discovery_ids) & set(evaluation_ids)
        if id_overlap:
            raise ValueError("discovery and evaluation case IDs must be disjoint")

        discovery_hashes = {item.content_hash for item in self.discovery_cases}
        evaluation_hashes = {item.content_hash for item in self.evaluation_cases}
        if discovery_hashes & evaluation_hashes:
            raise ValueError("discovery and evaluation case content must be disjoint")

        expected_discovery_hash = fingerprint_case_fingerprints(self.discovery_cases)
        expected_evaluation_hash = fingerprint_case_fingerprints(self.evaluation_cases)
        if self.discovery_case_set_hash != expected_discovery_hash:
            raise ValueError("discovery_case_set_hash does not match manifest cases")
        if self.evaluation_case_set_hash != expected_evaluation_hash:
            raise ValueError("evaluation_case_set_hash does not match manifest cases")

        expected_content_hash = _canonical_hash(self._hash_payload())
        if self.content_hash != expected_content_hash:
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
            "discovery_cases": [item.model_dump(mode="json") for item in self.discovery_cases],
            "evaluation_cases": [item.model_dump(mode="json") for item in self.evaluation_cases],
            "discovery_case_set_hash": self.discovery_case_set_hash,
            "evaluation_case_set_hash": self.evaluation_case_set_hash,
        }


def fingerprint_attack_case(case: AttackCase) -> EvaluationCaseFingerprint:
    """Fingerprint normalized case content independently from its external case ID."""

    normalized = case.model_dump(mode="json")
    normalized.pop("id", None)
    return EvaluationCaseFingerprint(
        case_id=case.id,
        content_hash=_canonical_hash(normalized),
    )


def fingerprint_case_fingerprints(
    cases: Iterable[EvaluationCaseFingerprint],
) -> str:
    """Order-independent hash of case IDs and exact normalized case content."""

    normalized = sorted(
        (item.model_dump(mode="json") for item in cases),
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
) -> HeldOutEvaluationManifest:
    """Build a canonical immutable split manifest from normalized attack cases."""

    discovery = tuple(fingerprint_attack_case(case) for case in discovery_cases)
    evaluation = tuple(fingerprint_attack_case(case) for case in evaluation_cases)
    discovery_hash = fingerprint_case_fingerprints(discovery)
    evaluation_hash = fingerprint_case_fingerprints(evaluation)
    payload = {
        "schema_version": 1,
        "manifest_id": manifest_id,
        "exposure": exposure.value,
        "split_strategy": split_strategy,
        "corpus_snapshot_hash": corpus_snapshot_hash,
        "red_can_access_evaluation_content": False,
        "sequestered_source_id": sequestered_source_id,
        "discovery_cases": [item.model_dump(mode="json") for item in discovery],
        "evaluation_cases": [item.model_dump(mode="json") for item in evaluation],
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
    """Select one partition and fail if any case content differs from the manifest."""

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


def _canonical_hash(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(raw.encode()).hexdigest()
