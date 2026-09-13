"""Resolve a persisted local Reference admission bundle into exact runtime artifacts.

This is still a control-plane-only step. It performs no provider call and no inference. The
resolver proves that the current ModelsConfig, persisted qualification report and persisted
admission bundle still describe the same exact Red/Blue model set before later runtime layers
are allowed to consume the artifacts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .local_reference_admission import (
    LocalReferenceAdmissionBundle,
    build_local_reference_admission_bundle,
)
from .model_artifact import ModelArtifactIdentity
from .model_roles import ModelsConfig
from .offline_ollama_qualification import OfflineOllamaQualificationReport


@dataclass(frozen=True, slots=True)
class LocalReferenceRuntimeArtifacts:
    """Exact provider-neutral model artifacts admitted for a later Reference runtime."""

    bundle_sha256: str
    qualification_report_sha256: str
    red_planner: ModelArtifactIdentity
    red_mutator: ModelArtifactIdentity
    blue: ModelArtifactIdentity

    def red_artifact_map(self) -> dict[tuple[str, str], ModelArtifactIdentity]:
        """Return the exact artifact map expected by later Red role qualification."""

        return {
            (self.red_planner.provider_id, self.red_planner.model_id): self.red_planner,
            (self.red_mutator.provider_id, self.red_mutator.model_id): self.red_mutator,
        }

    def all_artifact_map(self) -> dict[tuple[str, str], ModelArtifactIdentity]:
        """Return exact Red and Blue artifacts without granting any runtime capability."""

        artifacts = self.red_artifact_map()
        artifacts[(self.blue.provider_id, self.blue.model_id)] = self.blue
        return artifacts


def load_local_reference_admission_bundle(
    path: str | Path,
    *,
    expected_bundle_sha256: str | None = None,
) -> LocalReferenceAdmissionBundle:
    """Load a persisted admission bundle and validate its stored content identity."""

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"local Reference admission bundle does not exist: {source}")
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid local Reference admission JSON {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("local Reference admission bundle must be a JSON object")

    normalized = dict(raw)
    declared_bundle_sha256 = normalized.pop("bundle_sha256", None)
    if not isinstance(declared_bundle_sha256, str):
        raise ValueError("local Reference admission bundle must include bundle_sha256")
    try:
        bundle = LocalReferenceAdmissionBundle.model_validate(normalized)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid local Reference admission bundle {source}: {exc}") from exc

    if declared_bundle_sha256 != bundle.bundle_sha256:
        raise ValueError("local Reference admission bundle_sha256 does not match content")
    if expected_bundle_sha256 is not None and expected_bundle_sha256 != bundle.bundle_sha256:
        raise ValueError("local Reference admission bundle does not match pinned bundle hash")
    return bundle


def resolve_local_reference_runtime_artifacts(
    *,
    models: ModelsConfig,
    report: OfflineOllamaQualificationReport,
    bundle: LocalReferenceAdmissionBundle,
) -> LocalReferenceRuntimeArtifacts:
    """Recompute admission and expose exact artifacts only when all inputs still agree."""

    if bundle.qualification_report_sha256 != report.report_sha256:
        raise ValueError("admission bundle qualification report does not match current report")
    if bundle.inventory_sha256 != report.inventory_sha256:
        raise ValueError("admission bundle inventory hash does not match current report")
    if bundle.artifact_set_sha256 != report.artifact_set_sha256:
        raise ValueError("admission bundle artifact set does not match current report")

    expected = build_local_reference_admission_bundle(
        models=models,
        report=report,
        blue_model=bundle.blue.model,
        blue_provider=bundle.blue.provider,
    )
    if expected != bundle:
        raise ValueError(
            "current ModelsConfig/report do not reproduce the persisted local Reference bundle"
        )

    identities = report.artifact_identities()
    by_participant = {item.participant.value: item for item in bundle.red_roles}
    planner_binding = by_participant["red_planner"]
    mutator_binding = by_participant["red_mutator"]
    planner = identities.get((planner_binding.provider, planner_binding.model))
    mutator = identities.get((mutator_binding.provider, mutator_binding.model))
    blue = identities.get((bundle.blue.provider, bundle.blue.model))
    if planner is None or mutator is None or blue is None:
        raise RuntimeError("admitted artifact disappeared after successful bundle recomputation")

    _require_binding_match(
        participant="red_planner",
        artifact=planner,
        artifact_identity_sha256=planner_binding.artifact_identity_sha256,
        artifact_digest=planner_binding.artifact_digest,
    )
    _require_binding_match(
        participant="red_mutator",
        artifact=mutator,
        artifact_identity_sha256=mutator_binding.artifact_identity_sha256,
        artifact_digest=mutator_binding.artifact_digest,
    )
    _require_binding_match(
        participant="blue",
        artifact=blue,
        artifact_identity_sha256=bundle.blue.artifact_identity_sha256,
        artifact_digest=bundle.blue.artifact_digest,
    )

    return LocalReferenceRuntimeArtifacts(
        bundle_sha256=bundle.bundle_sha256,
        qualification_report_sha256=report.report_sha256,
        red_planner=planner,
        red_mutator=mutator,
        blue=blue,
    )


def _require_binding_match(
    *,
    participant: str,
    artifact: ModelArtifactIdentity,
    artifact_identity_sha256: str,
    artifact_digest: str,
) -> None:
    if artifact.identity_sha256 != artifact_identity_sha256:
        raise ValueError(f"{participant} artifact identity does not match admission bundle")
    if artifact.artifact_digest != artifact_digest:
        raise ValueError(f"{participant} artifact digest does not match admission bundle")
    if not artifact.local_artifact:
        raise ValueError(f"{participant} artifact is no longer classified local")
