"""Offline admission bundle for the first local Reference Evaluation model set.

This module consumes only already-validated configuration and a persisted offline Ollama
qualification report. It performs no provider call, starts no runtime and sends no prompt.
Its purpose is to turn mutable model names into one hash-bound declaration of the exact
local Red and Blue artifacts intended for a later Reference Evaluation run.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_roles import ModelLocation, ModelRole, ModelRoleConfig, ModelsConfig
from .offline_ollama_qualification import OfflineOllamaQualificationReport

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_REQUIRED_RED_ROLES = (ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR)
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class LocalReferenceParticipant(StrEnum):
    """Model-backed participants required by Reference Evaluation v1."""

    RED_PLANNER = "red_planner"
    RED_MUTATOR = "red_mutator"
    BLUE = "blue"


class LocalReferenceRoleBinding(StrictModel):
    """One configured Red role bound to one exact verified local artifact."""

    participant: LocalReferenceParticipant
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    role_configuration_fingerprint: str = Field(pattern=_HASH_PATTERN)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    local_artifact: bool = True

    @model_validator(mode="after")
    def red_role_is_local(self) -> LocalReferenceRoleBinding:
        if self.participant == LocalReferenceParticipant.BLUE:
            raise ValueError("role binding cannot use participant=blue")
        if not self.local_artifact:
            raise ValueError("local Reference Red role cannot use a remote artifact")
        return self


class LocalReferenceBlueBinding(StrictModel):
    """Campaign-selected Blue model bound to one exact verified local artifact."""

    participant: LocalReferenceParticipant = LocalReferenceParticipant.BLUE
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    local_artifact: bool = True

    @model_validator(mode="after")
    def blue_is_local(self) -> LocalReferenceBlueBinding:
        if self.participant != LocalReferenceParticipant.BLUE:
            raise ValueError("Blue binding must use participant=blue")
        if not self.local_artifact:
            raise ValueError("local Reference Blue cannot use a remote artifact")
        return self


class LocalReferenceAdmissionBundle(StrictModel):
    """Hash-bound exact model assignment prepared before any local inference."""

    version: int = Field(ge=1, default=1)
    qualification_report_sha256: str = Field(pattern=_HASH_PATTERN)
    inventory_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_set_sha256: str = Field(pattern=_HASH_PATTERN)
    models_config_sha256: str = Field(pattern=_HASH_PATTERN)
    red_roles: tuple[LocalReferenceRoleBinding, ...]
    blue: LocalReferenceBlueBinding

    @model_validator(mode="after")
    def participant_set_is_complete_and_canonical(self) -> LocalReferenceAdmissionBundle:
        participants = tuple(item.participant for item in self.red_roles)
        expected = (
            LocalReferenceParticipant.RED_PLANNER,
            LocalReferenceParticipant.RED_MUTATOR,
        )
        if participants != expected:
            raise ValueError(
                "local Reference bundle must contain canonical planner/mutator roles"
            )
        if len({item.participant for item in self.red_roles}) != len(self.red_roles):
            raise ValueError("local Reference Red participants must be unique")
        return self

    @property
    def bundle_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def load_offline_ollama_qualification_report(
    path: str | Path,
    *,
    expected_report_sha256: str | None = None,
) -> OfflineOllamaQualificationReport:
    """Load one persisted report and validate its stored content identities.

    The hashes stored inside the JSON provide deterministic content identity, not a digital
    signature. If an independently pinned report hash is available, callers should pass it as
    ``expected_report_sha256`` so a rewritten file with recomputed self-hashes is also rejected.
    """

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"offline Ollama qualification report does not exist: {source}")
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid offline Ollama qualification JSON {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("offline Ollama qualification report must be a JSON object")

    normalized = dict(raw)
    declared_artifact_set = normalized.pop("artifact_set_sha256", None)
    declared_report = normalized.pop("report_sha256", None)
    if not isinstance(declared_artifact_set, str) or not isinstance(declared_report, str):
        raise ValueError(
            "offline Ollama qualification report must include "
            "artifact_set_sha256 and report_sha256"
        )
    try:
        report = OfflineOllamaQualificationReport.model_validate(normalized)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid offline Ollama qualification report {source}: {exc}") from exc

    if declared_artifact_set != report.artifact_set_sha256:
        raise ValueError(
            "offline Ollama qualification artifact_set_sha256 does not match content"
        )
    if declared_report != report.report_sha256:
        raise ValueError("offline Ollama qualification report_sha256 does not match content")
    if expected_report_sha256 is not None and expected_report_sha256 != report.report_sha256:
        raise ValueError("offline Ollama qualification report does not match pinned report hash")

    for item in report.artifacts:
        if item.model_id != item.identity.model_id:
            raise ValueError("offline Ollama qualification model ID does not match observation")
        if item.identity.provider_id != report.provider:
            raise ValueError("offline Ollama qualification provider does not match observation")
        if item.observation.source_response_sha256 != report.inventory_sha256:
            raise ValueError(
                "offline Ollama qualification observation does not match inventory hash"
            )
    return report


def build_local_reference_admission_bundle(
    *,
    models: ModelsConfig,
    report: OfflineOllamaQualificationReport,
    blue_model: str,
    blue_provider: str = "ollama",
) -> LocalReferenceAdmissionBundle:
    """Bind default Red roles and one campaign-selected Blue to exact local artifacts."""

    if not models.policy.local_first or models.policy.allow_cloud_fallback:
        raise ValueError(
            "local Reference admission requires local_first=true and "
            "allow_cloud_fallback=false"
        )
    if models.red_attacker_pool.enabled:
        raise ValueError("Reference Evaluation v1 admission requires the attacker pool disabled")
    if models.blue.source != "campaign":
        raise ValueError("Reference Evaluation v1 requires campaign-selected Blue")
    if report.provider != "ollama" or not report.require_local:
        raise ValueError(
            "local Reference admission requires a local Ollama qualification report"
        )
    if blue_provider != report.provider:
        raise ValueError("Blue provider does not match the offline qualification provider")

    artifacts = report.artifact_identities()
    red_bindings: list[LocalReferenceRoleBinding] = []
    for role in _REQUIRED_RED_ROLES:
        required_capabilities = (
            {"text", "reasoning"} if role == ModelRole.RED_PLANNER else {"text"}
        )
        config = models.role(role, required_capabilities=required_capabilities)
        _require_direct_local_ollama_role(role=role, config=config)
        artifact = artifacts.get((config.provider, config.model))
        if artifact is None:
            raise ValueError(
                f"verified local artifact missing for configured role "
                f"{role.value}: {config.model}"
            )
        if not artifact.local_artifact:
            raise ValueError(f"configured role {role.value} resolved to a remote artifact")
        participant = (
            LocalReferenceParticipant.RED_PLANNER
            if role == ModelRole.RED_PLANNER
            else LocalReferenceParticipant.RED_MUTATOR
        )
        red_bindings.append(
            LocalReferenceRoleBinding(
                participant=participant,
                provider=config.provider,
                model=config.model,
                role_configuration_fingerprint=config.configuration_fingerprint,
                artifact_identity_sha256=artifact.identity_sha256,
                artifact_digest=artifact.artifact_digest,
                local_artifact=artifact.local_artifact,
            )
        )

    blue_artifact = artifacts.get((blue_provider, blue_model))
    if blue_artifact is None:
        raise ValueError(
            f"verified local artifact missing for selected Blue model: {blue_model}"
        )
    if not blue_artifact.local_artifact:
        raise ValueError("selected Blue model resolved to a remote artifact")

    return LocalReferenceAdmissionBundle(
        qualification_report_sha256=report.report_sha256,
        inventory_sha256=report.inventory_sha256,
        artifact_set_sha256=report.artifact_set_sha256,
        models_config_sha256=_reference_models_config_sha256(models),
        red_roles=tuple(red_bindings),
        blue=LocalReferenceBlueBinding(
            provider=blue_provider,
            model=blue_model,
            artifact_identity_sha256=blue_artifact.identity_sha256,
            artifact_digest=blue_artifact.artifact_digest,
            local_artifact=blue_artifact.local_artifact,
        ),
    )


def _require_direct_local_ollama_role(
    *,
    role: ModelRole,
    config: ModelRoleConfig,
) -> None:
    if config.provider != "ollama":
        raise ValueError(f"Reference role {role.value} must use provider=ollama")
    if config.location != ModelLocation.LOCAL:
        raise ValueError(f"Reference role {role.value} must be classified local")
    if config.fallback:
        raise ValueError(f"Reference role {role.value} must not declare fallback models")
    if not config.endpoint:
        raise ValueError(f"Reference role {role.value} requires a direct local endpoint")
    parsed = urlparse(config.endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in _LOOPBACK_HOSTS:
        raise ValueError(f"Reference role {role.value} endpoint must use a loopback host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"Reference role {role.value} endpoint cannot contain credentials")


def _reference_models_config_sha256(models: ModelsConfig) -> str:
    """Hash only configuration that can affect Reference Evaluation v1 model routing."""

    roles = {
        role.value: models.role(role).configuration_fingerprint
        for role in _REQUIRED_RED_ROLES
    }
    return canonical_json_hash(
        {
            "version": models.version,
            "policy": models.policy.model_dump(mode="json"),
            "blue": models.blue.model_dump(mode="json"),
            "red_attacker_pool_enabled": models.red_attacker_pool.enabled,
            "roles": roles,
        }
    )
