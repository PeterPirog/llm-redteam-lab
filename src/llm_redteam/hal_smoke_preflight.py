"""Offline, fail-closed composition for the first real HAL AGENT smoke.

"Local" is an execution-location claim: selected models must be invoked through runtimes
operating on HAL. Zero-cloud measurement is stricter and additionally requires exact local
Ollama artifacts. This module composes those two claims without starting Docker, Ollama,
OpenCode, a GPU workload, or model inference.

The output is deliberately *not* runtime attestation. It is a deterministic launch contract
that enumerates the live HAL evidence still required before a trial may execute.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_networked_opencode_profile import DockerNetworkedOpenCodeAgentProfile
from .docker_ollama_staged_peer import DockerOllamaStagedPeerProfile
from .docker_sandbox import DockerSandboxProfile
from .domain import StrictModel, TargetClass, TargetMode
from .model_inventory import LocalOnlyAdmissionReport, require_local_model_endpoint
from .model_roles import ModelLocation, ModelRole, ModelsConfig
from .ollama_model_staging import OllamaStagedModelStoreIdentity
from .opencode_model_peer import (
    OpenCodeModelPeerBinding,
    OpenCodeProviderConfigDialect,
)
from .opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from .opencode_runtime import (
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)
from .reference_artifact_qualification import ReferenceArtifactQualificationReport
from .target_trial_isolation import TargetIsolationLevel
from .targets.opencode import OpenCodeConfig

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_IMAGE_REF_PATTERN = r"^.+@sha256:[0-9a-f]{64}$"
_IMAGE_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"

_LIVE_EVIDENCE_REQUIREMENTS = (
    "fresh_hal_openwebui_inventory",
    "fresh_hal_ollama_tags_snapshot",
    "exact_red_runtime_artifact_recheck",
    "docker_engine_version_observation",
    "owned_isolated_model_network_lease",
    "staged_blue_store_filesystem_reverification",
    "staged_blue_peer_mount_and_readiness_attestation",
    "runtime_blue_artifact_probe_binding",
    "disposable_workspace_materialization",
    "opencode_environment_attestation",
    "opencode_health_version_attestation",
    "per_trial_cleanup_proof",
)


class HalSmokeStaticPlan(StrictModel):
    """HAL smoke choices that can be proven without touching HAL runtime state."""

    version: int = Field(ge=1, default=1)
    locality_contract: str = "hal-execution-local-plus-exact-artifact-v1"
    execution_config_sha256: str = Field(pattern=_HASH_PATTERN)
    red_planner_model_id: str = Field(min_length=1)
    red_mutator_model_id: str = Field(min_length=1)
    blue_model_id: str = Field(min_length=1)
    red_planner_configuration_sha256: str = Field(pattern=_HASH_PATTERN)
    red_mutator_configuration_sha256: str = Field(pattern=_HASH_PATTERN)
    red_planner_endpoint_sha256: str = Field(pattern=_HASH_PATTERN)
    red_mutator_endpoint_sha256: str = Field(pattern=_HASH_PATTERN)
    target_class: TargetClass = TargetClass.CODING
    target_mode: TargetMode = TargetMode.AGENT
    required_isolation: TargetIsolationLevel = TargetIsolationLevel.DISPOSABLE_SANDBOX
    cloud_fallback_allowed: bool = False
    exact_local_artifact_required: bool = True

    @property
    def plan_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class HalSmokeRuntimePins(StrictModel):
    """Operator-supplied immutable runtime inputs collected before the live smoke."""

    version: int = Field(ge=1, default=1)
    staged_blue_store_identity: OllamaStagedModelStoreIdentity
    opencode_application_version: str = Field(min_length=1)
    opencode_image_ref: str = Field(pattern=_IMAGE_REF_PATTERN)
    opencode_image_id: str = Field(pattern=_IMAGE_ID_PATTERN)
    ollama_peer_image_ref: str = Field(pattern=_IMAGE_REF_PATTERN)
    ollama_peer_image_id: str = Field(pattern=_IMAGE_ID_PATTERN)
    provider_dialect: OpenCodeProviderConfigDialect = (
        OpenCodeProviderConfigDialect.PROVIDER_V1
    )
    model_endpoint_host: str = "model-peer"
    model_endpoint_port: int = Field(ge=1, le=65535, default=11434)
    workspace_root: str = "/workspace"
    opencode_port: int = Field(ge=1, le=65535, default=4096)
    opencode_password_env: str = "OPENCODE_SERVER_PASSWORD"
    agent_memory_limit_bytes: int = Field(ge=64 * 1024 * 1024, default=4 * 1024**3)
    agent_pids_limit: int = Field(ge=16, default=256)
    agent_cpus: float = Field(gt=0.0, default=4.0)
    model_peer_memory_limit_bytes: int = Field(gt=0, default=16 * 1024**3)
    model_peer_pids_limit: int = Field(gt=0, default=512)
    model_peer_cpus: float = Field(gt=0.0, default=8.0)
    model_peer_gpu_access: bool = True

    @model_validator(mode="after")
    def staged_store_is_exact_manifest_identity(self) -> HalSmokeRuntimePins:
        _normalize_sha256_digest(self.staged_blue_store_identity.manifest_digest)
        return self

    @property
    def pins_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class HalSmokeOfflineComposition(StrictModel):
    """Deterministic runtime contract; live evidence is intentionally still outstanding."""

    version: int = Field(ge=1, default=1)
    static_plan: HalSmokeStaticPlan
    runtime_pins_sha256: str = Field(pattern=_HASH_PATTERN)
    local_admission_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_qualification_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    blue_artifact_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    model_network: DockerIsolatedModelNetworkProfile
    model_peer: DockerOllamaStagedPeerProfile
    opencode_runtime: OpenCodeRuntimeProfile
    opencode_launch_policy: OpenCodeNetworkedLaunchPolicy
    opencode_agent: DockerNetworkedOpenCodeAgentProfile
    sandbox_policy: AgentSandboxPolicy
    target_config: OpenCodeConfig
    live_evidence_requirements: tuple[str, ...] = _LIVE_EVIDENCE_REQUIREMENTS

    @property
    def composition_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))

    @property
    def live_runtime_admitted(self) -> bool:
        """Offline composition can never substitute for runtime attestation."""

        return False


def build_hal_smoke_static_plan(
    *,
    models: ModelsConfig,
    blue_model_id: str,
) -> HalSmokeStaticPlan:
    """Validate the bounded first-smoke model policy without querying HAL."""

    if not blue_model_id.strip():
        raise ValueError("HAL smoke Blue model ID must be non-empty")
    if not models.policy.local_first:
        raise ValueError("HAL smoke requires models.policy.local_first=true")
    if models.policy.allow_cloud_fallback:
        raise ValueError("HAL smoke forbids cloud fallback")
    if models.red_attacker_pool.enabled:
        raise ValueError("first HAL instrumentation smoke requires attacker pool disabled")

    enabled_roles = {role for role, config in models.roles.items() if config.enabled}
    expected_roles = {ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR}
    if enabled_roles != expected_roles:
        unexpected = sorted(role.value for role in enabled_roles.difference(expected_roles))
        missing = sorted(role.value for role in expected_roles.difference(enabled_roles))
        details: list[str] = []
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected))
        if missing:
            details.append("missing=" + ",".join(missing))
        raise ValueError(
            "first HAL smoke enables exactly red_planner and red_mutator"
            + (": " + "; ".join(details) if details else "")
        )

    planner = models.role(
        ModelRole.RED_PLANNER,
        required_capabilities={"text", "reasoning"},
    )
    mutator = models.role(ModelRole.RED_MUTATOR, required_capabilities={"text"})
    for label, config in (("red_planner", planner), ("red_mutator", mutator)):
        if config.location != ModelLocation.LOCAL:
            raise ValueError(f"HAL smoke role is not declared local: {label}")
        if config.provider != "ollama":
            raise ValueError(f"first HAL smoke currently requires Ollama role: {label}")
        if config.endpoint is None:
            raise ValueError(f"HAL smoke role requires explicit endpoint: {label}")
        if config.fallback:
            raise ValueError(f"HAL smoke role cannot declare fallback models: {label}")

    planner_endpoint_sha256 = require_local_model_endpoint(
        planner.endpoint,
        label="red_planner",
    )
    mutator_endpoint_sha256 = require_local_model_endpoint(
        mutator.endpoint,
        label="red_mutator",
    )
    execution_config_sha256 = canonical_json_hash(
        {
            "version": models.version,
            "policy": models.policy.model_dump(mode="json"),
            "enabled_roles": {
                ModelRole.RED_PLANNER.value: planner.configuration_fingerprint,
                ModelRole.RED_MUTATOR.value: mutator.configuration_fingerprint,
            },
            "red_attacker_pool_enabled": False,
        }
    )
    return HalSmokeStaticPlan(
        execution_config_sha256=execution_config_sha256,
        red_planner_model_id=planner.model,
        red_mutator_model_id=mutator.model,
        blue_model_id=blue_model_id.strip(),
        red_planner_configuration_sha256=planner.configuration_fingerprint,
        red_mutator_configuration_sha256=mutator.configuration_fingerprint,
        red_planner_endpoint_sha256=planner_endpoint_sha256,
        red_mutator_endpoint_sha256=mutator_endpoint_sha256,
    )


def compose_hal_smoke_offline(
    *,
    static_plan: HalSmokeStaticPlan,
    admission: LocalOnlyAdmissionReport,
    qualification: ReferenceArtifactQualificationReport,
    pins: HalSmokeRuntimePins,
) -> HalSmokeOfflineComposition:
    """Bind exact model evidence and runtime pins into the launch contract."""

    _validate_model_evidence(
        static_plan=static_plan,
        admission=admission,
        qualification=qualification,
        pins=pins,
    )
    blue_binding = next(
        binding
        for binding in qualification.bindings
        if binding.model_id == static_plan.blue_model_id
    )

    network = DockerIsolatedModelNetworkProfile(
        model_endpoint_host=pins.model_endpoint_host,
        model_endpoint_port=pins.model_endpoint_port,
    )
    runtime = OpenCodeRuntimeProfile(
        workspace_root=pins.workspace_root,
        port=pins.opencode_port,
        server_password_env=pins.opencode_password_env,
    )
    model_binding = OpenCodeModelPeerBinding.from_network(
        network=network,
        provider_id="ollama",
        model_id=static_plan.blue_model_id,
        dialect=pins.provider_dialect,
    )
    launch_policy = OpenCodeNetworkedLaunchPolicy(
        runtime=runtime,
        model_binding=model_binding,
    )
    agent_sandbox = DockerSandboxProfile(
        image_ref=pins.opencode_image_ref,
        image_id=pins.opencode_image_id,
        container_workspace=pins.workspace_root,
        memory_limit_bytes=pins.agent_memory_limit_bytes,
        pids_limit=pins.agent_pids_limit,
        cpus=pins.agent_cpus,
    )
    agent_profile = DockerNetworkedOpenCodeAgentProfile.compose(
        sandbox=agent_sandbox,
        model_network=network,
        launch_policy=launch_policy,
    )
    sandbox_policy = AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=agent_profile.profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )
    target_config = OpenCodeConfig(
        id="hal-smoke-opencode",
        base_url=f"http://{runtime.hostname}:{runtime.port}",
        model_provider_id="ollama",
        model_id=static_plan.blue_model_id,
        workspace_root=runtime.workspace_root,
        application_version=pins.opencode_application_version,
        password_env=runtime.server_password_env,
    )
    launch_policy.validate_target_config(target_config)

    model_peer = DockerOllamaStagedPeerProfile(
        provider_id="ollama",
        model_id=static_plan.blue_model_id,
        image_ref=pins.ollama_peer_image_ref,
        image_id=pins.ollama_peer_image_id,
        command=("ollama", "serve"),
        readiness_command=("/usr/local/bin/rt-ollama-probe", "version"),
        readiness_required_json={"provider": "ollama", "ready": True},
        memory_limit_bytes=pins.model_peer_memory_limit_bytes,
        pids_limit=pins.model_peer_pids_limit,
        cpus=pins.model_peer_cpus,
        gpu_access=pins.model_peer_gpu_access,
        staged_store_identity_sha256=(
            pins.staged_blue_store_identity.identity_sha256
        ),
        container_models_path="/models",
    )

    return HalSmokeOfflineComposition(
        static_plan=static_plan,
        runtime_pins_sha256=pins.pins_sha256,
        local_admission_proof_sha256=admission.proof_sha256,
        artifact_qualification_proof_sha256=qualification.proof_sha256,
        blue_artifact_digest=blue_binding.artifact_digest,
        model_network=network,
        model_peer=model_peer,
        opencode_runtime=runtime,
        opencode_launch_policy=launch_policy,
        opencode_agent=agent_profile,
        sandbox_policy=sandbox_policy,
        target_config=target_config,
    )


def _validate_model_evidence(
    *,
    static_plan: HalSmokeStaticPlan,
    admission: LocalOnlyAdmissionReport,
    qualification: ReferenceArtifactQualificationReport,
    pins: HalSmokeRuntimePins,
) -> None:
    expected_pairs = {
        ("red_planner", static_plan.red_planner_model_id),
        ("red_mutator", static_plan.red_mutator_model_id),
        ("blue", static_plan.blue_model_id),
    }
    observed_pairs = {(binding.label, binding.model_id) for binding in admission.bindings}
    if observed_pairs != expected_pairs:
        raise ValueError("HAL admission bindings do not exactly match the static smoke plan")
    if admission.blue_model_id != static_plan.blue_model_id:
        raise ValueError("HAL admission Blue model differs from the static smoke plan")
    if qualification.local_admission_proof_sha256 != admission.proof_sha256:
        raise ValueError("artifact qualification does not bind the supplied HAL admission")

    expected_models = tuple(
        sorted(
            {
                static_plan.red_planner_model_id,
                static_plan.red_mutator_model_id,
                static_plan.blue_model_id,
            }
        )
    )
    if tuple(sorted(qualification.qualified_model_ids)) != expected_models:
        raise ValueError("artifact qualification does not exactly cover smoke models")

    store = pins.staged_blue_store_identity
    if store.model_id != static_plan.blue_model_id:
        raise ValueError("staged Blue store model differs from the static smoke plan")
    blue_bindings = [
        binding
        for binding in qualification.bindings
        if binding.model_id == static_plan.blue_model_id
    ]
    if len(blue_bindings) != 1:
        raise ValueError("artifact qualification must contain one exact Blue binding")
    qualified_digest = _normalize_sha256_digest(blue_bindings[0].artifact_digest)
    staged_digest = _normalize_sha256_digest(store.manifest_digest)
    if qualified_digest != staged_digest:
        raise ValueError("staged Blue manifest disagrees with qualified Blue artifact")


def _normalize_sha256_digest(value: str) -> str:
    normalized = value.strip().casefold()
    digest = normalized.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("artifact digest must be a SHA-256")
    return digest


def load_hal_smoke_runtime_pins(path: str | Path) -> HalSmokeRuntimePins:
    """Load immutable HAL runtime pins from YAML/JSON without contacting HAL."""

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"HAL smoke runtime pins do not exist: {source}")
    try:
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"HAL smoke runtime pins are not valid YAML/JSON: {source}") from exc
    if not isinstance(payload, dict):
        raise ValueError("HAL smoke runtime pins document must be an object")
    try:
        return HalSmokeRuntimePins.model_validate(payload)
    except ValueError as exc:
        raise ValueError(f"invalid HAL smoke runtime pins {source}: {exc}") from exc
