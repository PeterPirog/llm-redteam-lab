"""Logical and runtime identity for an isolated local-model OpenCode AGENT target.

The predeclared identity is pure configuration used by campaign planning.  The runtime
builder independently constructs the Docker-exec/health-gated target and only exposes it
when the verified Ollama artifact, model-network evidence and application policy agree
with that predeclared identity.
"""

from __future__ import annotations

from hashlib import sha256

from .agent_actions import canonical_json_hash
from .docker_exec_http import DockerExecContainerRef, DockerExecHttpProfile
from .docker_exec_opencode import build_attested_docker_exec_opencode_target
from .docker_networked_opencode_supervisor import DockerNetworkedOpenCodeLease
from .docker_ollama_artifact import DockerOllamaArtifactVerification
from .docker_supervisor import DockerCommandRunner
from .domain import EvidenceKind, EvidenceRecord, TargetIdentity
from .ollama_artifact import OllamaArtifactContract
from .opencode_health import HealthGatedOpenCodeTarget
from .opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from .opencode_runtime import AgentSandboxPolicy
from .targets.base import TargetRequest, TargetResponse
from .targets.opencode import OpenCodeConfig


class VerifiedModelArtifactOpenCodeTarget:
    """Attach verified model-artifact identity and provenance to an admitted target."""

    def __init__(
        self,
        target: HealthGatedOpenCodeTarget,
        verification: DockerOllamaArtifactVerification,
    ) -> None:
        self._target = target
        self.verification = verification
        self._emitted = False

    @property
    def identity(self) -> TargetIdentity:
        base = self._target.identity
        return base.model_copy(
            update={
                "model_digest": self.verification.artifact.identity.artifact_digest,
                "capabilities": base.capabilities | frozenset({"model_artifact_verified"}),
            }
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        response = await self._target.execute(request)
        if self._emitted:
            return response
        self._emitted = True
        evidence = EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="model_artifact_verification",
            observed_at="runtime",
            content_hash=self.verification.proof_sha256,
            data={
                "model_artifact_identity_sha256": (
                    self.verification.artifact.identity.identity_sha256
                ),
                "model_artifact_digest": (
                    self.verification.artifact.identity.artifact_digest
                ),
                "model_peer_artifact_binding_sha256": (
                    self.verification.binding.binding_sha256
                ),
                "artifact_probe_profile_sha256": (
                    self.verification.probe_profile_sha256
                ),
            },
            redacted=True,
        )
        return response.model_copy(update={"evidence": (*response.evidence, evidence)})

    async def aclose(self) -> None:
        await self._target.aclose()


def predeclared_networked_opencode_identity(
    *,
    config: OpenCodeConfig,
    launch_policy: OpenCodeNetworkedLaunchPolicy,
    sandbox_policy: AgentSandboxPolicy,
    artifact_contract: OllamaArtifactContract,
) -> TargetIdentity:
    """Compute the exact stable identity expected from every disposable trial lease."""

    launch_policy.model_binding.validate_target_config(config)
    if launch_policy.model_binding.provider_id != "ollama":
        raise ValueError("Ollama artifact contract requires an Ollama OpenCode provider")
    if artifact_contract.model_id != launch_policy.model_binding.model_id:
        raise ValueError("artifact contract model does not match OpenCode model binding")

    base = _base_opencode_identity(config)
    transport = DockerExecHttpProfile(
        runtime_profile_sha256=launch_policy.runtime.profile_sha256,
        username=config.username,
    )
    transport_configuration_hash = canonical_json_hash(
        {
            "base_target_configuration_hash": base.configuration_hash,
            "control_transport_profile_sha256": transport.profile_sha256,
        }
    )
    target_policy_sha256 = canonical_json_hash(
        {
            "runtime_profile_sha256": launch_policy.runtime.profile_sha256,
            "sandbox_policy_sha256": sandbox_policy.policy_sha256,
            "workspace_root_sha256": launch_policy.runtime.workspace_root_sha256,
            "mcp_fixture_bridge_sha256": (
                launch_policy.runtime.mcp_fixture_bridge.bridge_sha256
                if launch_policy.runtime.mcp_fixture_bridge is not None
                else None
            ),
        }
    )
    configuration_hash = canonical_json_hash(
        {
            "base_target_configuration_hash": transport_configuration_hash,
            "opencode_target_policy_sha256": target_policy_sha256,
        }
    )
    return base.model_copy(
        update={
            "configuration_hash": configuration_hash,
            "model_digest": artifact_contract.manifest_digest,
            "capabilities": base.capabilities
            | frozenset(
                {
                    "docker_exec_control_transport",
                    "runtime_attested",
                    "runtime_health_verified",
                    "model_artifact_verified",
                }
            ),
        }
    )


def build_verified_networked_opencode_target(
    *,
    config: OpenCodeConfig,
    launch_policy: OpenCodeNetworkedLaunchPolicy,
    sandbox_policy: AgentSandboxPolicy,
    runtime_lease: DockerNetworkedOpenCodeLease,
    artifact_verification: DockerOllamaArtifactVerification,
    artifact_contract: OllamaArtifactContract,
    runner: DockerCommandRunner | None = None,
) -> VerifiedModelArtifactOpenCodeTarget:
    """Build a usable target only when runtime evidence matches predeclared identity."""

    launch_policy.model_binding.validate_target_config(config)
    artifact = artifact_verification.artifact.identity
    if artifact.provider_id != launch_policy.model_binding.provider_id:
        raise ValueError("verified artifact provider does not match OpenCode model binding")
    if artifact.model_id != launch_policy.model_binding.model_id:
        raise ValueError("verified artifact model does not match OpenCode model binding")
    if artifact.artifact_digest != artifact_contract.manifest_digest:
        raise ValueError("verified artifact digest does not match predeclared artifact contract")
    if (
        runtime_lease.agent.network_attestation.model_peer_container_id_sha256
        != artifact_verification.container_id_sha256
    ):
        raise ValueError("artifact verification and AGENT network bind different model peers")

    container = DockerExecContainerRef(
        container_name=runtime_lease.agent.container_name,
        container_id_sha256=runtime_lease.agent.container_id_sha256,
    )
    attested = build_attested_docker_exec_opencode_target(
        config=config,
        runtime_profile=launch_policy.runtime,
        launch_plan=runtime_lease.launch_plan,
        container=container,
        runner=runner,
    )
    try:
        gated = HealthGatedOpenCodeTarget(attested, runtime_lease.health)
        verified = VerifiedModelArtifactOpenCodeTarget(gated, artifact_verification)
        expected = predeclared_networked_opencode_identity(
            config=config,
            launch_policy=launch_policy,
            sandbox_policy=sandbox_policy,
            artifact_contract=artifact_contract,
        )
        if verified.identity != expected:
            raise ValueError("runtime OpenCode target identity differs from predeclared Blue identity")
        return verified
    except Exception:
        # Construction has not escaped to campaign code yet.  The async client owns no
        # host socket (Docker-exec transport only), but the caller still closes it through
        # the surrounding trial lifecycle after a successful return.
        raise


def _base_opencode_identity(config: OpenCodeConfig) -> TargetIdentity:
    fingerprint = "|".join(
        [
            config.base_url.rstrip("/"),
            config.model_provider_id,
            config.model_id,
            config.agent,
            config.workspace_root or "",
            config.application_version or "",
            config.session_path,
            config.message_path_template,
            config.persisted_message_path_template,
            str(bool(config.password_env)),
        ]
    )
    return TargetIdentity(
        id=config.id,
        target_class="coding",
        target_mode="AGENT",
        model=f"{config.model_provider_id}/{config.model_id}",
        provider="opencode",
        runtime=config.base_url,
        application="OpenCode",
        application_version=config.application_version,
        configuration_hash=sha256(fingerprint.encode()).hexdigest(),
        capabilities=config.capabilities,
    )
