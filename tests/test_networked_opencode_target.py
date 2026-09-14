import asyncio
from hashlib import sha256

import pytest

from llm_redteam.docker_model_network import (
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
)
from llm_redteam.docker_networked_opencode_supervisor import DockerNetworkedOpenCodeLease
from llm_redteam.docker_networked_supervisor import DockerNetworkedAgentLease
from llm_redteam.docker_ollama_artifact import DockerOllamaArtifactVerification
from llm_redteam.docker_opencode_environment import (
    DockerNetworkedOpenCodeEnvironmentObservation,
)
from llm_redteam.model_artifact import (
    ModelArtifactIdentity,
    ModelArtifactObservation,
    bind_model_peer_artifact,
)
from llm_redteam.networked_opencode_target import (
    build_verified_networked_opencode_target,
    predeclared_networked_opencode_identity,
)
from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.opencode_health import OpenCodeHealthObservation
from llm_redteam.opencode_model_peer import OpenCodeModelPeerBinding
from llm_redteam.opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from llm_redteam.opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)
from llm_redteam.targets.opencode import OpenCodeConfig

_AGENT_ID = "a" * 64
_MODEL_CONTAINER_ID = "b" * 64
_MANIFEST = "c" * 64
_PEER_PROFILE_SHA = "d" * 64
_APP_VERSION = "1.15.13"


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(
        workspace_root="/workspace",
        hostname="127.0.0.1",
        port=4096,
    )


def _launch_policy() -> OpenCodeNetworkedLaunchPolicy:
    return OpenCodeNetworkedLaunchPolicy(
        runtime=_runtime(),
        model_binding=OpenCodeModelPeerBinding.from_network(
            network=_network(),
            provider_id="ollama",
            model_id="qwen-local",
        ),
    )


def _sandbox_policy() -> AgentSandboxPolicy:
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256="1" * 64,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )


def _config(**updates: object) -> OpenCodeConfig:
    values: dict[str, object] = {
        "id": "verified-local-opencode",
        "base_url": "http://127.0.0.1:4096",
        "model_provider_id": "ollama",
        "model_id": "qwen-local",
        "workspace_root": "/workspace",
        "application_version": _APP_VERSION,
    }
    values.update(updates)
    return OpenCodeConfig.model_validate(values)


def _contract(digest: str = _MANIFEST) -> OllamaArtifactContract:
    return OllamaArtifactContract(
        model_id="qwen-local",
        expected_manifest_digest=digest,
        require_local=True,
    )


def _artifact_verification(digest: str = _MANIFEST) -> DockerOllamaArtifactVerification:
    identity = ModelArtifactIdentity(
        provider_id="ollama",
        model_id="qwen-local",
        artifact_digest="sha256:" + digest,
        artifact_size_bytes=7_000_000_000,
        local_artifact=True,
        format="gguf",
        family="qwen",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )
    observation = ModelArtifactObservation(
        identity=identity,
        source_kind="ollama:/api/tags",
        source_response_sha256="2" * 64,
    )
    binding = bind_model_peer_artifact(
        peer_profile_sha256=_PEER_PROFILE_SHA,
        peer_provider_id="ollama",
        peer_model_id="qwen-local",
        artifact=identity,
    )
    return DockerOllamaArtifactVerification(
        container_id_sha256=_digest(_MODEL_CONTAINER_ID),
        probe_profile_sha256="3" * 64,
        probe_command_sha256="4" * 64,
        artifact=observation,
        binding=binding,
    )


def _runtime_lease(
    *,
    app_version: str = _APP_VERSION,
    model_container_hash: str | None = None,
) -> DockerNetworkedOpenCodeLease:
    runtime = _runtime()
    sandbox_policy = _sandbox_policy()
    sandbox = AgentSandboxAttestation(
        issuer="synthetic",
        isolation_id="docker-networked:" + _digest(_AGENT_ID),
        runtime_profile_sha256=runtime.profile_sha256,
        sandbox_policy_sha256=sandbox_policy.policy_sha256,
        workspace_root_sha256=runtime.workspace_root_sha256,
        proof_sha256="5" * 64,
    )
    network = _network()
    network_attestation = DockerIsolatedModelNetworkAttestation(
        issuer="synthetic-network",
        network_profile_sha256=network.profile_sha256,
        network_id_sha256="6" * 64,
        network_name_sha256="7" * 64,
        agent_container_id_sha256=_digest(_AGENT_ID),
        model_peer_container_id_sha256=(
            model_container_hash or _digest(_MODEL_CONTAINER_ID)
        ),
        model_endpoint_origin_sha256=_digest(network.model_endpoint_origin),
        network_inspection_sha256="8" * 64,
        agent_membership_sha256="9" * 64,
        model_membership_sha256="a" * 64,
    )
    agent = DockerNetworkedAgentLease(
        container_name="agent-peer",
        container_id_sha256=_digest(_AGENT_ID),
        launch_command_sha256="b" * 64,
        network_id_sha256="6" * 64,
        sandbox_attestation=sandbox,
        network_attestation=network_attestation,
    )
    launch_plan = _launch_policy().build_attested_plan(
        sandbox_policy=sandbox_policy,
        attestation=sandbox,
    )
    environment = DockerNetworkedOpenCodeEnvironmentObservation(
        container_id_sha256=_digest(_AGENT_ID),
        profile_sha256="c" * 64,
        command_sha256="d" * 64,
        public_environment_sha256="e" * 64,
        required_secret_names_sha256="f" * 64,
        redacted_observation_sha256="0" * 64,
    )
    health = OpenCodeHealthObservation(
        healthy=True,
        application_version=app_version,
        runtime_profile_sha256=runtime.profile_sha256,
        sandbox_attestation_sha256=sandbox.attestation_sha256,
        container_id_sha256=_digest(_AGENT_ID),
        endpoint_sha256="1" * 64,
        response_sha256="2" * 64,
    )
    return DockerNetworkedOpenCodeLease(
        agent=agent,
        environment=environment,
        launch_plan=launch_plan,
        health=health,
    )


def test_predeclared_identity_contains_exact_model_digest() -> None:
    identity = predeclared_networked_opencode_identity(
        config=_config(),
        launch_policy=_launch_policy(),
        sandbox_policy=_sandbox_policy(),
        artifact_contract=_contract(),
    )

    assert identity.model_digest == "sha256:" + _MANIFEST
    assert identity.model == "ollama/qwen-local"
    assert identity.application_version == _APP_VERSION
    assert "docker_exec_control_transport" in identity.capabilities
    assert "runtime_attested" in identity.capabilities
    assert "runtime_health_verified" in identity.capabilities
    assert "model_artifact_verified" in identity.capabilities


def test_runtime_target_identity_equals_predeclared_identity_without_execution() -> None:
    expected = predeclared_networked_opencode_identity(
        config=_config(),
        launch_policy=_launch_policy(),
        sandbox_policy=_sandbox_policy(),
        artifact_contract=_contract(),
    )
    target = build_verified_networked_opencode_target(
        config=_config(),
        launch_policy=_launch_policy(),
        sandbox_policy=_sandbox_policy(),
        runtime_lease=_runtime_lease(),
        artifact_verification=_artifact_verification(),
        artifact_contract=_contract(),
    )
    try:
        assert target.identity == expected
    finally:
        asyncio.run(target.aclose())


def test_runtime_builder_rejects_model_peer_cross_binding_before_target_creation() -> None:
    with pytest.raises(ValueError, match="different model peers"):
        build_verified_networked_opencode_target(
            config=_config(),
            launch_policy=_launch_policy(),
            sandbox_policy=_sandbox_policy(),
            runtime_lease=_runtime_lease(model_container_hash="f" * 64),
            artifact_verification=_artifact_verification(),
            artifact_contract=_contract(),
        )


def test_runtime_builder_rejects_application_version_drift() -> None:
    with pytest.raises(ValueError, match="application version"):
        build_verified_networked_opencode_target(
            config=_config(),
            launch_policy=_launch_policy(),
            sandbox_policy=_sandbox_policy(),
            runtime_lease=_runtime_lease(app_version="different-version"),
            artifact_verification=_artifact_verification(),
            artifact_contract=_contract(),
        )


def test_runtime_builder_rejects_artifact_digest_drift() -> None:
    with pytest.raises(ValueError, match="artifact digest"):
        build_verified_networked_opencode_target(
            config=_config(),
            launch_policy=_launch_policy(),
            sandbox_policy=_sandbox_policy(),
            runtime_lease=_runtime_lease(),
            artifact_verification=_artifact_verification(digest="f" * 64),
            artifact_contract=_contract(),
        )
