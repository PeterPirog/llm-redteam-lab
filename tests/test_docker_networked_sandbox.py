from hashlib import sha256

import pytest

from llm_redteam.docker_model_network import (
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
)
from llm_redteam.docker_networked_sandbox import (
    DockerNetworkedAgentProfile,
    attest_networked_docker_sandbox,
)
from llm_redteam.docker_sandbox import (
    DockerContainerInspection,
    DockerMountInspection,
    DockerSandboxProfile,
)
from llm_redteam.opencode_runtime import (
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)

_HASH = "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64
_IMAGE_REF = "synthetic/opencode@sha256:" + "c" * 64
_AGENT_ID = "d" * 64
_MODEL_ID = "e" * 64
_NETWORK_ID = "f" * 64
_NETWORK_NAME = "rt-model-net"
_WORKSPACE = "/tmp/rt-workspace"


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _base() -> DockerSandboxProfile:
    return DockerSandboxProfile(
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        memory_limit_bytes=512 * 1024 * 1024,
        pids_limit=128,
        cpus=2.0,
    )


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _profile() -> DockerNetworkedAgentProfile:
    return DockerNetworkedAgentProfile.compose(
        sandbox=_base(),
        model_network=_network(),
    )


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(workspace_root="/workspace")


def _policy(profile: DockerNetworkedAgentProfile) -> AgentSandboxPolicy:
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=profile.profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )


def _inspection(*, network_mode: str = _NETWORK_NAME) -> DockerContainerInspection:
    return DockerContainerInspection(
        container_id_sha256=_digest(_AGENT_ID),
        image_id=_IMAGE_ID,
        running=True,
        auto_remove=True,
        privileged=False,
        readonly_rootfs=True,
        network_mode=network_mode,
        cap_add=(),
        cap_drop=("ALL",),
        security_opt=("no-new-privileges:true",),
        pids_limit=128,
        memory_limit_bytes=512 * 1024 * 1024,
        nano_cpus=2_000_000_000,
        mounts=(
            DockerMountInspection(
                mount_type="bind",
                source_sha256=_digest(_WORKSPACE),
                destination="/workspace",
                read_write=True,
            ),
        ),
    )


def _network_attestation(
    *,
    agent_container_id_sha256: str | None = None,
) -> DockerIsolatedModelNetworkAttestation:
    network = _network()
    return DockerIsolatedModelNetworkAttestation(
        issuer="synthetic-network-verifier",
        network_profile_sha256=network.profile_sha256,
        network_id_sha256=_digest(_NETWORK_ID),
        network_name_sha256=_digest(_NETWORK_NAME),
        agent_container_id_sha256=(
            agent_container_id_sha256 or _digest(_AGENT_ID)
        ),
        model_peer_container_id_sha256=_digest(_MODEL_ID),
        model_endpoint_origin_sha256=_digest(network.model_endpoint_origin),
        network_inspection_sha256=_HASH,
        agent_membership_sha256="1" * 64,
        model_membership_sha256="2" * 64,
    )


def test_composition_preserves_base_profile_identity_and_adds_network_identity() -> None:
    base = _base()
    profile = DockerNetworkedAgentProfile.compose(
        sandbox=base,
        model_network=_network(),
    )

    assert base.profile_sha256 == _base().profile_sha256
    assert profile.profile_sha256 != base.profile_sha256
    assert profile.model_network_profile_sha256 == _network().profile_sha256
    assert profile.model_endpoint_origin_sha256 == _digest(
        _network().model_endpoint_origin
    )


def test_networked_launch_preserves_hardening_and_uses_exact_network() -> None:
    command = _profile().docker_run_command(
        container_name="agent-peer",
        workspace_host_path=_WORKSPACE,
        network_name=_NETWORK_NAME,
        command=("opencode", "serve"),
        detach=True,
    )

    assert ("--network", _NETWORK_NAME) == (
        command[command.index("--network")],
        command[command.index("--network") + 1],
    )
    assert "none" not in command
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges:true"
    assert command[command.index("--mount") + 1].endswith("dst=/workspace,rw")
    assert "--publish" not in command
    assert "-p" not in command


def test_attestation_requires_container_and_network_proofs_to_agree() -> None:
    profile = _profile()
    attestation = attest_networked_docker_sandbox(
        docker_profile=profile,
        model_network_profile=_network(),
        runtime_profile=_runtime(),
        sandbox_policy=_policy(profile),
        inspection=_inspection(),
        network_attestation=_network_attestation(),
        workspace_host_path=_WORKSPACE,
        network_name=_NETWORK_NAME,
    )

    assert attestation.issuer == "llm-redteam-docker-networked-agent-v1"
    assert attestation.runtime_profile_sha256 == _runtime().profile_sha256
    assert attestation.sandbox_policy_sha256 == _policy(profile).policy_sha256
    assert attestation.isolation_id.startswith("docker-networked:")


def test_attestation_rejects_wrong_or_offline_network_mode() -> None:
    profile = _profile()

    with pytest.raises(ValueError, match="network_mode"):
        attest_networked_docker_sandbox(
            docker_profile=profile,
            model_network_profile=_network(),
            runtime_profile=_runtime(),
            sandbox_policy=_policy(profile),
            inspection=_inspection(network_mode="none"),
            network_attestation=_network_attestation(),
            workspace_host_path=_WORKSPACE,
            network_name=_NETWORK_NAME,
        )


def test_attestation_rejects_cross_container_network_evidence() -> None:
    profile = _profile()

    with pytest.raises(ValueError, match="different AGENT containers"):
        attest_networked_docker_sandbox(
            docker_profile=profile,
            model_network_profile=_network(),
            runtime_profile=_runtime(),
            sandbox_policy=_policy(profile),
            inspection=_inspection(),
            network_attestation=_network_attestation(
                agent_container_id_sha256=_digest("other-agent")
            ),
            workspace_host_path=_WORKSPACE,
            network_name=_NETWORK_NAME,
        )


def test_attestation_rejects_general_endpoint_allowlist() -> None:
    profile = _profile()
    policy = AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=profile.profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
        allowed_network_endpoints=("http://127.0.0.1:9999",),
    )

    with pytest.raises(ValueError, match="external endpoint allowlist"):
        attest_networked_docker_sandbox(
            docker_profile=profile,
            model_network_profile=_network(),
            runtime_profile=_runtime(),
            sandbox_policy=policy,
            inspection=_inspection(),
            network_attestation=_network_attestation(),
            workspace_host_path=_WORKSPACE,
            network_name=_NETWORK_NAME,
        )


def test_network_profile_change_changes_networked_sandbox_identity() -> None:
    base = _base()
    first = DockerNetworkedAgentProfile.compose(
        sandbox=base,
        model_network=_network(),
    )
    second_network = DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11435,
    )
    second = DockerNetworkedAgentProfile.compose(
        sandbox=base,
        model_network=second_network,
    )

    assert first.profile_sha256 != second.profile_sha256
