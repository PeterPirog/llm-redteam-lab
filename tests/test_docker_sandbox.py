from copy import deepcopy

import pytest

from llm_redteam.docker_sandbox import (
    DockerContainerInspection,
    DockerSandboxProfile,
    attest_offline_docker_sandbox,
)
from llm_redteam.opencode_runtime import (
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)

_IMAGE_MANIFEST = "a" * 64
_IMAGE_ID = "b" * 64
_CONTAINER_ID = "c" * 64
_WORKSPACE = "/tmp/llm-redteam/workspace"


def _docker_profile(**updates: object) -> DockerSandboxProfile:
    values: dict[str, object] = {
        "image_ref": f"llm-redteam-opencode@sha256:{_IMAGE_MANIFEST}",
        "image_id": f"sha256:{_IMAGE_ID}",
        "memory_limit_bytes": 1_073_741_824,
        "pids_limit": 128,
        "cpus": 2.0,
    }
    values.update(updates)
    return DockerSandboxProfile.model_validate(values)


def _runtime_profile() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(
        workspace_root=_WORKSPACE,
        hostname="127.0.0.1",
        port=4096,
    )


def _policy(**updates: object) -> AgentSandboxPolicy:
    values: dict[str, object] = {
        "enforcement_kind": SandboxEnforcementKind.DOCKER,
        "disposable_workspace": True,
        "external_network_denied": True,
        "git_publication_denied": True,
        "allowed_network_endpoints": (),
    }
    values.update(updates)
    return AgentSandboxPolicy.model_validate(values)


def _inspect_payload(**host_config_updates: object) -> dict[str, object]:
    host_config: dict[str, object] = {
        "AutoRemove": True,
        "Privileged": False,
        "ReadonlyRootfs": True,
        "NetworkMode": "none",
        "CapAdd": None,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "PidsLimit": 128,
        "Memory": 1_073_741_824,
        "NanoCpus": 2_000_000_000,
    }
    host_config.update(host_config_updates)
    return {
        "Id": _CONTAINER_ID,
        "Image": f"sha256:{_IMAGE_ID}",
        "State": {"Running": True},
        "HostConfig": host_config,
        "Mounts": [
            {
                "Type": "bind",
                "Source": _WORKSPACE,
                "Destination": "/workspace",
                "RW": True,
            }
        ],
    }


def _attest(payload: dict[str, object] | None = None):
    inspection = DockerContainerInspection.from_docker_inspect(payload or _inspect_payload())
    return attest_offline_docker_sandbox(
        docker_profile=_docker_profile(),
        runtime_profile=_runtime_profile(),
        sandbox_policy=_policy(),
        inspection=inspection,
        workspace_host_path=_WORKSPACE,
    )


def test_offline_docker_command_is_fail_closed_and_digest_pinned() -> None:
    profile = _docker_profile()

    command = profile.docker_run_command(
        container_name="llm-redteam-case-1",
        workspace_host_path=_WORKSPACE,
        command=("opencode", "--version"),
    )

    assert command[:3] == ("docker", "run", "--rm")
    assert ("--pull", "never") == command[3:5]
    assert _adjacent(command, "--network", "none")
    assert "--read-only" in command
    assert _adjacent(command, "--cap-drop", "ALL")
    assert _adjacent(command, "--security-opt", "no-new-privileges:true")
    assert _adjacent(command, "--pids-limit", "128")
    assert _adjacent(command, "--memory", "1073741824")
    assert profile.image_ref in command
    assert command[-2:] == ("opencode", "--version")


def test_profile_requires_digest_pinned_image_and_absolute_workspace() -> None:
    with pytest.raises(ValueError):
        _docker_profile(image_ref="llm-redteam-opencode:latest")

    with pytest.raises(ValueError, match="absolute"):
        _docker_profile(container_workspace="relative/workspace")


def test_docker_inspection_issues_hash_only_attestation() -> None:
    inspection = DockerContainerInspection.from_docker_inspect(_inspect_payload())
    attestation = _attest()

    assert inspection.network_mode == "none"
    assert inspection.cap_drop == ("ALL",)
    assert attestation.issuer == "llm-redteam-docker-inspect-v1"
    assert attestation.isolation_id == f"docker:{inspection.container_id_sha256}"
    assert attestation.proof_sha256 == inspection.proof_sha256
    serialized = attestation.model_dump_json()
    assert _WORKSPACE not in serialized
    assert _CONTAINER_ID not in serialized


def test_windows_workspace_source_normalization_is_case_insensitive() -> None:
    profile = _docker_profile()
    runtime = OpenCodeRuntimeProfile(workspace_root=r"D:\\RT\\Workspace")
    payload = _inspect_payload()
    payload["Mounts"] = [
        {
            "Type": "bind",
            "Source": r"d:\\rt\\workspace",
            "Destination": "/workspace",
            "RW": True,
        }
    ]
    inspection = DockerContainerInspection.from_docker_inspect(payload)

    attestation = attest_offline_docker_sandbox(
        docker_profile=profile,
        runtime_profile=runtime,
        sandbox_policy=_policy(),
        inspection=inspection,
        workspace_host_path=r"D:\\RT\\Workspace",
    )

    assert attestation.workspace_root_sha256 == runtime.workspace_root_sha256


@pytest.mark.parametrize(
    ("updates", "failure"),
    [
        ({"NetworkMode": "bridge"}, "network_mode"),
        ({"Privileged": True}, "privileged"),
        ({"ReadonlyRootfs": False}, "readonly_rootfs"),
        ({"CapAdd": ["NET_ADMIN"]}, "cap_add"),
        ({"CapDrop": []}, "cap_drop_all"),
        ({"SecurityOpt": []}, "no_new_privileges"),
        ({"PidsLimit": 0}, "pids_limit"),
        ({"Memory": 0}, "memory_limit"),
        ({"NanoCpus": 0}, "cpu_limit"),
    ],
)
def test_docker_security_regressions_fail_closed(
    updates: dict[str, object],
    failure: str,
) -> None:
    payload = _inspect_payload(**updates)
    inspection = DockerContainerInspection.from_docker_inspect(payload)

    with pytest.raises(ValueError, match=failure):
        attest_offline_docker_sandbox(
            docker_profile=_docker_profile(),
            runtime_profile=_runtime_profile(),
            sandbox_policy=_policy(),
            inspection=inspection,
            workspace_host_path=_WORKSPACE,
        )


def test_extra_mount_or_docker_socket_fails_closed() -> None:
    payload = deepcopy(_inspect_payload())
    mounts = payload["Mounts"]
    assert isinstance(mounts, list)
    mounts.append(
        {
            "Type": "bind",
            "Source": "/var/run/docker.sock",
            "Destination": "/var/run/docker.sock",
            "RW": True,
        }
    )
    inspection = DockerContainerInspection.from_docker_inspect(payload)

    with pytest.raises(ValueError, match="mount_count"):
        attest_offline_docker_sandbox(
            docker_profile=_docker_profile(),
            runtime_profile=_runtime_profile(),
            sandbox_policy=_policy(),
            inspection=inspection,
            workspace_host_path=_WORKSPACE,
        )


def test_wrong_image_or_workspace_source_fails_closed() -> None:
    wrong_image = _inspect_payload()
    wrong_image["Image"] = f"sha256:{'d' * 64}"
    with pytest.raises(ValueError, match="image_id"):
        _attest(wrong_image)

    wrong_workspace = deepcopy(_inspect_payload())
    mounts = wrong_workspace["Mounts"]
    assert isinstance(mounts, list)
    mount = mounts[0]
    assert isinstance(mount, dict)
    mount["Source"] = "/tmp/other-workspace"
    with pytest.raises(ValueError, match="workspace_mount_source"):
        _attest(wrong_workspace)


def test_offline_profile_rejects_any_network_allowlist() -> None:
    policy = _policy(allowed_network_endpoints=("http://127.0.0.1:11434",))
    inspection = DockerContainerInspection.from_docker_inspect(_inspect_payload())

    with pytest.raises(ValueError, match="cannot allow network endpoints"):
        attest_offline_docker_sandbox(
            docker_profile=_docker_profile(),
            runtime_profile=_runtime_profile(),
            sandbox_policy=policy,
            inspection=inspection,
            workspace_host_path=_WORKSPACE,
        )


def _adjacent(command: tuple[str, ...], flag: str, value: str) -> bool:
    index = command.index(flag)
    return command[index + 1] == value
