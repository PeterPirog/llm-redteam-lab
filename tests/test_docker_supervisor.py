import json
import subprocess
from collections import deque

import pytest

from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.docker_supervisor import (
    CommandResult,
    DockerProcessSupervisor,
    SubprocessDockerCommandRunner,
)
from llm_redteam.opencode_runtime import (
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)

_CONTAINER_ID = "c" * 64
_OTHER_CONTAINER_ID = "d" * 64
_IMAGE_MANIFEST = "a" * 64
_IMAGE_ID = "b" * 64
_WORKSPACE = "/tmp/llm-redteam/workspace"
_NAME = "llm-redteam-case-1"


class FakeRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = deque(results)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.calls.append(argv)
        if not self.results:
            raise AssertionError(f"unexpected Docker command: {argv}")
        return self.results.popleft()


def _docker_profile() -> DockerSandboxProfile:
    return DockerSandboxProfile(
        image_ref=f"llm-redteam-opencode@sha256:{_IMAGE_MANIFEST}",
        image_id=f"sha256:{_IMAGE_ID}",
        memory_limit_bytes=1_073_741_824,
        pids_limit=128,
        cpus=2.0,
    )


def _runtime_profile() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(workspace_root=_WORKSPACE)


def _policy() -> AgentSandboxPolicy:
    profile = _docker_profile()
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=profile.profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
        allowed_network_endpoints=(),
    )


def _inspect_payload(
    *,
    container_id: str = _CONTAINER_ID,
    network_mode: str = "none",
) -> dict[str, object]:
    return {
        "Id": container_id,
        "Image": f"sha256:{_IMAGE_ID}",
        "State": {"Running": True},
        "HostConfig": {
            "AutoRemove": True,
            "Privileged": False,
            "ReadonlyRootfs": True,
            "NetworkMode": network_mode,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 128,
            "Memory": 1_073_741_824,
            "NanoCpus": 2_000_000_000,
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": _WORKSPACE,
                "Destination": "/workspace",
                "RW": True,
            }
        ],
    }


def _inspect_result(**kwargs: str) -> CommandResult:
    return CommandResult(stdout=json.dumps([_inspect_payload(**kwargs)]), returncode=0)


def _launch(supervisor: DockerProcessSupervisor):
    return supervisor.launch(
        docker_profile=_docker_profile(),
        runtime_profile=_runtime_profile(),
        sandbox_policy=_policy(),
        workspace_host_path=_WORKSPACE,
        container_name=_NAME,
        command=("sleep", "600"),
    )


def test_supervisor_returns_lease_only_after_independent_inspection() -> None:
    runner = FakeRunner(
        [
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            _inspect_result(),
        ]
    )
    supervisor = DockerProcessSupervisor(runner)

    lease = _launch(supervisor)

    launch = runner.calls[0]
    assert launch[:4] == ("docker", "run", "--rm", "--detach")
    assert runner.calls[1] == ("docker", "inspect", "--type", "container", _NAME)
    assert lease.attestation.issuer == "llm-redteam-docker-inspect-v1"
    assert lease.attestation.sandbox_policy_sha256 == _policy().policy_sha256
    assert lease.container_name == _NAME
    assert len(lease.launch_command_sha256) == 64


def test_failed_docker_run_never_cleans_up_by_unproven_name() -> None:
    runner = FakeRunner([CommandResult(returncode=125, stderr="synthetic failure")])
    supervisor = DockerProcessSupervisor(runner)

    with pytest.raises(RuntimeError, match="launch failed"):
        _launch(supervisor)

    assert len(runner.calls) == 1
    assert runner.calls[0][:2] == ("docker", "run")


def test_failed_attestation_removes_only_owned_container() -> None:
    bad = _inspect_result(network_mode="bridge")
    runner = FakeRunner(
        [
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            bad,
            bad,
            CommandResult(returncode=0),
        ]
    )
    supervisor = DockerProcessSupervisor(runner)

    with pytest.raises(ValueError, match="network_mode"):
        _launch(supervisor)

    assert runner.calls[-1] == ("docker", "rm", "--force", _NAME)


def test_name_reuse_during_attestation_is_not_removed() -> None:
    changed = _inspect_result(container_id=_OTHER_CONTAINER_ID)
    runner = FakeRunner(
        [
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            changed,
            changed,
        ]
    )
    supervisor = DockerProcessSupervisor(runner)

    with pytest.raises(RuntimeError, match="ownership changed"):
        _launch(supervisor)

    assert not any(call[:3] == ("docker", "rm", "--force") for call in runner.calls)


def test_release_checks_ownership_before_stopping() -> None:
    runner = FakeRunner(
        [
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            _inspect_result(),
            _inspect_result(container_id=_OTHER_CONTAINER_ID),
        ]
    )
    supervisor = DockerProcessSupervisor(runner)
    lease = _launch(supervisor)

    with pytest.raises(RuntimeError, match="no longer owns"):
        supervisor.release(lease)

    assert not any(call[:2] == ("docker", "stop") for call in runner.calls)
    assert not any(call[:3] == ("docker", "rm", "--force") for call in runner.calls)


def test_release_falls_back_to_force_remove_and_verifies_absence() -> None:
    runner = FakeRunner(
        [
            CommandResult(stdout=_CONTAINER_ID + "\n", returncode=0),
            _inspect_result(),
            _inspect_result(),
            CommandResult(returncode=1),
            CommandResult(returncode=0),
            CommandResult(returncode=1),
        ]
    )
    supervisor = DockerProcessSupervisor(runner, stop_timeout_seconds=2)
    lease = _launch(supervisor)

    supervisor.release(lease)

    assert ("docker", "stop", "--time", "2", _NAME) in runner.calls
    assert ("docker", "rm", "--force", _NAME) in runner.calls
    assert runner.calls[-1] == ("docker", "inspect", "--type", "container", _NAME)


def test_subprocess_runner_uses_shell_false(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = SubprocessDockerCommandRunner()

    result = runner.run(("docker", "version"), timeout_seconds=3.0)

    assert result.returncode == 0
    assert observed["argv"] == ("docker", "version")
    assert observed["shell"] is False
    assert observed["check"] is False
    assert observed["timeout"] == 3.0
