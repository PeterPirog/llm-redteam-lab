"""Trusted Docker lifecycle supervisor for authorized offline AGENT sandboxes.

The supervisor is intentionally separate from Blue/model code. It launches a detached
container using a predeclared :class:`DockerSandboxProfile`, obtains independent Docker
inspection evidence, verifies the evidence, and only then returns an attested lease.

The default subprocess runner never invokes a shell. CI exercises the lifecycle with a
fake command runner; no Docker daemon or model inference is required by the unit tests.
"""

from __future__ import annotations

import json
import subprocess
from hashlib import sha256
from typing import Protocol

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_sandbox import (
    DockerContainerInspection,
    DockerSandboxProfile,
    attest_offline_docker_sandbox,
)
from .domain import StrictModel
from .opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class CommandResult(StrictModel):
    """Minimal non-persistent result from one local supervisor command."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


class DockerCommandRunner(Protocol):
    """Injectable command boundary used by the Docker supervisor."""

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult: ...


class SubprocessDockerCommandRunner:
    """Execute Docker CLI commands without a shell or implicit command expansion."""

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Docker supervisor command timed out") from exc
        except OSError as exc:
            raise RuntimeError("Docker supervisor could not execute Docker CLI") from exc
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class DockerSandboxLease(StrictModel):
    """Runtime-only ownership token for one independently attested container."""

    container_name: str = Field(min_length=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    launch_command_sha256: str = Field(pattern=_HASH_PATTERN)
    attestation: AgentSandboxAttestation


class DockerProcessSupervisor:
    """Launch, attest and release one offline Docker sandbox fail closed."""

    def __init__(
        self,
        runner: DockerCommandRunner | None = None,
        *,
        command_timeout_seconds: float = 15.0,
        stop_timeout_seconds: int = 5,
    ) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        if stop_timeout_seconds < 0:
            raise ValueError("stop_timeout_seconds cannot be negative")
        self._runner = runner or SubprocessDockerCommandRunner()
        self._command_timeout_seconds = command_timeout_seconds
        self._stop_timeout_seconds = stop_timeout_seconds

    def launch(
        self,
        *,
        docker_profile: DockerSandboxProfile,
        runtime_profile: OpenCodeRuntimeProfile,
        sandbox_policy: AgentSandboxPolicy,
        workspace_host_path: str,
        container_name: str,
        command: tuple[str, ...],
    ) -> DockerSandboxLease:
        """Launch a detached container and return a lease only after attestation succeeds."""

        launch_command = docker_profile.docker_run_command(
            container_name=container_name,
            workspace_host_path=workspace_host_path,
            command=command,
            detach=True,
        )
        launch_result = self._runner.run(
            launch_command,
            timeout_seconds=self._command_timeout_seconds,
        )
        if launch_result.returncode != 0:
            # A failed `docker run` can mean the name already belonged to another
            # container. Never clean up by name unless ownership was established.
            raise RuntimeError("Docker sandbox launch failed")

        launched_id = _parse_container_id(launch_result.stdout)
        try:
            raw_inspection = self._inspect_raw(container_name)
            inspected_id = _raw_container_id(raw_inspection)
            if inspected_id != launched_id:
                raise RuntimeError("Docker sandbox ownership changed before attestation")
            inspection = DockerContainerInspection.from_docker_inspect(raw_inspection)
            attestation = attest_offline_docker_sandbox(
                docker_profile=docker_profile,
                runtime_profile=runtime_profile,
                sandbox_policy=sandbox_policy,
                inspection=inspection,
                workspace_host_path=workspace_host_path,
            )
        except Exception:
            self._remove_if_owned(container_name, launched_id)
            raise

        return DockerSandboxLease(
            container_name=container_name,
            container_id_sha256=sha256(launched_id.encode()).hexdigest(),
            launch_command_sha256=canonical_json_hash(list(launch_command)),
            attestation=attestation,
        )

    def release(self, lease: DockerSandboxLease) -> None:
        """Stop only the container still owned by this lease and verify removal."""

        raw_inspection = self._inspect_raw(lease.container_name)
        current_id = _raw_container_id(raw_inspection)
        if sha256(current_id.encode()).hexdigest() != lease.container_id_sha256:
            raise RuntimeError("Docker sandbox lease no longer owns the named container")

        stop_result = self._runner.run(
            (
                "docker",
                "stop",
                "--time",
                str(self._stop_timeout_seconds),
                lease.container_name,
            ),
            timeout_seconds=self._command_timeout_seconds,
        )
        if stop_result.returncode != 0:
            remove_result = self._runner.run(
                ("docker", "rm", "--force", lease.container_name),
                timeout_seconds=self._command_timeout_seconds,
            )
            if remove_result.returncode != 0:
                raise RuntimeError("Docker sandbox teardown failed")

        post = self._runner.run(
            ("docker", "inspect", "--type", "container", lease.container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if post.returncode == 0:
            try:
                records = _parse_inspect_records(post.stdout)
                remaining_id = _raw_container_id(records[0])
            except (ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError("Docker sandbox removal could not be verified") from exc
            if sha256(remaining_id.encode()).hexdigest() == lease.container_id_sha256:
                raise RuntimeError("Docker sandbox container still exists after teardown")
            raise RuntimeError("Docker sandbox name was reused during teardown")

    def _inspect_raw(self, container_name: str) -> dict[str, object]:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker sandbox inspection failed")
        try:
            records = _parse_inspect_records(result.stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker sandbox inspection payload is invalid") from exc
        return records[0]

    def _remove_if_owned(self, container_name: str, expected_id: str) -> None:
        """Remove an owned failed sandbox; never delete a container whose ID changed."""

        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            return
        try:
            records = _parse_inspect_records(result.stdout)
            current_id = _raw_container_id(records[0])
        except (ValueError, json.JSONDecodeError):
            return
        if current_id != expected_id:
            return
        remove_result = self._runner.run(
            ("docker", "rm", "--force", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if remove_result.returncode != 0:
            raise RuntimeError("Docker sandbox cleanup failed after rejected attestation")


def _parse_container_id(stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("Docker sandbox launch did not return exactly one container ID")
    container_id = lines[0]
    if len(container_id) != 64 or any(
        character not in "0123456789abcdef" for character in container_id
    ):
        raise RuntimeError("Docker sandbox launch returned an invalid container ID")
    return container_id


def _parse_inspect_records(stdout: str) -> list[dict[str, object]]:
    payload = json.loads(stdout)
    if not isinstance(payload, list) or len(payload) != 1:
        raise ValueError("Docker inspect must return exactly one record")
    record = payload[0]
    if not isinstance(record, dict):
        raise ValueError("Docker inspect record must be an object")
    return [record]


def _raw_container_id(record: dict[str, object]) -> str:
    value = record.get("Id")
    if not isinstance(value, str):
        raise ValueError("Docker inspect Id must be a string")
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("Docker inspect Id must be a full lowercase container ID")
    return value
