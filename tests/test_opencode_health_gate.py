import asyncio
import json
from collections import deque

import httpx
import pytest

from llm_redteam.docker_supervisor import (
    CommandResult,
    DockerProcessSupervisor,
    DockerSandboxLease,
)
from llm_redteam.opencode_health import (
    HealthGatedOpenCodeTarget,
    OpenCodeHealthObservation,
)
from llm_redteam.opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    AttestedOpenCodeTarget,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
    build_attested_opencode_launch_plan,
)
from llm_redteam.targets.base import TargetRequest
from llm_redteam.targets.opencode import OpenCodeConfig, OpenCodeTarget

_CONTAINER_ID = "c" * 64
_OTHER_CONTAINER_ID = "d" * 64
_RUNTIME_VERSION = "1.2.3-test"


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


def _profile() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(
        workspace_root="/workspace",
        hostname="127.0.0.1",
        port=4096,
    )


def _policy() -> AgentSandboxPolicy:
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.TRUSTED_HARNESS,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
        allowed_network_endpoints=("http://127.0.0.1:4096",),
    )


def _attestation() -> AgentSandboxAttestation:
    profile = _profile()
    policy = _policy()
    return AgentSandboxAttestation(
        issuer="synthetic-test-harness",
        isolation_id="synthetic-isolation",
        runtime_profile_sha256=profile.profile_sha256,
        sandbox_policy_sha256=policy.policy_sha256,
        workspace_root_sha256=profile.workspace_root_sha256,
        proof_sha256="a" * 64,
    )


def _plan():
    profile = _profile()
    policy = _policy()
    return build_attested_opencode_launch_plan(profile, policy, _attestation())


def _config() -> OpenCodeConfig:
    return OpenCodeConfig(
        id="health-gated-opencode",
        base_url="http://127.0.0.1:4096",
        model_provider_id="ollama",
        model_id="local-test-model",
        workspace_root="/workspace",
        application_version=_RUNTIME_VERSION,
    )


def _health(**updates: object) -> OpenCodeHealthObservation:
    plan = _plan()
    values: dict[str, object] = {
        "healthy": True,
        "application_version": _RUNTIME_VERSION,
        "runtime_profile_sha256": plan.runtime_profile_sha256,
        "sandbox_attestation_sha256": plan.sandbox_attestation_sha256,
        "container_id_sha256": "b" * 64,
        "endpoint_sha256": "e" * 64,
        "response_sha256": "f" * 64,
    }
    values.update(updates)
    return OpenCodeHealthObservation.model_validate(values)


def _lease() -> DockerSandboxLease:
    return DockerSandboxLease(
        container_name="llm-redteam-health-test",
        container_id_sha256=_sha(_CONTAINER_ID),
        launch_command_sha256="1" * 64,
        attestation=_attestation(),
    )


def _inspect_result(container_id: str = _CONTAINER_ID) -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout=json.dumps([{"Id": container_id}]),
    )


def _sha(value: str) -> str:
    from hashlib import sha256

    return sha256(value.encode()).hexdigest()


def test_docker_health_probe_is_bound_to_owned_container_and_loopback() -> None:
    runner = FakeRunner(
        [
            _inspect_result(),
            CommandResult(
                returncode=0,
                stdout=json.dumps({"healthy": True, "version": _RUNTIME_VERSION}) + "\n",
            ),
            _inspect_result(),
        ]
    )
    supervisor = DockerProcessSupervisor(runner)

    observation = supervisor.probe_opencode_health(_lease(), _profile())

    probe = runner.calls[1]
    assert probe[:3] == ("docker", "exec", "llm-redteam-health-test")
    assert "http://127.0.0.1:4096/global/health" in probe
    assert observation.healthy is True
    assert observation.application_version == _RUNTIME_VERSION
    assert observation.container_id_sha256 == _lease().container_id_sha256
    assert observation.sandbox_attestation_sha256 == _lease().attestation.attestation_sha256


def test_health_probe_rejects_name_reuse_after_response() -> None:
    runner = FakeRunner(
        [
            _inspect_result(),
            CommandResult(
                returncode=0,
                stdout=json.dumps({"healthy": True, "version": _RUNTIME_VERSION}),
            ),
            _inspect_result(_OTHER_CONTAINER_ID),
        ]
    )
    supervisor = DockerProcessSupervisor(runner)

    with pytest.raises(RuntimeError, match="no longer owns"):
        supervisor.probe_opencode_health(_lease(), _profile())


def test_health_probe_rejects_unhealthy_or_malformed_response() -> None:
    unhealthy = FakeRunner(
        [
            _inspect_result(),
            CommandResult(returncode=0, stdout='{"healthy":false,"version":"1.2.3"}'),
            _inspect_result(),
        ]
    )
    with pytest.raises(RuntimeError, match="unhealthy"):
        DockerProcessSupervisor(unhealthy).probe_opencode_health(_lease(), _profile())

    malformed = FakeRunner(
        [
            _inspect_result(),
            CommandResult(returncode=0, stdout="not-json"),
            _inspect_result(),
        ]
    )
    with pytest.raises(RuntimeError, match="valid JSON"):
        DockerProcessSupervisor(malformed).probe_opencode_health(_lease(), _profile())


def test_health_gate_rejects_version_runtime_or_attestation_mismatch() -> None:
    target = AttestedOpenCodeTarget(OpenCodeTarget(_config()), _plan())
    try:
        with pytest.raises(ValueError, match="version"):
            HealthGatedOpenCodeTarget(
                target,
                _health(application_version="different-version"),
            )
        with pytest.raises(ValueError, match="runtime profile"):
            HealthGatedOpenCodeTarget(
                target,
                _health(runtime_profile_sha256="9" * 64),
            )
        with pytest.raises(ValueError, match="sandbox attestation"):
            HealthGatedOpenCodeTarget(
                target,
                _health(sandbox_attestation_sha256="8" * 64),
            )
    finally:
        asyncio.run(target.aclose())


def test_health_gated_target_preserves_identity_and_adds_per_run_metadata() -> None:
    message = {
        "info": {"id": "msg-1", "finish": "stop"},
        "parts": [{"type": "text", "text": "ok"}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/session":
            return httpx.Response(200, json={"id": "session-1"})
        if request.method == "POST" and request.url.path == "/session/session-1/message":
            return httpx.Response(200, json=message)
        if request.method == "GET":
            return httpx.Response(200, json=message)
        return httpx.Response(404)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            attested = AttestedOpenCodeTarget(OpenCodeTarget(_config(), client=client), _plan())
            gated = HealthGatedOpenCodeTarget(attested, _health())
            response = await gated.execute(
                TargetRequest(attack_id="health-case", prompt="Return ok")
            )
            return attested.identity, gated.identity, response

    base_identity, gated_identity, response = asyncio.run(run())

    assert gated_identity.configuration_hash == base_identity.configuration_hash
    assert "runtime_health_verified" in gated_identity.capabilities
    assert response.provider_metadata["runtime_health_verified"] is True
    assert response.provider_metadata["runtime_application_version"] == _RUNTIME_VERSION
    assert len(response.provider_metadata["runtime_health_proof_sha256"]) == 64
