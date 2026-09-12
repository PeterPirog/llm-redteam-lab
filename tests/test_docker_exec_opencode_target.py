import asyncio
import base64
import json
from collections import deque
from hashlib import sha256

from llm_redteam.docker_exec_http import DockerExecContainerRef
from llm_redteam.docker_exec_opencode import (
    DockerExecOpenCodeTarget,
    build_attested_docker_exec_opencode_target,
)
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.opencode_runtime import OpenCodeLaunchPlan, OpenCodeRuntimeProfile
from llm_redteam.targets.base import TargetRequest
from llm_redteam.targets.opencode import OpenCodeConfig

_CONTAINER_ID = "a" * 64
_OTHER_CONTAINER_ID = "b" * 64


class FakeRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = deque(results)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.calls.append(argv)
        if not self.results:
            raise AssertionError(f"unexpected command: {argv}")
        return self.results.popleft()


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _inspect(container_id: str = _CONTAINER_ID) -> CommandResult:
    return CommandResult(
        stdout=json.dumps([{"Id": container_id}]),
        returncode=0,
    )


def _http_response(body: dict[str, object], status: int = 200) -> CommandResult:
    raw = json.dumps(body, separators=(",", ":")).encode()
    return CommandResult(
        stdout=json.dumps(
            {
                "status": status,
                "headers": [["Content-Type", "application/json"]],
                "body_b64": base64.b64encode(raw).decode(),
            }
        ),
        returncode=0,
    )


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(
        workspace_root="/workspace",
        hostname="127.0.0.1",
        port=4096,
        server_password_env="OPENCODE_SERVER_PASSWORD",
    )


def _config(*, username: str = "opencode") -> OpenCodeConfig:
    return OpenCodeConfig(
        id="docker-exec-opencode",
        base_url="http://127.0.0.1:4096",
        model_provider_id="ollama",
        model_id="synthetic-model",
        workspace_root="/workspace",
        application_version="test-version",
        password_env="OPENCODE_SERVER_PASSWORD",
        username=username,
    )


def _container(
    *,
    container_id: str = _CONTAINER_ID,
    name: str = "agent-peer",
) -> DockerExecContainerRef:
    return DockerExecContainerRef(
        container_name=name,
        container_id_sha256=_digest(container_id),
    )


def _launch_plan() -> OpenCodeLaunchPlan:
    runtime = _runtime()
    return OpenCodeLaunchPlan(
        cwd="/workspace",
        command=(
            "opencode",
            "--pure",
            "serve",
            "--hostname",
            "127.0.0.1",
            "--port",
            "4096",
        ),
        public_environment={},
        required_secret_env_names=("OPENCODE_SERVER_PASSWORD",),
        runtime_profile_sha256=runtime.profile_sha256,
        sandbox_policy_sha256="1" * 64,
        sandbox_attestation_sha256="2" * 64,
        workspace_root_sha256=runtime.workspace_root_sha256,
    )


def _message(text: str) -> dict[str, object]:
    return {
        "info": {
            "id": "msg-1",
            "finish": "stop",
            "cost": 0,
            "tokens": {"input": 5, "output": 3, "reasoning": 0},
        },
        "parts": [{"type": "text", "text": text}],
    }


def _successful_runner() -> FakeRunner:
    return FakeRunner(
        [
            _inspect(),
            _http_response({"id": "session-1"}),
            _inspect(),
            _inspect(),
            _http_response(_message("Immediate response")),
            _inspect(),
            _inspect(),
            _http_response(_message("Persisted response")),
            _inspect(),
        ]
    )


def test_full_opencode_flow_uses_container_managed_auth_without_host_secret(
    monkeypatch,
) -> None:
    monkeypatch.delenv("OPENCODE_SERVER_PASSWORD", raising=False)
    runner = _successful_runner()
    target = DockerExecOpenCodeTarget(
        _config(),
        runtime_profile=_runtime(),
        container=_container(),
        runner=runner,
    )

    async def run():
        try:
            return await target.execute(
                TargetRequest(attack_id="synthetic-case", prompt="synthetic probe")
            )
        finally:
            await target.aclose()

    response = asyncio.run(run())

    assert response.error_kind is None
    assert response.session_id == "session-1"
    assert response.text == "Persisted response"
    assert response.provider_metadata["durable_trace_verified"] is True
    assert response.provider_metadata["agent_trace_complete"] is True
    assert response.provider_metadata["control_transport"] == "docker-exec-loopback-http-v1"
    assert (
        response.provider_metadata["control_transport_container_id_sha256"]
        == _digest(_CONTAINER_ID)
    )
    exec_calls = [call for call in runner.calls if call[:2] == ("docker", "exec")]
    assert len(exec_calls) == 3
    assert all("OPENCODE_SERVER_PASSWORD" in call for call in exec_calls)
    assert not any("--publish" in call or "-p" in call for call in exec_calls)


def test_transport_policy_is_stable_across_disposable_container_replicates() -> None:
    first = DockerExecOpenCodeTarget(
        _config(),
        runtime_profile=_runtime(),
        container=_container(),
        runner=FakeRunner([]),
    )
    second = DockerExecOpenCodeTarget(
        _config(),
        runtime_profile=_runtime(),
        container=_container(
            container_id=_OTHER_CONTAINER_ID,
            name="agent-peer-2",
        ),
        runner=FakeRunner([]),
    )

    try:
        assert first.identity == second.identity
    finally:
        asyncio.run(first.aclose())
        asyncio.run(second.aclose())


def test_auth_username_changes_transport_and_target_identity() -> None:
    first = DockerExecOpenCodeTarget(
        _config(username="opencode"),
        runtime_profile=_runtime(),
        container=_container(),
        runner=FakeRunner([]),
    )
    second = DockerExecOpenCodeTarget(
        _config(username="redteam-reader"),
        runtime_profile=_runtime(),
        container=_container(),
        runner=FakeRunner([]),
    )

    try:
        assert first.transport.profile.profile_sha256 != second.transport.profile.profile_sha256
        assert first.identity.configuration_hash != second.identity.configuration_hash
    finally:
        asyncio.run(first.aclose())
        asyncio.run(second.aclose())


def test_attested_wrapper_binds_transport_policy_without_per_run_container_identity() -> None:
    first = build_attested_docker_exec_opencode_target(
        config=_config(),
        runtime_profile=_runtime(),
        launch_plan=_launch_plan(),
        container=_container(),
        runner=FakeRunner([]),
    )
    second = build_attested_docker_exec_opencode_target(
        config=_config(),
        runtime_profile=_runtime(),
        launch_plan=_launch_plan(),
        container=_container(
            container_id=_OTHER_CONTAINER_ID,
            name="agent-peer-2",
        ),
        runner=FakeRunner([]),
    )

    try:
        assert first.identity == second.identity
        assert "runtime_attested" in first.identity.capabilities
        assert "docker_exec_control_transport" in first.identity.capabilities
    finally:
        asyncio.run(first.aclose())
        asyncio.run(second.aclose())


def test_password_environment_binding_mismatch_fails_closed() -> None:
    config = _config().model_copy(update={"password_env": "OTHER_PASSWORD"})

    try:
        DockerExecOpenCodeTarget(
            config,
            runtime_profile=_runtime(),
            container=_container(),
            runner=FakeRunner([]),
        )
    except ValueError as exc:
        assert "password_env" in str(exc)
    else:
        raise AssertionError("password environment mismatch must fail closed")
