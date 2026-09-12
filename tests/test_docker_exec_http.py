import asyncio
import base64
import json
from collections import deque
from hashlib import sha256

import httpx
import pytest

from llm_redteam.docker_exec_http import (
    DockerExecContainerRef,
    DockerExecHttpTransport,
)
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.opencode_runtime import OpenCodeRuntimeProfile

_CONTAINER_ID = "a" * 64
_OTHER_ID = "b" * 64
_CONTAINER_NAME = "agent-peer"


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


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _inspect(container_id: str = _CONTAINER_ID) -> CommandResult:
    return CommandResult(
        stdout=json.dumps([{"Id": container_id}]),
        returncode=0,
    )


def _response(status: int = 200, body: bytes = b'{"healthy":true}') -> CommandResult:
    return CommandResult(
        stdout=json.dumps(
            {
                "status": status,
                "headers": [["Content-Type", "application/json"]],
                "body_b64": base64.b64encode(body).decode(),
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


def _container() -> DockerExecContainerRef:
    return DockerExecContainerRef(
        container_name=_CONTAINER_NAME,
        container_id_sha256=_digest(_CONTAINER_ID),
    )


def test_request_runs_inside_owned_container_without_published_port() -> None:
    runner = FakeRunner([_inspect(), _response(), _inspect()])
    transport = DockerExecHttpTransport(
        runtime_profile=_runtime(),
        container=_container(),
        runner=runner,
    )
    request = httpx.Request(
        "GET",
        "http://127.0.0.1:4096/global/health",
        headers={"Accept": "application/json"},
    )

    response = asyncio.run(transport.handle_async_request(request))

    assert response.status_code == 200
    assert response.json() == {"healthy": True}
    assert runner.calls[0] == (
        "docker",
        "inspect",
        "--type",
        "container",
        _CONTAINER_NAME,
    )
    exec_call = runner.calls[1]
    assert exec_call[:3] == ("docker", "exec", _CONTAINER_NAME)
    assert "--publish" not in exec_call
    assert "-p" not in exec_call
    assert "OPENCODE_SERVER_PASSWORD" in exec_call
    assert runner.calls[2] == runner.calls[0]


def test_authorization_value_is_never_forwarded_in_process_arguments() -> None:
    runner = FakeRunner([_inspect(), _response(), _inspect()])
    transport = DockerExecHttpTransport(
        runtime_profile=_runtime(),
        container=_container(),
        runner=runner,
    )
    request = httpx.Request(
        "POST",
        "http://127.0.0.1:4096/session",
        headers={
            "Authorization": "Basic SYNTHETIC_SECRET",
            "Content-Type": "application/json",
        },
        content=b'{"title":"synthetic"}',
    )

    asyncio.run(transport.handle_async_request(request))

    joined = " ".join(runner.calls[1])
    assert "SYNTHETIC_SECRET" not in joined
    encoded_headers = runner.calls[1][-4]
    forwarded = json.loads(base64.b64decode(encoded_headers).decode())
    lowered = {name.casefold(): value for name, value in forwarded.items()}
    assert "authorization" not in lowered
    assert lowered["content-type"] == "application/json"


def test_different_origin_is_rejected_before_any_docker_command() -> None:
    runner = FakeRunner([])
    transport = DockerExecHttpTransport(
        runtime_profile=_runtime(),
        container=_container(),
        runner=runner,
    )
    request = httpx.Request("GET", "http://example.invalid:4096/global/health")

    with pytest.raises(httpx.TransportError, match="different origin"):
        asyncio.run(transport.handle_async_request(request))

    assert runner.calls == []


def test_container_name_reuse_after_request_fails_closed() -> None:
    runner = FakeRunner([_inspect(), _response(), _inspect(_OTHER_ID)])
    transport = DockerExecHttpTransport(
        runtime_profile=_runtime(),
        container=_container(),
        runner=runner,
    )
    request = httpx.Request("GET", "http://127.0.0.1:4096/global/health")

    with pytest.raises(RuntimeError, match="ownership changed"):
        asyncio.run(transport.handle_async_request(request))


def test_transport_profile_is_stable_but_container_identity_is_per_run() -> None:
    first = DockerExecHttpTransport(
        runtime_profile=_runtime(),
        container=_container(),
        runner=FakeRunner([]),
    )
    second = DockerExecHttpTransport(
        runtime_profile=_runtime(),
        container=DockerExecContainerRef(
            container_name="another-run",
            container_id_sha256=_digest(_OTHER_ID),
        ),
        runner=FakeRunner([]),
    )

    assert first.profile.profile_sha256 == second.profile.profile_sha256
