"""HTTP transport through ``docker exec`` for loopback-only container services.

The control plane never publishes the target service port.  Each request is executed by
a constant Python stdlib client inside an independently owned Docker container. Request
method/path/body are data arguments, never shell syntax.  Container ownership is checked
before and after every request so name reuse cannot silently redirect the control plane.

Basic-auth passwords are never passed in command arguments: when configured, the in-
container client reads the password from the predeclared container environment variable.
"""

from __future__ import annotations

import asyncio
import base64
import json
from hashlib import sha256
from urllib.parse import urlsplit

import httpx
from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_supervisor import DockerCommandRunner, SubprocessDockerCommandRunner
from .domain import StrictModel
from .opencode_runtime import OpenCodeRuntimeProfile

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})

_EXEC_HTTP_SCRIPT = (
    "import base64,json,os,sys,urllib.error,urllib.request;"
    "method=sys.argv[1];url=sys.argv[2];"
    "headers=json.loads(base64.b64decode(sys.argv[3]).decode());"
    "body=base64.b64decode(sys.argv[4]) if sys.argv[4] else None;"
    "password_env=sys.argv[5];username=sys.argv[6];"
    "req=urllib.request.Request(url,data=body,method=method);"
    "[req.add_header(k,v) for k,v in headers.items()];"
    "password=os.getenv(password_env) if password_env else None;"
    "auth=base64.b64encode((username+':'+password).encode()).decode() if password else '';"
    "req.add_header('Authorization','Basic '+auth) if auth else None;"
    "status=0;rh=[];data=b'';"
    "\ntry:\n "
    "r=urllib.request.urlopen(req,timeout=120);"
    "status=r.status;rh=list(r.headers.items());data=r.read();r.close()"
    "\nexcept urllib.error.HTTPError as e:\n "
    "status=e.code;rh=list(e.headers.items());data=e.read();e.close()"
    "\nprint(json.dumps({'status':status,'headers':rh,"
    "'body_b64':base64.b64encode(data).decode()},separators=(',',':')))"
)


class DockerExecContainerRef(StrictModel):
    """Per-run reference to one already-owned Docker container."""

    container_name: str = Field(min_length=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)


class DockerExecHttpProfile(StrictModel):
    """Stable control-plane transport policy for one loopback OpenCode runtime."""

    version: int = Field(ge=1, default=1)
    runtime_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    username: str = Field(min_length=1)
    python_executable: str = Field(min_length=1, default="python")
    transport_kind: str = Field(default="docker-exec-loopback-http-v1")

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerExecHttpTransport(httpx.AsyncBaseTransport):
    """Tunnel HTTP requests into an owned container without publishing a host port."""

    def __init__(
        self,
        *,
        runtime_profile: OpenCodeRuntimeProfile,
        container: DockerExecContainerRef,
        username: str = "opencode",
        runner: DockerCommandRunner | None = None,
        command_timeout_seconds: float = 135.0,
        python_executable: str = "python",
    ) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        if not python_executable or any(
            character.isspace() for character in python_executable
        ):
            raise ValueError("python_executable must be one executable token")
        if not username:
            raise ValueError("username must be non-empty")
        self.runtime_profile = runtime_profile
        self.container = container
        self._runner = runner or SubprocessDockerCommandRunner()
        self._command_timeout_seconds = command_timeout_seconds
        self.profile = DockerExecHttpProfile(
            runtime_profile_sha256=runtime_profile.profile_sha256,
            username=username,
            python_executable=python_executable,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Execute one bounded HTTP exchange inside the owned container namespace."""

        url = self._validated_loopback_url(request.url)
        headers = self._safe_headers(request.headers)
        body = await request.aread()
        encoded_headers = base64.b64encode(
            json.dumps(headers, separators=(",", ":")).encode()
        ).decode()
        encoded_body = base64.b64encode(body).decode() if body else ""

        await asyncio.to_thread(self._require_owned_container)
        result = await asyncio.to_thread(
            self._runner.run,
            (
                "docker",
                "exec",
                self.container.container_name,
                self.profile.python_executable,
                "-c",
                _EXEC_HTTP_SCRIPT,
                request.method.upper(),
                url,
                encoded_headers,
                encoded_body,
                self.runtime_profile.server_password_env or "",
                self.profile.username,
            ),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise httpx.TransportError("Docker exec HTTP request failed", request=request)
        await asyncio.to_thread(self._require_owned_container)

        try:
            payload = json.loads(result.stdout.strip())
            status = payload["status"]
            response_headers = payload["headers"]
            response_body = base64.b64decode(payload["body_b64"], validate=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise httpx.TransportError(
                "Docker exec HTTP response envelope is invalid",
                request=request,
            ) from exc
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise httpx.TransportError("Docker exec HTTP status is invalid", request=request)
        if not isinstance(response_headers, list):
            raise httpx.TransportError("Docker exec HTTP headers are invalid", request=request)
        normalized_headers: list[tuple[str, str]] = []
        for item in response_headers:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not all(isinstance(value, str) for value in item)
            ):
                raise httpx.TransportError(
                    "Docker exec HTTP response header is invalid",
                    request=request,
                )
            normalized_headers.append((item[0], item[1]))
        return httpx.Response(
            status_code=status,
            headers=normalized_headers,
            content=response_body,
            request=request,
        )

    def _validated_loopback_url(self, request_url: httpx.URL) -> str:
        parsed = urlsplit(str(request_url))
        expected_host = self.runtime_profile.hostname.casefold()
        request_host = (parsed.hostname or "").casefold()
        expected_port = self.runtime_profile.port
        request_port = parsed.port or (80 if parsed.scheme == "http" else 443)
        if parsed.scheme != "http":
            raise httpx.TransportError("Docker exec transport requires HTTP loopback")
        if request_host != expected_host or request_port != expected_port:
            raise httpx.TransportError("Docker exec transport refused a different origin")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if ":" in self.runtime_profile.hostname:
            host = f"[{self.runtime_profile.hostname}]"
        else:
            host = self.runtime_profile.hostname
        return f"http://{host}:{expected_port}{path}"

    @staticmethod
    def _safe_headers(headers: httpx.Headers) -> dict[str, str]:
        safe: dict[str, str] = {}
        for name, value in headers.items():
            lowered = name.casefold()
            if lowered in _SENSITIVE_HEADERS or lowered in {"host", "content-length"}:
                continue
            safe[name] = value
        return safe

    def _require_owned_container(self) -> None:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", self.container.container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker exec transport cannot inspect owned container")
        try:
            payload = json.loads(result.stdout)
            if not isinstance(payload, list) or len(payload) != 1:
                raise ValueError("inspect cardinality")
            record = payload[0]
            if not isinstance(record, dict):
                raise ValueError("inspect shape")
            container_id = record.get("Id")
            if not isinstance(container_id, str):
                raise ValueError("inspect ID")
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker exec transport ownership proof is invalid") from exc
        if sha256(container_id.encode()).hexdigest() != self.container.container_id_sha256:
            raise RuntimeError("Docker exec transport container ownership changed")
