"""Direct ComfyUI PIPELINE target with durable history-backed image evidence."""

from __future__ import annotations

import asyncio
import copy
import json
import struct
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from urllib.parse import urlencode

import httpx
from pydantic import Field, model_validator

from ..domain import EvidenceKind, EvidenceRecord, StrictModel, TargetClass, TargetIdentity, TargetMode
from ..image_artifacts import ImageArtifactStore
from .base import SessionMode, TargetRequest, TargetResponse


class ComfyUIInputBinding(StrictModel):
    """Bind one campaign value to one ComfyUI API-format workflow input."""

    node_id: str = Field(min_length=1)
    input_name: str = Field(min_length=1)


class ComfyUIConfig(StrictModel):
    id: str = Field(min_length=1)
    base_url: str = Field(min_length=1)
    model: str = Field(min_length=1)
    workflow_api: dict[str, Any]
    prompt_binding: ComfyUIInputBinding
    seed_bindings: tuple[ComfyUIInputBinding, ...] = ()
    default_seed: int | None = Field(default=None, ge=0)
    output_node_ids: tuple[str, ...] = ()
    application_version: str | None = None
    queue_path: str = "/prompt"
    history_path_template: str = "/history/{prompt_id}"
    view_path: str = "/view"
    timeout_seconds: float = Field(gt=0.0, default=120.0)
    poll_interval_seconds: float = Field(ge=0.0, default=0.25)
    max_poll_attempts: int = Field(gt=0, default=480)
    max_images_per_request: int = Field(gt=0, le=16, default=1)
    capabilities: frozenset[str] = frozenset({"text", "image_generation", "workflow"})

    @model_validator(mode="after")
    def workflow_is_non_empty(self) -> ComfyUIConfig:
        if not self.workflow_api:
            raise ValueError("ComfyUI API-format workflow cannot be empty")
        return self


class ComfyUITarget:
    """Execute a deterministic API-format ComfyUI workflow and ingest final images.

    The adapter deliberately does not use websocket events as authoritative evidence.
    It queues a workflow through ``/prompt``, waits for the durable ``/history`` record,
    then downloads the exact recorded output through ``/view``. Raw image bytes enter
    only the configured image artifact store; normalized experiment evidence retains
    hashes and artifact references.
    """

    def __init__(
        self,
        config: ComfyUIConfig,
        artifacts: ImageArtifactStore,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self.artifacts = artifacts
        self._client = client or httpx.AsyncClient(timeout=config.timeout_seconds)
        self._owns_client = client is None
        self._workflow_hash = _canonical_hash(config.workflow_api)
        self._configuration_error = self._validate_bindings()

    @property
    def identity(self) -> TargetIdentity:
        fingerprint = {
            "base_url": self.config.base_url.rstrip("/"),
            "model": self.config.model,
            "workflow_hash": self._workflow_hash,
            "prompt_binding": self.config.prompt_binding.model_dump(mode="json"),
            "seed_bindings": [item.model_dump(mode="json") for item in self.config.seed_bindings],
            "default_seed": self.config.default_seed,
            "output_node_ids": self.config.output_node_ids,
            "application_version": self.config.application_version,
        }
        return TargetIdentity(
            id=self.config.id,
            target_class=TargetClass.IMAGE_GENERATION,
            target_mode=TargetMode.PIPELINE,
            model=self.config.model,
            provider="comfyui",
            runtime=self.config.base_url,
            application="ComfyUI",
            application_version=self.config.application_version,
            configuration_hash=_canonical_hash(fingerprint),
            capabilities=self.config.capabilities,
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        if self._configuration_error is not None:
            return TargetResponse(error_kind=f"configuration:{self._configuration_error}")
        if request.input_artifact_refs:
            return TargetResponse(error_kind="input:multimodal_not_supported")
        if request.session_mode == SessionMode.TARGET_MANAGED:
            return TargetResponse(error_kind="session:target_managed_not_supported")
        if request.conversation:
            return TargetResponse(error_kind="session:comfyui_has_no_conversation_memory")

        seed, seed_error = self._resolve_seed(request)
        if seed_error is not None:
            return TargetResponse(error_kind=seed_error)
        workflow = self._render_workflow(request.prompt, seed)

        prompt_id, queue_error = await self._queue(workflow)
        if queue_error is not None:
            return TargetResponse(error_kind=queue_error)
        assert prompt_id is not None

        record, history_error = await self._wait_for_history(prompt_id)
        if history_error is not None:
            return TargetResponse(error_kind=history_error)
        assert record is not None

        image_refs, output_error = self._image_refs(record)
        if output_error is not None:
            return TargetResponse(error_kind=output_error)

        evidence: list[EvidenceRecord] = []
        for image_ref in image_refs[: self.config.max_images_per_request]:
            item, error = await self._ingest_image(image_ref, seed=seed)
            if error is not None:
                return TargetResponse(error_kind=error)
            assert item is not None
            evidence.append(item)

        prompt_id_hash = sha256(prompt_id.encode()).hexdigest()
        evidence.append(
            EvidenceRecord(
                kind=EvidenceKind.METADATA,
                source="comfyui_target",
                observed_at=datetime.now(UTC).isoformat(),
                data={
                    "workflow_hash": self._workflow_hash,
                    "prompt_id_hash": prompt_id_hash,
                    "history_verified": True,
                    "image_count": len(evidence),
                    "seed": seed if seed is not None else -1,
                },
                redacted=True,
            )
        )
        return TargetResponse(
            text="Image generation completed",
            evidence=tuple(evidence),
            provider_metadata={
                "image_generated": True,
                "safety_refusal": False,
                "history_verified": True,
                "image_count": len(evidence) - 1,
                "workflow_hash": self._workflow_hash,
                "seed": seed if seed is not None else -1,
            },
        )

    def _validate_bindings(self) -> str | None:
        bindings = (self.config.prompt_binding, *self.config.seed_bindings)
        for binding in bindings:
            node = self.config.workflow_api.get(binding.node_id)
            if not isinstance(node, dict):
                return f"unknown_workflow_node:{binding.node_id}"
            inputs = node.get("inputs")
            if not isinstance(inputs, dict):
                return f"node_inputs_missing:{binding.node_id}"
            if binding.input_name not in inputs:
                return f"unknown_node_input:{binding.node_id}:{binding.input_name}"
        for node_id in self.config.output_node_ids:
            if node_id not in self.config.workflow_api:
                return f"unknown_output_node:{node_id}"
        return None

    def _resolve_seed(self, request: TargetRequest) -> tuple[int | None, str | None]:
        raw = request.metadata.get("seed")
        if raw is None:
            return self.config.default_seed, None
        try:
            seed = int(raw)
        except ValueError:
            return None, "input:invalid_seed"
        if seed < 0:
            return None, "input:invalid_seed"
        return seed, None

    def _render_workflow(self, prompt: str, seed: int | None) -> dict[str, Any]:
        workflow = copy.deepcopy(self.config.workflow_api)
        _set_binding(workflow, self.config.prompt_binding, prompt)
        if self.config.seed_bindings:
            if seed is None:
                raise ValueError("seed bindings require default_seed or request metadata seed")
            for binding in self.config.seed_bindings:
                _set_binding(workflow, binding, seed)
        return workflow

    async def _queue(self, workflow: dict[str, Any]) -> tuple[str | None, str | None]:
        try:
            response = await self._client.post(self._url(self.config.queue_path), json={"prompt": workflow})
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            return None, f"http_status:queue:{exc.response.status_code}"
        except httpx.HTTPError as exc:
            return None, f"transport:queue:{type(exc).__name__}"
        except ValueError:
            return None, "protocol:queue_invalid_json"
        if not isinstance(body, dict):
            return None, "protocol:queue_invalid_shape"
        prompt_id = body.get("prompt_id")
        if not isinstance(prompt_id, str) or not prompt_id:
            return None, "protocol:queue_missing_prompt_id"
        return prompt_id, None

    async def _wait_for_history(
        self, prompt_id: str
    ) -> tuple[dict[str, Any] | None, str | None]:
        path = self.config.history_path_template.format(prompt_id=prompt_id)
        for attempt in range(self.config.max_poll_attempts):
            try:
                response = await self._client.get(self._url(path))
                response.raise_for_status()
                body = response.json()
            except httpx.HTTPStatusError as exc:
                return None, f"http_status:history:{exc.response.status_code}"
            except httpx.HTTPError as exc:
                return None, f"transport:history:{type(exc).__name__}"
            except ValueError:
                return None, "protocol:history_invalid_json"

            record = _history_record(body, prompt_id)
            if record is not None:
                status_error = _history_failure(record)
                if status_error is not None:
                    return None, status_error
                if _history_complete(record):
                    return record, None
            if attempt + 1 < self.config.max_poll_attempts and self.config.poll_interval_seconds:
                await asyncio.sleep(self.config.poll_interval_seconds)
        return None, "timeout:history_not_complete"

    def _image_refs(
        self, record: dict[str, Any]
    ) -> tuple[list[dict[str, str]], str | None]:
        outputs = record.get("outputs")
        if not isinstance(outputs, dict):
            return [], "protocol:history_missing_outputs"
        selected = self.config.output_node_ids or tuple(str(key) for key in outputs)
        refs: list[dict[str, str]] = []
        for node_id in selected:
            node = outputs.get(node_id)
            if not isinstance(node, dict):
                continue
            images = node.get("images")
            if not isinstance(images, list):
                continue
            for raw in images:
                if not isinstance(raw, dict):
                    continue
                filename = raw.get("filename")
                subfolder = raw.get("subfolder", "")
                image_type = raw.get("type", "output")
                if all(isinstance(value, str) for value in (filename, subfolder, image_type)) and filename:
                    refs.append(
                        {"filename": filename, "subfolder": subfolder, "type": image_type}
                    )
        if not refs:
            return [], "protocol:history_missing_images"
        return refs, None

    async def _ingest_image(
        self, image_ref: dict[str, str], *, seed: int | None
    ) -> tuple[EvidenceRecord | None, str | None]:
        query = urlencode(image_ref)
        try:
            response = await self._client.get(f"{self._url(self.config.view_path)}?{query}")
            response.raise_for_status()
            data = response.content
        except httpx.HTTPStatusError as exc:
            return None, f"http_status:view:{exc.response.status_code}"
        except httpx.HTTPError as exc:
            return None, f"transport:view:{type(exc).__name__}"
        if not data:
            return None, "protocol:view_empty_image"

        try:
            mime_type = _image_mime(data, response.headers.get("content-type"))
            width, height = _image_dimensions(data, mime_type)
            artifact = self.artifacts.put(
                data,
                mime_type=mime_type,
                width=width,
                height=height,
                seed=seed,
                metadata={
                    "provider": "comfyui",
                    "workflow_hash": self._workflow_hash,
                    "output_type": image_ref["type"],
                },
            )
        except (ValueError, PermissionError, FileExistsError, OSError) as exc:
            return None, f"artifact:{type(exc).__name__}"

        return (
            EvidenceRecord(
                kind=EvidenceKind.IMAGE,
                source="comfyui.history+view",
                observed_at=datetime.now(UTC).isoformat(),
                content_hash=artifact.content_hash,
                artifact_ref=artifact.artifact_id,
                data={
                    "mime_type": artifact.mime_type,
                    "width": artifact.width,
                    "height": artifact.height,
                    "seed": seed if seed is not None else -1,
                    "output_type": image_ref["type"],
                    "workflow_hash": self._workflow_hash,
                },
                redacted=True,
            ),
            None,
        )

    def _url(self, path: str) -> str:
        return self.config.base_url.rstrip("/") + "/" + path.lstrip("/")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _set_binding(workflow: dict[str, Any], binding: ComfyUIInputBinding, value: object) -> None:
    node = workflow[binding.node_id]
    inputs = node["inputs"]
    inputs[binding.input_name] = value


def _history_record(body: object, prompt_id: str) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None
    raw = body.get(prompt_id)
    if isinstance(raw, dict):
        return raw
    if "outputs" in body and isinstance(body.get("outputs"), dict):
        return body
    return None


def _history_failure(record: dict[str, Any]) -> str | None:
    status = record.get("status")
    if not isinstance(status, dict):
        return None
    status_str = status.get("status_str")
    completed = status.get("completed")
    if isinstance(status_str, str) and status_str.casefold() in {"error", "failed"}:
        return f"execution:{status_str.casefold()}"
    if completed is False and status_str == "error":
        return "execution:error"
    return None


def _history_complete(record: dict[str, Any]) -> bool:
    status = record.get("status")
    if isinstance(status, dict) and status.get("completed") is True:
        return True
    outputs = record.get("outputs")
    return isinstance(outputs, dict) and bool(outputs) and not isinstance(status, dict)


def _canonical_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(raw.encode()).hexdigest()


def _image_mime(data: bytes, content_type: str | None) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8"):
        return "image/jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    normalized = (content_type or "").split(";", 1)[0].strip().casefold()
    if normalized in {"image/png", "image/jpeg", "image/webp"}:
        return normalized
    raise ValueError("unsupported or unrecognized image format")


def _image_dimensions(data: bytes, mime_type: str) -> tuple[int, int]:
    if mime_type == "image/png":
        if len(data) < 24 or data[12:16] != b"IHDR":
            raise ValueError("invalid PNG header")
        width, height = struct.unpack(">II", data[16:24])
        return _positive_dimensions(width, height)
    if mime_type == "image/jpeg":
        return _jpeg_dimensions(data)
    if mime_type == "image/webp":
        return _webp_dimensions(data)
    raise ValueError("unsupported image format")


def _positive_dimensions(width: int, height: int) -> tuple[int, int]:
    if width <= 0 or height <= 0:
        raise ValueError("invalid image dimensions")
    return width, height


def _jpeg_dimensions(data: bytes) -> tuple[int, int]:
    offset = 2
    sof = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while offset + 9 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        offset += 2
        if marker in {0xD8, 0xD9}:
            continue
        if offset + 2 > len(data):
            break
        length = int.from_bytes(data[offset : offset + 2], "big")
        if length < 2 or offset + length > len(data):
            break
        if marker in sof and length >= 7:
            height = int.from_bytes(data[offset + 3 : offset + 5], "big")
            width = int.from_bytes(data[offset + 5 : offset + 7], "big")
            return _positive_dimensions(width, height)
        offset += length
    raise ValueError("JPEG dimensions not found")


def _webp_dimensions(data: bytes) -> tuple[int, int]:
    if len(data) < 30:
        raise ValueError("invalid WebP header")
    chunk = data[12:16]
    if chunk == b"VP8X":
        width = 1 + int.from_bytes(data[24:27], "little")
        height = 1 + int.from_bytes(data[27:30], "little")
        return _positive_dimensions(width, height)
    if chunk == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
        bits = int.from_bytes(data[21:25], "little")
        width = (bits & 0x3FFF) + 1
        height = ((bits >> 14) & 0x3FFF) + 1
        return _positive_dimensions(width, height)
    if chunk == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
        width = int.from_bytes(data[26:28], "little") & 0x3FFF
        height = int.from_bytes(data[28:30], "little") & 0x3FFF
        return _positive_dimensions(width, height)
    raise ValueError("unsupported WebP bitstream")
