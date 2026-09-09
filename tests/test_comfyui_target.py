import asyncio
import json
import struct

import httpx

from llm_redteam.domain import EvidenceKind, TargetMode
from llm_redteam.image_artifacts import InMemoryImageArtifactStore
from llm_redteam.targets.base import ConversationMessage, MessageRole, SessionMode, TargetRequest
from llm_redteam.targets.comfyui import ComfyUIConfig, ComfyUIInputBinding, ComfyUITarget


def _png(width: int = 32, height: int = 16) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + struct.pack(">II", width, height)


def _workflow() -> dict[str, object]:
    return {
        "3": {
            "class_type": "KSampler",
            "inputs": {"seed": 123, "steps": 10},
        },
        "6": {
            "class_type": "CLIPTextEncode",
            "inputs": {"text": "ORIGINAL"},
        },
        "9": {
            "class_type": "SaveImage",
            "inputs": {"filename_prefix": "redteam"},
        },
    }


def _config(**updates: object) -> ComfyUIConfig:
    values: dict[str, object] = {
        "id": "comfyui-local",
        "base_url": "http://comfyui.local",
        "model": "synthetic-checkpoint.safetensors",
        "workflow_api": _workflow(),
        "prompt_binding": {"node_id": "6", "input_name": "text"},
        "seed_bindings": [{"node_id": "3", "input_name": "seed"}],
        "default_seed": 777,
        "output_node_ids": ["9"],
        "poll_interval_seconds": 0,
        "max_poll_attempts": 3,
    }
    values.update(updates)
    return ComfyUIConfig.model_validate(values)


def test_comfyui_queues_bound_workflow_then_uses_history_and_view() -> None:
    seen: list[tuple[str, str]] = []
    queued: dict[str, object] = {}
    history_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal history_reads
        seen.append((request.method, request.url.path))
        if request.method == "POST" and request.url.path == "/prompt":
            queued.update(json.loads(request.content)["prompt"])
            return httpx.Response(200, json={"prompt_id": "server-prompt-42"})
        if request.method == "GET" and request.url.path == "/history/server-prompt-42":
            history_reads += 1
            if history_reads == 1:
                return httpx.Response(200, json={})
            return httpx.Response(
                200,
                json={
                    "server-prompt-42": {
                        "outputs": {
                            "9": {
                                "images": [
                                    {
                                        "filename": "redteam_00001_.png",
                                        "subfolder": "",
                                        "type": "output",
                                    }
                                ]
                            }
                        },
                        "status": {"status_str": "success", "completed": True},
                    }
                },
            )
        if request.method == "GET" and request.url.path == "/view":
            assert request.url.params["filename"] == "redteam_00001_.png"
            assert request.url.params["type"] == "output"
            return httpx.Response(200, content=_png(), headers={"content-type": "image/png"})
        return httpx.Response(404)

    artifacts = InMemoryImageArtifactStore()

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            target = ComfyUITarget(_config(), artifacts, client=client)
            return target.identity, await target.execute(
                TargetRequest(
                    attack_id="IMG-REAL-001",
                    prompt="controlled synthetic visual probe",
                    metadata={"seed": "4242"},
                )
            )

    identity, response = asyncio.run(run())

    assert identity.target_mode == TargetMode.PIPELINE
    assert response.error_kind is None
    assert response.provider_metadata["history_verified"] is True
    assert response.provider_metadata["seed"] == 4242
    assert history_reads == 2
    assert queued["6"]["inputs"]["text"] == "controlled synthetic visual probe"
    assert queued["3"]["inputs"]["seed"] == 4242
    image_evidence = [item for item in response.evidence if item.kind == EvidenceKind.IMAGE]
    assert len(image_evidence) == 1
    assert image_evidence[0].data["width"] == 32
    assert image_evidence[0].data["height"] == 16
    assert image_evidence[0].artifact_ref is not None
    artifact, data = artifacts.get(image_evidence[0].artifact_ref)
    assert artifact.content_hash == image_evidence[0].content_hash
    assert data == _png()
    serialized = " ".join(item.model_dump_json() for item in response.evidence)
    assert "server-prompt-42" not in serialized
    assert seen[:3] == [
        ("POST", "/prompt"),
        ("GET", "/history/server-prompt-42"),
        ("GET", "/history/server-prompt-42"),
    ]


def test_invalid_workflow_binding_fails_before_network() -> None:
    called = False

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            target = ComfyUITarget(
                _config(prompt_binding={"node_id": "404", "input_name": "text"}),
                InMemoryImageArtifactStore(),
                client=client,
            )
            return await target.execute(TargetRequest(attack_id="A", prompt="probe"))

    response = asyncio.run(run())
    assert response.error_kind == "configuration:unknown_workflow_node:404"
    assert called is False


def test_direct_comfyui_rejects_conversation_memory_and_input_images_before_network() -> None:
    called = False

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            target = ComfyUITarget(_config(), InMemoryImageArtifactStore(), client=client)
            conversation = await target.execute(
                TargetRequest(
                    attack_id="A1",
                    prompt="next",
                    conversation=(ConversationMessage(role=MessageRole.USER, content="prior"),),
                )
            )
            managed = await target.execute(
                TargetRequest(
                    attack_id="A2",
                    prompt="next",
                    session_mode=SessionMode.TARGET_MANAGED,
                )
            )
            image_input = await target.execute(
                TargetRequest(
                    attack_id="A3",
                    prompt="next",
                    input_artifact_refs=("image-input",),
                )
            )
            return conversation, managed, image_input

    conversation, managed, image_input = asyncio.run(run())
    assert conversation.error_kind == "session:comfyui_has_no_conversation_memory"
    assert managed.error_kind == "session:target_managed_not_supported"
    assert image_input.error_kind == "input:multimodal_not_supported"
    assert called is False


def test_history_timeout_is_measurement_error_not_blue_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"prompt_id": "p-timeout"})
        if request.url.path == "/history/p-timeout":
            return httpx.Response(200, json={})
        return httpx.Response(404)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            target = ComfyUITarget(
                _config(max_poll_attempts=2),
                InMemoryImageArtifactStore(),
                client=client,
            )
            return await target.execute(TargetRequest(attack_id="A", prompt="probe"))

    response = asyncio.run(run())
    assert response.error_kind == "timeout:history_not_complete"


def test_seed_binding_requires_an_authorized_seed_before_network() -> None:
    called = False

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            target = ComfyUITarget(
                _config(default_seed=None),
                InMemoryImageArtifactStore(),
                client=client,
            )
            return await target.execute(TargetRequest(attack_id="A", prompt="probe"))

    response = asyncio.run(run())
    assert response.error_kind == "input:seed_required"
    assert called is False


def test_input_binding_model_rejects_empty_fields() -> None:
    try:
        ComfyUIInputBinding(node_id="", input_name="text")
    except ValueError:
        pass
    else:
        raise AssertionError("empty ComfyUI node binding must be rejected")
