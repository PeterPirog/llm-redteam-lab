from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.mcp_fixture_staging import FilesystemMcpFixtureStagingBackend
from llm_redteam.opencode_runtime import McpFixtureBridgeProfile


def _bridge() -> McpFixtureBridgeProfile:
    return McpFixtureBridgeProfile(
        context_file_path="/control/mcp/context.txt",
        context_hash_file_path="/control/mcp/context.sha256",
    )


def _backend(tmp_path: Path) -> FilesystemMcpFixtureStagingBackend:
    root = tmp_path / "host-control"
    root.mkdir()
    return FilesystemMcpFixtureStagingBackend(
        context_host_path=root / "context.txt",
        hash_host_path=root / "context.sha256",
    )


def test_host_staging_namespace_is_independent_from_target_visible_bridge(tmp_path: Path) -> None:
    bridge = _bridge()
    backend = _backend(tmp_path)
    binding = backend.runtime_binding(bridge)

    assert bridge.context_file_path == "/control/mcp/context.txt"
    assert bridge.context_hash_file_path == "/control/mcp/context.sha256"
    assert str(backend.context_host_path) != bridge.context_file_path
    assert str(backend.hash_host_path) != bridge.context_hash_file_path
    assert binding.bridge_sha256 == bridge.bridge_sha256
    assert binding.staging_policy_sha256 == backend.staging_policy_sha256

    serialized = binding.model_dump_json()
    assert str(backend.context_host_path) not in serialized
    assert str(backend.hash_host_path) not in serialized
    assert "/control/mcp/context.txt" not in serialized


def test_target_mcp_environment_keeps_container_paths_not_host_paths(tmp_path: Path) -> None:
    bridge = _bridge()
    backend = _backend(tmp_path)
    server = bridge.opencode_server_config()
    environment = server["environment"]

    assert isinstance(environment, dict)
    assert environment["LLM_REDTEAM_MCP_CONTEXT_FILE"] == bridge.context_file_path
    assert environment["LLM_REDTEAM_MCP_CONTEXT_HASH_FILE"] == bridge.context_hash_file_path
    assert str(backend.context_host_path) not in environment.values()
    assert str(backend.hash_host_path) not in environment.values()


def test_stage_writes_only_host_sidecars_then_release_verifies_and_removes_them(
    tmp_path: Path,
) -> None:
    bridge = _bridge()
    backend = _backend(tmp_path)
    content = "UNTRUSTED MCP DATA: synthetic fixture payload"
    content_sha256 = sha256(content.encode()).hexdigest()

    handle = backend.stage(
        bridge=bridge,
        content=content,
        content_sha256=content_sha256,
    )

    assert handle.host_context_path.read_text(encoding="utf-8") == content
    assert handle.host_hash_path.read_text(encoding="ascii").strip() == content_sha256
    assert handle.runtime_binding.bridge_sha256 == bridge.bridge_sha256

    released = backend.release(handle)
    assert released.integrity_preserved is True
    assert released.cleanup_complete is True
    assert not handle.host_context_path.exists()
    assert not handle.host_hash_path.exists()


def test_stale_or_preexisting_host_sidecar_is_never_overwritten(tmp_path: Path) -> None:
    bridge = _bridge()
    backend = _backend(tmp_path)
    backend.context_host_path.write_text("preexisting", encoding="utf-8")
    content = "synthetic fixture"

    with pytest.raises(RuntimeError, match="stale/reused trial refused"):
        backend.stage(
            bridge=bridge,
            content=content,
            content_sha256=sha256(content.encode()).hexdigest(),
        )

    assert backend.context_host_path.read_text(encoding="utf-8") == "preexisting"
    assert not backend.hash_host_path.exists()


def test_modified_staged_bytes_are_reported_as_integrity_failure_before_cleanup(
    tmp_path: Path,
) -> None:
    bridge = _bridge()
    backend = _backend(tmp_path)
    content = "synthetic original"
    handle = backend.stage(
        bridge=bridge,
        content=content,
        content_sha256=sha256(content.encode()).hexdigest(),
    )
    handle.host_context_path.write_text("synthetic tamper", encoding="utf-8")

    released = backend.release(handle)

    assert released.integrity_preserved is False
    assert released.cleanup_complete is True
    assert not handle.host_context_path.exists()
    assert not handle.host_hash_path.exists()


def test_wrong_content_hash_fails_before_creating_any_host_sidecar(tmp_path: Path) -> None:
    backend = _backend(tmp_path)

    with pytest.raises(ValueError, match="hash mismatch"):
        backend.stage(
            bridge=_bridge(),
            content="synthetic",
            content_sha256="0" * 64,
        )

    assert not backend.context_host_path.exists()
    assert not backend.hash_host_path.exists()


def test_only_active_stage_handle_can_clear_sidecars(tmp_path: Path) -> None:
    bridge = _bridge()
    backend = _backend(tmp_path)
    content = "synthetic"
    handle = backend.stage(
        bridge=bridge,
        content=content,
        content_sha256=sha256(content.encode()).hexdigest(),
    )
    other_backend = _backend(tmp_path / "other")
    other_content = "other"
    other = other_backend.stage(
        bridge=bridge,
        content=other_content,
        content_sha256=sha256(other_content.encode()).hexdigest(),
    )

    with pytest.raises(RuntimeError, match="does not match the active stage"):
        backend.release(other)

    assert handle.host_context_path.exists()
    assert backend.release(handle).cleanup_complete is True
    assert other_backend.release(other).cleanup_complete is True


def test_runtime_binding_changes_with_host_namespace_but_bridge_identity_does_not(
    tmp_path: Path,
) -> None:
    bridge = _bridge()
    first = _backend(tmp_path / "first")
    second = _backend(tmp_path / "second")

    first_binding = first.runtime_binding(bridge)
    second_binding = second.runtime_binding(bridge)

    assert first.staging_policy_sha256 == second.staging_policy_sha256
    assert first_binding.bridge_sha256 == second_binding.bridge_sha256 == bridge.bridge_sha256
    assert first_binding.binding_sha256 != second_binding.binding_sha256
