from pathlib import Path

import pytest

from llm_redteam.disposable_workspace import DisposableWorkspaceSupervisor


def _template(tmp_path: Path) -> Path:
    root = tmp_path / "template"
    root.mkdir()
    (root / "README.md").write_text("synthetic Blue project\n", encoding="utf-8")
    package = root / "src"
    package.mkdir()
    (package / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def test_prepare_materializes_exact_template_and_release_removes_it(tmp_path: Path) -> None:
    supervisor = DisposableWorkspaceSupervisor(
        template_root=_template(tmp_path),
        sandbox_root=tmp_path / "sandbox",
    )

    prepared = supervisor.prepare(trial_id="trial-a")

    assert prepared.path.is_dir()
    assert (prepared.path / "README.md").read_text(encoding="utf-8") == (
        "synthetic Blue project\n"
    )
    assert prepared.lease.initial_tree_sha256 == supervisor.profile.template_sha256

    (prepared.path / "src" / "main.py").write_text("VALUE = 2\n", encoding="utf-8")
    release = supervisor.release(prepared)

    assert release.cleanup_complete is True
    assert release.final_tree_sha256 != prepared.lease.initial_tree_sha256
    assert not prepared.path.exists()


def test_each_trial_gets_unique_workspace_lease(tmp_path: Path) -> None:
    supervisor = DisposableWorkspaceSupervisor(
        template_root=_template(tmp_path),
        sandbox_root=tmp_path / "sandbox",
    )

    first = supervisor.prepare(trial_id="trial-a")
    second = supervisor.prepare(trial_id="trial-b")

    assert first.lease.lease_id_hash != second.lease.lease_id_hash
    assert first.path != second.path

    supervisor.release(first)
    supervisor.release(second)


def test_duplicate_active_trial_id_is_rejected(tmp_path: Path) -> None:
    supervisor = DisposableWorkspaceSupervisor(
        template_root=_template(tmp_path),
        sandbox_root=tmp_path / "sandbox",
    )
    prepared = supervisor.prepare(trial_id="trial-a")

    with pytest.raises(RuntimeError, match="already active"):
        supervisor.prepare(trial_id="trial-a")

    supervisor.release(prepared)


def test_nonempty_unowned_sandbox_root_is_never_deleted(tmp_path: Path) -> None:
    template = _template(tmp_path)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    sentinel = sandbox / "do-not-delete.txt"
    sentinel.write_text("operator data\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="lacks laboratory ownership marker"):
        DisposableWorkspaceSupervisor(
            template_root=template,
            sandbox_root=sandbox,
        )

    assert sentinel.read_text(encoding="utf-8") == "operator data\n"


def test_invalid_ownership_marker_blocks_prepare_and_cleanup(tmp_path: Path) -> None:
    supervisor = DisposableWorkspaceSupervisor(
        template_root=_template(tmp_path),
        sandbox_root=tmp_path / "sandbox",
    )
    prepared = supervisor.prepare(trial_id="trial-a")
    marker = supervisor.sandbox_root / ".llm-redteam-blue-workspace-root-v1"
    marker.write_text("tampered\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="ownership marker is invalid"):
        supervisor.release(prepared)

    assert prepared.path.exists()


def test_symlink_in_template_is_rejected_when_supported(tmp_path: Path) -> None:
    template = _template(tmp_path)
    link = template / "linked-readme"
    try:
        link.symlink_to(template / "README.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(ValueError, match="forbid symlinks"):
        DisposableWorkspaceSupervisor(
            template_root=template,
            sandbox_root=tmp_path / "sandbox",
        )
