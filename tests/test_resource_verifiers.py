from pathlib import Path

from llm_redteam.agent_actions import AgentEffectState, agent_resource_category
from llm_redteam.resource_verifiers import ForbiddenPathVerifier


def test_forbidden_path_verifier_ignores_legitimate_workspace_changes(tmp_path: Path) -> None:
    verifier = ForbiddenPathVerifier(
        tmp_path,
        "ATTACK_MARKER.txt",
        verifier_id="attack-marker-v1",
    )
    before = verifier.capture()
    (tmp_path / "app.py").write_text("legitimate change", encoding="utf-8")
    after = verifier.capture()

    effect = verifier.assess(
        before,
        after,
        control_event_id="write-app",
        action_categories=frozenset({agent_resource_category(verifier.resource_hash)}),
    )

    assert effect is not None
    assert effect.state == AgentEffectState.ABSENT


def test_forbidden_path_verifier_observes_marker_creation(tmp_path: Path) -> None:
    verifier = ForbiddenPathVerifier(
        tmp_path,
        "ATTACK_MARKER.txt",
        verifier_id="attack-marker-v1",
    )
    before = verifier.capture()
    (tmp_path / "ATTACK_MARKER.txt").write_text("synthetic", encoding="utf-8")
    after = verifier.capture()

    effect = verifier.assess(
        before,
        after,
        control_event_id="write-marker",
        action_categories=verifier.categories,
    )

    assert effect is not None
    assert effect.state == AgentEffectState.OBSERVED
    assert effect.resource_hashes == frozenset({verifier.resource_hash})
    assert effect.effect_hash is not None


def test_forbidden_path_verifier_rejects_path_escape(tmp_path: Path) -> None:
    try:
        ForbiddenPathVerifier(
            tmp_path,
            "../outside.txt",
            verifier_id="escape-v1",
        )
    except ValueError as exc:
        assert "workspace-relative" in str(exc)
    else:
        raise AssertionError("path escape must be rejected")
