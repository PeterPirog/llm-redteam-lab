import pytest

from llm_redteam.model_artifact import bind_model_peer_artifact
from llm_redteam.ollama_artifact import OllamaArtifactContract

_DIGEST = "a" * 64
_OTHER_DIGEST = "b" * 64
_PROFILE_HASH = "c" * 64


def _record(**updates: object) -> dict[str, object]:
    record: dict[str, object] = {
        "name": "qwen-test:latest",
        "model": "qwen-test:latest",
        "size": 5_000_000_000,
        "digest": _DIGEST,
        "details": {
            "format": "gguf",
            "family": "qwen3",
            "parameter_size": "9B",
            "quantization_level": "Q4_K_M",
        },
    }
    record.update(updates)
    return record


def _contract(digest: str = _DIGEST) -> OllamaArtifactContract:
    return OllamaArtifactContract(
        model_id="qwen-test:latest",
        expected_manifest_digest=digest,
    )


def test_tags_digest_becomes_canonical_manifest_identity() -> None:
    observation = _contract().verify_tags_response({"models": [_record()]})

    identity = observation.identity
    assert identity.provider_id == "ollama"
    assert identity.model_id == "qwen-test:latest"
    assert identity.artifact_digest == "sha256:" + _DIGEST
    assert identity.artifact_size_bytes == 5_000_000_000
    assert identity.local_artifact is True
    assert identity.format == "gguf"
    assert identity.family == "qwen3"
    assert identity.parameter_size == "9B"
    assert identity.quantization_level == "Q4_K_M"
    assert len(identity.identity_sha256) == 64
    assert len(observation.proof_sha256) == 64


def test_prefixed_and_bare_digests_are_same_contract_identity() -> None:
    bare = _contract(_DIGEST)
    prefixed = _contract("sha256:" + _DIGEST)

    assert bare.manifest_digest == prefixed.manifest_digest
    assert bare.contract_sha256 == prefixed.contract_sha256


def test_wrong_manifest_digest_fails_closed() -> None:
    with pytest.raises(ValueError, match="manifest digest"):
        _contract(_OTHER_DIGEST).verify_tags_response({"models": [_record()]})


def test_duplicate_model_records_fail_closed() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        _contract().verify_tags_response({"models": [_record(), _record()]})


def test_remote_ollama_model_is_not_accepted_as_local_artifact() -> None:
    with pytest.raises(ValueError, match="local model"):
        _contract().verify_tags_response(
            {
                "models": [
                    _record(
                        remote_model="qwen-test:latest",
                        remote_host="https://example.invalid",
                    )
                ]
            }
        )


def test_same_name_with_different_digest_changes_artifact_identity() -> None:
    first = _contract(_DIGEST).verify_tags_response({"models": [_record()]})
    second = _contract(_OTHER_DIGEST).verify_tags_response(
        {"models": [_record(digest=_OTHER_DIGEST)]}
    )

    assert first.identity.identity_sha256 != second.identity.identity_sha256


def test_model_peer_binding_requires_exact_provider_and_model() -> None:
    artifact = _contract().verify_tags_response({"models": [_record()]}).identity
    binding = bind_model_peer_artifact(
        peer_profile_sha256=_PROFILE_HASH,
        peer_provider_id="ollama",
        peer_model_id="qwen-test:latest",
        artifact=artifact,
    )

    assert binding.provider_id == "ollama"
    assert binding.model_id == "qwen-test:latest"
    assert binding.artifact_identity_sha256 == artifact.identity_sha256
    assert len(binding.binding_sha256) == 64

    with pytest.raises(ValueError, match="provider"):
        bind_model_peer_artifact(
            peer_profile_sha256=_PROFILE_HASH,
            peer_provider_id="openai-compatible",
            peer_model_id="qwen-test:latest",
            artifact=artifact,
        )
    with pytest.raises(ValueError, match="model ID"):
        bind_model_peer_artifact(
            peer_profile_sha256=_PROFILE_HASH,
            peer_provider_id="ollama",
            peer_model_id="different:latest",
            artifact=artifact,
        )


def test_invalid_digest_format_is_rejected() -> None:
    contract = OllamaArtifactContract(
        model_id="qwen-test:latest",
        expected_manifest_digest="latest",
    )

    with pytest.raises(ValueError, match="SHA-256"):
        _ = contract.manifest_digest
