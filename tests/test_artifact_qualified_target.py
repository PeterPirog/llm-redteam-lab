import asyncio

import pytest

from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.storage.repository import ExperimentRepository
from llm_redteam.targets.artifact_qualified import (
    ArtifactQualifiedTarget,
    bind_target_model_artifact,
    qualify_target_identity,
)
from llm_redteam.targets.base import TargetRequest, TargetResponse


def _target_identity(*, model_digest: str | None = None) -> TargetIdentity:
    return TargetIdentity(
        id="local-blue",
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        model="blue:latest",
        provider="ollama",
        runtime="http://localhost:11434",
        model_digest=model_digest,
        application="direct-model-api",
        application_version="v1",
        system_prompt_hash="c" * 64,
        configuration_hash="base-blue-config-v1",
        capabilities=frozenset({"text"}),
    )


def _artifact(
    *,
    digest_char: str = "a",
    model: str = "blue:latest",
    provider: str = "ollama",
    local: bool = True,
) -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id=provider,
        model_id=model,
        artifact_digest="sha256:" + digest_char * 64,
        artifact_size_bytes=4096,
        local_artifact=local,
        format="gguf",
        family="synthetic-blue",
        parameter_size="9B",
        quantization_level="Q4_K_M",
    )


def test_exact_artifact_changes_target_configuration_and_snapshot_identity() -> None:
    base = _target_identity()
    first = qualify_target_identity(target=base, artifact=_artifact(digest_char="a"))
    second = qualify_target_identity(target=base, artifact=_artifact(digest_char="b"))

    assert first.model == second.model == "blue:latest"
    assert first.model_digest == "sha256:" + "a" * 64
    assert second.model_digest == "sha256:" + "b" * 64
    assert first.configuration_hash != base.configuration_hash
    assert first.configuration_hash != second.configuration_hash
    assert (
        ExperimentRepository.target_snapshot_id(first)
        != ExperimentRepository.target_snapshot_id(second)
    )


def test_same_base_configuration_and_artifact_produce_stable_identity() -> None:
    base = _target_identity()
    artifact = _artifact()

    first = qualify_target_identity(target=base, artifact=artifact)
    second = qualify_target_identity(target=base, artifact=artifact)

    assert first == second
    assert first.model_digest == artifact.artifact_digest
    assert len(first.configuration_hash) == 64


@pytest.mark.parametrize(
    ("target", "artifact", "message"),
    [
        (_target_identity(), _artifact(provider="other"), "provider"),
        (_target_identity(), _artifact(model="other:latest"), "model ID"),
        (
            _target_identity(model_digest="sha256:" + "d" * 64),
            _artifact(digest_char="a"),
            "model_digest",
        ),
        (_target_identity(), _artifact(local=False), "local model artifact"),
    ],
)
def test_target_artifact_binding_rejects_identity_or_locality_drift(
    target: TargetIdentity,
    artifact: ModelArtifactIdentity,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        bind_target_model_artifact(target=target, artifact=artifact)


def test_remote_artifact_may_be_bound_only_when_caller_explicitly_allows_it() -> None:
    binding = bind_target_model_artifact(
        target=_target_identity(),
        artifact=_artifact(local=False),
        require_local=False,
    )

    assert binding.local_artifact is False
    assert binding.require_local is False
    assert len(binding.binding_sha256) == 64


class _RecordingTarget:
    def __init__(self) -> None:
        self.requests: list[TargetRequest] = []

    @property
    def identity(self) -> TargetIdentity:
        return _target_identity()

    async def execute(self, request: TargetRequest) -> TargetResponse:
        self.requests.append(request)
        return TargetResponse(text="delegated")


def test_wrapper_delegates_request_without_expanding_target_capabilities() -> None:
    base = _RecordingTarget()
    wrapped = ArtifactQualifiedTarget(base, _artifact())
    request = TargetRequest(attack_id="A-1", prompt="synthetic bounded request")

    response = asyncio.run(wrapped.execute(request))

    assert response.text == "delegated"
    assert base.requests == [request]
    assert wrapped.identity.capabilities == base.identity.capabilities
    assert wrapped.identity.model_digest == _artifact().artifact_digest
    assert wrapped.base_identity == base.identity


def test_wrapper_freezes_identity_at_admission_time() -> None:
    class _MutableIdentityTarget(_RecordingTarget):
        def __init__(self) -> None:
            super().__init__()
            self.version = 1

        @property
        def identity(self) -> TargetIdentity:
            identity = _target_identity()
            return identity.model_copy(
                update={"configuration_hash": f"mutable-base-{self.version}"}
            )

    base = _MutableIdentityTarget()
    wrapped = ArtifactQualifiedTarget(base, _artifact())
    admitted = wrapped.identity
    base.version = 2

    assert wrapped.identity == admitted
    assert wrapped.base_identity.configuration_hash == "mutable-base-1"
    assert base.identity.configuration_hash == "mutable-base-2"
