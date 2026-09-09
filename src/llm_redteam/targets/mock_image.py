"""Deterministic image-generation target used to prove visual evaluation paths."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from uuid import uuid4

from ..domain import EvidenceKind, EvidenceRecord, TargetClass, TargetIdentity, TargetMode
from ..image_artifacts import ImageArtifactStore
from .base import SessionMode, TargetRequest, TargetResponse


class MockImageDisposition(StrEnum):
    SAFE_IMAGE = "safe_image"
    UNSAFE_IMAGE = "unsafe_image"
    SAFETY_REFUSAL = "safety_refusal"


class ScriptedImageTarget:
    """Emit a configured image/refusal sequence without real model inference.

    The bytes are synthetic fixtures. Safety semantics are intentionally not read
    by production judges; tests use a separately scripted multimodal Judge so the
    attacker/target is never its own evaluator.
    """

    def __init__(
        self,
        artifacts: ImageArtifactStore,
        *,
        sequence: tuple[MockImageDisposition, ...],
        target_id: str = "scripted-image-target",
        target_mode: TargetMode = TargetMode.PIPELINE,
    ) -> None:
        if not sequence:
            raise ValueError("image target sequence cannot be empty")
        self.artifacts = artifacts
        self.sequence = sequence
        self.target_id = target_id
        self.target_mode = target_mode
        self._session_turns: dict[str, int] = {}

    @property
    def identity(self) -> TargetIdentity:
        raw = "|".join(
            [self.target_id, self.target_mode.value, *(item.value for item in self.sequence)]
        )
        return TargetIdentity(
            id=self.target_id,
            target_class=TargetClass.IMAGE_GENERATION,
            target_mode=self.target_mode,
            model="deterministic-image-fixture",
            provider="mock",
            runtime="in-process",
            application="scripted-image-target",
            configuration_hash=sha256(raw.encode()).hexdigest(),
            capabilities=frozenset({"image_generation", "text", "multiturn"}),
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        session_id, ordinal, error = self._resolve_turn(request)
        if error:
            return TargetResponse(error_kind=error)

        disposition = self.sequence[min(ordinal - 1, len(self.sequence) - 1)]
        if disposition == MockImageDisposition.SAFETY_REFUSAL:
            evidence = EvidenceRecord(
                kind=EvidenceKind.GUARDRAIL,
                source="scripted_image_target",
                observed_at="deterministic-test",
                data={"decision": "blocked", "turn_ordinal": ordinal},
                redacted=True,
            )
            return TargetResponse(
                text="Synthetic safety refusal",
                evidence=(evidence,),
                provider_metadata={
                    "image_generated": False,
                    "safety_refusal": True,
                },
                session_id=session_id,
            )

        data = self._fixture_bytes(disposition, ordinal)
        seed = 1000 + ordinal
        artifact = self.artifacts.put(
            data,
            mime_type="image/png",
            width=64,
            height=64,
            seed=seed,
            metadata={"fixture": True, "turn_ordinal": ordinal},
        )
        evidence = EvidenceRecord(
            kind=EvidenceKind.IMAGE,
            source="scripted_image_target",
            observed_at="deterministic-test",
            content_hash=artifact.content_hash,
            artifact_ref=artifact.artifact_id,
            data={
                "mime_type": artifact.mime_type,
                "width": artifact.width,
                "height": artifact.height,
                "seed": seed,
                "turn_ordinal": ordinal,
            },
            redacted=True,
        )
        return TargetResponse(
            text="Synthetic image generated",
            evidence=(evidence,),
            provider_metadata={
                "image_generated": True,
                "safety_refusal": False,
            },
            session_id=session_id,
        )

    def _resolve_turn(self, request: TargetRequest) -> tuple[str | None, int, str | None]:
        if request.session_mode == SessionMode.TARGET_MANAGED:
            if request.session_id is None:
                session_id = f"image-session-{uuid4().hex}"
                self._session_turns[session_id] = 0
            else:
                session_id = request.session_id
                if session_id not in self._session_turns:
                    return None, 0, "session:unknown_image_session"
            ordinal = self._session_turns[session_id] + 1
            self._session_turns[session_id] = ordinal
            return session_id, ordinal, None

        raw_ordinal = request.metadata.get("turn_ordinal", "1")
        try:
            ordinal = int(raw_ordinal)
        except ValueError:
            return None, 0, "protocol:invalid_turn_ordinal"
        if ordinal <= 0:
            return None, 0, "protocol:invalid_turn_ordinal"
        return None, ordinal, None

    @staticmethod
    def _fixture_bytes(disposition: MockImageDisposition, ordinal: int) -> bytes:
        # Valid image decoding is not required for scripted tests; production visual
        # clients only send bytes supplied by real image-generation adapters.
        marker = f"SYNTHETIC_PNG:{disposition.value}:turn={ordinal}".encode()
        return b"\x89PNG\r\n\x1a\n" + marker
