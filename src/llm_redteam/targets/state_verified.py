"""Target decorator that adds deterministic pre/post system-state evidence.

The decorator is measurement infrastructure, not a Blue control. It never changes
permissions and preserves the wrapped target identity. State verifier evidence is added
after the wrapped target returns so provider self-report and independent post-state remain
separate trust domains.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from ..agent_actions import AgentEffectObservation, AgentEffectState
from ..domain import EvidenceKind, TargetIdentity
from ..state_verifiers import StateVerifier, VerifierSnapshot
from .base import TargetAdapter, TargetRequest, TargetResponse


@dataclass(frozen=True, slots=True)
class _ActionRef:
    control_event_id: str
    categories: frozenset[str]


class StateVerifyingTarget:
    """Decorate any target with deterministic post-state verification.

    Verifiers capture state immediately before and after one target request. If exactly
    one relevant tool event is present, a state change can be attributed to that event.
    Multiple relevant events with a changed state are deliberately marked UNKNOWN because
    a turn-level snapshot cannot prove which individual call caused the effect.

    State changes with no matching tool event are emitted as orphan trusted effects. This
    allows the Judge to detect system compromise even when the provider tool trace omitted
    the causal action. An incomplete verifier emits UNKNOWN state evidence and therefore
    cannot silently contribute to a PASS.
    """

    def __init__(
        self,
        target: TargetAdapter,
        verifiers: tuple[StateVerifier, ...],
    ) -> None:
        if not verifiers:
            raise ValueError("StateVerifyingTarget requires at least one state verifier")
        ids = [verifier.verifier_id for verifier in verifiers]
        if len(ids) != len(set(ids)):
            raise ValueError("state verifier IDs must be unique")
        self._target = target
        self._verifiers = verifiers

    @property
    def identity(self) -> TargetIdentity:
        # Verifiers belong to the measurement/Judge configuration, not the Blue target.
        return self._target.identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        before = {
            verifier.verifier_id: verifier.capture() for verifier in self._verifiers
        }
        response = await self._target.execute(request)
        after = {
            verifier.verifier_id: verifier.capture() for verifier in self._verifiers
        }
        action_refs, malformed_action_refs = self._action_refs(response)

        added = []
        for verifier in self._verifiers:
            prior = before[verifier.verifier_id]
            current = after[verifier.verifier_id]
            matching = [
                action
                for action in action_refs
                if verifier.categories.intersection(action.categories)
            ]
            if matching:
                ambiguous = len(matching) > 1
                for action in matching:
                    observation = verifier.assess(
                        prior,
                        current,
                        control_event_id=action.control_event_id,
                        action_categories=action.categories,
                        attribution_ambiguous=ambiguous,
                    )
                    if observation is not None:
                        added.append(observation.to_evidence())
                continue

            orphan = self._orphan_effect(
                verifier=verifier,
                before=prior,
                after=current,
                request=request,
            )
            if orphan is not None:
                added.append(orphan.to_evidence())

        metadata = dict(response.provider_metadata)
        metadata.update(
            {
                "state_verifier_count": len(self._verifiers),
                "state_verification_complete": all(
                    snapshot.complete for snapshot in (*before.values(), *after.values())
                ),
                "state_verifier_action_parse_complete": not malformed_action_refs,
            }
        )
        return response.model_copy(
            update={
                "evidence": response.evidence + tuple(added),
                "provider_metadata": metadata,
            }
        )

    @staticmethod
    def _action_refs(response: TargetResponse) -> tuple[list[_ActionRef], bool]:
        refs: list[_ActionRef] = []
        malformed = False
        for evidence in response.evidence:
            if evidence.kind != EvidenceKind.TOOL_CALL:
                continue
            try:
                event_id = evidence.data["control_event_id"]
                raw_categories = evidence.data["categories"]
                if not isinstance(event_id, str) or not event_id:
                    raise ValueError
                if not isinstance(raw_categories, list) or not all(
                    isinstance(value, str) for value in raw_categories
                ):
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                malformed = True
                continue
            refs.append(
                _ActionRef(
                    control_event_id=event_id,
                    categories=frozenset(raw_categories),
                )
            )
        return refs, malformed

    @staticmethod
    def _orphan_effect(
        *,
        verifier: StateVerifier,
        before: VerifierSnapshot,
        after: VerifierSnapshot,
        request: TargetRequest,
    ) -> AgentEffectObservation | None:
        if before.complete and after.complete and before.state_hash == after.state_hash:
            return None

        digest = sha256(
            (
                verifier.verifier_id
                + ":"
                + request.attack_id
                + ":"
                + before.state_hash
                + ":"
                + after.state_hash
            ).encode()
        ).hexdigest()[:24]
        state = (
            AgentEffectState.OBSERVED
            if before.complete and after.complete
            else AgentEffectState.UNKNOWN
        )
        effect_hash = (
            sha256(
                (
                    verifier.verifier_id
                    + ":"
                    + before.state_hash
                    + ":"
                    + after.state_hash
                ).encode()
            ).hexdigest()
            if state == AgentEffectState.OBSERVED
            else None
        )
        return AgentEffectObservation(
            control_event_id=f"orphan-state-{digest}",
            verifier_id=verifier.verifier_id,
            state=state,
            categories=verifier.categories,
            effect_hash=effect_hash,
            state_before_hash=before.state_hash,
            state_after_hash=after.state_hash,
            source="deterministic_state_verifier",
        )
