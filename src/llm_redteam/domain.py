"""Strict domain models shared by corpus, campaigns, evidence and reporting."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model that rejects silently ignored configuration fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TargetClass(StrEnum):
    CODING = "coding"
    REASONING = "reasoning"
    WRITING = "writing"
    IMAGE_GENERATION = "image_generation"


class TargetMode(StrEnum):
    MODEL = "MODEL"
    PIPELINE = "PIPELINE"
    AGENT = "AGENT"


class AttackTier(StrEnum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"
    T5 = "T5"


class CompromiseOutcome(StrEnum):
    PASS = "PASS"
    MODEL_COMPROMISE = "MODEL_COMPROMISE"
    SYSTEM_COMPROMISE = "SYSTEM_COMPROMISE"
    MODEL_AND_SYSTEM_COMPROMISE = "MODEL_AND_SYSTEM_COMPROMISE"
    PARTIAL = "PARTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class FindingStatus(StrEnum):
    SINGLE_OBSERVATION = "SINGLE_OBSERVATION"
    FLAKY = "FLAKY"
    REPRODUCIBLE = "REPRODUCIBLE"
    CONFIRMED = "CONFIRMED"


class SourceMode(StrEnum):
    NATIVE = "native"
    EXTERNAL = "external"
    GATED = "gated"
    VENDORED = "vendored"
    REFERENCE = "reference"


class SourceRef(StrictModel):
    mode: SourceMode
    name: str = Field(min_length=1)
    record_id: str | None = None
    revision: str | None = None
    license: str | None = None
    url: str | None = None
    content_hash: str | None = None


class SecurityObjective(StrictModel):
    invariant: str = Field(min_length=1)
    expected_safe_behavior: str = Field(min_length=1)
    forbidden_effect: str = Field(min_length=1)


class PayloadSpec(StrictModel):
    template: str | None = None
    text: str | None = None
    fixture: str | None = None

    @model_validator(mode="after")
    def exactly_one_payload_kind(self) -> PayloadSpec:
        populated = sum(value is not None for value in (self.template, self.text, self.fixture))
        if populated != 1:
            raise ValueError("payload requires exactly one of template, text, or fixture")
        return self


class GradingSpec(StrictModel):
    preferred: list[Literal["deterministic", "system_state", "semantic", "multimodal"]]
    detectors: list[str] = Field(min_length=1)


class AttackCase(StrictModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    target_classes: list[TargetClass] = Field(min_length=1)
    target_modes: list[TargetMode] = Field(min_length=1)
    attack_family: list[str] = Field(min_length=1)
    complexity_tier: AttackTier
    interaction_mode: Literal[
        "single_turn", "multi_turn", "environment_injection", "agentic"
    ]
    source: SourceRef
    security_objective: SecurityObjective
    payload: PayloadSpec
    variables: dict[str, str | int | float | bool] = Field(default_factory=dict)
    grading: GradingSpec
    tags: list[str] = Field(default_factory=list)
    enabled_by_default: bool = False

    @model_validator(mode="after")
    def multimodal_grading_matches_target(self) -> AttackCase:
        if "multimodal" in self.grading.preferred and TargetClass.IMAGE_GENERATION not in self.target_classes:
            raise ValueError("multimodal grading requires image_generation target class")
        if self.interaction_mode == "environment_injection" and TargetMode.AGENT not in self.target_modes:
            raise ValueError("environment_injection requires AGENT target mode")
        return self


class CorpusDocument(StrictModel):
    version: int = Field(ge=1)
    cases: list[AttackCase]

    @model_validator(mode="after")
    def unique_case_ids(self) -> CorpusDocument:
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("attack case IDs must be unique within a corpus document")
        return self


class TargetIdentity(StrictModel):
    id: str = Field(min_length=1)
    target_class: TargetClass
    target_mode: TargetMode
    model: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    runtime: str | None = None
    model_digest: str | None = None
    application: str | None = None
    application_version: str | None = None
    system_prompt_hash: str | None = None
    configuration_hash: str = Field(min_length=1)
    capabilities: frozenset[str] = frozenset()


class SecurityInvariant(StrictModel):
    id: str = Field(min_length=1)
    rule: str = Field(min_length=1)
    forbidden_effect: str = Field(min_length=1)
    deterministic_detector: str | None = None


class EvidenceKind(StrEnum):
    TRANSCRIPT = "transcript"
    TOOL_CALL = "tool_call"
    SYSTEM_STATE = "system_state"
    FILESYSTEM = "filesystem"
    SHELL = "shell"
    NETWORK = "network"
    GUARDRAIL = "guardrail"
    IMAGE = "image"
    METADATA = "metadata"
    JUDGE = "judge"


class EvidenceRecord(StrictModel):
    kind: EvidenceKind
    source: str = Field(min_length=1)
    observed_at: str
    content_hash: str | None = None
    artifact_ref: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    redacted: bool = True


class ExecutionResult(StrictModel):
    execution_id: str = Field(min_length=1)
    attack_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    outcome: CompromiseOutcome
    model_compromise: bool
    system_compromise: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: tuple[EvidenceRecord, ...] = ()
    error_kind: str | None = None

    @model_validator(mode="after")
    def outcome_consistent_with_flags(self) -> ExecutionResult:
        expected = {
            (False, False): CompromiseOutcome.PASS,
            (True, False): CompromiseOutcome.MODEL_COMPROMISE,
            (False, True): CompromiseOutcome.SYSTEM_COMPROMISE,
            (True, True): CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE,
        }
        if self.outcome in expected.values() and self.outcome != expected[
            (self.model_compromise, self.system_compromise)
        ]:
            raise ValueError("compromise outcome is inconsistent with compromise flags")
        if self.outcome == CompromiseOutcome.ERROR and not self.error_kind:
            raise ValueError("ERROR outcome requires error_kind")
        return self


class CampaignBudget(StrictModel):
    max_attacks: int = Field(gt=0)
    max_generations: int = Field(gt=0)
    max_turns_per_attack: int = Field(gt=0)
    max_model_calls: int = Field(gt=0)
    max_total_output_tokens: int = Field(gt=0)
    max_image_generations: int = Field(ge=0)
    wall_clock_seconds: int = Field(gt=0)
    stop_after_confirmed_cheap_failure: bool = True
    max_non_progress_attempts: int = Field(gt=0, default=3)
