"""Normalized, privacy-conscious evidence for agent tool activity.

Tool completion, authorization and real-world/system-state effects are deliberately
separate evidence channels. A provider reporting that a tool call completed is not
by itself proof that a forbidden effect occurred.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from pydantic import Field, model_validator

from .domain import EvidenceKind, EvidenceRecord, StrictModel


class AgentActionPhase(StrEnum):
    """Observed lifecycle stage of one agent tool call."""

    REQUESTED = "requested"
    EXECUTED = "executed"
    ERROR = "error"
    DENIED = "denied"


class AgentAuthorizationDecision(StrEnum):
    """Decision emitted by a runtime authorization/control layer."""

    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"


class AgentEffectState(StrEnum):
    """Independent conclusion about whether a security-relevant effect occurred."""

    OBSERVED = "observed"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class AgentActionObservation(StrictModel):
    """Normalized tool-call observation without retaining raw tool input/output."""

    control_event_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    message_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    phase: AgentActionPhase
    categories: frozenset[str] = frozenset()
    resource_hashes: frozenset[str] = frozenset()
    input_hash: str = Field(min_length=1)
    output_hash: str | None = None
    error_hash: str | None = None
    source: str = Field(min_length=1, default="agent")

    def to_evidence(self) -> EvidenceRecord:
        return EvidenceRecord(
            kind=EvidenceKind.TOOL_CALL,
            source=self.source,
            observed_at=datetime.now(UTC).isoformat(),
            content_hash=self.input_hash,
            data={
                "control_event_id": self.control_event_id,
                "session_id": self.session_id,
                "message_id": self.message_id,
                "tool": self.tool,
                "phase": self.phase.value,
                "categories": sorted(self.categories),
                "resource_hashes": sorted(self.resource_hashes),
                "input_hash": self.input_hash,
                "output_hash": self.output_hash or "",
                "error_hash": self.error_hash or "",
            },
            redacted=True,
        )


class AgentAuthorizationObservation(StrictModel):
    """Runtime authorization decision linked to one tool-control event."""

    control_event_id: str = Field(min_length=1)
    decision: AgentAuthorizationDecision
    control_id: str = Field(min_length=1)
    decision_hash: str | None = None
    source: str = Field(min_length=1, default="authorization_layer")

    def to_evidence(self) -> EvidenceRecord:
        return EvidenceRecord(
            kind=EvidenceKind.GUARDRAIL,
            source=self.source,
            observed_at=datetime.now(UTC).isoformat(),
            content_hash=self.decision_hash,
            data={
                "control_event_id": self.control_event_id,
                "decision": self.decision.value,
                "control_id": self.control_id,
            },
            redacted=True,
        )


class AgentEffectObservation(StrictModel):
    """Independent state-verifier result linked to one tool-control event.

    `verifier_id` is matched against the Judge policy, so target-controlled text
    cannot make itself authoritative by merely claiming that an effect occurred.
    """

    control_event_id: str = Field(min_length=1)
    verifier_id: str = Field(min_length=1)
    state: AgentEffectState
    categories: frozenset[str] = Field(min_length=1)
    resource_hashes: frozenset[str] = frozenset()
    effect_hash: str | None = None
    state_before_hash: str | None = None
    state_after_hash: str | None = None
    source: str = Field(min_length=1, default="system_state_verifier")

    @model_validator(mode="after")
    def observed_effect_requires_a_fingerprint(self) -> AgentEffectObservation:
        if self.state == AgentEffectState.OBSERVED and self.effect_hash is None:
            raise ValueError("observed agent effect requires effect_hash")
        return self

    def to_evidence(self) -> EvidenceRecord:
        return EvidenceRecord(
            kind=EvidenceKind.SYSTEM_STATE,
            source=self.source,
            observed_at=datetime.now(UTC).isoformat(),
            content_hash=self.effect_hash,
            data={
                "control_event_id": self.control_event_id,
                "verifier_id": self.verifier_id,
                "state": self.state.value,
                "categories": sorted(self.categories),
                "resource_hashes": sorted(self.resource_hashes),
                "effect_hash": self.effect_hash or "",
                "state_before_hash": self.state_before_hash or "",
                "state_after_hash": self.state_after_hash or "",
            },
            redacted=True,
        )


def canonical_json_hash(value: object) -> str:
    """Hash arbitrary JSON-like data deterministically without persisting its raw value."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode()).hexdigest()


def classify_agent_action(
    tool: str,
    tool_input: dict[str, Any],
    *,
    workspace_root: str | None = None,
) -> frozenset[str]:
    """Assign coarse security-relevant categories to a tool call.

    The classifier intentionally uses conservative categories instead of trying
    to reproduce a provider's authorization engine. Policy decisions remain in
    deterministic system-state detectors.
    """

    normalized_tool = tool.casefold()
    categories: set[str] = {"tool_call"}

    if normalized_tool in {"bash", "shell"}:
        categories.add("shell")
        command = _first_string(tool_input, "command", "cmd", "script")
        if command:
            if re.search(r"(?:^|[;&|]\s*)git\s+push(?:\s|$)", command, re.IGNORECASE):
                categories.add("git_push")
                categories.add("network")
            if re.search(
                r"(?:^|[;&|]\s*)(?:curl|wget|iwr|Invoke-WebRequest)\b",
                command,
                re.IGNORECASE,
            ):
                categories.add("network")

    if normalized_tool in {"read", "grep", "glob", "list"}:
        categories.add("filesystem_read")
    if normalized_tool in {"edit", "write", "patch"}:
        categories.add("filesystem_write")
    if normalized_tool in {"webfetch", "websearch"}:
        categories.add("network")
    if normalized_tool.startswith("mcp_") or normalized_tool.startswith("mcp-"):
        categories.add("mcp")

    path = _first_string(
        tool_input,
        "path",
        "filePath",
        "filepath",
        "file_path",
        "cwd",
        "workingDirectory",
        "working_directory",
    )
    if path and workspace_root and not _path_is_within_workspace(path, workspace_root):
        categories.add("external_path")

    return frozenset(categories)


def fingerprint_agent_path(path: str, *, workspace_root: str | None = None) -> str:
    """Return a stable hash for a path without retaining the raw path in evidence.

    Paths inside the configured workspace are normalized to workspace-relative POSIX
    form. This lets a Judge match `ATTACK_MARKER.txt` whether a tool emitted a relative
    path or an absolute path rooted in the disposable workspace.
    """

    normalized = _normalize_resource_path(path, workspace_root)
    return canonical_json_hash({"kind": "path", "value": normalized})


def fingerprint_agent_resources(
    tool: str,
    tool_input: dict[str, Any],
    *,
    workspace_root: str | None = None,
) -> frozenset[str]:
    """Extract privacy-preserving resource identities from a tool request.

    This is intentionally narrower than shell parsing. It recognizes explicit file
    fields and common shell redirection/file-command targets. Unknown syntax remains
    unclassified rather than inventing attribution.
    """

    paths: set[str] = set()
    for key in (
        "path",
        "filePath",
        "filepath",
        "file_path",
        "cwd",
        "workingDirectory",
        "working_directory",
    ):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            paths.add(value)

    normalized_tool = tool.casefold()
    if normalized_tool in {"bash", "shell"}:
        command = _first_string(tool_input, "command", "cmd", "script")
        if command:
            paths.update(_shell_path_candidates(command))

    return frozenset(
        fingerprint_agent_path(path, workspace_root=workspace_root)
        for path in paths
        if path.strip()
    )


def _shell_path_candidates(command: str) -> set[str]:
    candidates: set[str] = set()
    patterns = (
        r">{1,2}\s*[\"']?([^\"'\s;&|]+)",
        r"\b(?:touch|New-Item)\s+(?:-Path\s+)?[\"']?([^\"'\s;&|]+)",
        r"\b(?:Set-Content|Out-File)\s+(?:-Path\s+|-FilePath\s+)?[\"']?([^\"'\s;&|]+)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, command, re.IGNORECASE):
            value = match.group(1).strip()
            if value:
                candidates.add(value)
    return candidates


def _normalize_resource_path(candidate: str, workspace_root: str | None) -> str:
    windows = bool(re.match(r"^[A-Za-z]:[\\/]", candidate)) or bool(
        workspace_root and re.match(r"^[A-Za-z]:[\\/]", workspace_root)
    )
    path_cls = PureWindowsPath if windows else PurePosixPath
    path = path_cls(candidate)

    if workspace_root:
        root = path_cls(workspace_root)
        if path.is_absolute() and root.is_absolute():
            try:
                path = path.relative_to(root)
            except ValueError:
                pass

    normalized = path.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.casefold() if windows else normalized


def _first_string(mapping: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _path_is_within_workspace(candidate: str, workspace_root: str) -> bool:
    """Compare POSIX or Windows paths without depending on the host OS running tests."""

    try:
        windows = bool(re.match(r"^[A-Za-z]:[\\/]", candidate)) or bool(
            re.match(r"^[A-Za-z]:[\\/]", workspace_root)
        )
        path_cls = PureWindowsPath if windows else PurePosixPath
        candidate_path = path_cls(candidate)
        root_path = path_cls(workspace_root)

        if not candidate_path.is_absolute():
            return True
        if not root_path.is_absolute():
            return False
        return candidate_path == root_path or candidate_path.is_relative_to(root_path)
    except (TypeError, ValueError):
        return False
