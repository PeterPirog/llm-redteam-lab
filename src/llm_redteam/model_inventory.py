"""Fail-closed admission for local-only model execution.

OpenWebUI may expose Ollama cloud proxies with ``connection_type=local`` because the
client connection is local even though inference is remote. Cost/security policy must
therefore use provider metadata, not UI connection labels: a model is admitted as local
only when both ``remote_model`` and ``remote_host`` are absent.

The parser intentionally retains only measurement-safe model metadata. User IDs, access
grants and other control-plane fields from an OpenWebUI inventory response are ignored.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_roles import ModelLocation, ModelsConfig

_HASH_PATTERN = r"^[0-9a-f]{64}$"

_PROVIDER_CAPABILITY_MAP = {
    "completion": "text",
    "thinking": "reasoning",
    "vision": "vision",
    "tools": "tools",
    "embedding": "embedding",
}


class OllamaInventoryRecord(StrictModel):
    """Security/cost relevant subset of one Ollama-backed OpenWebUI model record."""

    model_id: str = Field(min_length=1, max_length=256)
    digest: str = Field(pattern=_HASH_PATTERN)
    artifact_size_bytes: int = Field(ge=0)
    family: str | None = None
    parameter_size: str | None = None
    quantization_level: str | None = None
    context_length: int | None = Field(default=None, ge=1)
    provider_capabilities: frozenset[str] = frozenset()
    remote_model: str | None = None
    remote_host: str | None = None

    @property
    def is_strictly_local(self) -> bool:
        return self.remote_model is None and self.remote_host is None

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(
            _PROVIDER_CAPABILITY_MAP[value]
            for value in self.provider_capabilities
            if value in _PROVIDER_CAPABILITY_MAP
        )

    @property
    def artifact_digest(self) -> str:
        return f"sha256:{self.digest}"

    @property
    def stable_payload(self) -> dict[str, object]:
        """Return order-stable measurement fields for hashing and provenance."""

        return {
            "model_id": self.model_id,
            "digest": self.digest,
            "artifact_size_bytes": self.artifact_size_bytes,
            "family": self.family,
            "parameter_size": self.parameter_size,
            "quantization_level": self.quantization_level,
            "context_length": self.context_length,
            "provider_capabilities": sorted(self.provider_capabilities),
            "remote_model": self.remote_model,
            "remote_host": self.remote_host,
        }

    @property
    def record_sha256(self) -> str:
        return canonical_json_hash(self.stable_payload)


class OpenWebUIOllamaInventory(StrictModel):
    """Normalized Ollama inventory with deterministic local-only admission semantics."""

    version: int = Field(ge=1, default=1)
    records: tuple[OllamaInventoryRecord, ...]

    @model_validator(mode="after")
    def model_ids_are_unique(self) -> "OpenWebUIOllamaInventory":
        ids = [record.model_id for record in self.records]
        if len(ids) != len(set(ids)):
            raise ValueError("Ollama inventory model IDs must be unique")
        return self

    @classmethod
    def from_openwebui_response(cls, payload: object) -> "OpenWebUIOllamaInventory":
        if not isinstance(payload, dict):
            raise ValueError("OpenWebUI model inventory must be a JSON object")
        data = payload.get("data")
        if not isinstance(data, list):
            raise ValueError("OpenWebUI model inventory must contain a data list")

        records: list[OllamaInventoryRecord] = []
        for item in data:
            if not isinstance(item, dict) or item.get("owned_by") != "ollama":
                continue
            ollama = item.get("ollama")
            if not isinstance(ollama, dict):
                raise ValueError("Ollama-owned inventory item lacks Ollama metadata")

            model_id = item.get("id")
            digest = ollama.get("digest")
            size = ollama.get("size")
            if not isinstance(model_id, str) or not model_id:
                raise ValueError("Ollama inventory item lacks model ID")
            if not isinstance(digest, str):
                raise ValueError(f"Ollama model {model_id} lacks digest")
            digest = digest.strip().casefold().removeprefix("sha256:")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(f"Ollama model {model_id} has invalid SHA-256 digest")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise ValueError(f"Ollama model {model_id} has invalid artifact size")

            details = ollama.get("details") or {}
            if not isinstance(details, dict):
                raise ValueError(f"Ollama model {model_id} has invalid details")
            raw_capabilities = ollama.get("capabilities") or []
            if not isinstance(raw_capabilities, list) or not all(
                isinstance(value, str) for value in raw_capabilities
            ):
                raise ValueError(f"Ollama model {model_id} has invalid capabilities")

            context_length = details.get("context_length")
            if context_length is not None and (
                not isinstance(context_length, int)
                or isinstance(context_length, bool)
                or context_length < 1
            ):
                raise ValueError(f"Ollama model {model_id} has invalid context length")

            records.append(
                OllamaInventoryRecord(
                    model_id=model_id,
                    digest=digest,
                    artifact_size_bytes=size,
                    family=_optional_nonempty_string(details.get("family")),
                    parameter_size=_optional_nonempty_string(details.get("parameter_size")),
                    quantization_level=_optional_nonempty_string(
                        details.get("quantization_level")
                    ),
                    context_length=context_length,
                    provider_capabilities=frozenset(raw_capabilities),
                    remote_model=_optional_nonempty_string(ollama.get("remote_model")),
                    remote_host=_optional_nonempty_string(ollama.get("remote_host")),
                )
            )
        if not records:
            raise ValueError("OpenWebUI inventory contains no Ollama models")
        return cls(records=tuple(sorted(records, key=lambda record: record.model_id)))

    @property
    def inventory_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "records": [record.stable_payload for record in self.records],
            }
        )

    @property
    def local_records(self) -> tuple[OllamaInventoryRecord, ...]:
        return tuple(record for record in self.records if record.is_strictly_local)

    def require_local(
        self,
        model_id: str,
        *,
        required_capabilities: set[str] | frozenset[str] = frozenset(),
    ) -> OllamaInventoryRecord:
        matches = [record for record in self.records if record.model_id == model_id]
        if len(matches) != 1:
            raise ValueError(f"model inventory must resolve exactly one model: {model_id}")
        record = matches[0]
        if not record.is_strictly_local:
            raise ValueError(
                f"model is a remote Ollama proxy and is blocked by local-only policy: {model_id}"
            )
        missing = set(required_capabilities).difference(record.capabilities)
        if missing:
            raise ValueError(
                f"local model {model_id} lacks capabilities: {', '.join(sorted(missing))}"
            )
        return record


class LocalOnlyAdmissionReport(StrictModel):
    """Hash-safe proof that all selected Red/Blue role models are local artifacts."""

    inventory_sha256: str = Field(pattern=_HASH_PATTERN)
    admitted_model_ids: tuple[str, ...]
    admitted_record_sha256s: tuple[str, ...]
    blue_model_id: str | None = None

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def validate_local_only_model_selection(
    *,
    models: ModelsConfig,
    inventory: OpenWebUIOllamaInventory,
    blue_model_id: str | None = None,
    blue_required_capabilities: set[str] | frozenset[str] = frozenset({"text"}),
) -> LocalOnlyAdmissionReport:
    """Fail closed unless every enabled role and optional Blue model is truly local."""

    if not models.policy.local_first:
        raise ValueError("local-only admission requires models.policy.local_first=true")
    if models.policy.allow_cloud_fallback:
        raise ValueError("local-only admission forbids cloud fallback")

    admitted: dict[str, OllamaInventoryRecord] = {}

    def admit(config, *, label: str) -> None:
        if not config.enabled:
            return
        if config.location != ModelLocation.LOCAL:
            raise ValueError(f"model role is not declared local: {label}")
        admitted[config.model] = inventory.require_local(
            config.model,
            required_capabilities=set(config.capabilities),
        )

    for role, config in models.roles.items():
        admit(config, label=role.value)
    for variant in models.red_attacker_pool.enabled_variants:
        admit(variant.planner, label=f"{variant.id}:red_planner")
        admit(variant.mutator, label=f"{variant.id}:red_mutator")

    if blue_model_id is not None:
        admitted[blue_model_id] = inventory.require_local(
            blue_model_id,
            required_capabilities=blue_required_capabilities,
        )

    ordered = tuple(sorted(admitted.values(), key=lambda record: record.model_id))
    return LocalOnlyAdmissionReport(
        inventory_sha256=inventory.inventory_sha256,
        admitted_model_ids=tuple(record.model_id for record in ordered),
        admitted_record_sha256s=tuple(record.record_sha256 for record in ordered),
        blue_model_id=blue_model_id,
    )


def load_openwebui_ollama_inventory(path: str | Path) -> OpenWebUIOllamaInventory:
    """Load a saved OpenWebUI `/api/models` response, allowing Markdown code fences."""

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"model inventory does not exist: {source}")
    text = source.read_text(encoding="utf-8").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) < 3 or not lines[-1].strip().startswith("```"):
            raise ValueError("fenced model inventory is incomplete")
        text = "\n".join(lines[1:-1]).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"model inventory is not valid JSON: {source}") from exc
    return OpenWebUIOllamaInventory.from_openwebui_response(payload)


def _optional_nonempty_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
