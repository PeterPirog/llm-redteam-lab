"""Fail-closed admission for local-only model execution.

OpenWebUI may expose Ollama cloud proxies with ``connection_type=local`` because the
client connection is local even though inference is remote. Cost/security policy must
therefore use provider metadata, not UI connection labels: a model is admitted as local
only when both ``remote_model`` and ``remote_host`` are absent.

A local artifact identity is not enough by itself. The configured inference endpoint must
also be local (loopback by default), otherwise a locally named model could still route
traffic to a remote service. The parser intentionally retains only measurement-safe model
metadata; user IDs, access grants and other OpenWebUI control-plane fields are ignored.
"""

from __future__ import annotations

import json
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_roles import ModelLocation, ModelRoleConfig, ModelsConfig

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
    def model_ids_are_unique(self) -> OpenWebUIOllamaInventory:
        ids = [record.model_id for record in self.records]
        if len(ids) != len(set(ids)):
            raise ValueError("Ollama inventory model IDs must be unique")
        return self

    @classmethod
    def from_openwebui_response(cls, payload: object) -> OpenWebUIOllamaInventory:
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

            remote_model = _optional_remote_string(
                ollama.get("remote_model"),
                field_name="remote_model",
                model_id=model_id,
            )
            remote_host = _optional_remote_string(
                ollama.get("remote_host"),
                field_name="remote_host",
                model_id=model_id,
            )
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
                    remote_model=remote_model,
                    remote_host=remote_host,
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


class LocalModelAdmissionBinding(StrictModel):
    """Hash-safe binding of one execution role to a local artifact and endpoint."""

    label: str = Field(min_length=1)
    model_id: str = Field(min_length=1)
    inventory_record_sha256: str = Field(pattern=_HASH_PATTERN)
    endpoint_sha256: str = Field(pattern=_HASH_PATTERN)


class LocalOnlyAdmissionReport(StrictModel):
    """Proof that selected execution roles bind local artifacts to local endpoints."""

    inventory_sha256: str = Field(pattern=_HASH_PATTERN)
    bindings: tuple[LocalModelAdmissionBinding, ...]
    blue_model_id: str | None = None

    @property
    def admitted_model_ids(self) -> tuple[str, ...]:
        return tuple(sorted({binding.model_id for binding in self.bindings}))

    @property
    def admitted_record_sha256s(self) -> tuple[str, ...]:
        return tuple(
            sorted({binding.inventory_record_sha256 for binding in self.bindings})
        )

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def validate_local_only_model_selection(
    *,
    models: ModelsConfig,
    inventory: OpenWebUIOllamaInventory,
    blue_model_id: str | None = None,
    blue_endpoint: str | None = None,
    blue_required_capabilities: set[str] | frozenset[str] = frozenset({"text"}),
    allowed_endpoint_hosts: set[str] | frozenset[str] = frozenset(),
) -> LocalOnlyAdmissionReport:
    """Fail closed unless every enabled role and optional Blue route is truly local."""

    if not models.policy.local_first:
        raise ValueError("local-only admission requires models.policy.local_first=true")
    if models.policy.allow_cloud_fallback:
        raise ValueError("local-only admission forbids cloud fallback")

    normalized_allowed_hosts = frozenset(
        host.strip().casefold() for host in allowed_endpoint_hosts
    )
    bindings: list[LocalModelAdmissionBinding] = []

    def admit(config: ModelRoleConfig, *, label: str) -> None:
        if not config.enabled:
            return
        if config.location != ModelLocation.LOCAL:
            raise ValueError(f"model role is not declared local: {label}")
        if config.endpoint is None:
            raise ValueError(f"local-only model role requires explicit endpoint: {label}")
        endpoint_sha256 = require_local_model_endpoint(
            config.endpoint,
            label=label,
            allowed_hosts=normalized_allowed_hosts,
        )
        record = inventory.require_local(
            config.model,
            required_capabilities=set(config.capabilities),
        )
        bindings.append(
            LocalModelAdmissionBinding(
                label=label,
                model_id=record.model_id,
                inventory_record_sha256=record.record_sha256,
                endpoint_sha256=endpoint_sha256,
            )
        )

    for role, config in models.roles.items():
        admit(config, label=role.value)
    for variant in models.red_attacker_pool.enabled_variants:
        admit(variant.planner, label=f"{variant.id}:red_planner")
        admit(variant.mutator, label=f"{variant.id}:red_mutator")

    if blue_model_id is not None:
        if blue_endpoint is None:
            raise ValueError("local-only Blue model requires explicit endpoint")
        endpoint_sha256 = require_local_model_endpoint(
            blue_endpoint,
            label="blue",
            allowed_hosts=normalized_allowed_hosts,
        )
        record = inventory.require_local(
            blue_model_id,
            required_capabilities=blue_required_capabilities,
        )
        bindings.append(
            LocalModelAdmissionBinding(
                label="blue",
                model_id=record.model_id,
                inventory_record_sha256=record.record_sha256,
                endpoint_sha256=endpoint_sha256,
            )
        )

    ordered = tuple(sorted(bindings, key=lambda item: (item.label, item.model_id)))
    return LocalOnlyAdmissionReport(
        inventory_sha256=inventory.inventory_sha256,
        bindings=ordered,
        blue_model_id=blue_model_id,
    )


def require_local_model_endpoint(
    endpoint: str,
    *,
    label: str,
    allowed_hosts: set[str] | frozenset[str] = frozenset(),
) -> str:
    """Validate one inference endpoint and return its stable SHA-256 fingerprint."""

    normalized = endpoint.strip()
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError(f"local-only model endpoint is not HTTP(S): {label}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"local-only model endpoint cannot contain credentials: {label}")
    if parsed.query or parsed.fragment:
        raise ValueError(f"local-only model endpoint cannot contain query or fragment: {label}")
    host = parsed.hostname.strip().casefold()
    allowed = {value.strip().casefold() for value in allowed_hosts}
    if host != "localhost" and host not in allowed:
        try:
            address = ip_address(host)
        except ValueError as exc:
            raise ValueError(
                f"model endpoint host is not loopback or explicitly allowed: {label}"
            ) from exc
        if not address.is_loopback:
            raise ValueError(
                f"model endpoint host is not loopback or explicitly allowed: {label}"
            )
    return sha256(normalized.encode()).hexdigest()


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


def _optional_remote_string(
    value: object,
    *,
    field_name: str,
    model_id: str,
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Ollama model {model_id} has invalid {field_name}")
    normalized = value.strip()
    return normalized or None
