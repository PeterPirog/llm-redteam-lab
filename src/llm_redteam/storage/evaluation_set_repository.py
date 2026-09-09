"""Persistence helpers for immutable held-out evaluation manifests."""

from __future__ import annotations

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from ..evaluation_sets import HeldOutEvaluationManifest
from .evaluation_set_models import EvaluationSetManifestRow


def save_evaluation_set_manifest(
    engine: Engine,
    manifest: HeldOutEvaluationManifest,
) -> str:
    """Persist one manifest immutably and return its content-addressed hash."""

    with Session(engine) as session, session.begin():
        existing_by_hash = session.get(EvaluationSetManifestRow, manifest.content_hash)
        if existing_by_hash is not None:
            restored = _manifest_from_row(existing_by_hash)
            if restored == manifest:
                return manifest.content_hash
            raise ValueError("evaluation manifest hash collision or corrupted stored manifest")

        existing_by_id = session.scalar(
            select(EvaluationSetManifestRow).where(
                EvaluationSetManifestRow.manifest_id == manifest.manifest_id
            )
        )
        if existing_by_id is not None:
            raise ValueError("evaluation manifest_id is immutable once persisted")

        session.add(
            EvaluationSetManifestRow(
                manifest_hash=manifest.content_hash,
                manifest_id=manifest.manifest_id,
                schema_version=manifest.schema_version,
                exposure=manifest.exposure.value,
                split_strategy=manifest.split_strategy,
                corpus_snapshot_hash=manifest.corpus_snapshot_hash,
                red_can_access_evaluation_content=manifest.red_can_access_evaluation_content,
                sequestered_source_id=manifest.sequestered_source_id,
                discovery_cases=[
                    item.model_dump(mode="json") for item in manifest.discovery_cases
                ],
                evaluation_cases=[
                    item.model_dump(mode="json") for item in manifest.evaluation_cases
                ],
                discovery_case_set_hash=manifest.discovery_case_set_hash,
                evaluation_case_set_hash=manifest.evaluation_case_set_hash,
            )
        )
    return manifest.content_hash


def load_evaluation_set_manifest(
    engine: Engine,
    manifest_hash: str,
) -> HeldOutEvaluationManifest | None:
    """Load a manifest by hash and re-run all integrity validators."""

    with Session(engine) as session:
        row = session.get(EvaluationSetManifestRow, manifest_hash)
        if row is None:
            return None
        return _manifest_from_row(row)


def load_evaluation_set_manifest_by_id(
    engine: Engine,
    manifest_id: str,
) -> HeldOutEvaluationManifest | None:
    """Resolve an immutable human-readable manifest ID to its verified manifest."""

    with Session(engine) as session:
        row = session.scalar(
            select(EvaluationSetManifestRow).where(
                EvaluationSetManifestRow.manifest_id == manifest_id
            )
        )
        if row is None:
            return None
        return _manifest_from_row(row)


def _manifest_from_row(row: EvaluationSetManifestRow) -> HeldOutEvaluationManifest:
    return HeldOutEvaluationManifest(
        schema_version=row.schema_version,
        manifest_id=row.manifest_id,
        exposure=row.exposure,
        split_strategy=row.split_strategy,
        corpus_snapshot_hash=row.corpus_snapshot_hash,
        red_can_access_evaluation_content=row.red_can_access_evaluation_content,
        sequestered_source_id=row.sequestered_source_id,
        discovery_cases=tuple(row.discovery_cases),
        evaluation_cases=tuple(row.evaluation_cases),
        discovery_case_set_hash=row.discovery_case_set_hash,
        evaluation_case_set_hash=row.evaluation_case_set_hash,
        content_hash=row.manifest_hash,
    )
