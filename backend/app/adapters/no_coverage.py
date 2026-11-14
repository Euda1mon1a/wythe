"""No-coverage placeholder adapters for absent or unsupported repository tiers."""

from __future__ import annotations

from pathlib import Path

from app.adapters.base import ManipulatorExtractionResult, TruthExtractionResult


class NoTruthAdapter:
    """Explicit placeholder truth adapter when a stack has no supported DB schema extractor."""

    name = "no-truth"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str = "backend",
        pg_dsn: str | None = None,
    ) -> TruthExtractionResult:
        _ = (repo_root, backend_subdir, pg_dsn)
        return TruthExtractionResult(
            nodes=[],
            table_symbol_map={},
            function_symbol_map={},
            notes=[
                (
                    "Database/persistence schema coverage is absent or unsupported (no-truth adapter); "
                    "SQL table lineage was not verified."
                )
            ],
            coverage_complete=False,
        )


class NoManipulatorAdapter:
    """Explicit placeholder manipulator adapter for frontend-only or unsupported backends."""

    name = "no-manipulator"

    def extract(
        self,
        repo_root: Path,
        backend_subdir: str = "backend",
        truth: TruthExtractionResult | None = None,
    ) -> ManipulatorExtractionResult:
        _ = (repo_root, backend_subdir, truth)
        return ManipulatorExtractionResult(
            nodes=[],
            edges=[],
            routes=[],
            findings=[],
            notes=[
                (
                    "Backend manipulation/route coverage is absent or unsupported (no-manipulator adapter); "
                    "HTTP endpoint backing could not be verified."
                )
            ],
            coverage_complete=False,
        )
