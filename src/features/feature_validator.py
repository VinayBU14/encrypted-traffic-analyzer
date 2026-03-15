
"""Feature schema validation utilities for strict train/inference consistency checks."""

from __future__ import annotations

import math
from typing import Any

from src.features.schema import ALL_FEATURE_COLUMNS, SCHEMA_VERSION


class FeatureValidator:
    """Validate feature rows, schema versions, and feature matrices with hard failures."""

    def validate_feature_row(self, row: dict[str, Any]) -> None:
        """Validate one feature row against required columns and numeric constraints."""
        for column in ALL_FEATURE_COLUMNS:
            if column not in row:
                raise ValueError(f"Feature validation failed: missing column '{column}'")

            value = row[column]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(
                    f"Feature validation failed: non-numeric value in '{column}'"
                )

            numeric = float(value)
            if math.isnan(numeric):
                raise ValueError(f"Feature validation failed: NaN value in '{column}'")
            if math.isinf(numeric):
                raise ValueError(f"Feature validation failed: infinite value in '{column}'")

    def validate_schema_version(self, version: str) -> None:
        """Validate schema version equality against the canonical schema version."""
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"Schema version mismatch: expected {SCHEMA_VERSION}, got {version}"
            )

    def validate_feature_matrix(self, rows: list[dict[str, Any]]) -> None:
        """Validate every row in a matrix and raise aggregated errors if any rows fail."""
        errors: list[str] = []
        for index, row in enumerate(rows):
            try:
                self.validate_feature_row(row)
            except (ValueError, TypeError) as exc:
                errors.append(f"row[{index}]: {exc}")

        if errors:
            raise ValueError("Feature matrix validation failed:\n" + "\n".join(errors))


def validate_row(row: dict[str, Any]) -> None:
    """Convenience row validator using a new FeatureValidator instance."""
    FeatureValidator().validate_feature_row(row)


def validate_schema(version: str) -> None:
    """Convenience schema-version validator using a new FeatureValidator instance."""
    FeatureValidator().validate_schema_version(version)
