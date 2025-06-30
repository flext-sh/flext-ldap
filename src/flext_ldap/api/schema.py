"""Schema processing API for LDAP directory services.

This module provides the foundational classes for schema processing,
validation, and transformation between different LDAP server formats.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from pathlib import Path

    from flext_ldap.core.config import ApplicationConfig

logger = structlog.get_logger()


class SchemaProcessorBase(ABC):
    """Base class for schema processing implementations.

    This abstract base class provides the foundation for implementing
    schema validation, transformation, and conversion logic for different
    LDAP directory servers.
    """

    def __init__(self, config: ApplicationConfig) -> None:
        """Initialize schema processor with configuration.

        Args:
            config: Application configuration containing schema processing settings
        """
        self.config = config
        self.performance_metrics: dict[str, Any] = {}
        self.schema_mappings: dict[str, Any] = {}

    @abstractmethod
    def process(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Process entries with schema validation and transformation.

        Args:
            entries: List of LDAP entries containing schema attributes

        Returns:
            Dict containing processed entries and schema statistics
        """

    def validate_schema(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Validate schema compliance of an entry.

        Args:
            entry: LDAP entry to validate

        Returns:
            Dict containing validation results and any schema issues
        """
        validation_result = {
            "entry_dn": entry.get("dn", ""),
            "is_valid": True,
            "issues": [],
            "warnings": []
        }

        # Basic validation - check for required attributes
        object_classes = entry.get("objectClass", [])
        if not object_classes:
            validation_result["is_valid"] = False
            validation_result["issues"].append("Missing objectClass attribute")

        return validation_result

    def transform_schema_attributes(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Transform schema attributes for compatibility.

        Args:
            entry: LDAP entry with schema attributes

        Returns:
            Entry with transformed schema attributes
        """
        # Default implementation: return entry unchanged
        return entry.copy()

    def _log_performance(self, operation: str, duration: float, count: int) -> None:
        """Log performance metrics for schema operations.

        Args:
            operation: Name of the schema operation
            duration: Time taken in seconds
            count: Number of items processed
        """
        self.performance_metrics[operation] = {
            "duration": duration,
            "count": count,
            "rate": count / duration if duration > 0 else 0,
            "timestamp": time.time()
        }

        logger.info(
            f"📋 Schema {operation} completed",
            duration=f"{duration:.2f}s",
            count=count,
            rate=f"{count / duration:.1f}/s" if duration > 0 else "instant"
        )

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get performance metrics for schema operations.

        Returns:
            Dict containing performance statistics
        """
        return self.performance_metrics.copy()

    def get_schema_mappings(self) -> dict[str, Any]:
        """Get schema transformation mappings.

        Returns:
            Dict containing schema mapping rules
        """
        return self.schema_mappings.copy()

    def _create_output_directory(self, output_path: Path) -> None:
        """Create output directory if it doesn't exist.

        Args:
            output_path: Path where output files will be created
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)


class DefaultSchemaProcessor(SchemaProcessorBase):
    """Default implementation of schema processor.

    Provides basic schema processing capabilities that can be extended
    by specific implementations.
    """

    def process(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Process entries with default schema handling.

        Args:
            entries: List of LDAP entries

        Returns:
            Dict with processed entries and schema validation results
        """
        start_time = time.time()

        logger.info(f"📋 Processing {len(entries)} entries for schema validation")

        processed_entries = []
        validation_results = []
        schema_transformations = 0

        for entry in entries:
            # Validate schema
            validation_result = self.validate_schema(entry)
            validation_results.append(validation_result)

            # Transform schema attributes
            transformed_entry = self.transform_schema_attributes(entry)
            processed_entries.append(transformed_entry)

            # Count transformations
            if transformed_entry != entry:
                schema_transformations += 1

        duration = time.time() - start_time
        self._log_performance("default_schema_processing", duration, len(entries))

        # Calculate validation statistics
        valid_entries = sum(1 for r in validation_results if r["is_valid"])
        total_issues = sum(len(r["issues"]) for r in validation_results)

        return {
            "entries": processed_entries,
            "total_entries": len(entries),
            "valid_entries": valid_entries,
            "invalid_entries": len(entries) - valid_entries,
            "total_issues": total_issues,
            "schema_transformations": schema_transformations,
            "validation_results": validation_results,
            "processing_time": duration,
            "processor_type": "default_schema"
        }
