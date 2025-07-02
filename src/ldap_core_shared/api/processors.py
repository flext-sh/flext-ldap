"""Generic processor framework for LDAP migration projects.

This module provides base processor classes that can be extended by specific
migration projects while maintaining consistent patterns and performance monitoring.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from pathlib import Path


class BaseProcessor(ABC):
    """Abstract base class for all migration processors.

    Provides common functionality and interface for specialized processors
    in any LDAP migration project.
    """

    def __init__(self, config: Any) -> None:
        """Initialize processor with configuration."""
        self.config = config
        self._performance_metrics: dict[str, Any] = {}

    @abstractmethod
    def process(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Process data according to processor's responsibility.

        Returns:
            Processing results dictionary

        """

    def _log_performance(self, operation: str, duration: float, count: int = 0) -> None:
        """Log performance metrics for operations."""
        self._performance_metrics[operation] = {
            "duration": duration,
            "count": count,
            "rate": count / duration if duration > 0 else 0,
        }
        logger.debug(
            (
                f"⚡ {operation}: {duration:.2f}s, {count} items, {count / duration:.1f}/s"
                if duration > 0
                else f"⚡ {operation}: {duration:.2f}s"
            ),
        )

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get accumulated performance metrics."""
        return self._performance_metrics.copy()

    def _validate_file_exists(self, file_path: Path) -> None:
        """Validate that a file exists and is readable."""
        if not file_path.exists():
            msg = f"File not found: {file_path}"
            logger.error(msg)
            raise FileNotFoundError(msg)
        if not file_path.is_file():
            msg = f"Path is not a file: {file_path}"
            logger.error(msg)
            raise ValueError(msg)

    def _create_output_directory(self, output_path: Path) -> None:
        """Create output directory if it doesn't exist."""
        output_path.parent.mkdir(parents=True, exist_ok=True)


class LDIFProcessorBase(BaseProcessor):
    """Base class for LDIF processing operations."""

    def __init__(self, config: Any) -> None:
        """Initialize LDIF processor."""
        super().__init__(config)
        self.entries_processed: int = 0
        self.errors_encountered: int = 0

    def _track_processing_stats(self, entry_count: int, error_count: int = 0) -> None:
        """Track processing statistics."""
        self.entries_processed += entry_count
        self.errors_encountered += error_count

    def get_processing_stats(self) -> dict[str, int | float]:
        """Get processing statistics."""
        return {
            "entries_processed": self.entries_processed,
            "errors_encountered": self.errors_encountered,
            "success_rate": (
                (self.entries_processed - self.errors_encountered)
                / self.entries_processed
                if self.entries_processed > 0
                else 0
            ),
        }


class HierarchyProcessorBase(BaseProcessor):
    """Base class for hierarchy processing operations."""

    def __init__(self, config: Any) -> None:
        """Initialize hierarchy processor."""
        super().__init__(config)
        self.hierarchy_mappings: dict[str, str] = {}
        self.dependency_tree: dict[str, list[str]] = {}

    def _build_dependency_tree(self, entries: list[dict[str, Any]]) -> None:
        """Build dependency tree for hierarchy validation."""
        for entry in entries:
            dn = entry.get("dn", "")
            # This is a base implementation - specific processors should override
            # with their own hierarchy logic
            self.hierarchy_mappings[dn] = dn

    def get_hierarchy_info(self) -> dict[str, Any]:
        """Get hierarchy processing information."""
        return {
            "total_entries": len(self.hierarchy_mappings),
            "dependency_nodes": len(self.dependency_tree),
            "hierarchy_mappings": self.hierarchy_mappings,
            "dependency_tree": self.dependency_tree,
        }


class ACLProcessorBase(BaseProcessor):
    """Base class for ACL processing operations."""

    def __init__(self, config: Any) -> None:
        """Initialize ACL processor."""
        super().__init__(config)
        self.acl_conversions: dict[str, str] = {}
        self.acl_patterns: dict[str, Any] = {}

    def _convert_acl_values(self, values: list[str] | str) -> list[str]:
        """Convert ACL values using processor-specific patterns."""
        if isinstance(values, str):
            values = [values]

        converted_values = []
        for value in values:
            # Base implementation - specific processors should override
            converted = self._convert_single_acl(value)
            converted_values.append(converted)

            if converted != value:
                self.acl_conversions[value] = converted

        return converted_values

    def _convert_single_acl(self, acl_value: str) -> str:
        """Convert a single ACL value."""
        # Base implementation - should be overridden by specific processors
        return acl_value

    def get_acl_conversion_stats(self) -> dict[str, Any]:
        """Get ACL conversion statistics."""
        return {
            "total_conversions": len(self.acl_conversions),
            "conversion_patterns": self.acl_conversions,
            "supported_acl_types": list(self.acl_patterns.keys()),
        }


class SchemaProcessorBase(BaseProcessor):
    """Base class for schema processing operations."""

    def __init__(self, config: Any) -> None:
        """Initialize schema processor."""
        super().__init__(config)
        self.discovered_schema: dict[str, Any] = {}
        self.schema_mappings: dict[str, str] = {}

    def _discover_schema_from_entries(self, entries: list[dict[str, Any]]) -> None:
        """Discover schema information from LDAP entries."""
        object_classes = set()
        attributes = set()

        for entry in entries:
            # Collect objectClass values
            if "objectClass" in entry:
                oc_values = entry["objectClass"]
                if isinstance(oc_values, str):
                    oc_values = [oc_values]
                object_classes.update(oc_values)

            # Collect all attributes
            for attr_name in entry:
                if attr_name != "dn":
                    attributes.add(attr_name)

        self.discovered_schema = {
            "object_classes": sorted(object_classes),
            "attributes": sorted(attributes),
            "total_object_classes": len(object_classes),
            "total_attributes": len(attributes),
        }

    def get_schema_info(self) -> dict[str, Any]:
        """Get schema processing information."""
        return {
            "discovery_summary": self.discovered_schema,
            "transformation_mappings": self.schema_mappings,
            "performance_metrics": self.get_performance_metrics(),
        }


def create_processor_performance_monitor() -> dict[str, Any]:
    """Create a performance monitoring context for processors."""
    return {
        "start_time": time.time(),
        "operations": [],
        "total_entries": 0,
        "total_errors": 0,
    }


def finalize_processor_performance(monitor: dict[str, Any]) -> dict[str, Any]:
    """Finalize performance monitoring and return metrics."""
    end_time = time.time()
    duration = end_time - monitor["start_time"]

    return {
        "total_duration": duration,
        "total_entries": monitor["total_entries"],
        "total_errors": monitor["total_errors"],
        "average_rate": monitor["total_entries"] / duration if duration > 0 else 0,
        "success_rate": (
            (monitor["total_entries"] - monitor["total_errors"])
            / monitor["total_entries"]
            if monitor["total_entries"] > 0
            else 0
        ),
        "operations": monitor["operations"],
    }
