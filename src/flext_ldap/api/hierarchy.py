"""Hierarchy processing API for LDAP directory services.

This module provides the foundational classes for hierarchy processing
and DN (Distinguished Name) operations.
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from pathlib import Path

    from flext_ldap.core.config import ApplicationConfig

logger = structlog.get_logger()


def normalize_dn(dn: str) -> str:
    """Normalize a DN by removing extra whitespace and standardizing format.

    Args:
        dn: Distinguished Name to normalize

    Returns:
        Normalized DN string

    """
    if not dn:
        return ""

    # Remove extra whitespace around commas and equals signs
    normalized = re.sub(r"\s*,\s*", ",", dn.strip())
    return re.sub(r"\s*=\s*", "=", normalized)


def parse_dn(dn: str) -> list[tuple[str, str]]:
    """Parse a DN into its component parts.

    Args:
        dn: Distinguished Name to parse

    Returns:
        List of (attribute, value) tuples

    """
    if not dn:
        return []

    normalized = normalize_dn(dn)
    components = []

    # Simple regex-based parsing (can be enhanced for edge cases)
    for component in normalized.split(","):
        if "=" in component:
            attr, value = component.split("=", 1)
            components.append((attr.strip(), value.strip()))

    return components


def get_parent_dn(dn: str) -> str:
    """Get the parent DN of a given DN.

    Args:
        dn: Distinguished Name

    Returns:
        Parent DN string, or empty string if no parent

    """
    if not dn:
        return ""

    normalized = normalize_dn(dn)

    # Find the first comma that's not within quotes
    comma_index = normalized.find(",")
    if comma_index == -1:
        return ""  # No parent (root DN)

    return normalized[comma_index + 1 :].strip()


def get_dn_depth(dn: str) -> int:
    """Get the depth (number of components) of a DN.

    Args:
        dn: Distinguished Name

    Returns:
        Number of DN components

    """
    components = parse_dn(dn)
    return len(components)


class HierarchyProcessorBase(ABC):
    """Base class for hierarchy processing implementations.

    This abstract base class provides the foundation for implementing
    hierarchy processing and DN sorting logic for LDAP directory entries.
    """

    def __init__(self, config: ApplicationConfig) -> None:
        """Initialize hierarchy processor with configuration.

        Args:
            config: Application configuration containing hierarchy processing settings

        """
        self.config = config
        self.performance_metrics: dict[str, Any] = {}

    @abstractmethod
    def process(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Process entries and sort by hierarchy.

        Args:
            entries: List of LDAP entries to sort

        Returns:
            Dict containing sorted entries and processing statistics

        """

    def sort_by_hierarchy(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sort entries by DN hierarchy (parents before children).

        Args:
            entries: List of LDAP entries to sort

        Returns:
            List of entries sorted by hierarchy

        """

        def get_entry_dn(entry: dict[str, Any]) -> str:
            """Extract DN from entry."""
            return entry.get("dn", "") or entry.get("distinguishedName", "")

        def dn_sort_key(entry: dict[str, Any]) -> tuple[int, str]:
            """Generate sort key for DN hierarchy."""
            dn = get_entry_dn(entry)
            depth = get_dn_depth(dn)
            return (depth, dn.lower())

        # Log hierarchy analysis
        dn_depths = {}
        for entry in entries:
            dn = get_entry_dn(entry)
            if dn:
                depth = get_dn_depth(dn)
                if depth not in dn_depths:
                    dn_depths[depth] = 0
                dn_depths[depth] += 1

        logger.info(
            "🔄 Hierarchy analysis complete",
            total_entries=len(entries),
            depth_distribution=dn_depths,
            max_depth=max(dn_depths.keys()) if dn_depths else 0,
        )

        return sorted(entries, key=dn_sort_key)

    def validate_hierarchy_dependencies(
        self, entries: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Validate that parent entries exist for all child entries.

        Args:
            entries: List of LDAP entries

        Returns:
            Dict containing validation results

        """
        all_dns = set()
        missing_parents = []

        # Collect all DNs
        for entry in entries:
            dn = entry.get("dn", "") or entry.get("distinguishedName", "")
            if dn:
                all_dns.add(normalize_dn(dn))

        # Check for missing parents
        for entry in entries:
            dn = entry.get("dn", "") or entry.get("distinguishedName", "")
            if dn:
                parent_dn = get_parent_dn(dn)
                if parent_dn and normalize_dn(parent_dn) not in all_dns:
                    missing_parents.append(
                        {"child_dn": dn, "missing_parent": parent_dn}
                    )

        return {
            "total_entries": len(entries),
            "valid_dns": len(all_dns),
            "missing_parents": missing_parents,
            "hierarchy_complete": len(missing_parents) == 0,
        }

    def _log_performance(self, operation: str, duration: float, count: int) -> None:
        """Log performance metrics for hierarchy operations.

        Args:
            operation: Name of the hierarchy operation
            duration: Time taken in seconds
            count: Number of items processed

        """
        self.performance_metrics[operation] = {
            "duration": duration,
            "count": count,
            "rate": count / duration if duration > 0 else 0,
            "timestamp": time.time(),
        }

        logger.info(
            f"🔄 Hierarchy {operation} completed",
            duration=f"{duration:.2f}s",
            count=count,
            rate=f"{count / duration:.1f}/s" if duration > 0 else "instant",
        )

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get performance metrics for hierarchy operations.

        Returns:
            Dict containing performance statistics

        """
        return self.performance_metrics.copy()

    def _create_output_directory(self, output_path: Path) -> None:
        """Create output directory if it doesn't exist.

        Args:
            output_path: Path where output files will be created

        """
        output_path.parent.mkdir(parents=True, exist_ok=True)


class DefaultHierarchyProcessor(HierarchyProcessorBase):
    """Default implementation of hierarchy processor.

    Provides basic hierarchy processing capabilities that can be extended
    by specific implementations.
    """

    def process(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Process entries with default hierarchy sorting.

        Args:
            entries: List of LDAP entries

        Returns:
            Dict with sorted entries and processing statistics

        """
        start_time = time.time()

        logger.info(f"🔄 Processing {len(entries)} entries for hierarchy sorting")

        # Sort entries by hierarchy
        sorted_entries = self.sort_by_hierarchy(entries)

        duration = time.time() - start_time
        self._log_performance("default_hierarchy_processing", duration, len(entries))

        return {
            "entries": sorted_entries,
            "total_entries": len(entries),
            "hierarchy_sorts": 1,
            "processing_time": duration,
            "processor_type": "default_hierarchy",
        }
