"""ACL processing API for LDAP directory services.

This module provides the foundational classes for ACL (Access Control List) processing
and conversion between different LDAP server formats.
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


class ACLProcessorBase(ABC):
    """Base class for ACL processing implementations.

    This abstract base class provides the foundation for implementing
    ACL conversion and processing logic for different LDAP directory servers.
    """

    def __init__(self, config: ApplicationConfig) -> None:
        """Initialize ACL processor with configuration.

        Args:
            config: Application configuration containing ACL processing settings

        """
        self.config = config
        self.performance_metrics: dict[str, Any] = {}
        self.acl_conversions: dict[str, str] = {}
        self.supported_acl_types = [
            "aci",
            "aclEntry",
            "entryLevelRights",
            "attributeLevelRights",
        ]

    @abstractmethod
    def process(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Process entries and convert ACLs.

        Args:
            entries: List of LDAP entries containing ACL attributes

        Returns:
            Dict containing processed entries and conversion statistics

        """

    def _log_performance(self, operation: str, duration: float, count: int) -> None:
        """Log performance metrics for ACL operations.

        Args:
            operation: Name of the ACL operation
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
            "🔐 ACL %s completed",
            operation,
            extra={
                "duration": f"{duration:.2f}s",
                "count": count,
                "rate": f"{count / duration:.1f}/s" if duration > 0 else "instant",
            }
        )

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get performance metrics for ACL operations.

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

    def has_acl_attributes(self, entry: dict[str, Any]) -> bool:
        """Check if entry contains ACL attributes that need processing.

        Args:
            entry: LDAP entry to check

        Returns:
            True if entry has ACL attributes, False otherwise

        """
        return any(attr in entry for attr in self.supported_acl_types)

    def extract_acl_attributes(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Extract ACL-related attributes from an entry.

        Args:
            entry: LDAP entry

        Returns:
            Dict containing only ACL attributes

        """
        acl_attrs = {}
        for attr in self.supported_acl_types:
            if attr in entry:
                acl_attrs[attr] = entry[attr]
        return acl_attrs

    def validate_acl_format(self, acl_value: str, acl_type: str) -> bool:
        """Validate ACL format based on type.

        Args:
            acl_value: ACL value to validate
            acl_type: Type of ACL (aci, aclEntry, etc.)

        Returns:
            True if format is valid, False otherwise

        """
        if not acl_value or not isinstance(acl_value, str):
            return False

        if acl_type == "aci":
            # Basic ACI format validation
            return "(" in acl_value and ")" in acl_value and "acl" in acl_value.lower()
        if acl_type == "aclEntry":
            # Basic aclEntry format validation
            return "#" in acl_value and len(acl_value.split("#")) >= 3
        # Generic validation - non-empty string
        return len(acl_value.strip()) > 0


class DefaultACLProcessor(ACLProcessorBase):
    """Default implementation of ACL processor.

    Provides basic ACL processing capabilities that can be extended
    by specific implementations.
    """

    def process(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Process entries with default ACL handling and validation.

        Args:
            entries: List of LDAP entries

        Returns:
            Dict with processed entries and ACL validation results

        """
        start_time = time.time()

        logger.info("🔐 Processing %d entries for ACL validation", len(entries))

        processed_entries = []
        acl_entries_found = 0
        validation_issues = []

        for i, entry in enumerate(entries):
            processed_entry = entry.copy()

            if self.has_acl_attributes(entry):
                acl_entries_found += 1

                # Validate each ACL attribute
                acl_attrs = self.extract_acl_attributes(entry)
                for attr_name, attr_values in acl_attrs.items():
                    if isinstance(attr_values, str):
                        attr_values = [attr_values]

                    for value in attr_values:
                        if not self.validate_acl_format(value, attr_name):
                            validation_issues.append(
                                {
                                    "entry_index": i,
                                    "entry_dn": entry.get("dn", f"entry_{i}"),
                                    "attribute": attr_name,
                                    "issue": "Invalid ACL format",
                                    "value": value[:100] + "..."
                                    if len(value) > 100
                                    else value,
                                }
                            )
                            logger.warning(
                                "⚠️ Invalid ACL format in entry %d",
                                i,
                                extra={
                                    "attribute": attr_name,
                                    "dn": entry.get("dn", "unknown"),
                                }
                            )

            processed_entries.append(processed_entry)

        duration = time.time() - start_time
        self._log_performance("default_acl_processing", duration, len(entries))

        logger.info(
            "✅ ACL processing completed",
            total_entries=len(entries),
            acl_entries=acl_entries_found,
            validation_issues=len(validation_issues),
            duration=f"{duration:.2f}s",
        )

        return {
            "entries": processed_entries,
            "total_entries": len(entries),
            "acl_entries_found": acl_entries_found,
            "acl_conversions": 0,  # Default processor doesn't convert
            "validation_issues": validation_issues,
            "processing_time": duration,
            "processor_type": "default_acl",
        }
