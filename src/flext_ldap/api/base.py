"""Base processor API for LDAP operations.

This module provides the foundational base classes for all LDAP processing
operations, including common functionality and interfaces.
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


class BaseProcessor(ABC):
    """Abstract base processor for all LDAP operations.

    This class provides common functionality shared by all processor
    implementations, including configuration management, performance
    tracking, and utility methods.
    """

    def __init__(self, config: ApplicationConfig) -> None:
        """Initialize base processor with configuration.

        Args:
            config: Application configuration for processor settings
        """
        self.config = config
        self.performance_metrics: dict[str, Any] = {}
        self._operation_start_time: float = 0.0

    @abstractmethod
    def process(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Process LDAP entries.

        Args:
            entries: List of LDAP entries to process

        Returns:
            Dict containing processed entries and operation results
        """

    def _start_operation(self, operation_name: str) -> None:
        """Start timing an operation.

        Args:
            operation_name: Name of the operation being timed
        """
        self._operation_start_time = time.time()
        logger.debug(f"🚀 Starting {operation_name}")

    def _end_operation(self, operation_name: str, count: int = 0) -> float:
        """End timing an operation and log results.

        Args:
            operation_name: Name of the operation that completed
            count: Number of items processed

        Returns:
            Duration of the operation in seconds
        """
        duration = time.time() - self._operation_start_time

        self.performance_metrics[operation_name] = {
            "duration": duration,
            "count": count,
            "rate": count / duration if duration > 0 else 0,
            "timestamp": time.time()
        }

        logger.info(
            f"✅ {operation_name} completed",
            duration=f"{duration:.2f}s",
            count=count,
            rate=f"{count / duration:.1f}/s" if duration > 0 else "instant"
        )

        return duration

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get performance metrics for all operations.

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

    def _validate_entries(self, entries: list[dict[str, Any]]) -> bool:
        """Validate that entries list is properly formatted.

        Args:
            entries: List of LDAP entries to validate

        Returns:
            True if entries are valid, False otherwise
        """
        if not isinstance(entries, list):
            logger.error("❌ Entries must be a list")
            return False

        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                logger.error(f"❌ Entry {i} must be a dictionary")
                return False

        return True

    def _log_processing_start(self, entries: list[dict[str, Any]], operation: str) -> None:
        """Log the start of processing operation.

        Args:
            entries: List of entries being processed
            operation: Name of the processing operation
        """
        logger.info(
            f"🔄 Starting {operation}",
            entry_count=len(entries),
            processor_type=self.__class__.__name__
        )

    def _log_processing_complete(
        self,
        result: dict[str, Any],
        operation: str
    ) -> None:
        """Log the completion of processing operation.

        Args:
            result: Processing result dictionary
            operation: Name of the processing operation
        """
        logger.info(
            f"✅ {operation} completed",
            processed_entries=result.get("total_entries", 0),
            processing_time=f"{result.get('processing_time', 0):.2f}s",
            processor_type=self.__class__.__name__
        )


class DefaultProcessor(BaseProcessor):
    """Default implementation of base processor.

    Provides a simple pass-through implementation that can be used
    as a starting point for custom processors.
    """

    def process(self, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Process entries with default (pass-through) behavior.

        Args:
            entries: List of LDAP entries

        Returns:
            Dict with processed entries (unchanged from input)
        """
        self._start_operation("default_processing")

        if not self._validate_entries(entries):
            return {
                "entries": [],
                "total_entries": 0,
                "processing_time": 0,
                "error": "Invalid entries format"
            }

        self._log_processing_start(entries, "default processing")

        # Default implementation: pass through entries unchanged
        processed_entries = [entry.copy() for entry in entries]

        duration = self._end_operation("default_processing", len(entries))

        result = {
            "entries": processed_entries,
            "total_entries": len(entries),
            "processing_time": duration,
            "processor_type": "default",
            "modifications": 0
        }

        self._log_processing_complete(result, "default processing")

        return result
