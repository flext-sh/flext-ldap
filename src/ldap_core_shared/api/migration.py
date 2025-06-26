"""Generic Migration API - ZERO TOLERANCE for hardcoded business logic.

This module provides a generic migration framework that can be extended by
specific migration projects like client-a-oud-mig. Contains ONLY generic functionality
with NO business-specific logic.

Key Principles:
- Generic configuration management
- Pluggable processor architecture
- Universal validation patterns
- Enterprise-grade error handling

Business Logic Location:
- Project-specific business rules MUST remain in project repositories
- This module provides framework, not business implementation
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, TypeVar

from loguru import logger

from ldap_core_shared.api.exceptions import (
    LDAPMigrationError,
    MigrationConfigurationError,
    ProcessorError,
)
from ldap_core_shared.api.results import Result
from ldap_core_shared.utils.performance import PerformanceMonitor

if TYPE_CHECKING:
    from pathlib import Path

    from ldap_core_shared.api.config import MigrationConfig

T = TypeVar("T")


class MigrationProcessor(Protocol):
    """Protocol for migration processors - ZERO TOLERANCE for implementation details."""

    def process(self, entries: List[Dict[str, Any]]) -> Result[List[Dict[str, Any]]]:
        """Process entries and return result with success/error information."""
        ...

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics from processor."""
        ...


class GenericMigrationOrchestrator(ABC):
    """Generic migration orchestrator - NO business logic, only framework.

    This class provides the framework for migration orchestration.
    Business-specific logic MUST be implemented in subclasses.
    """

    def __init__(self, config: MigrationConfig) -> None:
        """Initialize generic migration orchestrator.

        Args:
            config: Generic migration configuration from ldap-core-shared
        """
        self.config = config
        self.performance_monitor = PerformanceMonitor("generic_migration")
        self.processors: List[MigrationProcessor] = []

        logger.info("✅ Generic migration orchestrator initialized")

    def add_processor(self, processor: MigrationProcessor) -> None:
        """Add a processor to the migration pipeline.

        Args:
            processor: Migration processor implementing the protocol
        """
        self.processors.append(processor)
        logger.debug(f"➕ Added processor: {type(processor).__name__}")

    @abstractmethod
    def load_entries(self) -> Result[List[Dict[str, Any]]]:
        """Load entries for migration - MUST be implemented by subclasses.

        Returns:
            Result containing loaded entries or error information
        """
        ...

    @abstractmethod
    def categorize_entries(self, entries: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize entries - MUST be implemented by subclasses.

        Args:
            entries: List of entries to categorize

        Returns:
            Dict mapping category names to entry lists
        """
        ...

    @abstractmethod
    def write_output(
        self, categories: Dict[str, List[Dict[str, Any]]], output_dir: Path
    ) -> Result[Dict[str, Any]]:
        """Write categorized entries to output - MUST be implemented by subclasses.

        Args:
            categories: Categorized entries
            output_dir: Output directory

        Returns:
            Result with output information or error
        """
        ...

    def execute_migration(self, output_dir: Optional[Path] = None) -> Result[Dict[str, Any]]:
        """Execute generic migration pipeline - NO business logic.

        Args:
            output_dir: Optional output directory

        Returns:
            Result with migration summary or error information
        """
        start_time = time.time()
        self.performance_monitor.reset()

        try:
            # Step 1: Load entries (delegate to subclass)
            logger.info("📋 Loading entries for migration")
            load_result = self.load_entries()
            if not load_result.success:
                return Result.fail(f"Failed to load entries: {load_result.error}")

            entries = load_result.data or []
            logger.info(f"✅ Loaded {len(entries)} entries")

            # Step 2: Process through pipeline
            logger.info("🔄 Processing entries through pipeline")
            processed_entries = entries

            for processor in self.processors:
                result = processor.process(processed_entries)
                if not result.success:
                    return Result.fail(
                        f"Processor {type(processor).__name__} failed: {result.error}"
                    )
                processed_entries = result.data or []

            logger.info(f"✅ Processed {len(processed_entries)} entries through pipeline")

            # Step 3: Categorize entries (delegate to subclass)
            logger.info("📂 Categorizing entries")
            categories = self.categorize_entries(processed_entries)
            logger.info(f"✅ Categorized entries into {len(categories)} categories")

            # Step 4: Write output (delegate to subclass)
            if output_dir:
                logger.info(f"💾 Writing output to {output_dir}")
                output_result = self.write_output(categories, output_dir)
                if not output_result.success:
                    return Result.fail(f"Failed to write output: {output_result.error}")

            # Step 5: Generate summary
            duration = time.time() - start_time

            summary = {
                "success": True,
                "total_entries": len(entries),
                "processed_entries": len(processed_entries),
                "categories": {cat: len(entries) for cat, entries in categories.items()},
                "duration_seconds": duration,
                "entries_per_second": len(processed_entries) / duration if duration > 0 else 0,
                "processors_used": [type(p).__name__ for p in self.processors],
                "performance_metrics": self.performance_monitor.get_metrics(),
            }

            if output_dir:
                summary["output_directory"] = str(output_dir)

            return Result.ok(summary)

        except Exception as e:
            logger.error(f"❌ Migration failed: {e}")
            return Result.fail(f"Migration execution failed: {e}")

    def validate_configuration(self) -> Result[bool]:
        """Validate migration configuration - generic validation only.

        Returns:
            Result indicating validation success or failure
        """
        try:
            # Generic validation - business-specific validation in subclasses
            if not self.config.source_ldif_path_obj.exists():
                return Result.fail(f"Source path does not exist: {self.config.source_ldif_path}")

            if not self.config.output_path_obj.parent.exists():
                return Result.fail(
                    f"Output parent directory does not exist: {self.config.output_path}"
                )

            if self.config.batch_size <= 0:
                return Result.fail("Batch size must be positive")

            if self.config.max_workers <= 0:
                return Result.fail("Max workers must be positive")

            logger.info("✅ Generic migration configuration validated")
            return Result.ok(True)

        except Exception as e:
            return Result.fail(f"Configuration validation failed: {e}")

    def get_migration_plan(self) -> Dict[str, Any]:
        """Get generic migration plan - NO business logic.

        Returns:
            Dictionary with generic migration plan information
        """
        return {
            "migration_type": "Generic LDAP Migration",
            "source_path": str(self.config.source_ldif_path),
            "output_path": str(self.config.output_path),
            "batch_size": self.config.batch_size,
            "max_workers": self.config.max_workers,
            "processors": [type(p).__name__ for p in self.processors],
            "configuration": {
                "enable_transformations": self.config.enable_transformations,
                "continue_on_errors": self.config.continue_on_errors,
                "generate_summary": self.config.generate_summary,
            },
        }


class GenericEntryProcessor(ABC):
    """Generic entry processor base class - NO business logic.

    Provides common functionality for entry processing without business-specific rules.
    """

    def __init__(self, config: MigrationConfig) -> None:
        """Initialize generic processor.

        Args:
            config: Generic migration configuration
        """
        self.config = config
        self.performance_metrics: Dict[str, Any] = {}

    def _log_performance(self, operation: str, duration: float, count: int = 0) -> None:
        """Log performance metrics for operation.

        Args:
            operation: Operation name
            duration: Duration in seconds
            count: Number of items processed
        """
        self.performance_metrics[operation] = {
            "duration": duration,
            "count": count,
            "rate": count / duration if duration > 0 else 0,
        }

        logger.info(f"⏱️ {operation}: {duration:.2f}s, {count} items, {count/duration:.1f}/s")

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics.

        Returns:
            Dictionary with performance metrics
        """
        return self.performance_metrics.copy()

    @abstractmethod
    def process(self, entries: List[Dict[str, Any]]) -> Result[List[Dict[str, Any]]]:
        """Process entries - MUST be implemented by subclasses.

        Args:
            entries: List of entries to process

        Returns:
            Result with processed entries or error
        """
        ...


def create_migration_config_from_env() -> Result[MigrationConfig]:
    """Create migration configuration from environment variables.

    Returns:
        Result containing MigrationConfig or error
    """
    try:
        from ldap_core_shared.api.config import load_migration_config_from_env

        config = load_migration_config_from_env()
        return Result.ok(config)

    except Exception as e:
        return Result.fail(f"Failed to load migration config from environment: {e}")


def validate_migration_setup(config: MigrationConfig) -> Result[List[str]]:
    """Validate migration setup and return list of issues.

    Args:
        config: Migration configuration to validate

    Returns:
        Result containing list of validation issues (empty if valid)
    """
    issues = []

    try:
        if not config.source_ldif_path_obj.exists():
            issues.append(f"Source path does not exist: {config.source_ldif_path}")

        if not config.source_ldif_path_obj.is_dir():
            issues.append(f"Source path is not a directory: {config.source_ldif_path}")

        # Check for LDIF files
        ldif_files = list(config.source_ldif_path_obj.glob("*.ldif"))
        if not ldif_files:
            issues.append(f"No LDIF files found in source path: {config.source_ldif_path}")

        # Check output path can be created
        try:
            config.output_path_obj.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            issues.append(f"Cannot create output path {config.output_path}: {e}")

        # Validate configuration values
        if config.batch_size <= 0:
            issues.append("batch_size must be positive")

        if config.max_workers <= 0:
            issues.append("max_workers must be positive")

        return Result.ok(issues)

    except Exception as e:
        return Result.fail(f"Migration setup validation failed: {e}")


__all__ = [
    "MigrationProcessor",
    "GenericMigrationOrchestrator",
    "GenericEntryProcessor",
    "create_migration_config_from_env",
    "validate_migration_setup",
]
