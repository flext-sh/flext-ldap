"""LDIF Processor - True Facade with Pure Delegation.

This module implements the True Facade pattern by providing LDIF processing
that delegates entirely to the existing ldif/processor.py infrastructure.

TRUE FACADE PATTERN: 100% DELEGATION TO EXISTING LDIF INFRASTRUCTURE
- Delegates ALL LDIF operations to ldif.processor.LDIFProcessor
- Provides backward compatibility interface
- Maintains consistent Result patterns
- Zero code duplication - pure delegation

MIGRATION FROM DUPLICATED IMPLEMENTATION:
- Previous implementation: 408 lines of duplicated LDIF processing logic
- New implementation: Pure delegation to existing production-validated infrastructure
- All functionality preserved through delegation
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from ldap_core_shared.domain.results import LDAPOperationResult
from ldap_core_shared.ldif.processor import (
    LDIFEntry,
)
from ldap_core_shared.ldif.processor import (
    LDIFProcessingConfig as ProductionLDIFProcessingConfig,
)

# Delegate to existing production-validated LDIF infrastructure
from ldap_core_shared.ldif.processor import (
    LDIFProcessor as ProductionLDIFProcessor,
)
from ldap_core_shared.utils.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ldap_core_shared.domain.results import LDAPOperationResult

logger = get_logger(__name__)


class LDIFProcessingConfig:
    """LDIF processing config - delegates to production configuration."""

    def __init__(self, **kwargs) -> None:
        """Initialize config - creates production config internally."""
        self._production_config = ProductionLDIFProcessingConfig(**kwargs)

    def __getattr__(self, name):
        """Delegate all attribute access to production config."""
        return getattr(self._production_config, name)


class LDIFProcessor:
    """LDIF Processor - True Facade with Pure Delegation.

    TRUE FACADE PATTERN: 100% DELEGATION TO PRODUCTION LDIF INFRASTRUCTURE
    ======================================================================

    This class implements the True Facade pattern by providing LDIF processing
    that delegates entirely to the existing ldif/processor.py infrastructure
    without any reimplementation.

    PURE DELEGATION ARCHITECTURE:
    - Delegates ALL LDIF operations to ldif.processor.LDIFProcessor
    - Provides backward compatibility for existing code
    - Maintains consistent interface patterns
    - Zero code duplication - pure delegation
    - Uses existing production-validated LDIF infrastructure

    DELEGATION TARGET:
    - ldif.processor.LDIFProcessor: Production-validated LDIF processing with
      enterprise patterns, performance monitoring, validation, streaming

    MIGRATION BENEFITS:
    - Eliminated 408 lines of duplicated LDIF processing logic
    - Leverages existing production-tested infrastructure
    - Automatic improvements from production LDIF processor
    - Consistent behavior across all LDIF usage
    """

    def __init__(
        self, config: LDIFProcessingConfig | dict[str, Any] | None = None
    ) -> None:
        """Initialize LDIF processor facade.

        Args:
            config: LDIF processing configuration (converted to production format)

        """
        if config is None:
            config = {}
        elif isinstance(config, dict):
            config = LDIFProcessingConfig(**config)

        # Delegate to existing production LDIF processor
        self._production_processor = ProductionLDIFProcessor(
            config._production_config
            if hasattr(config, "_production_config")
            else config,
        )

    def process_file(
        self,
        file_path: Path | str,
        **kwargs,
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Process LDIF file - delegates to production processor."""
        return self._production_processor.parse_file(file_path, **kwargs)

    def process_stream(self, stream, **kwargs) -> LDAPOperationResult[list[LDIFEntry]]:
        """Process LDIF stream - delegates to production processor."""
        # Handle stream by reading content first
        if hasattr(stream, "read"):
            content = stream.read()
        elif hasattr(stream, "getvalue"):
            content = stream.getvalue()
        else:
            content = str(stream)
        return self._production_processor.parse_string(content, **kwargs)

    def validate_ldif(self, content: str | Path, **kwargs) -> bool:
        """Validate LDIF content - delegates to production processor."""
        # Production processor validates during parsing
        try:
            if isinstance(content, str | Path):
                if isinstance(content, str):
                    result = self._production_processor.parse_string(content)
                else:
                    result = self._production_processor.parse_file(content)
                return result.success
            return False
        except Exception:
            return False

    def parse_ldif_entries(
        self,
        content: str | Path,
        **kwargs,
    ) -> Iterator[dict[str, Any]]:
        """Parse LDIF entries - delegates to production processor."""
        if isinstance(content, str):
            result = self._production_processor.parse_string(content)
            if result.success:
                for entry in result.data:
                    yield {"dn": entry.dn, "attributes": entry.attributes}
        else:
            # Use streaming for files
            for entry in self._production_processor.stream_file(content):
                yield {"dn": entry.dn, "attributes": entry.attributes}

    def get_statistics(self) -> dict[str, Any]:
        """Get processing statistics - delegates to production processor."""
        # Production processor uses performance stats
        performance_result = self._production_processor.get_performance_stats()
        return {
            "total_operations": performance_result.total_operations,
            "successful_operations": performance_result.successful_operations,
            "failed_operations": performance_result.failed_operations,
            "operations_per_second": performance_result.operations_per_second,
            "total_duration": performance_result.total_duration,
            "memory_peak_mb": performance_result.memory_peak_mb,
        }

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get performance metrics - delegates to production processor."""
        return self.get_statistics()

    def close(self) -> None:
        """Close processor - delegates to production processor."""
        if hasattr(self._production_processor, "close"):
            self._production_processor.close()


# ================================================================================
# HELPER FUNCTIONS - Direct delegation for common operations
# ================================================================================


def create_ldif_processor(config: dict[str, Any] | None = None) -> LDIFProcessor:
    """Create LDIF processor - convenience function with pure delegation."""
    return LDIFProcessor(config)


def process_ldif_file(
    file_path: Path | str,
    **kwargs,
) -> LDAPOperationResult[list[LDIFEntry]]:
    """Process LDIF file - convenience function with pure delegation."""
    processor = LDIFProcessor()
    return processor.process_file(file_path, **kwargs)


def validate_ldif_file(file_path: Path | str) -> bool:
    """Validate LDIF file - convenience function with pure delegation."""
    processor = LDIFProcessor()
    return processor.validate_ldif(file_path)


def parse_ldif_file(file_path: Path | str) -> Iterator[dict[str, Any]]:
    """Parse LDIF file entries - convenience function with pure delegation."""
    processor = LDIFProcessor()
    return processor.parse_ldif_entries(file_path)
