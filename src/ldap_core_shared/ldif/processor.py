"""Enterprise LDIF Processor with Production-Validated Patterns."""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import ldif
from pydantic import BaseModel, ConfigDict, Field, ValidationError

# Constants for magic values
from ldap_core_shared.domain.results import (
    LDAPOperationResult,
    LDAPPerformanceResult,
)
from ldap_core_shared.utils.constants import (
    DEFAULT_LARGE_LIMIT,
    DEFAULT_MAX_ITEMS,
    TARGET_OPERATIONS_PER_SECOND,
    TARGET_OPERATIONS_PER_SECOND_A_GRADE,
    TARGET_OPERATIONS_PER_SECOND_B_GRADE,
)
from ldap_core_shared.utils.performance import PerformanceMonitor

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)


class LDIFProcessingConfig(BaseModel):
    """Enterprise LDIF processing configuration with production defaults."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    encoding: str = Field(default="utf-8", description="File encoding")
    chunk_size: int = Field(
        default=DEFAULT_LARGE_LIMIT,
        ge=1,
        description="Entries per chunk for streaming",
    )
    max_entries: int = Field(
        default=100000,
        ge=1,
        description="Maximum entries to process",
    )
    validate_dn: bool = Field(
        default=True,
        description="Validate DN format",
    )
    normalize_attributes: bool = Field(
        default=True,
        description="Normalize attribute names",
    )
    preserve_binary: bool = Field(
        default=True,
        description="Preserve binary attribute values",
    )
    error_tolerance: int = Field(
        default=10,
        ge=0,
        description="Maximum parsing errors allowed",
    )
    performance_monitoring: bool = Field(
        default=True,
        description="Enable performance monitoring",
    )
    memory_limit_mb: int = Field(
        default=375,
        ge=DEFAULT_MAX_ITEMS,
        description="Memory usage limit in MB",
    )


class LDIFEntry(BaseModel):
    """Enterprise LDIF entry with comprehensive validation and utilities."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    dn: str = Field(..., description="Distinguished Name")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Entry attributes",
    )
    changetype: str | None = Field(
        default=None,
        description="LDIF changetype",
    )
    controls: list[str] = Field(
        default_factory=list,
        description="LDAP controls",
    )
    entry_size_bytes: int = Field(
        default=0,
        ge=0,
        description="Entry size in bytes",
    )
    validation_status: str = Field(
        default="valid",
        description="Entry validation status",
    )

    def get_object_classes(self) -> list[str]:
        """Get object classes for this entry."""
        for key, values in self.attributes.items():
            if key.lower() == "objectclass":
                return values
        return []

    def has_attribute(self, attr_name: str) -> bool:
        """Check if entry has specific attribute."""
        return attr_name.lower() in {k.lower() for k in self.attributes}

    def get_attribute_values(self, attr_name: str) -> list[str]:
        """Get values for specific attribute (case-insensitive)."""
        for key, values in self.attributes.items():
            if key.lower() == attr_name.lower():
                return values
        return []


class LDIFProcessor:
    """Enterprise-grade LDIF processor with streaming and validation."""

    def __init__(self, config: LDIFProcessingConfig | None = None) -> None:
        """Initialize enterprise LDIF processor.

        Args:
            config: Processing configuration (uses defaults if None)

        """
        self.config = config or LDIFProcessingConfig()
        self.performance_monitor = PerformanceMonitor("ldif_processor")
        self._stats = {
            "entries_processed": 0,
            "entries_valid": 0,
            "entries_invalid": 0,
            "parsing_errors": 0,
            "validation_errors": 0,
            "memory_usage_mb": 0.0,
            "processing_rate": 0.0,
        }
        self._reset_stats()

    def parse_file(
        self,
        file_path: Path | str,
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Parse LDIF file with enterprise validation and error recovery.

        Args:
            file_path: Path to LDIF file

        Returns:
            Operation result with parsed entries or error details

        """
        file_path = Path(file_path)

        with self.performance_monitor.measure_operation("ldif_parse_file") as ctx:
            try:
                return self._execute_file_parse(file_path, ctx)
            except FileNotFoundError:
                return self._handle_file_not_found_error(file_path, ctx)
            except PermissionError:
                return self._handle_permission_error(file_path, ctx)
            except ValidationError as validation_error:
                return self._handle_validation_error(validation_error, file_path, ctx)
            except (ValueError, TypeError, UnicodeDecodeError) as parse_error:
                return self._handle_parse_error(parse_error, file_path, ctx)

    def parse_string(
        self,
        ldif_content: str,
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Parse LDIF content from string with enterprise validation.

        Args:
            ldif_content: LDIF content as string

        Returns:
            Operation result with parsed entries

        """
        with self.performance_monitor.measure_operation("ldif_parse_string") as ctx:
            try:
                # Validate content length
                if not ldif_content.strip():
                    return self._handle_empty_content_error(ldif_content, ctx)

                # Parse content with internal implementation
                entries = self._parse_string_internal(ldif_content)

                # Update operation context
                ctx["success"] = True
                ctx["entries_count"] = len(entries)

                return self._create_success_result(
                    entries,
                    "parse_string",
                    {
                        "content_length": len(ldif_content),
                        "entries_count": len(entries),
                    },
                )

            except ValidationError as validation_error:
                return self._handle_string_validation_error(
                    validation_error,
                    ldif_content,
                    ctx,
                )

            except (ValueError, TypeError, UnicodeDecodeError) as parse_error:
                return self._handle_string_parse_error(parse_error, ldif_content, ctx)

    def stream_file(self, file_path: Path | str) -> Iterator[LDIFEntry]:
        """Stream LDIF file for memory-efficient processing of large files.

        Args:
            file_path: Path to LDIF file

        Yields:
            Individual LDIF entries

        """
        file_path = Path(file_path)

        try:
            with file_path.open("r", encoding=self.config.encoding) as f:
                parser = ldif.LDIFRecordList(f)
                parser.parse()

                for dn, attrs in parser.all_records:
                    try:
                        entry = self._create_ldif_entry(dn, attrs)
                        if entry:
                            yield entry
                            self._stats["entries_processed"] += 1
                            self._stats["entries_valid"] += 1
                    except ValidationError as validation_error:
                        self._handle_stream_validation_error(dn, validation_error)

        except Exception:
            logger.exception(
                "Failed to stream LDIF file",
                extra={"file_path": str(file_path)},
            )
            raise

    def stream_chunks(self, file_path: Path | str) -> Iterator[list[LDIFEntry]]:
        """Stream LDIF file in chunks for batch processing.

        Args:
            file_path: Path to LDIF file

        Yields:
            Chunks of LDIF entries

        """
        chunk = []

        for entry in self.stream_file(file_path):
            chunk.append(entry)

            if len(chunk) >= self.config.chunk_size:
                yield chunk
                chunk = []

        # Yield remaining entries
        if chunk:
            yield chunk

    def get_performance_stats(self) -> LDAPPerformanceResult:
        """Get processing performance statistics.

        Returns:
            Performance statistics and metrics

        """
        metrics = self.performance_monitor.get_metrics()

        return LDAPPerformanceResult(
            operation_name="ldif_processing",
            total_operations=int(self._stats["entries_processed"]),
            successful_operations=int(self._stats.get("successful_entries", 0)),
            failed_operations=int(self._stats.get("failed_entries", 0)),
            total_duration=metrics.total_duration,
            average_duration=metrics.total_duration
            / max(self._stats["entries_processed"], 1),
            operations_per_second=(
                self._stats["entries_processed"] / metrics.total_duration
                if metrics.total_duration > 0
                else 0
            ),
            memory_peak_mb=self._stats["memory_usage_mb"],
            cpu_usage_percent=0.0,
            pool_size=1,
            pool_utilization=0.0,
            connection_reuse_rate=0.0,
        )

    def _parse_file_internal(self, file_path: Path) -> list[LDIFEntry]:
        """Internal file parsing implementation."""
        entries = []
        self._reset_stats()

        try:
            with file_path.open("r", encoding=self.config.encoding) as f:
                parser = ldif.LDIFRecordList(f)
                parser.parse()

                for dn, attrs in parser.all_records:
                    try:
                        entry = self._create_ldif_entry(dn, attrs)
                        if entry:
                            entries.append(entry)
                            self._stats["entries_valid"] += 1
                    except ValidationError as validation_error:
                        self._handle_parse_validation_error(dn, validation_error)

                    self._stats["entries_processed"] += 1

                    if self._stats["entries_processed"] >= self.config.max_entries:
                        logger.warning(
                            "Reached maximum entries limit",
                            extra={"max_entries": self.config.max_entries},
                        )
                        break

        except Exception:
            self._stats["parsing_errors"] += 1
            raise

        return entries

    def _parse_string_internal(self, content: str) -> list[LDIFEntry]:
        """Internal string parsing implementation."""
        entries = []
        self._reset_stats()

        try:
            parser = ldif.LDIFRecordList(io.StringIO(content))
            parser.parse()

            for dn, attrs in parser.all_records:
                try:
                    entry = self._create_ldif_entry(dn, attrs)
                    if entry:
                        entries.append(entry)
                        self._stats["entries_valid"] += 1
                except ValidationError as validation_error:
                    self._handle_parse_validation_error(dn, validation_error)

                self._stats["entries_processed"] += 1

        except Exception:
            self._stats["parsing_errors"] += 1
            raise

        return entries

    def _create_ldif_entry(
        self,
        dn: str,
        attrs: dict[str, list[bytes] | list[str]],
    ) -> LDIFEntry | None:
        """Create and validate LDIF entry from parsed data.

        Args:
            dn: Distinguished Name
            attrs: Entry attributes

        Returns:
            Validated LDIF entry or None if invalid

        """
        try:
            # Validate DN format if configured
            if self.config.validate_dn and not self._is_valid_dn(dn):
                self._raise_invalid_dn_error(dn)

            # Convert and normalize attributes
            normalized_attrs = {}
            entry_size = 0

            for attr_name, attr_values in attrs.items():
                # Normalize attribute name case
                norm_name = (
                    attr_name
                    if not self.config.normalize_attributes
                    else attr_name.lower()
                )

                # Convert values to strings
                str_values = []
                for value in attr_values:
                    if isinstance(value, bytes):
                        if self.config.preserve_binary:
                            # For binary data, convert to base64 or keep as bytes representation
                            str_values.append(value.decode("utf-8", errors="replace"))
                        else:
                            str_values.append(value.decode("utf-8"))
                    else:
                        str_values.append(str(value))

                    # Track entry size
                    entry_size += len(str(value))

                normalized_attrs[norm_name] = str_values

            return LDIFEntry(
                dn=dn,
                attributes=normalized_attrs,
                entry_size_bytes=entry_size,
            )

        except ValidationError:
            logger.debug(
                "Failed to create LDIF entry due to validation error",
                extra={"dn": dn},
            )
            return None
        except (UnicodeDecodeError, ValueError, TypeError):
            logger.debug(
                "Failed to create LDIF entry due to data error",
                extra={"dn": dn},
            )
            return None

    def _is_valid_dn(self, dn: str) -> bool:
        """Validate DN format according to RFC 2253.

        Args:
            dn: Distinguished Name to validate

        Returns:
            True if DN format is valid

        """
        if not dn or not isinstance(dn, str):
            return False

        # Basic DN validation - contains at least one RDN with =
        return "=" in dn

    def _calculate_performance_grade(self, entries_per_second: float) -> str:
        """Calculate performance grade based on processing rate.

        Args:
            entries_per_second: Processing rate

        Returns:
            Performance grade (A+, A, B, C)

        """
        if entries_per_second >= TARGET_OPERATIONS_PER_SECOND:
            return "A+"
        if entries_per_second >= TARGET_OPERATIONS_PER_SECOND_A_GRADE:
            return "A"
        if entries_per_second >= TARGET_OPERATIONS_PER_SECOND_B_GRADE:
            return "B"
        return "C"

    def _reset_stats(self) -> None:
        """Reset processing statistics to initial state."""
        self._stats = {
            "entries_processed": 0,
            "entries_valid": 0,
            "entries_invalid": 0,
            "parsing_errors": 0,
            "validation_errors": 0,
            "memory_usage_mb": 0.0,
            "processing_rate": 0.0,
        }

    def _validate_file_access(self, file_path: Path) -> None:
        """Validate file accessibility and permissions.

        Args:
            file_path: Path to validate

        Raises:
            FileNotFoundError: If file does not exist
            PermissionError: If file is not readable

        """
        if not file_path.exists():
            file_not_found_msg = f"File not found: {file_path}"
            raise FileNotFoundError(file_not_found_msg)

        if not file_path.is_file():
            not_a_file_msg = f"Path is not a file: {file_path}"
            raise ValueError(not_a_file_msg)

        if not file_path.stat().st_size:
            empty_file_msg = f"File is empty: {file_path}"
            raise ValueError(empty_file_msg)

        # Check read permissions
        try:
            with file_path.open("r", encoding=self.config.encoding) as f:
                f.read(1)  # Try to read one character
        except PermissionError:
            raise
        except UnicodeDecodeError as decode_error:
            encoding_error_msg = (
                f"File encoding error with {self.config.encoding}: {decode_error!s}"
            )
            raise ValueError(encoding_error_msg) from decode_error

    def _raise_invalid_dn_error(self, dn: str) -> None:
        """Raise validation error for invalid DN.

        Args:
            dn: Invalid DN

        """
        invalid_dn_msg = f"Invalid DN format: {dn}"
        raise ValidationError(invalid_dn_msg)

    def _create_success_result(
        self,
        entries: list[LDIFEntry],
        operation: str,
        additional_metadata: dict[str, str | int],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Create success operation result.

        Args:
            entries: Parsed entries
            operation: Operation name
            additional_metadata: Additional metadata

        Returns:
            Success operation result

        """
        metadata = {"stats": self._stats.copy()}
        metadata.update(additional_metadata)

        return LDAPOperationResult[list[LDIFEntry]](
            success=True,
            data=entries,
            operation=operation,
            metadata=metadata,
        )

    def _handle_file_not_found_error(
        self,
        file_path: Path,
        ctx: dict[str, str | bool],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Handle file not found error.

        Args:
            file_path: File path that was not found
            ctx: Operation context

        Returns:
            Error operation result

        """
        file_not_found_msg = f"File not found: {file_path}"
        logger.error("LDIF file not found", extra={"file_path": str(file_path)})
        ctx["success"] = False
        ctx["error"] = file_not_found_msg

        return LDAPOperationResult[list[LDIFEntry]](
            success=False,
            error_message=file_not_found_msg,
            operation="parse_file",
            metadata={"file_path": str(file_path), "stats": self._stats.copy()},
        )

    def _handle_permission_error(
        self,
        file_path: Path,
        ctx: dict[str, str | bool],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Handle permission error.

        Args:
            file_path: File path with permission issues
            ctx: Operation context

        Returns:
            Error operation result

        """
        permission_error_msg = f"Permission denied: {file_path}"
        logger.error(
            "LDIF file permission denied",
            extra={"file_path": str(file_path)},
        )
        ctx["success"] = False
        ctx["error"] = permission_error_msg

        return LDAPOperationResult[list[LDIFEntry]](
            success=False,
            error_message=permission_error_msg,
            operation="parse_file",
            metadata={"file_path": str(file_path), "stats": self._stats.copy()},
        )

    def _handle_validation_error(
        self,
        validation_error: ValidationError,
        file_path: Path,
        ctx: dict[str, str | bool],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Handle validation error.

        Args:
            validation_error: Validation error
            file_path: File path being processed
            ctx: Operation context

        Returns:
            Error operation result

        """
        validation_error_msg = f"Validation failed: {validation_error!s}"
        logger.error(
            "LDIF validation error",
            extra={"error": str(validation_error)},
        )
        ctx["success"] = False
        ctx["error"] = validation_error_msg

        return LDAPOperationResult[list[LDIFEntry]](
            success=False,
            error_message=validation_error_msg,
            operation="parse_file",
            metadata={"file_path": str(file_path), "stats": self._stats.copy()},
        )

    def _handle_parse_error(
        self,
        parse_error: Exception,
        file_path: Path,
        ctx: dict[str, str | bool],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Handle general parse error.

        Args:
            parse_error: Parse error
            file_path: File path being processed
            ctx: Operation context

        Returns:
            Error operation result

        """
        parse_error_msg = f"Parse failed: {parse_error!s}"
        logger.error("LDIF parse error", extra={"file_path": str(file_path)})
        ctx["success"] = False
        ctx["error"] = parse_error_msg

        return LDAPOperationResult[list[LDIFEntry]](
            success=False,
            error_message=parse_error_msg,
            operation="parse_file",
            metadata={"file_path": str(file_path), "stats": self._stats.copy()},
        )

    def _handle_empty_content_error(
        self,
        ldif_content: str,
        ctx: dict[str, str | bool],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Handle empty content error.

        Args:
            ldif_content: Empty LDIF content
            ctx: Operation context

        Returns:
            Error operation result

        """
        empty_content_msg = "LDIF content is empty"
        ctx["success"] = False
        ctx["error"] = empty_content_msg

        return LDAPOperationResult[list[LDIFEntry]](
            success=False,
            error_message=empty_content_msg,
            operation="parse_string",
            metadata={
                "content_length": len(ldif_content),
                "stats": self._stats.copy(),
            },
        )

    def _handle_string_validation_error(
        self,
        validation_error: ValidationError,
        ldif_content: str,
        ctx: dict[str, str | bool],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Handle string validation error.

        Args:
            validation_error: Validation error
            ldif_content: LDIF content being processed
            ctx: Operation context

        Returns:
            Error operation result

        """
        validation_error_msg = f"Validation failed: {validation_error!s}"
        logger.error(
            "LDIF string validation error",
            extra={"error": str(validation_error)},
        )
        ctx["success"] = False
        ctx["error"] = validation_error_msg

        return LDAPOperationResult[list[LDIFEntry]](
            success=False,
            error_message=validation_error_msg,
            operation="parse_string",
            metadata={
                "content_length": len(ldif_content),
                "stats": self._stats.copy(),
            },
        )

    def _handle_string_parse_error(
        self,
        parse_error: Exception,
        ldif_content: str,
        ctx: dict[str, str | bool],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Handle string parse error.

        Args:
            parse_error: Parse error
            ldif_content: LDIF content being processed
            ctx: Operation context

        Returns:
            Error operation result

        """
        parse_error_msg = f"Parse failed: {parse_error!s}"
        logger.error("LDIF string parse error")
        ctx["success"] = False
        ctx["error"] = parse_error_msg

        return LDAPOperationResult[list[LDIFEntry]](
            success=False,
            error_message=parse_error_msg,
            operation="parse_string",
            metadata={
                "content_length": len(ldif_content),
                "stats": self._stats.copy(),
            },
        )

    def _handle_stream_validation_error(
        self,
        dn: str,
        validation_error: ValidationError,
    ) -> None:
        """Handle validation error during streaming.

        Args:
            dn: Distinguished Name of invalid entry
            validation_error: Validation error

        """
        logger.warning(
            "Skipping invalid entry due to validation error",
            extra={"dn": dn, "error": str(validation_error)},
        )
        self._stats["entries_invalid"] += 1
        self._stats["validation_errors"] += 1

        if self._stats["validation_errors"] > self.config.error_tolerance:
            too_many_errors_msg = (
                f"Too many validation errors: {self._stats['validation_errors']}"
            )
            raise ValueError(too_many_errors_msg) from validation_error

    def _handle_parse_validation_error(
        self,
        dn: str,
        validation_error: ValidationError,
    ) -> None:
        """Handle validation error during parsing.

        Args:
            dn: Distinguished Name of invalid entry
            validation_error: Validation error

        """
        logger.warning(
            "Skipping invalid entry due to validation error",
            extra={"dn": dn, "error": str(validation_error)},
        )
        self._stats["entries_invalid"] += 1
        self._stats["validation_errors"] += 1

        if self._stats["validation_errors"] > self.config.error_tolerance:
            raise validation_error

    def _execute_file_parse(
        self,
        file_path: Path,
        ctx: dict[str, str | bool],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Execute file parsing with validation.

        Args:
            file_path: Path to LDIF file
            ctx: Operation context

        Returns:
            Success operation result

        """
        # Validate file existence and accessibility
        self._validate_file_access(file_path)

        # Parse file with internal implementation
        entries = self._parse_file_internal(file_path)

        # Update operation context
        ctx["success"] = True
        ctx["entries_count"] = len(entries)

        return self._create_success_result(
            entries,
            "parse_file",
            {"file_path": str(file_path), "entries_count": len(entries)},
        )


# Backward compatibility alias - maintain existing API for enterprise integration
RFC2849LDIFProcessor = LDIFProcessor
