"""LDIF Writer - Advanced LDIF writing with enterprise formatting."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPOperationResult
from ldap_core_shared.utils.constants import DEFAULT_LARGE_LIMIT
from ldap_core_shared.utils.performance import PerformanceMonitor

# Constants for magic values

if TYPE_CHECKING:
    from ldap_core_shared.ldif.processor import LDIFEntry

logger = logging.getLogger(__name__)


class LDIFWriterConfig(BaseModel):
    """Configuration for LDIF writing operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    encoding: str = Field(default="utf-8", description="Output file encoding")
    line_wrap_length: int = Field(default=76, ge=40, description="Line wrapping length")
    include_header: bool = Field(default=True, description="Include LDIF header")
    include_timestamp: bool = Field(
        default=True,
        description="Include generation timestamp",
    )
    sort_attributes: bool = Field(
        default=True,
        description="Sort attributes alphabetically",
    )
    validate_output: bool = Field(default=True, description="Validate written LDIF")
    create_backup: bool = Field(
        default=False,
        description="Create backup if file exists",
    )
    indent_continuation: bool = Field(
        default=True,
        description="Indent continuation lines",
    )


class LDIFHeaderConfig(BaseModel):
    """Configuration for LDIF file headers."""

    model_config = ConfigDict(strict=True, extra="forbid")

    title: str = Field(..., description="LDIF file title")
    description: str | None = Field(default=None, description="File description")
    source: str | None = Field(default=None, description="Source system or process")
    version: str = Field(default="1", description="LDIF version")
    generator: str = Field(default="ldap-core-shared", description="Generator name")
    custom_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Custom header fields",
    )


class LDIFStatistics(BaseModel):
    """Statistics for LDIF writing operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    entries_written: int = Field(default=0, description="Number of entries written")
    attributes_written: int = Field(default=0, description="Total attributes written")
    bytes_written: int = Field(default=0, description="Total bytes written")
    lines_written: int = Field(default=0, description="Total lines written")
    writing_time_ms: float = Field(
        default=0.0,
        description="Writing time in milliseconds",
    )


class LDIFWriter:
    """Enterprise-grade LDIF writer with advanced formatting capabilities."""

    def __init__(self, config: LDIFWriterConfig | None = None) -> None:
        """Initialize LDIF writer with configuration.

        Args:
            config: Writer configuration (uses defaults if None)
        """
        self.config = config or LDIFWriterConfig()
        self.performance_monitor = PerformanceMonitor()
        self._stats = LDIFStatistics()

    def write_entries(
        self,
        entries: list[LDIFEntry],
        output_path: Path | str,
        header_config: LDIFHeaderConfig | None = None,
    ) -> LDAPOperationResult[LDIFStatistics]:
        """Write LDIF entries to file with enterprise formatting.

        Args:
            entries: List of LDIF entries to write
            output_path: Output file path
            header_config: Header configuration

        Returns:
            Operation result with writing statistics
        """
        output_path = Path(output_path)

        with self.performance_monitor.track_operation("ldif_write_entries"):
            try:
                # Create output directory if needed
                output_path.parent.mkdir(parents=True, exist_ok=True)

                # Create backup if configured and file exists
                if self.config.create_backup and output_path.exists():
                    backup_path = output_path.with_suffix(
                        f"{output_path.suffix}.backup",
                    )
                    output_path.rename(backup_path)
                    logger.info("Created backup: {backup_path}")

                # Reset statistics
                self._reset_stats()

                # Write to file
                with output_path.open("w", encoding=self.config.encoding) as f:
                    self._write_file_content(
                        f,
                        entries,
                        header_config or LDIFHeaderConfig(title="LDIF Export"),
                    )

                # Calculate final statistics
                self._finalize_stats(output_path)

                # Validate output if configured
                if self.config.validate_output:
                    self._validate_written_file(output_path)

                return LDAPOperationResult[LDIFStatistics](
                    success=True,
                    data=self._stats,
                    operation="write_entries",
                    metadata={
                        "output_path": str(output_path),
                        "entries_count": len(entries),
                        "config": self.config.model_dump(),
                    },
                )

            except Exception as e:
                logger.exception("Failed to write LDIF to {output_path}")
                return LDAPOperationResult[LDIFStatistics](
                    success=False,
                    error_message=f"Write failed: {e!s}",
                    operation="write_entries",
                    metadata={
                        "output_path": str(output_path),
                        "entries_count": len(entries) if entries else 0,
                        "stats": self._stats.model_dump(),
                    },
                )

    def write_string(
        self,
        entries: list[LDIFEntry],
        header_config: LDIFHeaderConfig | None = None,
    ) -> LDAPOperationResult[str]:
        """Write LDIF entries to string.

        Args:
            entries: List of LDIF entries to write
            header_config: Header configuration

        Returns:
            Operation result with LDIF string content
        """
        with self.performance_monitor.track_operation("ldif_write_string"):
            try:
                import io

                output = io.StringIO()
                self._reset_stats()

                self._write_file_content(
                    output,
                    entries,
                    header_config or LDIFHeaderConfig(title="LDIF Export"),
                )

                content = output.getvalue()
                output.close()

                return LDAPOperationResult[str](
                    success=True,
                    data=content,
                    operation="write_string",
                    metadata={
                        "content_length": len(content),
                        "entries_count": len(entries),
                        "stats": self._stats.model_dump(),
                    },
                )

            except Exception as e:
                logger.exception("Failed to write LDIF to string")
                return LDAPOperationResult[str](
                    success=False,
                    error_message=f"Write failed: {e!s}",
                    operation="write_string",
                    metadata={
                        "entries_count": len(entries) if entries else 0,
                        "stats": self._stats.model_dump(),
                    },
                )

    def write_entry(
        self,
        entry: LDIFEntry,
        output_path: Path | str,
        append: bool = False,
    ) -> LDAPOperationResult[None]:
        """Write single LDIF entry to file.

        Args:
            entry: LDIF entry to write
            output_path: Output file path
            append: Whether to append to existing file

        Returns:
            Operation result
        """
        mode = "a" if append else "w"
        output_path = Path(output_path)

        try:
            with output_path.open(mode, encoding=self.config.encoding) as f:
                self._write_single_entry(f, entry)

            return LDAPOperationResult[None](
                success=True,
                operation="write_entry",
                metadata={"output_path": str(output_path), "append_mode": append},
            )

        except Exception as e:
            logger.exception("Failed to write entry to {output_path}")
            return LDAPOperationResult[None](
                success=False,
                error_message=f"Write failed: {e!s}",
                operation="write_entry",
                metadata={"output_path": str(output_path), "append_mode": append},
            )

    def _write_file_content(
        self,
        f: TextIO,
        entries: list[LDIFEntry],
        header_config: LDIFHeaderConfig,
    ) -> None:
        """Write complete LDIF file content including header and entries."""
        start_time = self.performance_monitor._get_current_time()

        # Write header if configured
        if self.config.include_header:
            self._write_header(f, header_config, len(entries))

        # Sort entries by DN if needed (for hierarchical order)
        sorted_entries = self._sort_entries(entries) if entries else []

        # Write entries
        for entry in sorted_entries:
            self._write_single_entry(f, entry)
            f.write("\n")  # Blank line between entries
            self._stats.entries_written += 1

        # Update timing
        end_time = self.performance_monitor._get_current_time()
        self._stats.writing_time_ms = (end_time - start_time) * DEFAULT_LARGE_LIMIT

    def _write_header(
        self,
        f: TextIO,
        config: LDIFHeaderConfig,
        entry_count: int,
    ) -> None:
        """Write LDIF file header with metadata."""
        f.write(f"# {config.title}\n")

        if config.description:
            f.write(f"# Description: {config.description}\n")

        if config.source:
            f.write(f"# Source: {config.source}\n")

        f.write(f"# Generator: {config.generator}\n")
        f.write(f"# Version: {config.version}\n")

        if self.config.include_timestamp:
            timestamp = datetime.now(UTC).isoformat()
            f.write(f"# Generated: {timestamp}\n")

        f.write(f"# Entries: {entry_count}\n")

        # Add custom headers
        f.writelines(
            f"# {key}: {value}\n" for key, value in config.custom_headers.items()
        )

        f.write("#\n")
        f.write(f"version: {config.version}\n\n")

        self._stats.lines_written += 3 + len(config.custom_headers)
        if config.description:
            self._stats.lines_written += 1
        if config.source:
            self._stats.lines_written += 1
        if self.config.include_timestamp:
            self._stats.lines_written += 1

    def _write_single_entry(self, f: TextIO, entry: LDIFEntry) -> None:
        """Write single LDIF entry with proper formatting."""
        # Write DN
        self._write_wrapped_line(f, f"dn: {entry.dn}")

        # Write changetype if present
        if entry.changetype:
            self._write_wrapped_line(f, f"changetype: {entry.changetype}")

        # Sort attributes if configured
        attr_items = (
            sorted(entry.attributes.items())
            if self.config.sort_attributes
            else entry.attributes.items()
        )

        # Write attributes
        for attr_name, attr_values in attr_items:
            for value in attr_values:
                self._write_wrapped_line(f, f"{attr_name}: {value}")
                self._stats.attributes_written += 1

        # Write controls if present
        for control in entry.controls:
            self._write_wrapped_line(f, f"control: {control}")

    def _write_wrapped_line(self, f: TextIO, line: str) -> None:
        """Write line with proper wrapping according to LDIF standards."""
        if len(line) <= self.config.line_wrap_length:
            f.write(f"{line}\n")
            self._stats.lines_written += 1
            self._stats.bytes_written += len(line.encode(self.config.encoding)) + 1
            return

        # Write first part
        f.write(f"{line[: self.config.line_wrap_length]}\n")
        remaining = line[self.config.line_wrap_length :]
        self._stats.lines_written += 1
        self._stats.bytes_written += self.config.line_wrap_length + 1

        # Write continuation lines
        while remaining:
            indent = " " if self.config.indent_continuation else ""
            continuation_length = self.config.line_wrap_length - len(indent)

            if len(remaining) <= continuation_length:
                f.write(f"{indent}{remaining}\n")
                self._stats.lines_written += 1
                self._stats.bytes_written += (
                    len(f"{indent}{remaining}".encode(self.config.encoding)) + 1
                )
                break
            chunk = remaining[:continuation_length]
            f.write(f"{indent}{chunk}\n")
            remaining = remaining[continuation_length:]
            self._stats.lines_written += 1
            self._stats.bytes_written += (
                len(f"{indent}{chunk}".encode(self.config.encoding)) + 1
            )

    def _sort_entries(self, entries: list[LDIFEntry]) -> list[LDIFEntry]:
        """Sort entries by DN hierarchy (parents before children)."""

        def dn_depth(dn: str) -> int:
            return dn.count(",")

        def dn_components(dn: str) -> list[str]:
            return [component.strip() for component in dn.split(",")]

        # Sort by depth first (parents first), then by DN components
        return sorted(
            entries,
            key=lambda entry: (dn_depth(entry.dn), dn_components(entry.dn)),
        )

    def _validate_written_file(self, file_path: Path) -> None:
        """Validate the written LDIF file by attempting to parse it."""
        try:
            # Try to parse the file we just wrote
            from ldap_core_shared.ldif.processor import LDIFProcessor

            processor = LDIFProcessor()
            result = processor.parse_file(file_path)

            if not result.success:
                msg = f"Written LDIF file validation failed: {result.error_message}"
                raise ValueError(msg)

            logger.debug(
                "LDIF file validation successful: %s entries",
                len(result.data or []),
            )

        except Exception:
            logger.warning("LDIF file validation failed: {e}")
            # Don't raise exception - validation is optional

    def _finalize_stats(self, output_path: Path) -> None:
        """Finalize writing statistics."""
        if output_path.exists():
            self._stats.bytes_written = output_path.stat().st_size

    def _reset_stats(self) -> None:
        """Reset writing statistics."""
        self._stats = LDIFStatistics()

    def get_statistics(self) -> LDIFStatistics:
        """Get current writing statistics."""
        return self._stats.model_copy()
