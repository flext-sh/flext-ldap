"""LDIF Merger - Advanced LDIF file merging and deduplication.

This module provides sophisticated LDIF merging capabilities for combining
multiple LDIF files with conflict resolution and deduplication.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from flext_ldapsor import LDIFEntry
from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class MergeConfig(BaseModel):
    """Configuration for LDIF merge operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    remove_duplicates: bool = Field(
        default=True,
        description="Remove duplicate entries",
    )
    conflict_resolution: str = Field(
        default="first_wins",
        description="How to resolve conflicts",
    )
    sort_output: bool = Field(default=True, description="Sort merged output by DN")
    preserve_order: bool = Field(default=False, description="Preserve input file order")


class MergeStatistics(BaseModel):
    """Statistics from merge operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    input_files: int = Field(default=0, description="Number of input files")
    total_input_entries: int = Field(default=0, description="Total input entries")
    unique_entries: int = Field(default=0, description="Unique entries after merge")
    duplicates_removed: int = Field(
        default=0,
        description="Number of duplicates removed",
    )
    conflicts_resolved: int = Field(
        default=0,
        description="Number of conflicts resolved",
    )


class LDIFMerger:
    """Advanced LDIF merger with conflict resolution and deduplication."""

    def __init__(self, config: MergeConfig | None = None) -> None:
        """Initialize LDIF merger with configuration."""
        self.config = config or MergeConfig()

    def merge_files(
        self,
        input_files: list[Path | str],
        output_path: Path | str,
        header_config: LDIFHeaderConfig | None = None,
    ) -> LDAPOperationResult[MergeStatistics]:
        """Merge multiple LDIF files into single output file.

        Args:
            input_files: List of input LDIF files
            output_path: Output file path
            header_config: Header configuration for output

        Returns:
            Operation result with merge statistics
        """
        try:
            from flext_ldap.ldif.processor import LDIFProcessor

            processor = LDIFProcessor()
            all_entries = []
            stats = MergeStatistics(input_files=len(input_files))

            # Read all input files
            for file_path in input_files:
                result = processor.parse_file(file_path)
                if result.success and result.data:
                    all_entries.extend(result.data)
                    stats.total_input_entries += len(result.data)
                else:
                    logger.warning(
                        "Failed to parse %s: %s",
                        file_path,
                        result.error_message,
                    )

            # Merge and deduplicate
            merged_entries = self._merge_entries(all_entries, stats)

            # Write output
            writer = LDIFWriter()
            header = header_config or LDIFHeaderConfig(
                title="Merged LDIF",
                description=f"Merged from {len(input_files)} files",
            )

            write_result = writer.write_entries(merged_entries, output_path, header)

            if not write_result.success:
                return LDAPOperationResult[MergeStatistics](
                    success=False,
                    error_message=f"Failed to write merged file: {write_result.error_message}",
                    operation="merge_files",
                )

            stats.unique_entries = len(merged_entries)

            return LDAPOperationResult[MergeStatistics](
                success=True,
                data=stats,
                operation="merge_files",
                metadata={
                    "output_path": str(output_path),
                    "input_files": [str(f) for f in input_files],
                },
            )

        except Exception as e:
            logger.exception("Failed to merge LDIF files")
            return LDAPOperationResult[MergeStatistics](
                success=False,
                error_message=f"Merge failed: {e!s}",
                operation="merge_files",
            )

    def merge_entries(self, entry_lists: list[list[LDIFEntry]]) -> list[LDIFEntry]:
        """Merge multiple lists of entries.

        Args:
            entry_lists: List of entry lists to merge

        Returns:
            Merged and deduplicated list of entries
        """
        all_entries = []
        for entries in entry_lists:
            all_entries.extend(entries)

        stats = MergeStatistics()
        return self._merge_entries(all_entries, stats)

    def _merge_entries(
        self,
        entries: list[LDIFEntry],
        stats: MergeStatistics,
    ) -> list[LDIFEntry]:
        """Internal merge implementation with deduplication and conflict resolution."""
        if not self.config.remove_duplicates:
            return self._sort_entries(entries) if self.config.sort_output else entries

        # Group entries by DN
        dn_groups: dict[str, list[LDIFEntry]] = {}
        for entry in entries:
            dn_key = entry.dn.lower()
            if dn_key not in dn_groups:
                dn_groups[dn_key] = []
            dn_groups[dn_key].append(entry)

        # Resolve conflicts for each DN
        merged_entries = []
        for dn_key, entry_group in dn_groups.items():
            if len(entry_group) == 1:
                merged_entries.append(entry_group[0])
            else:
                # Multiple entries for same DN - resolve conflict
                resolved = self._resolve_conflict(entry_group)
                merged_entries.append(resolved)
                stats.duplicates_removed += len(entry_group) - 1
                stats.conflicts_resolved += 1

        return (
            self._sort_entries(merged_entries)
            if self.config.sort_output
            else merged_entries
        )

    def _resolve_conflict(self, entries: list[LDIFEntry]) -> LDIFEntry:
        """Resolve conflict between entries with same DN."""
        if self.config.conflict_resolution == "first_wins":
            return entries[0]
        if self.config.conflict_resolution == "last_wins":
            return entries[-1]
        if self.config.conflict_resolution == "merge_attributes":
            return self._merge_attributes(entries)
        if self.config.conflict_resolution == "most_complete":
            return self._select_most_complete(entries)
        return entries[0]

    def _merge_attributes(self, entries: list[LDIFEntry]) -> LDIFEntry:
        """Merge attributes from multiple entries with same DN."""
        base_entry = entries[0]
        merged_attributes = base_entry.attributes.copy()

        for entry in entries[1:]:
            for attr_name, attr_values in entry.attributes.items():
                if attr_name in merged_attributes:
                    # Merge values, removing duplicates
                    existing_values = set(merged_attributes[attr_name])
                    new_values = [v for v in attr_values if v not in existing_values]
                    merged_attributes[attr_name].extend(new_values)
                else:
                    # New attribute
                    merged_attributes[attr_name] = attr_values.copy()

        return LDIFEntry(
            dn=base_entry.dn,
            attributes=merged_attributes,
            changetype=base_entry.changetype,
            controls=base_entry.controls,
        )

    def _select_most_complete(self, entries: list[LDIFEntry]) -> LDIFEntry:
        """Select entry with most attributes/values."""

        def entry_completeness(entry: LDIFEntry) -> int:
            return sum(len(values) for values in entry.attributes.values())

        return max(entries, key=entry_completeness)

    def _sort_entries(self, entries: list[LDIFEntry]) -> list[LDIFEntry]:
        """Sort entries by DN hierarchy."""

        def dn_sort_key(entry: LDIFEntry) -> tuple[int, str]:
            dn_parts = entry.dn.lower().split(",")
            return (len(dn_parts), entry.dn.lower())

        return sorted(entries, key=dn_sort_key)
