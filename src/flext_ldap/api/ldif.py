"""LDIF processing API for FLEXT LDAP."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class LDIFHeaderConfig:
    """Configuration for LDIF headers."""

    version: str = "1"
    comments: list[str] = None
    custom_headers: dict[str, str] = None

    def __post_init__(self) -> None:
        if self.comments is None:
            self.comments = []
        if self.custom_headers is None:
            self.custom_headers = {}


@dataclass
class LDIFProcessingConfig:
    """Configuration for LDIF processing."""

    max_line_length: int = 76
    encoding: str = "utf-8"
    validate_entries: bool = True
    strict_mode: bool = False
    include_operational_attrs: bool = False


@dataclass
class LDIFWriterConfig:
    """Configuration for LDIF writer."""

    header: LDIFHeaderConfig = None
    processing: LDIFProcessingConfig = None

    def __post_init__(self) -> None:
        if self.header is None:
            self.header = LDIFHeaderConfig()
        if self.processing is None:
            self.processing = LDIFProcessingConfig()


class LDIFProcessorBase(ABC):
    """Base class for LDIF processors."""

    def __init__(self, config: LDIFProcessingConfig = None) -> None:
        self.config = config or LDIFProcessingConfig()

    @abstractmethod
    def process_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Process a single LDIF entry."""

    @abstractmethod
    def process_file(self, input_path: Path, output_path: Path) -> None:
        """Process an entire LDIF file."""


class LDIFWriter:
    """LDIF writer implementation."""

    def __init__(self, config: LDIFWriterConfig = None) -> None:
        self.config = config or LDIFWriterConfig()

    def write_header(self, output_file: Any) -> None:
        """Write LDIF header."""
        output_file.write(f"version: {self.config.header.version}\n")
        for comment in self.config.header.comments:
            output_file.write(f"# {comment}\n")
        for key, value in self.config.header.custom_headers.items():
            output_file.write(f"# {key}: {value}\n")
        output_file.write("\n")

    def write_entry(self, entry: dict[str, Any], output_file: Any) -> None:
        """Write a single LDIF entry."""
        if "dn" in entry:
            output_file.write(f"dn: {entry['dn']}\n")

        for attr, values in entry.items():
            if attr == "dn":
                continue

            if isinstance(values, list):
                for value in values:
                    output_file.write(f"{attr}: {value}\n")
            else:
                output_file.write(f"{attr}: {values}\n")

        output_file.write("\n")

    def write_file(self, entries: list[dict[str, Any]], output_path: Path) -> None:
        """Write entries to LDIF file."""
        with open(output_path, "w", encoding=self.config.processing.encoding) as f:
            self.write_header(f)
            for entry in entries:
                self.write_entry(entry, f)


class DefaultLDIFProcessor(LDIFProcessorBase):
    """Default LDIF processor implementation."""

    def process_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Process a single LDIF entry (pass-through by default)."""
        return entry

    def process_file(self, input_path: Path, output_path: Path) -> None:
        """Process an entire LDIF file."""
        entries = []
        # Basic LDIF parsing (simplified)
        with open(input_path, encoding=self.config.encoding) as f:
            current_entry: dict[str, Any] = {}
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("version:"):
                    continue
                if ":" in line:
                    attr, value = line.split(":", 1)
                    value = value.strip()
                    if attr in current_entry:
                        if not isinstance(current_entry[attr], list):
                            current_entry[attr] = [current_entry[attr]]
                        attr_list = current_entry[attr]
                        if isinstance(attr_list, list):
                            attr_list.append(value)
                    else:
                        current_entry[attr] = value
                elif not line and current_entry:
                    processed_entry = self.process_entry(current_entry)
                    entries.append(processed_entry)
                    current_entry = {}

            # Handle last entry
            if current_entry:
                processed_entry = self.process_entry(current_entry)
                entries.append(processed_entry)

        # Write processed entries
        writer = LDIFWriter(LDIFWriterConfig())
        writer.write_file(entries, output_path)
