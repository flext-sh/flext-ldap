"""Comprehensive tests for LDIF Processor.

This module provides enterprise-grade testing for the LDIF processing
system, including unit tests, integration tests, and performance validation.

Test Coverage:
    - LDIF parsing and validation
    - Streaming processing for large files
    - Memory-efficient chunked processing
    - Error handling and recovery
    - Performance monitoring and metrics

Version: 1.0.0-enterprise
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from ldap_core_shared.ldif.processor import (
    LDIFEntry,
    LDIFProcessingConfig,
    LDIFProcessor,
)

if TYPE_CHECKING:
    from collections.abc import Generator


class TestLDIFProcessingConfig:
    """Test LDIF processing configuration."""

    def test_config_creation_with_defaults(self) -> None:
        """Test config creation with default values."""
        config = LDIFProcessingConfig()

        assert config.encoding == "utf-8"
        assert config.chunk_size == 1000
        assert config.max_entries == 100000
        assert config.validate_dn is True
        assert config.normalize_attributes is True
        assert config.preserve_binary is True
        assert config.error_tolerance == 10
        assert config.performance_monitoring is True
        assert config.memory_limit_mb == 375

    def test_config_creation_with_custom_values(self) -> None:
        """Test config creation with custom values."""
        config = LDIFProcessingConfig(
            encoding="latin-1",
            chunk_size=500,
            max_entries=50000,
            validate_dn=False,
            normalize_attributes=False,
            preserve_binary=False,
            error_tolerance=5,
            performance_monitoring=False,
            memory_limit_mb=256,
        )

        assert config.encoding == "latin-1"
        assert config.chunk_size == 500
        assert config.max_entries == 50000
        assert config.validate_dn is False
        assert config.normalize_attributes is False
        assert config.preserve_binary is False
        assert config.error_tolerance == 5
        assert config.performance_monitoring is False
        assert config.memory_limit_mb == 256

    def test_config_validation_errors(self) -> None:
        """Test config validation with invalid values."""
        # Test invalid chunk_size
        with pytest.raises(ValidationError):
            LDIFProcessingConfig(chunk_size=0)

        # Test invalid max_entries
        with pytest.raises(ValidationError):
            LDIFProcessingConfig(max_entries=0)

        # Test invalid error_tolerance
        with pytest.raises(ValidationError):
            LDIFProcessingConfig(error_tolerance=-1)

        # Test invalid memory_limit_mb
        with pytest.raises(ValidationError):
            LDIFProcessingConfig(memory_limit_mb=50)

    def test_config_immutability(self) -> None:
        """Test that config is immutable after creation."""
        config = LDIFProcessingConfig()

        # Should not be able to modify frozen model
        with pytest.raises(ValidationError):
            config.encoding = "ascii"  # type: ignore[misc]


class TestLDIFEntry:
    """Test LDIF entry model."""

    def test_entry_creation(self) -> None:
        """Test basic LDIF entry creation."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["test@example.com"],
            },
        )

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.attributes["cn"] == ["test"]
        assert entry.attributes["objectClass"] == ["person", "inetOrgPerson"]
        assert entry.attributes["mail"] == ["test@example.com"]
        assert entry.changetype is None
        assert entry.controls == []
        assert entry.entry_size_bytes == 0
        assert entry.validation_status == "valid"

    def test_entry_with_changetype_and_controls(self) -> None:
        """Test LDIF entry with changetype and controls."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
            changetype="add",
            controls=["1.2.3.4", "5.6.7.8"],
            entry_size_bytes=256,
            validation_status="validated",
        )

        assert entry.changetype == "add"
        assert entry.controls == ["1.2.3.4", "5.6.7.8"]
        assert entry.entry_size_bytes == 256
        assert entry.validation_status == "validated"

    def test_get_object_classes(self) -> None:
        """Test getting object classes from entry."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person", "inetOrgPerson"],
            },
        )

        object_classes = entry.get_object_classes()
        assert object_classes == ["person", "inetOrgPerson"]

    def test_get_object_classes_missing(self) -> None:
        """Test getting object classes when not present."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )

        object_classes = entry.get_object_classes()
        assert object_classes == []

    def test_has_attribute(self) -> None:
        """Test checking if entry has attribute."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "Mail": ["test@example.com"],  # Mixed case
            },
        )

        assert entry.has_attribute("cn") is True
        assert entry.has_attribute("CN") is True  # Case insensitive
        assert entry.has_attribute("mail") is True  # Case insensitive
        assert entry.has_attribute("Mail") is True
        assert entry.has_attribute("nonexistent") is False

    def test_get_attribute_values(self) -> None:
        """Test getting attribute values."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "Mail": ["test@example.com", "test2@example.com"],
            },
        )

        cn_values = entry.get_attribute_values("cn")
        assert cn_values == ["test"]

        mail_values = entry.get_attribute_values("mail")  # Case insensitive
        assert mail_values == ["test@example.com", "test2@example.com"]

        empty_values = entry.get_attribute_values("nonexistent")
        assert empty_values == []


class TestLDIFProcessor:
    """Test LDIF processor functionality."""

    @pytest.fixture
    def processor(self) -> LDIFProcessor:
        """Create test processor with default config."""
        return LDIFProcessor()

    @pytest.fixture
    def custom_processor(self) -> LDIFProcessor:
        """Create test processor with custom config."""
        config = LDIFProcessingConfig(
            chunk_size=100,
            validate_dn=False,
            normalize_attributes=False,
            error_tolerance=5,
        )
        return LDIFProcessor(config)

    @pytest.fixture
    def sample_ldif_content(self) -> str:
        """Create sample LDIF content for testing."""
        return """dn: cn=test1,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: test1
sn: User1
mail: test1@example.com

dn: cn=test2,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: test2
sn: User2
mail: test2@example.com

"""

    @pytest.fixture
    def temp_ldif_file(self, sample_ldif_content: str) -> Generator[Path, None, None]:
        """Create temporary LDIF file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(sample_ldif_content)
            temp_path = Path(f.name)

        yield temp_path

        # Cleanup
        temp_path.unlink(missing_ok=True)

    def test_processor_initialization_default(self) -> None:
        """Test processor initialization with default config."""
        processor = LDIFProcessor()

        assert processor.config.encoding == "utf-8"
        assert processor.config.chunk_size == 1000
        assert processor.performance_monitor is not None

    def test_processor_initialization_custom(self) -> None:
        """Test processor initialization with custom config."""
        config = LDIFProcessingConfig(chunk_size=500)
        processor = LDIFProcessor(config)

        assert processor.config.chunk_size == 500

    def test_parse_string_success(
        self,
        processor: LDIFProcessor,
        sample_ldif_content: str,
    ) -> None:
        """Test successful string parsing."""
        result = processor.parse_string(sample_ldif_content)

        assert result.success is True
        assert result.data is not None
        assert len(result.data) == 2
        assert result.operation == "parse_string"
        assert result.metadata is not None
        assert result.metadata["entries_count"] == 2
        assert result.metadata["content_length"] == len(sample_ldif_content)

        # Check first entry
        first_entry = result.data[0]
        assert first_entry.dn == "cn=test1,dc=example,dc=com"
        assert "person" in first_entry.get_object_classes()
        assert first_entry.get_attribute_values("cn") == ["test1"]

    def test_parse_string_empty_content(self, processor: LDIFProcessor) -> None:
        """Test parsing empty string content."""
        result = processor.parse_string("")

        assert result.success is False
        assert result.error_message == "LDIF content is empty"
        assert result.operation == "parse_string"

    def test_parse_string_whitespace_only(self, processor: LDIFProcessor) -> None:
        """Test parsing whitespace-only content."""
        result = processor.parse_string("   \n\t  ")

        assert result.success is False
        assert result.error_message == "LDIF content is empty"

    def test_parse_file_success(
        self,
        processor: LDIFProcessor,
        temp_ldif_file: Path,
    ) -> None:
        """Test successful file parsing."""
        result = processor.parse_file(temp_ldif_file)

        assert result.success is True
        assert result.data is not None
        assert len(result.data) == 2
        assert result.operation == "parse_file"
        assert result.metadata is not None
        assert result.metadata["entries_count"] == 2
        assert result.metadata["file_path"] == str(temp_ldif_file)

    def test_parse_file_not_found(self, processor: LDIFProcessor) -> None:
        """Test parsing non-existent file."""
        non_existent_file = Path("/non/existent/file.ldif")
        result = processor.parse_file(non_existent_file)

        assert result.success is False
        assert "File not found" in result.error_message
        assert result.operation == "parse_file"

    def test_parse_file_empty_file(self, processor: LDIFProcessor) -> None:
        """Test parsing empty file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            empty_file = Path(f.name)

        try:
            result = processor.parse_file(empty_file)

            assert result.success is False
            assert "File is empty" in result.error_message

        finally:
            empty_file.unlink(missing_ok=True)

    def test_stream_file(
        self,
        processor: LDIFProcessor,
        temp_ldif_file: Path,
    ) -> None:
        """Test file streaming functionality."""
        entries = list(processor.stream_file(temp_ldif_file))

        assert len(entries) == 2
        assert entries[0].dn == "cn=test1,dc=example,dc=com"
        assert entries[1].dn == "cn=test2,dc=example,dc=com"

    def test_stream_chunks(
        self,
        processor: LDIFProcessor,
        temp_ldif_file: Path,
    ) -> None:
        """Test chunked streaming functionality."""
        # Use small chunk size for testing
        processor.config = LDIFProcessingConfig(chunk_size=1)

        chunks = list(processor.stream_chunks(temp_ldif_file))

        assert len(chunks) == 2  # Two chunks of 1 entry each
        assert len(chunks[0]) == 1
        assert len(chunks[1]) == 1

    def test_get_performance_stats(self, processor: LDIFProcessor) -> None:
        """Test performance statistics retrieval."""
        # Parse some content to generate stats
        sample_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

"""
        processor.parse_string(sample_content)

        stats = processor.get_performance_stats()

        assert stats.entries_processed >= 1
        assert stats.processing_time_ms >= 0
        assert stats.entries_per_second >= 0
        assert stats.performance_grade in ["A+", "A", "B", "C"]
        assert stats.metadata is not None

    def test_normalize_attributes(self, processor: LDIFProcessor) -> None:
        """Test attribute normalization."""
        content = """dn: cn=test,dc=example,dc=com
ObjectClass: person
CN: test
Mail: test@example.com

"""
        result = processor.parse_string(content)

        assert result.success is True
        entry = result.data[0]

        # Attributes should be normalized to lowercase
        assert "objectclass" in entry.attributes
        assert "cn" in entry.attributes
        assert "mail" in entry.attributes

    def test_disable_attribute_normalization(
        self,
        custom_processor: LDIFProcessor,
    ) -> None:
        """Test disabled attribute normalization."""
        content = """dn: cn=test,dc=example,dc=com
ObjectClass: person
CN: test
Mail: test@example.com

"""
        result = custom_processor.parse_string(content)

        assert result.success is True
        entry = result.data[0]

        # Attributes should preserve original case
        assert "ObjectClass" in entry.attributes
        assert "CN" in entry.attributes
        assert "Mail" in entry.attributes

    def test_dn_validation(self, processor: LDIFProcessor) -> None:
        """Test DN validation functionality."""
        # Valid DN
        content_valid = """dn: cn=test,dc=example,dc=com
objectClass: person

"""
        result = processor.parse_string(content_valid)
        assert result.success is True

        # Invalid DN (no equals sign)
        content_invalid = """dn: invalid-dn-format
objectClass: person

"""
        result = processor.parse_string(content_invalid)
        # Should still succeed but entry might be skipped
        assert result.success is True

    def test_error_tolerance(self, processor: LDIFProcessor) -> None:
        """Test error tolerance handling."""
        # Create content with invalid entries
        invalid_content = """dn:
objectClass: person

dn:
objectClass: person

dn: cn=valid,dc=example,dc=com
objectClass: person
cn: valid

"""
        result = processor.parse_string(invalid_content)

        # Should succeed with valid entry
        assert result.success is True
        assert len(result.data) == 1
        assert result.data[0].dn == "cn=valid,dc=example,dc=com"

    @patch("ldap_core_shared.ldif.processor.ldif.LDIFRecordList")
    def test_parse_string_ldif_exception(
        self,
        mock_ldif_class: MagicMock,
        processor: LDIFProcessor,
    ) -> None:
        """Test handling of LDIF parsing exceptions."""
        # Mock LDIF parser to raise exception
        mock_parser = MagicMock()
        mock_parser.parse.side_effect = ValueError("LDIF parse error")
        mock_ldif_class.return_value = mock_parser

        result = processor.parse_string("dn: cn=test,dc=example,dc=com\n")

        assert result.success is False
        assert "Parse failed" in result.error_message

    def test_binary_data_handling(self, processor: LDIFProcessor) -> None:
        """Test handling of binary data in LDIF."""
        # Note: This is a simplified test - real binary data handling
        # would require proper base64 encoding in LDIF format
        content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test

"""
        result = processor.parse_string(content)

        assert result.success is True
        assert len(result.data) == 1

    def test_max_entries_limit(self, processor: LDIFProcessor) -> None:
        """Test maximum entries limit enforcement."""
        # Set very low limit
        processor.config = LDIFProcessingConfig(max_entries=1)

        content = """dn: cn=test1,dc=example,dc=com
objectClass: person
cn: test1

dn: cn=test2,dc=example,dc=com
objectClass: person
cn: test2

"""
        result = processor.parse_string(content)

        assert result.success is True
        # Should only process first entry due to limit
        assert len(result.data) == 1

    def test_entry_size_calculation(self, processor: LDIFProcessor) -> None:
        """Test entry size calculation."""
        content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
description: This is a longer description field

"""
        result = processor.parse_string(content)

        assert result.success is True
        entry = result.data[0]
        assert entry.entry_size_bytes > 0


@pytest.mark.benchmark(group="ldif_performance")
class TestLDIFProcessorPerformance:
    """Performance tests for LDIF processor."""

    @pytest.fixture
    def large_ldif_content(self) -> str:
        """Generate large LDIF content for performance testing."""
        entries = []
        for i in range(1000):
            entry = f"""dn: cn=user{i:04d},ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: user{i:04d}
sn: User{i:04d}
mail: user{i:04d}@example.com
description: Test user number {i:04d}

"""
            entries.append(entry)
        return "".join(entries)

    def test_parse_large_content_performance(
        self,
        large_ldif_content: str,
        benchmark: pytest.fixture,  # type: ignore[type-arg]
    ) -> None:
        """Benchmark parsing large LDIF content."""
        processor = LDIFProcessor()

        def parse_content() -> None:
            result = processor.parse_string(large_ldif_content)
            assert result.success is True
            assert len(result.data) == 1000

        benchmark(parse_content)

    def test_streaming_performance(
        self,
        large_ldif_content: str,
    ) -> None:
        """Test streaming performance with large content."""
        processor = LDIFProcessor()

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(large_ldif_content)
            temp_path = Path(f.name)

        try:
            entries = list(processor.stream_file(temp_path))
            assert len(entries) == 1000

            # Test chunked streaming
            chunks = list(processor.stream_chunks(temp_path))
            total_entries = sum(len(chunk) for chunk in chunks)
            assert total_entries == 1000

        finally:
            temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    # Run tests with coverage
    pytest.main(
        [
            __file__,
            "-v",
            "--cov=ldap_core_shared.ldif.processor",
            "--cov-report=term-missing",
            "--cov-report=html",
        ],
    )
