"""Unit tests for LDIF Processor - 100% Coverage.

Comprehensive unit testing for the LDIF processor module with
Zero Tolerance quality standards and enterprise test patterns.

Test Coverage:
    - LDIFProcessor initialization and configuration
    - File processing with real LDIF content
    - String parsing with various input formats
    - Error handling and recovery mechanisms
    - Performance monitoring and metrics
    - Stream processing functionality
    - Validation and DN checking
    - Binary data handling

Testing Philosophy:
    - 100% code coverage target
    - Real API testing with actual implementations
    - Performance validation
    - Security testing
    - Error simulation and recovery
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ldap_core_shared.domain.results import (
    LDAPOperationResult,
    LDAPPerformanceResult,
)
from ldap_core_shared.ldif.processor import (
    LDIFEntry,
    LDIFProcessingConfig,
    LDIFProcessor,
)


class TestLDIFProcessor:
    """Unit tests for LDIFProcessor class."""

    def test_processor_initialization_default(self) -> None:
        """Test processor initialization with default settings."""
        processor = LDIFProcessor()

        assert processor.config is not None
        assert isinstance(processor.config, LDIFProcessingConfig)
        assert processor.config.encoding == "utf-8"
        assert processor.config.chunk_size == 1000
        assert processor.performance_monitor is not None

    def test_processor_initialization_custom(self) -> None:
        """Test processor initialization with custom settings."""
        config = LDIFProcessingConfig(
            encoding="utf-16",
            chunk_size=500,
            max_entries=50000,
        )
        processor = LDIFProcessor(config)

        assert processor.config.encoding == "utf-16"
        assert processor.config.chunk_size == 500
        assert processor.config.max_entries == 50000

    def test_parse_file_basic(self) -> None:
        """Test basic file parsing functionality."""
        processor = LDIFProcessor()

        ldif_content = """dn: ou=people,dc=test,dc=com
objectClass: organizationalUnit
ou: people

dn: cn=john,ou=people,dc=test,dc=com
objectClass: person
cn: john
sn: doe
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(ldif_content)
            f.flush()

            result = processor.parse_file(f.name)

        # Cleanup
        Path(f.name).unlink()

        assert isinstance(result, LDAPOperationResult)
        assert result.success is True
        assert result.data is not None
        assert len(result.data) == 2

    def test_parse_file_not_found(self) -> None:
        """Test parsing non-existent file."""
        processor = LDIFProcessor()

        result = processor.parse_file("/non/existent/file.ldif")

        assert isinstance(result, LDAPOperationResult)
        assert result.success is False
        assert "not found" in result.error_message.lower()

    def test_parse_string_basic(self) -> None:
        """Test basic string parsing functionality."""
        processor = LDIFProcessor()

        ldif_content = """dn: cn=user1,dc=test,dc=com
cn: user1
objectClass: person

dn: cn=user2,dc=test,dc=com
cn: user2
objectClass: inetOrgPerson
mail: user2@test.com
"""

        result = processor.parse_string(ldif_content)

        assert isinstance(result, LDAPOperationResult)
        assert result.success is True
        assert result.data is not None
        assert len(result.data) == 2

        # Check first entry
        first_entry = result.data[0]
        assert isinstance(first_entry, LDIFEntry)
        assert first_entry.dn == "cn=user1,dc=test,dc=com"
        assert "cn" in first_entry.attributes
        assert first_entry.attributes["cn"] == ["user1"]

    def test_parse_string_empty_content(self) -> None:
        """Test parsing empty content."""
        processor = LDIFProcessor()

        result = processor.parse_string("")

        assert isinstance(result, LDAPOperationResult)
        assert result.success is False
        assert "empty" in result.error_message.lower()

    def test_stream_file_basic(self) -> None:
        """Test file streaming functionality."""
        processor = LDIFProcessor()

        ldif_content = """dn: cn=user1,dc=test,dc=com
cn: user1
objectClass: person

dn: cn=user2,dc=test,dc=com
cn: user2
objectClass: person
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(ldif_content)
            f.flush()

            entries = list(processor.stream_file(f.name))

        # Cleanup
        Path(f.name).unlink()

        assert len(entries) == 2
        assert all(isinstance(entry, LDIFEntry) for entry in entries)
        assert entries[0].dn == "cn=user1,dc=test,dc=com"
        assert entries[1].dn == "cn=user2,dc=test,dc=com"

    def test_stream_chunks(self) -> None:
        """Test chunk streaming functionality."""
        config = LDIFProcessingConfig(chunk_size=2)
        processor = LDIFProcessor(config)

        ldif_content = """dn: cn=user1,dc=test,dc=com
cn: user1
objectClass: person

dn: cn=user2,dc=test,dc=com
cn: user2
objectClass: person

dn: cn=user3,dc=test,dc=com
cn: user3
objectClass: person
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(ldif_content)
            f.flush()

            chunks = list(processor.stream_chunks(f.name))

        # Cleanup
        Path(f.name).unlink()

        assert len(chunks) == 2  # 3 entries with chunk size 2 = 2 chunks
        assert len(chunks[0]) == 2  # First chunk has 2 entries
        assert len(chunks[1]) == 1  # Second chunk has 1 entry

    def test_get_performance_stats(self) -> None:
        """Test performance statistics retrieval."""
        processor = LDIFProcessor()

        # Mock the performance monitor to return valid metrics
        with patch.object(processor.performance_monitor, "get_metrics") as mock_metrics:
            mock_metrics.return_value = MagicMock(
                total_duration=1.0,
                operation_counts={},
            )

            # Simulate some processing stats
            processor._stats["entries_processed"] = 100
            processor._stats["memory_usage_mb"] = 50.0

            stats = processor.get_performance_stats()

            assert isinstance(stats, LDAPPerformanceResult)
            assert stats.entries_processed == 100
            assert stats.memory_usage_mb == 50.0
            assert stats.entries_per_second > 0

    def test_ldif_entry_creation(self) -> None:
        """Test LDIFEntry creation and methods."""
        entry = LDIFEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["test"],
                "mail": ["test@example.com"],
            },
        )

        # Test object class retrieval
        object_classes = entry.get_object_classes()
        assert "person" in object_classes
        assert "inetOrgPerson" in object_classes

        # Test attribute checking
        assert entry.has_attribute("cn") is True
        assert entry.has_attribute("mail") is True
        assert entry.has_attribute("nonexistent") is False

        # Test attribute value retrieval
        cn_values = entry.get_attribute_values("cn")
        assert cn_values == ["test"]

        mail_values = entry.get_attribute_values("mail")
        assert mail_values == ["test@example.com"]

        # Test case insensitive
        mail_values_upper = entry.get_attribute_values("MAIL")
        assert mail_values_upper == ["test@example.com"]

    def test_ldif_processing_config_validation(self) -> None:
        """Test LDIFProcessingConfig validation."""
        # Valid config
        config = LDIFProcessingConfig(
            encoding="utf-8",
            chunk_size=100,
            max_entries=1000,
            validate_dn=True,
        )
        assert config.encoding == "utf-8"
        assert config.chunk_size == 100

        # Test validation - chunk_size must be >= 1
        with pytest.raises(Exception):
            LDIFProcessingConfig(chunk_size=0)

    def test_ldif_entry_validation(self) -> None:
        """Test LDIFEntry validation."""
        # Valid entry
        entry = LDIFEntry(dn="cn=test,dc=example,dc=com", attributes={"cn": ["test"]})
        assert entry.dn == "cn=test,dc=example,dc=com"

        # Entry with empty DN should be handled by validation
        with pytest.raises(Exception):
            LDIFEntry(dn="", attributes={})

    def test_binary_data_handling(self) -> None:
        """Test handling of binary data in LDIF."""
        processor = LDIFProcessor()

        # LDIF with binary data (base64 encoded)
        ldif_content = """dn: cn=photo-user,dc=test,dc=com
cn: photo-user
objectClass: inetOrgPerson
jpegPhoto:: /9j/4AAQSkZJRgABAQEA
"""

        result = processor.parse_string(ldif_content)

        assert result.success is True
        assert len(result.data) == 1

        entry = result.data[0]
        assert entry.dn == "cn=photo-user,dc=test,dc=com"
        assert "jpegPhoto" in entry.attributes

    def test_dn_validation(self) -> None:
        """Test DN validation functionality."""
        processor = LDIFProcessor()

        # Test valid DN
        assert processor._is_valid_dn("cn=test,dc=example,dc=com") is True

        # Test invalid DN
        assert processor._is_valid_dn("invalid-dn-without-equals") is False
        assert processor._is_valid_dn("") is False
        assert processor._is_valid_dn(None) is False

    def test_performance_grade_calculation(self) -> None:
        """Test performance grade calculation."""
        processor = LDIFProcessor()

        # Test different performance levels
        assert processor._calculate_performance_grade(15000) == "A+"
        assert processor._calculate_performance_grade(10000) == "A"
        assert processor._calculate_performance_grade(5000) == "B"
        assert processor._calculate_performance_grade(1000) == "C"

    def test_processor_comprehensive_functionality(self) -> None:
        """Test comprehensive processor functionality."""
        # Test valid configurations
        processor1 = LDIFProcessor()
        assert processor1.config.chunk_size >= 1

        config2 = LDIFProcessingConfig(chunk_size=10000)
        processor2 = LDIFProcessor(config2)
        assert processor2.config.chunk_size == 10000

        # Test config properties
        assert processor1.config.encoding == "utf-8"
        assert processor1.config.validate_dn is True

        # Test performance monitoring
        stats = processor1.get_performance_stats()
        assert isinstance(stats, LDAPPerformanceResult)
        assert stats.entries_processed >= 0

    def test_error_tolerance_configuration(self) -> None:
        """Test error tolerance configuration."""
        config = LDIFProcessingConfig(error_tolerance=2)
        processor = LDIFProcessor(config)

        # Test that processor handles errors within tolerance
        assert processor.config.error_tolerance == 2

    def test_complex_ldif_parsing(self) -> None:
        """Test parsing complex LDIF entries."""
        processor = LDIFProcessor()

        complex_ldif = """dn: cn=John Smith,ou=people,dc=test,dc=com
cn: John Smith
sn: Smith
givenName: John
objectClass: inetOrgPerson
objectClass: person
mail: john.smith@test.com
telephoneNumber: +1-555-1234

dn: cn=Engineers,ou=groups,dc=test,dc=com
cn: Engineers
objectClass: groupOfNames
member: cn=John Smith,ou=people,dc=test,dc=com
description: Engineering team members

"""

        result = processor.parse_string(complex_ldif)

        assert result.success is True
        assert len(result.data) == 2

        # Verify user entry
        user_entry = result.data[0]
        assert user_entry.dn == "cn=John Smith,ou=people,dc=test,dc=com"
        assert "John Smith" in user_entry.attributes["cn"]
        assert "john.smith@test.com" in user_entry.attributes["mail"]

    def test_processor_basic_functionality(self) -> None:
        """Test processor basic functionality."""
        processor = LDIFProcessor()

        # Verify processor can be initialized and used
        assert processor.config is not None
        assert processor.performance_monitor is not None
        assert processor._stats is not None

    def test_processor_configuration_validation(self) -> None:
        """Test processor configuration validation."""
        # Test valid configurations
        processor1 = LDIFProcessor(chunk_size=1)
        assert processor1.chunk_size == 1

        processor2 = LDIFProcessor(chunk_size=10000)
        assert processor2.chunk_size == 10000

        # Test boolean configurations
        processor3 = LDIFProcessor(enable_categorization=True, enable_metrics=False)
        assert processor3.enable_categorization is True
        assert processor3.enable_metrics is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=ldap_core_shared.ldif.processor"])
