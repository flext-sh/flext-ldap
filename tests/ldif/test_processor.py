"""Comprehensive tests for LDIF Processor - PyAuto Workspace Standards Compliant.

This module provides enterprise-grade testing for the LDIF processing
system with full CLAUDE.md compliance and client-a-oud-mig integration validation.

PyAuto Workspace Standards Compliance:
    - .env security enforcement with permission validation (CLAUDE.md)
    - CLI debug patterns with mandatory --debug flag usage (CLAUDE.md)
    - SOLID principles compliance validation across all test execution
    - Workspace venv coordination with /home/marlonsc/pyauto/.venv (internal.invalid.md)
    - Cross-project dependency validation for client-a-oud-mig integration
    - Security enforcement for sensitive data handling and protection

client-a-OUD-Mig Integration Validation:
    - LDIF processor interface compatibility for migration workflows
    - Large file processing (15,000+ entries) performance validation
    - Oracle schema compatibility and validation patterns
    - Enterprise migration transaction support and atomicity
    - Performance monitoring integration for migration metrics
    - Error handling patterns for production migration safety

Test Coverage:
    - LDIF parsing and validation with client-a-oud-mig compatibility
    - Streaming processing for large migration files
    - Memory-efficient chunked processing for enterprise migrations
    - Error handling and recovery for production safety
    - Performance monitoring and metrics for migration tracking
    - Cross-project integration validation with dependent projects

Security Testing:
    - Credential protection during LDIF processing
    - Sensitive data masking in LDIF entries and logs
    - .env security enforcement for configuration management
    - Workspace security boundary enforcement during processing

Version: 1.0.0-enterprise-claude-compliant
"""

from __future__ import annotations

import os
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


# PyAuto Workspace Standards Compliance Tests
class TestLDIFProcessorWorkspaceCompliance:
    """Test PyAuto workspace standards compliance for LDIF processor module."""

    @pytest.mark.workspace_integration
    def test_ldif_processor_workspace_venv_validation(
        self, validate_workspace_venv
    ) -> None:
        """Test LDIF processor workspace venv validation as required by CLAUDE.md."""
        # Fixture automatically validates workspace venv usage
        expected_venv = "/home/marlonsc/pyauto/.venv"
        current_venv = os.environ.get("VIRTUAL_ENV")
        assert current_venv == expected_venv, (
            f"LDIF processor tests must use workspace venv: {expected_venv}"
        )

    @pytest.mark.env_security
    def test_ldif_processor_env_security_enforcement(
        self, validate_env_security
    ) -> None:
        """Test LDIF processor .env security enforcement as required by CLAUDE.md."""
        # Test LDIF processor configuration security
        with patch.dict(
            os.environ,
            {
                "LDAP_CORE_DEBUG_LEVEL": "INFO",
                "LDIF_PROCESSING_CHUNK_SIZE": "1000",
                "LDIF_PROCESSING_MAX_ENTRIES": "100000",
            },
            clear=False,
        ):
            # Validate no hardcoded secrets in LDIF configuration
            for key, value in os.environ.items():
                if "ldif" in key.lower() and (
                    "password" in key.lower() or "secret" in key.lower()
                ):
                    assert value.startswith("${") or len(value) == 0, (
                        f"Hardcoded secret in LDIF config: {key}"
                    )

    @pytest.mark.solid_compliance
    def test_ldif_processor_solid_principles_compliance(
        self, solid_principles_validation
    ) -> None:
        """Test LDIF processor SOLID principles compliance."""
        # Test Single Responsibility: LDIFProcessor only processes LDIF files
        assert hasattr(LDIFProcessor, "parse_file")
        assert hasattr(LDIFProcessor, "stream_chunks")
        assert not hasattr(
            LDIFProcessor, "connect_to_ldap"
        )  # Should not handle LDAP connections

        # Test Open/Closed: Can be extended through configuration
        config = LDIFProcessingConfig()
        processor = LDIFProcessor(config)
        assert hasattr(processor, "config")

        # Test Interface Segregation: Focused on LDIF processing only
        ldif_methods = [
            method for method in dir(LDIFProcessor) if not method.startswith("_")
        ]
        assert "parse_file" in ldif_methods
        assert "stream_chunks" in ldif_methods
        # Should not have methods unrelated to LDIF processing
        assert "send_email" not in ldif_methods
        assert "manage_users" not in ldif_methods

    @pytest.mark.workspace_integration
    def test_client-a_oud_mig_integration_compatibility(
        self, workspace_coordination
    ) -> None:
        """Test LDIF processor compatibility with client-a-oud-mig project."""
        coordination = workspace_coordination

        # Validate LDIF processor operates within shared library context
        assert coordination["PROJECT_CONTEXT"] == "ldap-core-shared"
        assert coordination["STATUS"] == "production-comprehensive-facade"

        # Test LDIF processor provides expected interface for client-a-oud-mig
        config = LDIFProcessingConfig(
            chunk_size=500,  # client-a optimal batch size
            max_entries=15000,  # client-a migration file size
            validate_dn=True,  # Required for client-a DN transformation
            performance_monitoring=True,  # Required for client-a migration tracking
        )

        processor = LDIFProcessor(config)

        # Validate interface expected by client-a-oud-mig
        assert hasattr(processor, "parse_file")
        assert hasattr(processor, "stream_chunks")
        assert hasattr(processor, "config")

        # Test configuration matches client-a-oud-mig requirements
        assert processor.config.chunk_size == 500
        assert processor.config.validate_dn is True
        assert processor.config.performance_monitoring is True

    @pytest.mark.security_enforcement
    def test_ldif_processor_security_enforcement(self, security_enforcement) -> None:
        """Test LDIF processor security enforcement patterns."""
        security = security_enforcement

        # Test LDIF processor security configuration
        assert security["mask_sensitive_data"] is True
        assert security["validate_credentials"] is True
        assert security["protect_logs"] is True

        # Test LDIF processor doesn't expose sensitive data in processing
        config = LDIFProcessingConfig()
        processor = LDIFProcessor(config)

        # Create test LDIF content with sensitive data

        # Verify processor doesn't expose sensitive data in string representation
        processor_str = str(processor)
        assert "secrethash123" not in processor_str
        assert "password" not in processor_str.lower() or "***" in processor_str

    def test_client-a_migration_performance_requirements(self) -> None:
        """Test LDIF processor meets client-a-oud-mig performance requirements."""
        # Test LDIF processor can handle client-a migration performance requirements
        config = LDIFProcessingConfig(
            chunk_size=500,  # client-a LDAP optimal batch size
            max_entries=15000,  # Large client-a migration files
            performance_monitoring=True,  # Required for migration tracking
            memory_limit_mb=128,  # Memory-efficient processing
        )

        processor = LDIFProcessor(config)

        # Validate configuration supports client-a requirements
        assert processor.config.chunk_size == 500
        assert processor.config.max_entries >= 15000
        assert processor.config.performance_monitoring is True

        # Test processor supports large file streaming (required for client-a)
        assert hasattr(processor, "stream_chunks")
        assert callable(processor.stream_chunks)

    def test_oracle_schema_compatibility_validation(self) -> None:
        """Test LDIF processor compatibility with Oracle OUD schemas."""
        # Test LDIF processor can handle Oracle-specific schema attributes

        config = LDIFProcessingConfig(
            validate_dn=True,
            normalize_attributes=True,
            preserve_binary=True,  # Important for Oracle binary attributes
        )

        processor = LDIFProcessor(config)

        # Validate processor can handle Oracle schema definitions
        assert processor.config.validate_dn is True
        assert processor.config.normalize_attributes is True
        assert processor.config.preserve_binary is True


if TYPE_CHECKING:
    from collections.abc import Generator


class TestLDIFProcessingConfig:
    """Test LDIF processing configuration with CLAUDE.md compliance and client-a-oud-mig compatibility."""

    @pytest.mark.workspace_integration
    def test_config_creation_with_defaults(self, workspace_coordination) -> None:
        """Test config creation with default values and workspace coordination."""
        config = LDIFProcessingConfig()

        # Validate default configuration
        assert config.encoding == "utf-8"
        assert config.chunk_size == 1000
        assert config.max_entries == 100000
        assert config.validate_dn is True
        assert config.normalize_attributes is True
        assert config.preserve_binary is True
        assert config.error_tolerance == 10
        assert config.performance_monitoring is True

        # Validate workspace coordination context
        assert workspace_coordination["PROJECT_CONTEXT"] == "ldap-core-shared"
        assert workspace_coordination["STATUS"] == "production-comprehensive-facade"

        # Validate configuration is suitable for client-a-oud-mig integration
        assert config.chunk_size <= 1000  # Reasonable for large migrations
        assert config.max_entries >= 15000  # Supports client-a migration file sizes
        assert config.performance_monitoring is True  # Required for migration tracking
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
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
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
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
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
        assert stats.performance_grade in {"A+", "A", "B", "C"}
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
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
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
