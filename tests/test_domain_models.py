from typing import Any

"""
Tests for domain models.

Comprehensive tests for LDAP domain models to ensure reliability
and correctness across all shared components.
"""

from datetime import datetime
from pathlib import Path

import pytest

from ldap_core_shared.domain.models import (
    EntryProcessingResult,
    LDAPConnectionConfig,
    LDAPEntry,
    LDIFGenerationResult,
    MigrationReport,
    MigrationStage,
    MigrationStats,
    ValidationResult,
)


class TestLDAPConnectionConfig:
    """Test LDAP connection configuration."""

    def test_valid_config_creation(self) -> Any:
        """Test creating valid LDAP connection config."""
        config = LDAPConnectionConfig(
            host="ldap.example.com",
            port=389,
            bind_dn="cn=admin,dc=example,dc=com",
            password="secret",
            base_dn="dc=example,dc=com",
        )

        assert config.host == "ldap.example.com"
        assert config.port == 389
        assert config.bind_dn == "cn=admin,dc=example,dc=com"
        assert config.password == "secret"
        assert config.base_dn == "dc=example,dc=com"
        assert config.use_ssl is False

    def test_ssl_config(self) -> Any:
        """Test SSL configuration."""
        config = LDAPConnectionConfig(
            host="ldaps.example.com",
            port=636,
            bind_dn="cn=admin,dc=example,dc=com",
            password="secret",
            base_dn="dc=example,dc=com",
            use_ssl=True,
        )

        assert config.port == 636
        assert config.use_ssl is True

    def test_invalid_port_validation(self) -> Any:
        """Test port validation."""
        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            LDAPConnectionConfig(
                host="ldap.example.com",
                port=0,
                bind_dn="cn=admin,dc=example,dc=com",
                password="secret",
                base_dn="dc=example,dc=com",
            )

        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            LDAPConnectionConfig(
                host="ldap.example.com",
                port=70000,
                bind_dn="cn=admin,dc=example,dc=com",
                password="secret",
                base_dn="dc=example,dc=com",
            )


class TestLDAPEntry:
    """Test LDAP entry model."""

    def test_valid_entry_creation(self) -> Any:
        """Test creating valid LDAP entry."""
        entry = LDAPEntry(
            dn="cn=john,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["john@example.com"],
            },
        )

        assert entry.dn == "cn=john,ou=users,dc=example,dc=com"
        assert entry.attributes["cn"] == ["john"]
        assert "person" in entry.attributes["objectClass"]

    def test_empty_dn_validation(self) -> Any:
        """Test DN validation."""
        with pytest.raises(ValueError, match="DN cannot be empty"):
            LDAPEntry(dn="", attributes={})

        with pytest.raises(ValueError, match="DN cannot be empty"):
            LDAPEntry(dn="   ", attributes={})

    def test_get_attribute_case_insensitive(self) -> Any:
        """Test case-insensitive attribute retrieval."""
        entry = LDAPEntry(
            dn="cn=john,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john"],
                "Mail": ["john@example.com"],
                "OBJECTCLASS": ["person"],
            },
        )

        assert entry.get_attribute("cn") == ["john"]
        assert entry.get_attribute("CN") == ["john"]
        assert entry.get_attribute("mail") == ["john@example.com"]
        assert entry.get_attribute("MAIL") == ["john@example.com"]
        assert entry.get_attribute("objectclass") == ["person"]
        assert entry.get_attribute("nonexistent") is None

    def test_has_object_class(self) -> Any:
        """Test object class checking."""
        entry = LDAPEntry(
            dn="cn=john,ou=users,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson", "organizationalPerson"]
            },
        )

        assert entry.has_object_class("person") is True
        assert entry.has_object_class("PERSON") is True
        assert entry.has_object_class("inetOrgPerson") is True
        assert entry.has_object_class("group") is False

        # Test entry without objectClass
        entry_no_oc = LDAPEntry(
            dn="cn=test,dc=example,dc=com", attributes={"cn": ["test"]}
        )
        assert entry_no_oc.has_object_class("person") is False


class TestMigrationStats:
    """Test migration statistics."""

    def test_empty_stats(self) -> Any:
        """Test empty statistics."""
        stats = MigrationStats()

        assert stats.total_processed == 0
        assert stats.successful == 0
        assert stats.skipped == 0
        assert stats.failed == 0
        assert stats.errors == []
        assert stats.success_rate == 0.0

    def test_success_rate_calculation(self) -> Any:
        """Test success rate calculation."""
        stats = MigrationStats(total_processed=100, successful=80, skipped=15, failed=5)

        assert stats.success_rate == 95.0  # (80 + 15) / 100 * 100

    def test_success_rate_with_failures(self) -> Any:
        """Test success rate with failures."""
        stats = MigrationStats(
            total_processed=100, successful=70, skipped=10, failed=20
        )

        assert stats.success_rate == 80.0  # (70 + 10) / 100 * 100


class TestMigrationStage:
    """Test migration stage model."""

    def test_valid_stage_creation(self) -> Any:
        """Test creating valid migration stage."""
        stage = MigrationStage(
            name="Schema Migration",
            filename="01_schema.ldif",
            description="Migrate schema definitions",
            critical=True,
            order=1,
        )

        assert stage.name == "Schema Migration"
        assert stage.filename == "01_schema.ldif"
        assert stage.description == "Migrate schema definitions"
        assert stage.critical is True
        assert stage.order == 1

    def test_negative_order_validation(self) -> Any:
        """Test order validation."""
        with pytest.raises(ValueError, match="Order must be non-negative"):
            MigrationStage(
                name="Test", filename="test.ldif", description="Test stage", order=-1
            )


class TestMigrationReport:
    """Test migration report model."""

    def test_duration_calculation(self) -> Any:
        """Test duration calculation."""
        start_time = datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime(2024, 1, 1, 10, 5, 30)

        report = MigrationReport(
            start_time=start_time, end_time=end_time, config={"test": "config"}
        )

        assert report.duration == 330.0  # 5 minutes 30 seconds

    def test_duration_none_when_not_finished(self) -> Any:
        """Test duration is None when migration not finished."""
        report = MigrationReport(start_time=datetime.now(), config={"test": "config"})

        assert report.duration is None


class TestLDIFGenerationResult:
    """Test LDIF generation result."""

    def test_successful_generation(self) -> Any:
        """Test successful LDIF generation result."""
        result = LDIFGenerationResult(
            stage="hierarchy",
            filename="00_hierarchy.ldif",
            file_path=Path("/tmp/00_hierarchy.ldif"),
            success=True,
            lines_generated=150,
        )

        assert result.stage == "hierarchy"
        assert result.filename == "00_hierarchy.ldif"
        assert result.success is True
        assert result.lines_generated == 150
        assert result.error_message is None

    def test_failed_generation(self) -> Any:
        """Test failed LDIF generation result."""
        result = LDIFGenerationResult(
            stage="data",
            filename="02_data.ldif",
            success=False,
            error_message="Schema validation failed",
        )

        assert result.success is False
        assert result.error_message == "Schema validation failed"
        assert result.lines_generated == 0


class TestValidationResult:
    """Test validation result model."""

    def test_successful_validation(self) -> Any:
        """Test successful validation result."""
        result = ValidationResult(
            check_name="Schema Compatibility",
            success=True,
            message="All schemas are compatible",
            count=25,
            details={"compatible_schemas": 25, "incompatible_schemas": 0},
        )

        assert result.check_name == "Schema Compatibility"
        assert result.success is True
        assert result.message == "All schemas are compatible"
        assert result.count == 25
        assert result.details["compatible_schemas"] == 25

    def test_failed_validation(self) -> Any:
        """Test failed validation result."""
        result = ValidationResult(
            check_name="Connectivity Test",
            success=False,
            message="Connection timeout",
            details={"error_code": "TIMEOUT", "host": "ldap.example.com"},
        )

        assert result.success is False
        assert result.message == "Connection timeout"
        assert result.details["error_code"] == "TIMEOUT"


class TestEntryProcessingResult:
    """Test entry processing result."""

    def test_successful_processing(self) -> Any:
        """Test successful entry processing."""
        result = EntryProcessingResult(
            dn="cn=john,ou=users,dc=example,dc=com",
            success=True,
            action="add",
            message="Entry added successfully",
            original_attributes={"cn": ["john"]},
            processed_attributes={"cn": ["john"], "objectClass": ["person"]},
        )

        assert result.dn == "cn=john,ou=users,dc=example,dc=com"
        assert result.success is True
        assert result.action == "add"
        assert result.message == "Entry added successfully"
        assert result.original_attributes["cn"] == ["john"]
        assert "objectClass" in result.processed_attributes

    def test_skipped_processing(self) -> Any:
        """Test skipped entry processing."""
        result = EntryProcessingResult(
            dn="cn=admin,dc=example,dc=com",
            success=True,
            action="skip",
            message="Entry already exists",
        )

        assert result.action == "skip"
        assert result.success is True
        assert result.message == "Entry already exists"

    def test_failed_processing(self) -> Any:
        """Test failed entry processing."""
        result = EntryProcessingResult(
            dn="cn=invalid,dc=example,dc=com",
            success=False,
            action="error",
            message="Schema validation failed",
        )

        assert result.success is False
        assert result.action == "error"
        assert result.message == "Schema validation failed"
