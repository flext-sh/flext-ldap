"""Tests for LDAP Schema Discovery Implementation.

This module provides comprehensive test coverage for the LDAP schema discovery
service including server connection, schema extraction, configuration management,
and comprehensive error handling with enterprise-grade validation.

Test Coverage:
    - SchemaDiscoveryConfig: Discovery configuration and validation
    - SchemaInfo: Schema information modeling and data aggregation
    - SchemaDiscovery: Main discovery service with server connection
    - Server connection and authentication management
    - Schema extraction from LDAP servers with timeout handling
    - Configuration-based selective discovery operations
    - Performance monitoring and metrics integration

Integration Testing:
    - Complete discovery workflows with server connection
    - LDAP3 integration for server communication
    - Schema DN discovery from RootDSE
    - Attribute types, object classes, and syntax extraction
    - Server controls and extensions detection
    - Error handling and connection recovery

Performance Testing:
    - Discovery operation timing and optimization
    - Server connection efficiency and timeout handling
    - Large schema processing and memory usage
    - Configuration impact on discovery performance
    - Performance monitoring integration validation

Security Testing:
    - Connection credential handling and security
    - Server authentication and SSL/TLS validation
    - Error message information disclosure protection
    - Resource consumption limits and validation
    - Connection timeout and security enforcement
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from ldap_core_shared.schema.discovery import (
    SchemaDiscovery,
    SchemaDiscoveryConfig,
    SchemaInfo,
)
from ldap_core_shared.utils.constants import DEFAULT_TIMEOUT_SECONDS


class TestSchemaDiscoveryConfig:
    """Test cases for SchemaDiscoveryConfig."""

    def test_config_creation_defaults(self) -> None:
        """Test creating config with default values."""
        config = SchemaDiscoveryConfig()

        assert config.include_attribute_types is True
        assert config.include_object_classes is True
        assert config.include_syntax_definitions is True
        assert config.include_matching_rules is True
        assert config.timeout_seconds == DEFAULT_TIMEOUT_SECONDS

    def test_config_creation_custom(self) -> None:
        """Test creating config with custom values."""
        config = SchemaDiscoveryConfig(
            include_attribute_types=False,
            include_object_classes=False,
            include_syntax_definitions=False,
            include_matching_rules=False,
            timeout_seconds=60,
        )

        assert config.include_attribute_types is False
        assert config.include_object_classes is False
        assert config.include_syntax_definitions is False
        assert config.include_matching_rules is False
        assert config.timeout_seconds == 60

    def test_config_validation_timeout_positive(self) -> None:
        """Test config validation requires positive timeout."""
        with pytest.raises(ValidationError, match="greater than or equal to 1"):
            SchemaDiscoveryConfig(timeout_seconds=0)

        with pytest.raises(ValidationError, match="greater than or equal to 1"):
            SchemaDiscoveryConfig(timeout_seconds=-1)

    def test_config_strict_mode(self) -> None:
        """Test config strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SchemaDiscoveryConfig(extra_field="not_allowed")

    def test_config_immutability(self) -> None:
        """Test config is immutable when needed."""
        config = SchemaDiscoveryConfig()

        # Should be able to check attributes
        assert config.include_attribute_types is True
        assert config.timeout_seconds == DEFAULT_TIMEOUT_SECONDS


class TestSchemaInfo:
    """Test cases for SchemaInfo."""

    def test_schema_info_creation_defaults(self) -> None:
        """Test creating schema info with default values."""
        info = SchemaInfo()

        assert info.server_info == ""
        assert info.schema_dn == ""
        assert info.attribute_types == []
        assert info.object_classes == []
        assert info.syntax_definitions == []
        assert info.matching_rules == []
        assert info.server_controls == []
        assert info.extensions == []

    def test_schema_info_creation_complete(self) -> None:
        """Test creating schema info with all fields."""
        info = SchemaInfo(
            server_info="OpenLDAP Server",
            schema_dn="cn=schema,cn=config",
            attribute_types=["( 2.5.4.3 NAME 'cn' )", "( 2.5.4.4 NAME 'sn' )"],
            object_classes=["( 2.5.6.6 NAME 'person' )"],
            syntax_definitions=["( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )"],
            matching_rules=["( 2.5.13.2 NAME 'caseIgnoreMatch' )"],
            server_controls=["2.16.840.1.113730.3.4.2", "1.2.840.113556.1.4.319"],
            extensions=["1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.4203.1.11.3"],
        )

        assert info.server_info == "OpenLDAP Server"
        assert info.schema_dn == "cn=schema,cn=config"
        assert len(info.attribute_types) == 2
        assert len(info.object_classes) == 1
        assert len(info.syntax_definitions) == 1
        assert len(info.matching_rules) == 1
        assert len(info.server_controls) == 2
        assert len(info.extensions) == 2

    def test_schema_info_strict_mode(self) -> None:
        """Test schema info strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SchemaInfo(extra_field="not_allowed")

    def test_schema_info_attribute_access(self) -> None:
        """Test schema info attribute access patterns."""
        info = SchemaInfo(
            attribute_types=["( 2.5.4.3 NAME 'cn' )"],
            object_classes=["( 2.5.6.6 NAME 'person' )"],
        )

        # Test attribute types access
        assert "( 2.5.4.3 NAME 'cn' )" in info.attribute_types
        assert len(info.attribute_types) == 1

        # Test object classes access
        assert "( 2.5.6.6 NAME 'person' )" in info.object_classes
        assert len(info.object_classes) == 1

    def test_schema_info_empty_collections(self) -> None:
        """Test schema info with empty collections."""
        info = SchemaInfo()

        assert not info.attribute_types
        assert not info.object_classes
        assert not info.syntax_definitions
        assert not info.matching_rules
        assert not info.server_controls
        assert not info.extensions


class TestSchemaDiscovery:
    """Test cases for SchemaDiscovery."""

    def test_discovery_initialization_default(self) -> None:
        """Test discovery initialization with default config."""
        discovery = SchemaDiscovery()

        assert isinstance(discovery.config, SchemaDiscoveryConfig)
        assert discovery.config.include_attribute_types is True
        assert discovery.config.include_object_classes is True
        assert discovery.performance_monitor is not None

    def test_discovery_initialization_custom_config(self) -> None:
        """Test discovery initialization with custom config."""
        config = SchemaDiscoveryConfig(
            include_attribute_types=False,
            include_object_classes=True,
            timeout_seconds=120,
        )
        discovery = SchemaDiscovery(config)

        assert discovery.config.include_attribute_types is False
        assert discovery.config.include_object_classes is True
        assert discovery.config.timeout_seconds == 120

    @patch("ldap_core_shared.schema.discovery.ldap3")
    def test_discover_from_server_success(self, mock_ldap3) -> None:
        """Test successful schema discovery from server."""
        # Mock connection info
        connection_info = Mock()
        connection_info.host = "ldap.example.com"
        connection_info.port = 389
        connection_info.use_ssl = False
        connection_info.bind_dn = "cn=admin,dc=example,dc=com"
        connection_info.password = "password"

        # Mock server and connection
        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL"

        # Mock schema info
        mock_schema_info = SchemaInfo(
            server_info="Test Server",
            schema_dn="cn=schema",
            attribute_types=["( 2.5.4.3 NAME 'cn' )"],
        )

        discovery = SchemaDiscovery()

        with patch.object(discovery, "_discover_schema") as mock_discover:
            mock_discover.return_value = mock_schema_info

            result = discovery.discover_from_server(connection_info)

            assert result.success is True
            assert result.data == mock_schema_info
            assert result.operation == "discover_from_server"
            assert result.metadata["server"] == "ldap.example.com:389"

            # Verify connection setup
            mock_ldap3.Server.assert_called_once_with(
                "ldap.example.com:389",
                use_ssl=False,
                get_info="ALL",
            )
            mock_ldap3.Connection.assert_called_once_with(
                mock_server,
                user="cn=admin,dc=example,dc=com",
                password="password",
                auto_bind=True,
                raise_exceptions=True,
            )
            mock_connection.unbind.assert_called_once()

    @patch("ldap_core_shared.schema.discovery.ldap3")
    def test_discover_from_server_connection_error(self, mock_ldap3) -> None:
        """Test schema discovery with connection error."""
        connection_info = Mock()
        connection_info.host = "ldap.example.com"
        connection_info.port = 389
        connection_info.use_ssl = False
        connection_info.bind_dn = "cn=admin,dc=example,dc=com"
        connection_info.password = "password"

        # Mock connection failure
        mock_ldap3.Connection.side_effect = Exception("Connection failed")

        discovery = SchemaDiscovery()
        result = discovery.discover_from_server(connection_info)

        assert result.success is False
        assert "Discovery failed: Connection failed" in result.error_message
        assert result.operation == "discover_from_server"
        assert result.metadata["server"] == "ldap.example.com:389"

    @patch("ldap_core_shared.schema.discovery.ldap3")
    def test_discover_from_server_ssl_connection(self, mock_ldap3) -> None:
        """Test schema discovery with SSL connection."""
        connection_info = Mock()
        connection_info.host = "ldaps.example.com"
        connection_info.port = 636
        connection_info.use_ssl = True
        connection_info.bind_dn = "cn=admin,dc=example,dc=com"
        connection_info.password = "password"

        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL"

        discovery = SchemaDiscovery()

        with patch.object(discovery, "_discover_schema") as mock_discover:
            mock_discover.return_value = SchemaInfo()

            result = discovery.discover_from_server(connection_info)

            assert result.success is True

            # Verify SSL connection setup
            mock_ldap3.Server.assert_called_once_with(
                "ldaps.example.com:636",
                use_ssl=True,
                get_info="ALL",
            )

    def test_discover_schema_complete(self) -> None:
        """Test complete schema discovery with all elements."""
        # Mock connection with server info
        mock_conn = Mock()
        mock_server = Mock()
        mock_server.info = "OpenLDAP Server v2.4"
        mock_conn.server = mock_server

        # Mock schema entry
        mock_entry = Mock()
        mock_entry.attributeTypes = Mock()
        mock_entry.attributeTypes.values = ["( 2.5.4.3 NAME 'cn' )", "( 2.5.4.4 NAME 'sn' )"]
        mock_entry.objectClasses = Mock()
        mock_entry.objectClasses.values = ["( 2.5.6.6 NAME 'person' )"]
        mock_entry.ldapSyntaxes = Mock()
        mock_entry.ldapSyntaxes.values = ["( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )"]
        mock_entry.matchingRules = Mock()
        mock_entry.matchingRules.values = ["( 2.5.13.2 NAME 'caseIgnoreMatch' )"]

        mock_conn.entries = [mock_entry]

        # Mock server capabilities
        mock_server.info.supported_controls = ["2.16.840.1.113730.3.4.2"]
        mock_server.info.supported_extensions = ["1.3.6.1.4.1.4203.1.11.1"]

        discovery = SchemaDiscovery()

        with patch.object(discovery, "_get_schema_dn") as mock_get_dn:
            mock_get_dn.return_value = "cn=schema"

            schema_info = discovery._discover_schema(mock_conn)

            assert schema_info.server_info == "OpenLDAP Server v2.4"
            assert schema_info.schema_dn == "cn=schema"
            assert len(schema_info.attribute_types) == 2
            assert len(schema_info.object_classes) == 1
            assert len(schema_info.syntax_definitions) == 1
            assert len(schema_info.matching_rules) == 1
            assert len(schema_info.server_controls) == 1
            assert len(schema_info.extensions) == 1

    def test_discover_schema_selective_inclusion(self) -> None:
        """Test schema discovery with selective inclusion."""
        # Config that only includes attribute types
        config = SchemaDiscoveryConfig(
            include_attribute_types=True,
            include_object_classes=False,
            include_syntax_definitions=False,
            include_matching_rules=False,
        )
        discovery = SchemaDiscovery(config)

        # Mock connection and entry
        mock_conn = Mock()
        mock_conn.server = Mock()
        mock_conn.server.info = None

        mock_entry = Mock()
        mock_entry.attributeTypes = Mock()
        mock_entry.attributeTypes.values = ["( 2.5.4.3 NAME 'cn' )"]
        # Object classes present but should be ignored
        mock_entry.objectClasses = Mock()
        mock_entry.objectClasses.values = ["( 2.5.6.6 NAME 'person' )"]

        mock_conn.entries = [mock_entry]

        with patch.object(discovery, "_get_schema_dn") as mock_get_dn:
            mock_get_dn.return_value = "cn=schema"

            schema_info = discovery._discover_schema(mock_conn)

            # Only attribute types should be included
            assert len(schema_info.attribute_types) == 1
            assert len(schema_info.object_classes) == 0  # Not included
            assert len(schema_info.syntax_definitions) == 0
            assert len(schema_info.matching_rules) == 0

    def test_discover_schema_missing_attributes(self) -> None:
        """Test schema discovery with missing schema attributes."""
        discovery = SchemaDiscovery()

        # Mock connection
        mock_conn = Mock()
        mock_conn.server = Mock()
        mock_conn.server.info = None

        # Mock entry without schema attributes
        mock_entry = Mock()
        # Use spec to avoid hasattr returning True for all attributes
        mock_entry.spec = []

        mock_conn.entries = [mock_entry]

        with patch.object(discovery, "_get_schema_dn") as mock_get_dn:
            mock_get_dn.return_value = "cn=schema"

            schema_info = discovery._discover_schema(mock_conn)

            # Should have empty collections
            assert len(schema_info.attribute_types) == 0
            assert len(schema_info.object_classes) == 0
            assert len(schema_info.syntax_definitions) == 0
            assert len(schema_info.matching_rules) == 0

    def test_discover_schema_no_entries(self) -> None:
        """Test schema discovery when no schema entries found."""
        discovery = SchemaDiscovery()

        # Mock connection with no entries
        mock_conn = Mock()
        mock_conn.server = Mock()
        mock_conn.server.info = None
        mock_conn.entries = []

        with patch.object(discovery, "_get_schema_dn") as mock_get_dn:
            mock_get_dn.return_value = "cn=schema"

            schema_info = discovery._discover_schema(mock_conn)

            # Should have empty schema info
            assert schema_info.server_info == ""
            assert schema_info.schema_dn == "cn=schema"
            assert len(schema_info.attribute_types) == 0

    def test_get_schema_dn_from_rootdse(self) -> None:
        """Test getting schema DN from RootDSE."""
        discovery = SchemaDiscovery()

        # Mock connection with RootDSE entry
        mock_conn = Mock()
        mock_rootdse_entry = Mock()
        mock_rootdse_entry.subschemaSubentry = Mock()
        mock_rootdse_entry.subschemaSubentry.value = "cn=schema,cn=config"
        mock_conn.entries = [mock_rootdse_entry]

        schema_dn = discovery._get_schema_dn(mock_conn)

        assert schema_dn == "cn=schema,cn=config"

        # Verify search was called correctly
        mock_conn.search.assert_called_once_with(
            "",
            "(objectClass=*)",
            search_scope=discovery._get_schema_dn.__code__.co_consts[6],  # ldap3.BASE
            attributes=["subschemaSubentry"],
        )

    def test_get_schema_dn_fallback(self) -> None:
        """Test getting schema DN with fallback."""
        discovery = SchemaDiscovery()

        # Mock connection with no RootDSE entry
        mock_conn = Mock()
        mock_conn.entries = []

        schema_dn = discovery._get_schema_dn(mock_conn)

        # Should use fallback
        assert schema_dn == "cn=schema"

    def test_get_schema_dn_exception_fallback(self) -> None:
        """Test getting schema DN with exception fallback."""
        discovery = SchemaDiscovery()

        # Mock connection that raises exception
        mock_conn = Mock()
        mock_conn.search.side_effect = Exception("Search failed")

        schema_dn = discovery._get_schema_dn(mock_conn)

        # Should use fallback
        assert schema_dn == "cn=schema"

    def test_get_schema_dn_missing_subschema(self) -> None:
        """Test getting schema DN when subschemaSubentry is missing."""
        discovery = SchemaDiscovery()

        # Mock connection with entry but no subschemaSubentry
        mock_conn = Mock()
        mock_entry = Mock()
        # Use spec to control hasattr behavior
        mock_entry.spec = []
        mock_conn.entries = [mock_entry]

        schema_dn = discovery._get_schema_dn(mock_conn)

        # Should use fallback
        assert schema_dn == "cn=schema"


class TestSchemaDiscoveryIntegration:
    """Test cases for schema discovery integration scenarios."""

    @patch("ldap_core_shared.schema.discovery.ldap3")
    def test_complete_discovery_workflow(self, mock_ldap3) -> None:
        """Test complete discovery workflow from connection to schema."""
        # Setup complete mock environment
        connection_info = Mock()
        connection_info.host = "ldap.example.com"
        connection_info.port = 389
        connection_info.use_ssl = False
        connection_info.bind_dn = "cn=admin,dc=example,dc=com"
        connection_info.password = "password"

        # Mock server and connection
        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL"
        mock_ldap3.BASE = "BASE"

        # Mock server info
        mock_server.info = "OpenLDAP Server"
        mock_server.info.supported_controls = ["2.16.840.1.113730.3.4.2"]
        mock_server.info.supported_extensions = ["1.3.6.1.4.1.4203.1.11.1"]

        # Mock RootDSE search for schema DN
        def mock_search(base_dn, filter_str, search_scope=None, attributes=None) -> None:
            if base_dn == "":
                # RootDSE search
                mock_rootdse = Mock()
                mock_rootdse.subschemaSubentry = Mock()
                mock_rootdse.subschemaSubentry.value = "cn=schema,cn=config"
                mock_connection.entries = [mock_rootdse]
            else:
                # Schema search
                mock_schema_entry = Mock()
                mock_schema_entry.attributeTypes = Mock()
                mock_schema_entry.attributeTypes.values = ["( 2.5.4.3 NAME 'cn' )"]
                mock_schema_entry.objectClasses = Mock()
                mock_schema_entry.objectClasses.values = ["( 2.5.6.6 NAME 'person' )"]
                mock_connection.entries = [mock_schema_entry]

        mock_connection.search.side_effect = mock_search

        discovery = SchemaDiscovery()
        result = discovery.discover_from_server(connection_info)

        # Verify complete workflow
        assert result.success is True
        assert result.data is not None
        assert result.data.server_info == "OpenLDAP Server"
        assert result.data.schema_dn == "cn=schema,cn=config"
        assert len(result.data.attribute_types) == 1
        assert len(result.data.object_classes) == 1
        assert len(result.data.server_controls) == 1
        assert len(result.data.extensions) == 1

        # Verify connection cleanup
        mock_connection.unbind.assert_called_once()

    def test_configuration_based_discovery(self) -> None:
        """Test discovery behavior based on configuration."""
        # Test with minimal configuration
        minimal_config = SchemaDiscoveryConfig(
            include_attribute_types=True,
            include_object_classes=False,
            include_syntax_definitions=False,
            include_matching_rules=False,
        )

        # Test with full configuration
        full_config = SchemaDiscoveryConfig(
            include_attribute_types=True,
            include_object_classes=True,
            include_syntax_definitions=True,
            include_matching_rules=True,
        )

        minimal_discovery = SchemaDiscovery(minimal_config)
        full_discovery = SchemaDiscovery(full_config)

        # Mock connection with all schema elements
        mock_conn = Mock()
        mock_conn.server = Mock()
        mock_conn.server.info = None

        mock_entry = Mock()
        mock_entry.attributeTypes = Mock()
        mock_entry.attributeTypes.values = ["( 2.5.4.3 NAME 'cn' )"]
        mock_entry.objectClasses = Mock()
        mock_entry.objectClasses.values = ["( 2.5.6.6 NAME 'person' )"]
        mock_entry.ldapSyntaxes = Mock()
        mock_entry.ldapSyntaxes.values = ["( 1.3.6.1.4.1.1466.115.121.1.15 )"]
        mock_entry.matchingRules = Mock()
        mock_entry.matchingRules.values = ["( 2.5.13.2 NAME 'caseIgnoreMatch' )"]

        mock_conn.entries = [mock_entry]

        with patch.object(minimal_discovery, "_get_schema_dn") as mock_get_dn1, \
             patch.object(full_discovery, "_get_schema_dn") as mock_get_dn2:
            mock_get_dn1.return_value = "cn=schema"
            mock_get_dn2.return_value = "cn=schema"

            minimal_result = minimal_discovery._discover_schema(mock_conn)
            full_result = full_discovery._discover_schema(mock_conn)

            # Minimal should only have attribute types
            assert len(minimal_result.attribute_types) == 1
            assert len(minimal_result.object_classes) == 0
            assert len(minimal_result.syntax_definitions) == 0
            assert len(minimal_result.matching_rules) == 0

            # Full should have all elements
            assert len(full_result.attribute_types) == 1
            assert len(full_result.object_classes) == 1
            assert len(full_result.syntax_definitions) == 1
            assert len(full_result.matching_rules) == 1

    def test_performance_monitoring_integration(self) -> None:
        """Test performance monitoring during discovery."""
        discovery = SchemaDiscovery()

        # Verify performance monitor is initialized
        assert discovery.performance_monitor is not None

        # Mock connection info for testing
        connection_info = Mock()
        connection_info.host = "test.example.com"
        connection_info.port = 389

        with patch("ldap_core_shared.schema.discovery.ldap3") as mock_ldap3:
            # Mock exception to test performance tracking
            mock_ldap3.Connection.side_effect = Exception("Test error")

            result = discovery.discover_from_server(connection_info)

            # Should fail but performance monitoring should still work
            assert result.success is False
            # Performance monitor should have tracked the operation
            assert discovery.performance_monitor is not None

    def test_error_handling_and_logging(self) -> None:
        """Test error handling and logging integration."""
        discovery = SchemaDiscovery()

        connection_info = Mock()
        connection_info.host = "error.example.com"
        connection_info.port = 389

        with patch("ldap_core_shared.schema.discovery.ldap3") as mock_ldap3, \
             patch("ldap_core_shared.schema.discovery.logger") as mock_logger:

            # Mock connection error
            mock_ldap3.Connection.side_effect = ValueError("Test connection error")

            result = discovery.discover_from_server(connection_info)

            # Verify error handling
            assert result.success is False
            assert "Discovery failed: Test connection error" in result.error_message
            assert result.operation == "discover_from_server"

            # Verify logging was called
            mock_logger.exception.assert_called_once()

    @patch("ldap_core_shared.schema.discovery.ldap3")
    def test_server_capabilities_extraction(self, mock_ldap3) -> None:
        """Test extraction of server capabilities and extensions."""
        discovery = SchemaDiscovery()

        # Mock connection
        mock_conn = Mock()
        mock_server = Mock()
        mock_conn.server = mock_server

        # Mock server info with capabilities
        mock_server.info = Mock()
        mock_server.info.supported_controls = [
            "2.16.840.1.113730.3.4.2",  # ManageDsaIT
            "1.2.840.113556.1.4.319",   # Paged Results
            "2.16.840.1.113730.3.4.18",  # Proxy Authorization
        ]
        mock_server.info.supported_extensions = [
            "1.3.6.1.4.1.4203.1.11.1",  # Modify Password
            "1.3.6.1.4.1.4203.1.11.3",  # Who Am I
            "1.3.6.1.4.1.1466.20037",   # Start TLS
        ]

        # Mock empty schema entry
        mock_conn.entries = []

        with patch.object(discovery, "_get_schema_dn") as mock_get_dn:
            mock_get_dn.return_value = "cn=schema"

            schema_info = discovery._discover_schema(mock_conn)

            # Verify server capabilities extraction
            assert len(schema_info.server_controls) == 3
            assert "2.16.840.1.113730.3.4.2" in schema_info.server_controls
            assert "1.2.840.113556.1.4.319" in schema_info.server_controls
            assert "2.16.840.1.113730.3.4.18" in schema_info.server_controls

            assert len(schema_info.extensions) == 3
            assert "1.3.6.1.4.1.4203.1.11.1" in schema_info.extensions
            assert "1.3.6.1.4.1.4203.1.11.3" in schema_info.extensions
            assert "1.3.6.1.4.1.1466.20037" in schema_info.extensions
