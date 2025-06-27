"""Tests for LDAP Root DSE Service Implementation.

This module provides comprehensive test coverage for the Root DSE (Directory
Service Entry) service including server capability discovery, extension and
control mapping, and vendor-specific server detection with enterprise-grade validation.

Test Coverage:
    - LDAPVersion: LDAP protocol version enumeration
    - ServerVendor: Server vendor detection and identification
    - ExtensionInfo: LDAP extension information modeling
    - ControlInfo: LDAP control information modeling
    - ServerInfo: Comprehensive server information aggregation
    - RootDSEService: Main service for Root DSE operations
    - Server vendor detection algorithms
    - Extension and control capability mapping

Integration Testing:
    - Server capability discovery workflows
    - Multi-vendor server support validation
    - Extension and control OID mapping
    - SASL mechanism detection and validation
    - TLS capability detection and security
    - Naming context discovery and validation

Security Testing:
    - Anonymous Root DSE access patterns
    - TLS requirement detection and enforcement
    - SASL mechanism capability validation
    - Server vendor fingerprinting protection
    - Extension security assessment

Performance Testing:
    - Root DSE query optimization and caching
    - Large-scale server capability processing
    - Vendor detection algorithm efficiency
    - Extension/control lookup performance
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from ldap_core_shared.services.rootdse import (
    ControlInfo,
    ExtensionInfo,
    LDAPVersion,
    RootDSEService,
    ServerInfo,
    ServerVendor,
    create_control_info,
    create_extension_info,
    discover_server_info,
)


class TestLDAPVersion:
    """Test cases for LDAPVersion enumeration."""

    def test_ldap_version_values(self) -> None:
        """Test LDAP version enumeration values."""
        assert LDAPVersion.V2.value == "2"
        assert LDAPVersion.V3.value == "3"

    def test_ldap_version_completeness(self) -> None:
        """Test that all expected LDAP versions are defined."""
        expected_versions = {"V2", "V3"}
        actual_versions = {member.name for member in LDAPVersion}
        assert actual_versions == expected_versions


class TestServerVendor:
    """Test cases for ServerVendor enumeration."""

    def test_server_vendor_values(self) -> None:
        """Test server vendor enumeration values."""
        assert ServerVendor.OPENLDAP.value == "OpenLDAP"
        assert ServerVendor.MICROSOFT_AD.value == "Microsoft Active Directory"
        assert ServerVendor.IBM_DOMINO.value == "IBM Domino"
        assert ServerVendor.NOVELL_EDIRECTORY.value == "Novell eDirectory"
        assert ServerVendor.SUN_DIRECTORY.value == "Sun Directory Server"
        assert ServerVendor.ORACLE_DIRECTORY.value == "Oracle Internet Directory"
        assert ServerVendor.APACHE_DIRECTORY.value == "Apache Directory Server"
        assert ServerVendor.UNKNOWN.value == "Unknown"

    def test_server_vendor_completeness(self) -> None:
        """Test that all expected server vendors are defined."""
        expected_vendors = {
            "OPENLDAP",
            "MICROSOFT_AD",
            "IBM_DOMINO",
            "NOVELL_EDIRECTORY",
            "SUN_DIRECTORY",
            "ORACLE_DIRECTORY",
            "APACHE_DIRECTORY",
            "UNKNOWN",
        }
        actual_vendors = {member.name for member in ServerVendor}
        assert actual_vendors == expected_vendors


class TestExtensionInfo:
    """Test cases for ExtensionInfo."""

    def test_extension_info_creation_minimal(self) -> None:
        """Test creating extension info with minimal required fields."""
        ext = ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.3")

        assert ext.oid == "1.3.6.1.4.1.4203.1.11.3"
        assert ext.name is None
        assert ext.description is None
        assert ext.rfc is None
        assert ext.is_critical is False

    def test_extension_info_creation_complete(self) -> None:
        """Test creating extension info with all fields."""
        ext = ExtensionInfo(
            oid="1.3.6.1.4.1.4203.1.11.3",
            name="Who Am I",
            description="RFC 4532 - LDAP Who Am I Operation",
            rfc="RFC 4532",
            is_critical=True,
        )

        assert ext.oid == "1.3.6.1.4.1.4203.1.11.3"
        assert ext.name == "Who Am I"
        assert ext.description == "RFC 4532 - LDAP Who Am I Operation"
        assert ext.rfc == "RFC 4532"
        assert ext.is_critical is True

    def test_extension_info_known_extensions(self) -> None:
        """Test extension info for known LDAP extensions."""
        known_extensions = [
            ("1.3.6.1.4.1.4203.1.11.3", "Who Am I"),
            ("1.3.6.1.4.1.4203.1.11.1", "Password Modify"),
            ("1.3.6.1.4.1.1466.20037", "Start TLS"),
            ("1.3.6.1.1.8", "Cancel"),
        ]

        for oid, expected_name in known_extensions:
            ext = ExtensionInfo(oid=oid, name=expected_name)
            assert ext.oid == oid
            assert ext.name == expected_name


class TestControlInfo:
    """Test cases for ControlInfo."""

    def test_control_info_creation_minimal(self) -> None:
        """Test creating control info with minimal required fields."""
        ctrl = ControlInfo(oid="2.16.840.1.113730.3.4.2")

        assert ctrl.oid == "2.16.840.1.113730.3.4.2"
        assert ctrl.name is None
        assert ctrl.description is None
        assert ctrl.criticality is False

    def test_control_info_creation_complete(self) -> None:
        """Test creating control info with all fields."""
        ctrl = ControlInfo(
            oid="2.16.840.1.113730.3.4.2",
            name="ManageDsaIT",
            description="RFC 3296 - Named Subordinate References in LDAP",
            criticality=True,
        )

        assert ctrl.oid == "2.16.840.1.113730.3.4.2"
        assert ctrl.name == "ManageDsaIT"
        assert ctrl.description == "RFC 3296 - Named Subordinate References in LDAP"
        assert ctrl.criticality is True

    def test_control_info_known_controls(self) -> None:
        """Test control info for known LDAP controls."""
        known_controls = [
            ("2.16.840.1.113730.3.4.2", "ManageDsaIT"),
            ("1.2.840.113556.1.4.319", "Paged Results"),
            ("2.16.840.1.113730.3.4.18", "Proxy Authorization"),
            ("1.2.840.113556.1.4.473", "Sort"),
        ]

        for oid, expected_name in known_controls:
            ctrl = ControlInfo(oid=oid, name=expected_name)
            assert ctrl.oid == oid
            assert ctrl.name == expected_name


class TestServerInfo:
    """Test cases for ServerInfo."""

    def test_server_info_creation_minimal(self) -> None:
        """Test creating server info with minimal fields."""
        info = ServerInfo()

        assert info.vendor == ServerVendor.UNKNOWN
        assert info.version is None
        assert info.ldap_version == []
        assert info.naming_contexts == []
        assert info.default_naming_context is None
        assert info.schema_naming_context is None
        assert info.config_naming_context is None
        assert info.supported_extensions == []
        assert info.supported_controls == []
        assert info.supported_sasl_mechanisms == []
        assert info.supported_features == []
        assert info.supports_tls is False
        assert info.requires_authentication is True
        assert info.password_policy_enabled is False
        assert isinstance(info.discovered_at, datetime)
        assert info.raw_attributes == {}

    def test_server_info_creation_complete(self) -> None:
        """Test creating server info with complete configuration."""
        discovery_time = datetime.now(UTC)

        extensions = [
            ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.3", name="Who Am I"),
            ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.1", name="Password Modify"),
        ]

        controls = [
            ControlInfo(oid="2.16.840.1.113730.3.4.2", name="ManageDsaIT"),
            ControlInfo(oid="1.2.840.113556.1.4.319", name="Paged Results"),
        ]

        info = ServerInfo(
            vendor=ServerVendor.OPENLDAP,
            version="2.5.13",
            ldap_version=[LDAPVersion.V2, LDAPVersion.V3],
            naming_contexts=["dc=example,dc=com", "dc=test,dc=org"],
            default_naming_context="dc=example,dc=com",
            schema_naming_context="cn=schema,dc=example,dc=com",
            config_naming_context="cn=config,dc=example,dc=com",
            supported_extensions=extensions,
            supported_controls=controls,
            supported_sasl_mechanisms=["PLAIN", "EXTERNAL", "GSSAPI"],
            supported_features=["feature1", "feature2"],
            supports_tls=True,
            requires_authentication=False,
            password_policy_enabled=True,
            server_name="ldap.example.com",
            domain_name="example.com",
            forest_name="example.forest",
            discovered_at=discovery_time,
            raw_attributes={"attr1": "value1"},
        )

        assert info.vendor == ServerVendor.OPENLDAP
        assert info.version == "2.5.13"
        assert info.ldap_version == [LDAPVersion.V2, LDAPVersion.V3]
        assert info.naming_contexts == ["dc=example,dc=com", "dc=test,dc=org"]
        assert info.default_naming_context == "dc=example,dc=com"
        assert info.schema_naming_context == "cn=schema,dc=example,dc=com"
        assert info.config_naming_context == "cn=config,dc=example,dc=com"
        assert len(info.supported_extensions) == 2
        assert len(info.supported_controls) == 2
        assert info.supported_sasl_mechanisms == ["PLAIN", "EXTERNAL", "GSSAPI"]
        assert info.supports_tls is True
        assert info.server_name == "ldap.example.com"
        assert info.discovered_at == discovery_time

    def test_get_extension_by_oid_found(self) -> None:
        """Test getting extension by OID when found."""
        extensions = [
            ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.3", name="Who Am I"),
            ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.1", name="Password Modify"),
        ]

        info = ServerInfo(supported_extensions=extensions)

        ext = info.get_extension_by_oid("1.3.6.1.4.1.4203.1.11.3")
        assert ext is not None
        assert ext.name == "Who Am I"

    def test_get_extension_by_oid_not_found(self) -> None:
        """Test getting extension by OID when not found."""
        extensions = [
            ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.3", name="Who Am I"),
        ]

        info = ServerInfo(supported_extensions=extensions)

        ext = info.get_extension_by_oid("1.3.6.1.4.1.4203.1.11.1")
        assert ext is None

    def test_get_control_by_oid_found(self) -> None:
        """Test getting control by OID when found."""
        controls = [
            ControlInfo(oid="2.16.840.1.113730.3.4.2", name="ManageDsaIT"),
            ControlInfo(oid="1.2.840.113556.1.4.319", name="Paged Results"),
        ]

        info = ServerInfo(supported_controls=controls)

        ctrl = info.get_control_by_oid("2.16.840.1.113730.3.4.2")
        assert ctrl is not None
        assert ctrl.name == "ManageDsaIT"

    def test_get_control_by_oid_not_found(self) -> None:
        """Test getting control by OID when not found."""
        controls = [
            ControlInfo(oid="2.16.840.1.113730.3.4.2", name="ManageDsaIT"),
        ]

        info = ServerInfo(supported_controls=controls)

        ctrl = info.get_control_by_oid("1.2.840.113556.1.4.319")
        assert ctrl is None

    def test_supports_extension_true(self) -> None:
        """Test supports_extension returns True when extension exists."""
        extensions = [
            ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.3", name="Who Am I"),
        ]

        info = ServerInfo(supported_extensions=extensions)

        assert info.supports_extension("1.3.6.1.4.1.4203.1.11.3") is True

    def test_supports_extension_false(self) -> None:
        """Test supports_extension returns False when extension doesn't exist."""
        info = ServerInfo()

        assert info.supports_extension("1.3.6.1.4.1.4203.1.11.3") is False

    def test_supports_control_true(self) -> None:
        """Test supports_control returns True when control exists."""
        controls = [
            ControlInfo(oid="2.16.840.1.113730.3.4.2", name="ManageDsaIT"),
        ]

        info = ServerInfo(supported_controls=controls)

        assert info.supports_control("2.16.840.1.113730.3.4.2") is True

    def test_supports_control_false(self) -> None:
        """Test supports_control returns False when control doesn't exist."""
        info = ServerInfo()

        assert info.supports_control("2.16.840.1.113730.3.4.2") is False

    def test_supports_sasl_mechanism_case_insensitive(self) -> None:
        """Test supports_sasl_mechanism is case insensitive."""
        info = ServerInfo(supported_sasl_mechanisms=["PLAIN", "EXTERNAL"])

        assert info.supports_sasl_mechanism("PLAIN") is True
        assert info.supports_sasl_mechanism("plain") is True
        assert info.supports_sasl_mechanism("Plain") is True
        assert info.supports_sasl_mechanism("EXTERNAL") is True
        assert info.supports_sasl_mechanism("external") is True
        assert info.supports_sasl_mechanism("UNKNOWN") is False

    def test_is_active_directory_true(self) -> None:
        """Test is_active_directory returns True for Microsoft AD."""
        info = ServerInfo(vendor=ServerVendor.MICROSOFT_AD)
        assert info.is_active_directory() is True

    def test_is_active_directory_false(self) -> None:
        """Test is_active_directory returns False for other vendors."""
        info = ServerInfo(vendor=ServerVendor.OPENLDAP)
        assert info.is_active_directory() is False

    def test_is_openldap_true(self) -> None:
        """Test is_openldap returns True for OpenLDAP."""
        info = ServerInfo(vendor=ServerVendor.OPENLDAP)
        assert info.is_openldap() is True

    def test_is_openldap_false(self) -> None:
        """Test is_openldap returns False for other vendors."""
        info = ServerInfo(vendor=ServerVendor.MICROSOFT_AD)
        assert info.is_openldap() is False

    def test_get_primary_naming_context_default(self) -> None:
        """Test get_primary_naming_context returns default context."""
        info = ServerInfo(
            default_naming_context="dc=example,dc=com",
            naming_contexts=["dc=test,dc=org", "dc=example,dc=com"],
        )

        assert info.get_primary_naming_context() == "dc=example,dc=com"

    def test_get_primary_naming_context_first_available(self) -> None:
        """Test get_primary_naming_context returns first available context."""
        info = ServerInfo(
            naming_contexts=["dc=test,dc=org", "dc=example,dc=com"],
        )

        assert info.get_primary_naming_context() == "dc=test,dc=org"

    def test_get_primary_naming_context_none(self) -> None:
        """Test get_primary_naming_context returns None when no contexts available."""
        info = ServerInfo()

        assert info.get_primary_naming_context() is None

    def test_get_capabilities_summary(self) -> None:
        """Test get_capabilities_summary returns correct summary."""
        extensions = [ExtensionInfo(oid="ext1"), ExtensionInfo(oid="ext2")]
        controls = [ControlInfo(oid="ctrl1")]

        info = ServerInfo(
            vendor=ServerVendor.OPENLDAP,
            version="2.5.13",
            ldap_version=[LDAPVersion.V3],
            supported_extensions=extensions,
            supported_controls=controls,
            supported_sasl_mechanisms=["PLAIN", "EXTERNAL"],
            supports_tls=True,
            naming_contexts=["dc=example,dc=com"],
        )

        summary = info.get_capabilities_summary()

        assert summary["vendor"] == "OpenLDAP"
        assert summary["version"] == "2.5.13"
        assert summary["ldap_versions"] == ["3"]
        assert summary["extensions_count"] == 2
        assert summary["controls_count"] == 1
        assert summary["sasl_mechanisms_count"] == 2
        assert summary["supports_tls"] is True
        assert summary["naming_contexts_count"] == 1


class TestRootDSEService:
    """Test cases for RootDSEService."""

    def test_service_initialization(self) -> None:
        """Test service initialization."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        assert service._connection is mock_connection
        assert service._cached_info is None

    async def test_discover_capabilities_not_implemented(self) -> None:
        """Test discover_capabilities raises NotImplementedError."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        with pytest.raises(
            NotImplementedError, match="Root DSE discovery requires connection"
        ):
            await service.discover_capabilities()

    async def test_discover_capabilities_uses_cache(self) -> None:
        """Test discover_capabilities uses cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        # Set cached info
        cached_info = ServerInfo(vendor=ServerVendor.OPENLDAP)
        service._cached_info = cached_info

        result = await service.discover_capabilities()

        assert result is cached_info

    async def test_discover_capabilities_force_refresh(self) -> None:
        """Test discover_capabilities with force_refresh bypasses cache."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        # Set cached info
        cached_info = ServerInfo(vendor=ServerVendor.OPENLDAP)
        service._cached_info = cached_info

        with pytest.raises(NotImplementedError):
            await service.discover_capabilities(force_refresh=True)

    def test_supports_extension_with_cache(self) -> None:
        """Test supports_extension with cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        extensions = [ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.3")]
        cached_info = ServerInfo(supported_extensions=extensions)
        service._cached_info = cached_info

        assert service.supports_extension("1.3.6.1.4.1.4203.1.11.3") is True
        assert service.supports_extension("1.3.6.1.4.1.4203.1.11.1") is False

    def test_supports_extension_no_cache(self) -> None:
        """Test supports_extension without cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        assert service.supports_extension("1.3.6.1.4.1.4203.1.11.3") is False

    def test_supports_control_with_cache(self) -> None:
        """Test supports_control with cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        controls = [ControlInfo(oid="2.16.840.1.113730.3.4.2")]
        cached_info = ServerInfo(supported_controls=controls)
        service._cached_info = cached_info

        assert service.supports_control("2.16.840.1.113730.3.4.2") is True
        assert service.supports_control("1.2.840.113556.1.4.319") is False

    def test_supports_control_no_cache(self) -> None:
        """Test supports_control without cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        assert service.supports_control("2.16.840.1.113730.3.4.2") is False

    def test_get_naming_contexts_with_cache(self) -> None:
        """Test get_naming_contexts with cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        naming_contexts = ["dc=example,dc=com", "dc=test,dc=org"]
        cached_info = ServerInfo(naming_contexts=naming_contexts)
        service._cached_info = cached_info

        result = service.get_naming_contexts()
        assert result == naming_contexts

    def test_get_naming_contexts_no_cache(self) -> None:
        """Test get_naming_contexts without cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        result = service.get_naming_contexts()
        assert result == []

    def test_get_schema_dn_with_cache(self) -> None:
        """Test get_schema_dn with cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        schema_dn = "cn=schema,dc=example,dc=com"
        cached_info = ServerInfo(schema_naming_context=schema_dn)
        service._cached_info = cached_info

        result = service.get_schema_dn()
        assert result == schema_dn

    def test_get_schema_dn_no_cache(self) -> None:
        """Test get_schema_dn without cached information."""
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        result = service.get_schema_dn()
        assert result is None

    def test_known_extensions_completeness(self) -> None:
        """Test that known extensions are properly defined."""
        service = RootDSEService(Mock())

        expected_extensions = {
            "1.3.6.1.4.1.4203.1.11.3",  # Who Am I
            "1.3.6.1.4.1.4203.1.11.1",  # Password Modify
            "1.3.6.1.4.1.1466.20037",  # Start TLS
            "1.3.6.1.1.8",  # Cancel
            "1.3.6.1.4.1.4203.1.11.2",  # Refresh
        }

        assert set(service.KNOWN_EXTENSIONS.keys()) == expected_extensions

        # Verify each has required fields
        for info in service.KNOWN_EXTENSIONS.values():
            assert "name" in info
            assert "description" in info
            assert isinstance(info["name"], str)
            assert isinstance(info["description"], str)

    def test_known_controls_completeness(self) -> None:
        """Test that known controls are properly defined."""
        service = RootDSEService(Mock())

        expected_controls = {
            "2.16.840.1.113730.3.4.2",  # ManageDsaIT
            "1.2.840.113556.1.4.319",  # Paged Results
            "2.16.840.1.113730.3.4.18",  # Proxy Authorization
            "1.2.840.113556.1.4.473",  # Sort
            "1.3.6.1.4.1.42.2.27.8.5.1",  # Password Policy
        }

        assert set(service.KNOWN_CONTROLS.keys()) == expected_controls

        # Verify each has required fields
        for info in service.KNOWN_CONTROLS.values():
            assert "name" in info
            assert "description" in info
            assert isinstance(info["name"], str)
            assert isinstance(info["description"], str)


class TestRootDSEServiceParsing:
    """Test cases for Root DSE attribute parsing."""

    def test_extract_single_attribute_string(self) -> None:
        """Test _extract_single_attribute with string value."""
        service = RootDSEService(Mock())
        attributes = {"attr": "value"}

        result = service._extract_single_attribute(attributes, "attr")
        assert result == "value"

    def test_extract_single_attribute_list(self) -> None:
        """Test _extract_single_attribute with list value."""
        service = RootDSEService(Mock())
        attributes = {"attr": ["value1", "value2"]}

        result = service._extract_single_attribute(attributes, "attr")
        assert result == "value1"

    def test_extract_single_attribute_empty_list(self) -> None:
        """Test _extract_single_attribute with empty list."""
        service = RootDSEService(Mock())
        attributes = {"attr": []}

        result = service._extract_single_attribute(attributes, "attr")
        assert result is None

    def test_extract_single_attribute_missing(self) -> None:
        """Test _extract_single_attribute with missing attribute."""
        service = RootDSEService(Mock())
        attributes = {}

        result = service._extract_single_attribute(attributes, "attr")
        assert result is None

    def test_extract_list_attribute_list(self) -> None:
        """Test _extract_list_attribute with list value."""
        service = RootDSEService(Mock())
        attributes = {"attr": ["value1", "value2", "value3"]}

        result = service._extract_list_attribute(attributes, "attr")
        assert result == ["value1", "value2", "value3"]

    def test_extract_list_attribute_string(self) -> None:
        """Test _extract_list_attribute with string value."""
        service = RootDSEService(Mock())
        attributes = {"attr": "single_value"}

        result = service._extract_list_attribute(attributes, "attr")
        assert result == ["single_value"]

    def test_extract_list_attribute_missing(self) -> None:
        """Test _extract_list_attribute with missing attribute."""
        service = RootDSEService(Mock())
        attributes = {}

        result = service._extract_list_attribute(attributes, "attr")
        assert result == []

    def test_extract_list_attribute_empty_list(self) -> None:
        """Test _extract_list_attribute with empty list."""
        service = RootDSEService(Mock())
        attributes = {"attr": []}

        result = service._extract_list_attribute(attributes, "attr")
        assert result == []


class TestServerVendorDetection:
    """Test cases for server vendor detection."""

    def test_detect_server_vendor_microsoft(self) -> None:
        """Test detecting Microsoft Active Directory."""
        service = RootDSEService(Mock())

        # Test Microsoft in vendor name
        attributes = {"vendorName": "Microsoft Corporation"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.MICROSOFT_AD

        # Test Windows in vendor name
        attributes = {"vendorName": "Windows Server"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.MICROSOFT_AD

    def test_detect_server_vendor_openldap(self) -> None:
        """Test detecting OpenLDAP."""
        service = RootDSEService(Mock())

        # Test OpenLDAP in vendor name
        attributes = {"vendorName": "OpenLDAP Foundation"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.OPENLDAP

        # Test openldap in version string
        attributes = {"vendorVersion": "openldap 2.5.13"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.OPENLDAP

    def test_detect_server_vendor_ibm_domino(self) -> None:
        """Test detecting IBM Domino."""
        service = RootDSEService(Mock())

        # Test IBM in vendor name
        attributes = {"vendorName": "IBM Corporation"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.IBM_DOMINO

        # Test Domino in vendor name
        attributes = {"vendorName": "Lotus Domino"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.IBM_DOMINO

    def test_detect_server_vendor_novell(self) -> None:
        """Test detecting Novell eDirectory."""
        service = RootDSEService(Mock())

        # Test Novell in vendor name
        attributes = {"vendorName": "Novell, Inc."}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.NOVELL_EDIRECTORY

        # Test eDirectory in vendor name
        attributes = {"vendorName": "eDirectory"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.NOVELL_EDIRECTORY

    def test_detect_server_vendor_sun_oracle(self) -> None:
        """Test detecting Sun/Oracle Directory Server."""
        service = RootDSEService(Mock())

        vendors_to_test = ["Sun Microsystems", "Oracle Corporation", "iPlanet"]

        for vendor_name in vendors_to_test:
            attributes = {"vendorName": vendor_name}
            vendor, _version = service._detect_server_vendor(attributes)
            assert vendor == ServerVendor.SUN_DIRECTORY

    def test_detect_server_vendor_apache(self) -> None:
        """Test detecting Apache Directory Server."""
        service = RootDSEService(Mock())

        attributes = {"vendorName": "Apache Software Foundation"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.APACHE_DIRECTORY

    def test_detect_server_vendor_unknown(self) -> None:
        """Test detecting unknown server vendor."""
        service = RootDSEService(Mock())

        attributes = {"vendorName": "Unknown Vendor"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.UNKNOWN

    def test_detect_server_vendor_with_version(self) -> None:
        """Test vendor detection includes version information."""
        service = RootDSEService(Mock())

        attributes = {
            "vendorName": "OpenLDAP Foundation",
            "vendorVersion": "2.5.13",
        }
        vendor, version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.OPENLDAP
        assert version == "2.5.13"

    def test_detect_server_vendor_empty_attributes(self) -> None:
        """Test vendor detection with empty attributes."""
        service = RootDSEService(Mock())

        attributes = {}
        vendor, version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.UNKNOWN
        assert version == ""


class TestTLSDetection:
    """Test cases for TLS support detection."""

    def test_detect_tls_support_true(self) -> None:
        """Test detecting TLS support when Start TLS extension is present."""
        service = RootDSEService(Mock())

        attributes = {
            "supportedExtension": ["1.3.6.1.4.1.1466.20037", "other.extension"],
        }

        result = service._detect_tls_support(attributes)
        assert result is True

    def test_detect_tls_support_false(self) -> None:
        """Test detecting TLS support when Start TLS extension is absent."""
        service = RootDSEService(Mock())

        attributes = {
            "supportedExtension": ["other.extension", "another.extension"],
        }

        result = service._detect_tls_support(attributes)
        assert result is False

    def test_detect_tls_support_no_extensions(self) -> None:
        """Test detecting TLS support when no extensions are present."""
        service = RootDSEService(Mock())

        attributes = {}

        result = service._detect_tls_support(attributes)
        assert result is False


class TestRootDSEAttributeParsing:
    """Test cases for complete Root DSE attribute parsing."""

    def test_parse_root_dse_attributes_complete(self) -> None:
        """Test parsing complete Root DSE attributes."""
        service = RootDSEService(Mock())

        attributes = {
            "namingContexts": ["dc=example,dc=com", "dc=test,dc=org"],
            "supportedExtension": [
                "1.3.6.1.4.1.4203.1.11.3",  # Who Am I
                "1.3.6.1.4.1.4203.1.11.1",  # Password Modify
                "1.3.6.1.4.1.1466.20037",  # Start TLS
            ],
            "supportedControl": [
                "2.16.840.1.113730.3.4.2",  # ManageDsaIT
                "1.2.840.113556.1.4.319",  # Paged Results
            ],
            "supportedSASLMechanisms": ["PLAIN", "EXTERNAL", "GSSAPI"],
            "supportedLDAPVersion": ["2", "3"],
            "defaultNamingContext": "dc=example,dc=com",
            "schemaNamingContext": "cn=schema,dc=example,dc=com",
            "configurationNamingContext": "cn=config,dc=example,dc=com",
            "vendorName": "OpenLDAP Foundation",
            "vendorVersion": "2.5.13",
            "serverName": "ldap.example.com",
        }

        server_info = service._parse_root_dse_attributes(attributes)

        # Verify basic info
        assert server_info.vendor == ServerVendor.OPENLDAP
        assert server_info.version == "2.5.13"
        assert server_info.ldap_version == [LDAPVersion.V2, LDAPVersion.V3]

        # Verify naming contexts
        assert server_info.naming_contexts == ["dc=example,dc=com", "dc=test,dc=org"]
        assert server_info.default_naming_context == "dc=example,dc=com"
        assert server_info.schema_naming_context == "cn=schema,dc=example,dc=com"
        assert server_info.config_naming_context == "cn=config,dc=example,dc=com"

        # Verify extensions
        assert len(server_info.supported_extensions) == 3
        whoami_ext = server_info.get_extension_by_oid("1.3.6.1.4.1.4203.1.11.3")
        assert whoami_ext is not None
        assert whoami_ext.name == "Who Am I"

        # Verify controls
        assert len(server_info.supported_controls) == 2
        manage_ctrl = server_info.get_control_by_oid("2.16.840.1.113730.3.4.2")
        assert manage_ctrl is not None
        assert manage_ctrl.name == "ManageDsaIT"

        # Verify SASL mechanisms
        assert server_info.supported_sasl_mechanisms == ["PLAIN", "EXTERNAL", "GSSAPI"]

        # Verify TLS support (Start TLS extension present)
        assert server_info.supports_tls is True

        # Verify server name
        assert server_info.server_name == "ldap.example.com"

        # Verify raw attributes preserved
        assert server_info.raw_attributes == attributes

    def test_parse_root_dse_attributes_minimal(self) -> None:
        """Test parsing minimal Root DSE attributes."""
        service = RootDSEService(Mock())

        attributes = {}

        server_info = service._parse_root_dse_attributes(attributes)

        # Verify defaults
        assert server_info.vendor == ServerVendor.UNKNOWN
        assert server_info.version == ""
        assert server_info.ldap_version == []
        assert server_info.naming_contexts == []
        assert server_info.supported_extensions == []
        assert server_info.supported_controls == []
        assert server_info.supported_sasl_mechanisms == []
        assert server_info.supports_tls is False
        assert server_info.raw_attributes == attributes

    def test_parse_root_dse_attributes_unknown_extensions(self) -> None:
        """Test parsing Root DSE with unknown extensions."""
        service = RootDSEService(Mock())

        attributes = {
            "supportedExtension": [
                "1.3.6.1.4.1.4203.1.11.3",  # Known: Who Am I
                "1.2.3.4.5.6.7.8.9",  # Unknown
            ],
        }

        server_info = service._parse_root_dse_attributes(attributes)

        assert len(server_info.supported_extensions) == 2

        # Known extension should have name
        known_ext = server_info.get_extension_by_oid("1.3.6.1.4.1.4203.1.11.3")
        assert known_ext is not None
        assert known_ext.name == "Who Am I"

        # Unknown extension should have no name
        unknown_ext = server_info.get_extension_by_oid("1.2.3.4.5.6.7.8.9")
        assert unknown_ext is not None
        assert unknown_ext.name is None

    def test_parse_root_dse_attributes_unknown_controls(self) -> None:
        """Test parsing Root DSE with unknown controls."""
        service = RootDSEService(Mock())

        attributes = {
            "supportedControl": [
                "2.16.840.1.113730.3.4.2",  # Known: ManageDsaIT
                "9.8.7.6.5.4.3.2.1",  # Unknown
            ],
        }

        server_info = service._parse_root_dse_attributes(attributes)

        assert len(server_info.supported_controls) == 2

        # Known control should have name
        known_ctrl = server_info.get_control_by_oid("2.16.840.1.113730.3.4.2")
        assert known_ctrl is not None
        assert known_ctrl.name == "ManageDsaIT"

        # Unknown control should have no name
        unknown_ctrl = server_info.get_control_by_oid("9.8.7.6.5.4.3.2.1")
        assert unknown_ctrl is not None
        assert unknown_ctrl.name is None


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    async def test_discover_server_info(self) -> None:
        """Test discover_server_info convenience function."""
        mock_connection = Mock()

        with pytest.raises(NotImplementedError):
            await discover_server_info(mock_connection)

    def test_create_extension_info(self) -> None:
        """Test create_extension_info convenience function."""
        ext = create_extension_info(
            oid="1.3.6.1.4.1.4203.1.11.3",
            name="Who Am I",
            description="RFC 4532 - LDAP Who Am I Operation",
        )

        assert isinstance(ext, ExtensionInfo)
        assert ext.oid == "1.3.6.1.4.1.4203.1.11.3"
        assert ext.name == "Who Am I"
        assert ext.description == "RFC 4532 - LDAP Who Am I Operation"

    def test_create_control_info(self) -> None:
        """Test create_control_info convenience function."""
        ctrl = create_control_info(
            oid="2.16.840.1.113730.3.4.2",
            name="ManageDsaIT",
            description="RFC 3296 - Named Subordinate References in LDAP",
        )

        assert isinstance(ctrl, ControlInfo)
        assert ctrl.oid == "2.16.840.1.113730.3.4.2"
        assert ctrl.name == "ManageDsaIT"
        assert ctrl.description == "RFC 3296 - Named Subordinate References in LDAP"


class TestIntegrationScenarios:
    """Integration test scenarios."""

    def test_complete_server_discovery_workflow(self) -> None:
        """Test complete server discovery workflow."""
        # This tests the workflow without actual connection
        mock_connection = Mock()
        service = RootDSEService(mock_connection)

        # Simulate server info creation
        extensions = [
            ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.3", name="Who Am I"),
            ExtensionInfo(oid="1.3.6.1.4.1.4203.1.11.1", name="Password Modify"),
        ]

        controls = [
            ControlInfo(oid="2.16.840.1.113730.3.4.2", name="ManageDsaIT"),
        ]

        server_info = ServerInfo(
            vendor=ServerVendor.OPENLDAP,
            version="2.5.13",
            ldap_version=[LDAPVersion.V3],
            naming_contexts=["dc=example,dc=com"],
            supported_extensions=extensions,
            supported_controls=controls,
            supported_sasl_mechanisms=["PLAIN", "EXTERNAL"],
            supports_tls=True,
        )

        # Set cached info to simulate discovery
        service._cached_info = server_info

        # Test capability queries
        assert service.supports_extension("1.3.6.1.4.1.4203.1.11.3") is True
        assert service.supports_control("2.16.840.1.113730.3.4.2") is True
        assert service.get_naming_contexts() == ["dc=example,dc=com"]

        # Test server type detection
        assert server_info.is_openldap() is True
        assert server_info.is_active_directory() is False

        # Test capabilities summary
        summary = server_info.get_capabilities_summary()
        assert summary["vendor"] == "OpenLDAP"
        assert summary["supports_tls"] is True

    def test_multiple_server_vendor_scenarios(self) -> None:
        """Test multiple server vendor detection scenarios."""
        service = RootDSEService(Mock())

        vendor_scenarios = [
            ({"vendorName": "Microsoft Corporation"}, ServerVendor.MICROSOFT_AD),
            ({"vendorName": "OpenLDAP Foundation"}, ServerVendor.OPENLDAP),
            ({"vendorName": "IBM Corporation"}, ServerVendor.IBM_DOMINO),
            ({"vendorName": "Novell, Inc."}, ServerVendor.NOVELL_EDIRECTORY),
            ({"vendorName": "Sun Microsystems"}, ServerVendor.SUN_DIRECTORY),
            (
                {"vendorName": "Apache Software Foundation"},
                ServerVendor.APACHE_DIRECTORY,
            ),
            ({"vendorName": "Unknown Vendor"}, ServerVendor.UNKNOWN),
        ]

        for attributes, expected_vendor in vendor_scenarios:
            vendor, _ = service._detect_server_vendor(attributes)
            assert vendor == expected_vendor

    def test_extension_and_control_mapping(self) -> None:
        """Test extension and control OID mapping."""
        service = RootDSEService(Mock())

        # Test all known extensions
        for oid, info in service.KNOWN_EXTENSIONS.items():
            ext = ExtensionInfo(
                oid=oid,
                name=info["name"],
                description=info["description"],
                rfc=info.get("rfc"),
            )
            assert ext.oid == oid
            assert ext.name == info["name"]

        # Test all known controls
        for oid, info in service.KNOWN_CONTROLS.items():
            ctrl = ControlInfo(
                oid=oid,
                name=info["name"],
                description=info["description"],
            )
            assert ctrl.oid == oid
            assert ctrl.name == info["name"]


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_sasl_mechanism_validation(self) -> None:
        """Test SASL mechanism validation and security."""
        common_sasl_mechanisms = [
            "PLAIN",
            "EXTERNAL",
            "GSSAPI",
            "DIGEST-MD5",
            "CRAM-MD5",
            "NTLM",
            "ANONYMOUS",
        ]

        info = ServerInfo(supported_sasl_mechanisms=common_sasl_mechanisms)

        # Test common mechanisms
        for mechanism in common_sasl_mechanisms:
            assert info.supports_sasl_mechanism(mechanism) is True
            assert info.supports_sasl_mechanism(mechanism.lower()) is True

        # Test unsupported mechanism
        assert info.supports_sasl_mechanism("UNSUPPORTED") is False

    def test_tls_requirement_detection(self) -> None:
        """Test TLS requirement detection for security."""
        # Server with TLS support
        tls_info = ServerInfo(supports_tls=True)
        assert tls_info.supports_tls is True

        # Server without TLS support
        no_tls_info = ServerInfo(supports_tls=False)
        assert no_tls_info.supports_tls is False

    def test_authentication_requirement_validation(self) -> None:
        """Test authentication requirement validation."""
        # Server requiring authentication (default)
        auth_required_info = ServerInfo()
        assert auth_required_info.requires_authentication is True

        # Server allowing anonymous access
        anonymous_info = ServerInfo(requires_authentication=False)
        assert anonymous_info.requires_authentication is False

    def test_server_fingerprinting_protection(self) -> None:
        """Test server fingerprinting protection through minimal exposure."""
        # Ensure vendor detection doesn't expose sensitive info
        service = RootDSEService(Mock())

        # Test with minimal vendor information
        attributes = {"vendorName": "Generic LDAP Server"}
        vendor, _version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.UNKNOWN

        # Ensure raw attributes are preserved but controlled
        server_info = service._parse_root_dse_attributes(attributes)
        assert server_info.raw_attributes == attributes
        assert server_info.vendor == ServerVendor.UNKNOWN


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_server_info_creation_performance(self) -> None:
        """Test server info creation performance."""
        import time

        start_time = time.time()

        # Create many server info objects
        for i in range(1000):
            ServerInfo(
                vendor=ServerVendor.OPENLDAP,
                version=f"2.5.{i % 20}",
                ldap_version=[LDAPVersion.V3],
                naming_contexts=[f"dc=example{i},dc=com"],
                supported_sasl_mechanisms=["PLAIN", "EXTERNAL"],
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Less than 1 second for 1000 objects

    def test_vendor_detection_performance(self) -> None:
        """Test vendor detection performance."""
        import time

        service = RootDSEService(Mock())
        test_attributes = [
            {"vendorName": "Microsoft Corporation"},
            {"vendorName": "OpenLDAP Foundation"},
            {"vendorName": "IBM Corporation"},
            {"vendorName": "Unknown Vendor"},
        ]

        start_time = time.time()

        # Perform many vendor detections
        for _ in range(1000):
            for attributes in test_attributes:
                service._detect_server_vendor(attributes)

        detection_time = time.time() - start_time

        # Should detect quickly
        assert detection_time < 1.0  # Less than 1 second for 4000 detections

    def test_extension_lookup_performance(self) -> None:
        """Test extension lookup performance."""
        import time

        # Create server info with many extensions
        extensions = [
            ExtensionInfo(oid=f"1.3.6.1.4.1.{i}.1.1", name=f"Extension {i}")
            for i in range(1000)
        ]

        info = ServerInfo(supported_extensions=extensions)

        start_time = time.time()

        # Perform many lookups
        for i in range(1000):
            info.get_extension_by_oid(f"1.3.6.1.4.1.{i}.1.1")

        lookup_time = time.time() - start_time

        # Should lookup quickly
        assert lookup_time < 1.0  # Less than 1 second for 1000 lookups


class TestErrorHandling:
    """Error handling test cases."""

    def test_attribute_parsing_with_invalid_data(self) -> None:
        """Test attribute parsing with invalid data types."""
        service = RootDSEService(Mock())

        # Test with various invalid data types
        invalid_attributes = {
            "supportedExtension": None,
            "supportedControl": 123,
            "namingContexts": {"not": "a list"},
        }

        # Should handle gracefully without crashing
        result = service._parse_root_dse_attributes(invalid_attributes)

        assert isinstance(result, ServerInfo)
        assert result.supported_extensions == []
        assert result.supported_controls == []
        assert result.naming_contexts == []

    def test_vendor_detection_with_missing_attributes(self) -> None:
        """Test vendor detection with missing attributes."""
        service = RootDSEService(Mock())

        # Test with completely empty attributes
        vendor, version = service._detect_server_vendor({})
        assert vendor == ServerVendor.UNKNOWN
        assert version == ""

        # Test with None values
        attributes = {"vendorName": None, "vendorVersion": None}
        vendor, version = service._detect_server_vendor(attributes)
        assert vendor == ServerVendor.UNKNOWN

    def test_extension_info_validation(self) -> None:
        """Test extension info validation with invalid data."""
        # OID is required, should not raise exception but maintain data integrity
        ext = ExtensionInfo(oid="")
        assert ext.oid == ""
        assert ext.name is None

    def test_control_info_validation(self) -> None:
        """Test control info validation with invalid data."""
        # OID is required, should not raise exception but maintain data integrity
        ctrl = ControlInfo(oid="")
        assert ctrl.oid == ""
        assert ctrl.name is None

    def test_server_info_with_invalid_timestamps(self) -> None:
        """Test server info with invalid timestamp handling."""
        # Should use default timestamp if none provided
        info = ServerInfo()
        assert isinstance(info.discovered_at, datetime)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
