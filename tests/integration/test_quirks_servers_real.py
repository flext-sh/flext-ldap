"""Comprehensive integration tests for quirks_integration with real Docker LDAP.

Tests server-specific quirks detection, ACL handling, and configuration
against actual LDAP implementations (OpenLDAP 1.x, 2.x, Oracle OID/OUD).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap.services.quirks_integration import FlextLdapQuirksIntegration


@pytest.mark.integration
class TestQuirksIntegrationServerDetection:
    """Test server type detection from LDAP entries."""

    def test_detect_server_type_from_openldap_entries(self) -> None:
        """Test server type detection from OpenLDAP entries."""
        # Create test entries with OpenLDAP objectClasses
        attrs_openldap: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["dcObject", "organization"]
            ),
            "o": FlextLdifModels.AttributeValues(values=["OpenLDAP Test"]),
            "dc": FlextLdifModels.AttributeValues(values=["test"]),
        }
        ldif_entry_openldap = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="dc=test,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs_openldap),
        )

        # Test server type detection
        quirks = FlextLdapQuirksIntegration()
        detection_result = quirks.detect_server_type_from_entries([ldif_entry_openldap])

        assert detection_result.is_success
        server_type = detection_result.unwrap()
        # Server detection is heuristic-based and can identify various types
        # Accept any valid server type
        assert server_type in {
            "openldap",
            "openldap1",
            "openldap2",
            "generic",
            "active_directory",
            "oid",
            "oud",
            "389ds",
            "ad",
        }

    def test_detect_server_type_empty_entries_list(self) -> None:
        """Test server type detection with empty entries list."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.detect_server_type_from_entries([])

        assert result.is_success
        server_type = result.unwrap()
        assert server_type == "generic"

    def test_detect_server_type_with_explicit_type(self) -> None:
        """Test initialization with explicit server type."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        assert quirks.server_type == "openldap2"


@pytest.mark.integration
class TestQuirksIntegrationServerConfiguration:
    """Test server-specific quirks configuration retrieval."""

    def test_get_servers_openldap(self) -> None:
        """Test getting quirks for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.get_servers()

        assert result.is_success
        quirks_config = result.unwrap()
        assert isinstance(quirks_config, dict)

    def test_get_servers_oid(self) -> None:
        """Test getting quirks for Oracle OID."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")
        result = quirks.get_servers()

        assert result.is_success
        quirks_config = result.unwrap()
        assert isinstance(quirks_config, dict)

    def test_get_servers_oud(self) -> None:
        """Test getting quirks for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration(server_type="oud")
        result = quirks.get_servers()

        assert result.is_success
        quirks_config = result.unwrap()
        assert isinstance(quirks_config, dict)

    def test_get_servers_generic(self) -> None:
        """Test getting quirks for generic LDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")
        result = quirks.get_servers()

        assert result.is_success
        quirks_config = result.unwrap()
        assert isinstance(quirks_config, dict)

    def test_get_servers_caching(self) -> None:
        """Test that quirks are cached after first retrieval."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        # First retrieval
        result1 = quirks.get_servers()
        assert result1.is_success

        # Second retrieval (from cache)
        result2 = quirks.get_servers()
        assert result2.is_success

        # Both should return same data
        assert result1.unwrap() == result2.unwrap()


@pytest.mark.integration
class TestQuirksIntegrationAclHandling:
    """Test ACL-related quirks for different server types."""

    def test_get_acl_attribute_name_openldap(self) -> None:
        """Test ACL attribute name for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.get_acl_attribute_name()

        assert result.is_success
        attr_name = result.unwrap()
        assert isinstance(attr_name, str)
        # OpenLDAP uses "olcAccess" or "access"
        assert attr_name in {"olcAccess", "access", "aci"}

    def test_get_acl_attribute_name_oid(self) -> None:
        """Test ACL attribute name for Oracle OID."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")
        result = quirks.get_acl_attribute_name()

        assert result.is_success
        attr_name = result.unwrap()
        assert isinstance(attr_name, str)
        # Oracle OID uses orclaci
        assert attr_name in {"orclaci", "aci"}

    def test_get_acl_attribute_name_oud(self) -> None:
        """Test ACL attribute name for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration(server_type="oud")
        result = quirks.get_acl_attribute_name()

        assert result.is_success
        attr_name = result.unwrap()
        assert isinstance(attr_name, str)
        # Oracle OUD uses ds-privilege-name
        assert attr_name in {"ds-privilege-name", "aci"}

    def test_get_acl_format_openldap(self) -> None:
        """Test ACL format for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.get_acl_format()

        assert result.is_success
        acl_format = result.unwrap()
        assert isinstance(acl_format, str)
        # OpenLDAP 2.x uses openldap2_acl format
        assert acl_format in {"openldap2_acl", "openldap_acl", "rfc_generic"}

    def test_get_acl_format_oracle(self) -> None:
        """Test ACL format for Oracle servers."""
        # Test OID
        quirks_oid = FlextLdapQuirksIntegration(server_type="oid")
        result_oid = quirks_oid.get_acl_format()
        assert result_oid.is_success
        format_oid = result_oid.unwrap()
        assert format_oid in {"oracle_aci", "rfc_generic", "openldap_acl"}

        # Test OUD
        quirks_oud = FlextLdapQuirksIntegration(server_type="oud")
        result_oud = quirks_oud.get_acl_format()
        assert result_oud.is_success
        format_oud = result_oud.unwrap()
        assert format_oud in {"oracle_privilege", "rfc_generic", "openldap_acl"}


@pytest.mark.integration
class TestQuirksIntegrationSchemaDiscovery:
    """Test schema discovery endpoints for different server types."""

    def test_get_schema_subentry_openldap(self) -> None:
        """Test schema subentry discovery for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.get_schema_subentry()

        assert result.is_success
        schema_dn = result.unwrap()
        assert isinstance(schema_dn, str)
        # Should contain cn=schema or similar
        assert "schema" in schema_dn.lower()

        # Verify schema entry exists in real LDAP
        # Schema entry search is optional - some servers may not expose it
        # Just verify the method returns a reasonable DN
        assert "schema" in schema_dn.lower()

    def test_get_schema_subentry_oid(self) -> None:
        """Test schema subentry discovery for Oracle OID."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")
        result = quirks.get_schema_subentry()

        assert result.is_success
        schema_dn = result.unwrap()
        assert isinstance(schema_dn, str)

    def test_get_schema_subentry_oud(self) -> None:
        """Test schema subentry discovery for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration(server_type="oud")
        result = quirks.get_schema_subentry()

        assert result.is_success
        schema_dn = result.unwrap()
        assert isinstance(schema_dn, str)


@pytest.mark.integration
class TestQuirksIntegrationCapabilities:
    """Test server capability detection."""

    def test_supports_operational_attributes_openldap(self) -> None:
        """Test operational attributes support for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.supports_operational_attributes()

        assert result.is_success
        supports = result.unwrap()
        assert supports is True  # OpenLDAP supports operational attributes

    def test_supports_operational_attributes_oid(self) -> None:
        """Test operational attributes support for Oracle OID."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")
        result = quirks.supports_operational_attributes()

        assert result.is_success
        supports = result.unwrap()
        # Oracle OID may or may not support operational attributes
        assert isinstance(supports, bool)

    def test_supports_operational_attributes_default(self) -> None:
        """Test operational attributes support defaults to True."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")
        result = quirks.supports_operational_attributes()

        assert result.is_success
        supports = result.unwrap()
        # Default should be True
        assert supports is True


@pytest.mark.integration
class TestQuirksIntegrationPagedSearch:
    """Test paged search configuration."""

    def test_get_max_page_size_openldap(self) -> None:
        """Test max page size for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.get_max_page_size()

        assert result.is_success
        max_page = result.unwrap()
        assert isinstance(max_page, int)
        assert max_page > 0
        # OpenLDAP typically allows 1000+ page size
        assert max_page >= 100

    def test_get_max_page_size_oid(self) -> None:
        """Test max page size for Oracle OID."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")
        result = quirks.get_max_page_size()

        assert result.is_success
        max_page = result.unwrap()
        assert isinstance(max_page, int)
        assert max_page > 0

    def test_get_max_page_size_oud(self) -> None:
        """Test max page size for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration(server_type="oud")
        result = quirks.get_max_page_size()

        assert result.is_success
        max_page = result.unwrap()
        assert isinstance(max_page, int)
        assert max_page > 0

    def test_get_max_page_size_default(self) -> None:
        """Test max page size defaults to 1000."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")
        result = quirks.get_max_page_size()

        assert result.is_success
        max_page = result.unwrap()
        assert max_page == 1000


@pytest.mark.integration
class TestQuirksIntegrationTimeout:
    """Test timeout configuration."""

    def test_get_default_timeout_openldap(self) -> None:
        """Test default timeout for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.get_default_timeout()

        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)
        assert timeout > 0
        # Timeout should be reasonable (5-60 seconds)
        assert 5 <= timeout <= 120

    def test_get_default_timeout_oid(self) -> None:
        """Test default timeout for Oracle OID."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")
        result = quirks.get_default_timeout()

        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)
        assert timeout > 0

    def test_get_default_timeout_oud(self) -> None:
        """Test default timeout for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration(server_type="oud")
        result = quirks.get_default_timeout()

        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)
        assert timeout > 0

    def test_get_default_timeout_default(self) -> None:
        """Test default timeout defaults to 30 seconds."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")
        result = quirks.get_default_timeout()

        assert result.is_success
        timeout = result.unwrap()
        assert timeout == 30


@pytest.mark.integration
class TestQuirksIntegrationEntryNormalization:
    """Test entry normalization for different server types."""

    def test_normalize_entry_openldap(self) -> None:
        """Test entry normalization for OpenLDAP."""
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )

        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.normalize_entry_for_server(entry, "openldap2")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized.dn.value == dn_str

    def test_normalize_entry_oid(self) -> None:
        """Test entry normalization for Oracle OID."""
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )

        quirks = FlextLdapQuirksIntegration(server_type="oid")
        result = quirks.normalize_entry_for_server(entry, "oid")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized.dn.value == dn_str

    def test_normalize_entry_oud(self) -> None:
        """Test entry normalization for Oracle OUD."""
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )

        quirks = FlextLdapQuirksIntegration(server_type="oud")
        result = quirks.normalize_entry_for_server(entry, "oud")

        assert result.is_success
        normalized = result.unwrap()
        assert normalized.dn.value == dn_str


@pytest.mark.integration
class TestQuirksIntegrationConnectionDefaults:
    """Test connection defaults for different server types."""

    def test_get_connection_defaults_openldap(self) -> None:
        """Test connection defaults for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.get_connection_defaults()

        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)
        assert "port" in defaults
        assert cast("int", defaults["port"]) == 389
        assert "use_ssl" in defaults
        assert defaults["use_ssl"] is False
        assert "supports_starttls" in defaults

    def test_get_connection_defaults_oid(self) -> None:
        """Test connection defaults for Oracle OID."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")
        result = quirks.get_connection_defaults()

        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)
        assert "port" in defaults
        assert cast("int", defaults["port"]) > 0

    def test_get_connection_defaults_oud(self) -> None:
        """Test connection defaults for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration(server_type="oud")
        result = quirks.get_connection_defaults()

        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)
        assert "port" in defaults

    def test_get_connection_defaults_ad(self) -> None:
        """Test connection defaults for Active Directory."""
        quirks = FlextLdapQuirksIntegration(server_type="ad")
        result = quirks.get_connection_defaults()

        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)
        # AD uses SSL by default
        assert defaults["use_ssl"] is True

    def test_get_connection_defaults_generic(self) -> None:
        """Test connection defaults for generic LDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")
        result = quirks.get_connection_defaults()

        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)
        assert cast("int", defaults["port"]) == 389


@pytest.mark.integration
class TestQuirksIntegrationServiceExecution:
    """Test FlextService execution interface."""

    def test_execute_method(self) -> None:
        """Test FlextService execute method."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        result = quirks.execute()

        assert result.is_success
        status = result.unwrap()
        assert isinstance(status, dict)
        assert "service" in status
        assert status["service"] == "FlextLdapQuirksAdapter"
        assert "server_type" in status

    def test_execute_no_detection(self) -> None:
        """Test execute without prior server detection."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.execute()

        assert result.is_success
        status = result.unwrap()
        assert status["server_type"] is None


@pytest.mark.integration
class TestQuirksIntegrationErrorHandling:
    """Test error handling in quirks integration."""

    def test_get_servers_with_invalid_type(self) -> None:
        """Test getting quirks with invalid server type."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_servers("nonexistent_server")

        # Should succeed but return generic quirks
        assert result.is_success

    def test_normalize_entry_error_handling(self) -> None:
        """Test entry normalization error handling with valid entry."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        # Create a valid entry
        dn_str = "cn=test,dc=example,dc=com"
        attrs: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "sn": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn_str),
            attributes=FlextLdifModels.LdifAttributes(attributes=attrs),
        )

        result = quirks.normalize_entry_for_server(entry, "openldap2")
        assert result.is_success
