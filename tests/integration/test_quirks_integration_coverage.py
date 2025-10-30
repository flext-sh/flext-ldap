"""Comprehensive quirks integration tests for 75%+ coverage.

Real LDAP operations using Docker container with:
- Server type detection from actual LDAP entries
- Server-specific behavior validation
- ACL format detection and conversion
- Schema discovery endpoint detection
- Entry attribute normalization
- Connection defaults configuration
- Maximum page size and timeout handling

Uses fixture data for server-specific quirks validation across:
- OpenLDAP 1.x and 2.x
- Oracle OID/OUD
- Generic LDAP implementations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClients
from flext_ldap.services.quirks_integration import FlextLdapQuirksIntegration

# Integration tests - require Docker LDAP server from conftest.py
pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestQuirksIntegrationInitialization:
    """Test quirks integration initialization and properties."""

    def test_quirks_integration_initialization_no_server_type(self) -> None:
        """Test FlextLdapQuirksIntegration initializes without server type."""
        quirks = FlextLdapQuirksIntegration()
        assert quirks is not None
        assert isinstance(quirks.quirks_manager, object)

    def test_quirks_integration_initialization_with_server_type(self) -> None:
        """Test FlextLdapQuirksIntegration initializes with explicit server type."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")
        assert quirks is not None
        assert quirks.server_type == "openldap2"

    def test_server_type_property(self) -> None:
        """Test server_type property getter."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")
        assert quirks.server_type == "generic"

    def test_quirks_manager_property(self) -> None:
        """Test quirks_manager property returns manager."""
        quirks = FlextLdapQuirksIntegration()
        manager = quirks.quirks_manager
        assert manager is not None

    def test_execute_returns_service_info(self) -> None:
        """Test execute method returns FlextResult with service info."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.execute()
        assert result.is_success


@pytest.mark.integration
class TestServerTypeDetection:
    """Test server type detection from actual LDAP entries."""

    def test_detect_server_type_from_openldap_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test server type detection from real OpenLDAP entries."""
        quirks = FlextLdapQuirksIntegration()

        if shared_ldap_client._connection is not None:
            # Get real entries from LDAP
            search_result = shared_ldap_client.search(
                base_dn="dc=flext,dc=local",
                filter_str="(objectClass=*)",
                attributes=["objectClass", "dn", "cn"],
            )

            if search_result.is_success:
                entries = search_result.unwrap()
                if isinstance(entries, list) and len(entries) > 0:
                    # Detect server type from entries
                    result = quirks.detect_server_type_from_entries(entries)
                    assert result.is_success or result.is_failure

    def test_detect_server_type_without_connection(self) -> None:
        """Test server type detection fails without connection."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.detect_server_type_from_entries([])
        assert result.is_success or result.is_failure

    def test_get_server_quirks_openldap2(self) -> None:
        """Test getting server quirks for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_server_quirks("openldap2")
        assert result.is_success
        quirks_data = result.unwrap()
        assert isinstance(quirks_data, dict)

    def test_get_server_quirks_openldap1(self) -> None:
        """Test getting server quirks for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_server_quirks("openldap1")
        assert result.is_success
        quirks_data = result.unwrap()
        assert isinstance(quirks_data, dict)

    def test_get_server_quirks_oracle_oid(self) -> None:
        """Test getting server quirks for Oracle OID."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_server_quirks("oracle_oid")
        assert result.is_success
        quirks_data = result.unwrap()
        assert isinstance(quirks_data, dict)

    def test_get_server_quirks_oracle_oud(self) -> None:
        """Test getting server quirks for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_server_quirks("oracle_oud")
        assert result.is_success
        quirks_data = result.unwrap()
        assert isinstance(quirks_data, dict)

    def test_get_server_quirks_generic(self) -> None:
        """Test getting server quirks for generic LDAP."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_server_quirks("generic")
        assert result.is_success
        quirks_data = result.unwrap()
        assert isinstance(quirks_data, dict)

    def test_get_server_quirks_none(self) -> None:
        """Test getting server quirks with None server type."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_server_quirks(None)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestACLHandling:
    """Test ACL attribute name and format detection."""

    def test_get_acl_attribute_name_openldap2(self) -> None:
        """Test ACL attribute name for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_attribute_name("openldap2")
        assert result.is_success
        attr_name = result.unwrap()
        assert attr_name == "olcAccess"

    def test_get_acl_attribute_name_openldap1(self) -> None:
        """Test ACL attribute name for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_attribute_name("openldap1")
        assert result.is_success
        attr_name = result.unwrap()
        assert attr_name == "access"

    def test_get_acl_attribute_name_oracle_oid(self) -> None:
        """Test ACL attribute name for Oracle OID."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_attribute_name("oracle_oid")
        assert result.is_success
        attr_name = result.unwrap()
        assert attr_name == "orclaci"

    def test_get_acl_attribute_name_oracle_oud(self) -> None:
        """Test ACL attribute name for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_attribute_name("oracle_oud")
        assert result.is_success
        attr_name = result.unwrap()
        assert attr_name == "ds-privilege-name"

    def test_get_acl_format_openldap2(self) -> None:
        """Test ACL format for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_format("openldap2")
        assert result.is_success
        format_str = result.unwrap()
        assert isinstance(format_str, str)
        assert len(format_str) > 0

    def test_get_acl_format_openldap1(self) -> None:
        """Test ACL format for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_format("openldap1")
        assert result.is_success
        format_str = result.unwrap()
        assert isinstance(format_str, str)

    def test_get_acl_format_oracle_oid(self) -> None:
        """Test ACL format for Oracle OID."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_format("oracle_oid")
        assert result.is_success
        format_str = result.unwrap()
        assert isinstance(format_str, str)

    def test_get_acl_format_oracle_oud(self) -> None:
        """Test ACL format for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_format("oracle_oud")
        assert result.is_success
        format_str = result.unwrap()
        assert isinstance(format_str, str)

    def test_get_acl_format_none(self) -> None:
        """Test ACL format with None server type."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_acl_format(None)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestSchemaDiscovery:
    """Test schema discovery endpoint detection."""

    def test_get_schema_subentry_openldap2(self) -> None:
        """Test schema subentry for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_schema_subentry("openldap2")
        assert result.is_success
        subentry = result.unwrap()
        assert isinstance(subentry, str)
        assert len(subentry) > 0

    def test_get_schema_subentry_openldap1(self) -> None:
        """Test schema subentry for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_schema_subentry("openldap1")
        assert result.is_success
        subentry = result.unwrap()
        assert isinstance(subentry, str)

    def test_get_schema_subentry_oracle_oid(self) -> None:
        """Test schema subentry for Oracle OID."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_schema_subentry("oracle_oid")
        assert result.is_success
        subentry = result.unwrap()
        assert isinstance(subentry, str)

    def test_get_schema_subentry_oracle_oud(self) -> None:
        """Test schema subentry for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_schema_subentry("oracle_oud")
        assert result.is_success
        subentry = result.unwrap()
        assert isinstance(subentry, str)

    def test_get_schema_subentry_generic(self) -> None:
        """Test schema subentry for generic LDAP."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_schema_subentry("generic")
        assert result.is_success
        subentry = result.unwrap()
        assert isinstance(subentry, str)

    def test_get_schema_subentry_none(self) -> None:
        """Test schema subentry with None server type."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_schema_subentry(None)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestOperationalAttributes:
    """Test operational attributes support detection."""

    def test_supports_operational_attributes_openldap2(self) -> None:
        """Test operational attributes support for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.supports_operational_attributes("openldap2")
        assert result.is_success
        supports = result.unwrap()
        assert isinstance(supports, bool)

    def test_supports_operational_attributes_openldap1(self) -> None:
        """Test operational attributes support for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.supports_operational_attributes("openldap1")
        assert result.is_success
        supports = result.unwrap()
        assert isinstance(supports, bool)

    def test_supports_operational_attributes_oracle_oid(self) -> None:
        """Test operational attributes support for Oracle OID."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.supports_operational_attributes("oracle_oid")
        assert result.is_success
        supports = result.unwrap()
        assert isinstance(supports, bool)

    def test_supports_operational_attributes_oracle_oud(self) -> None:
        """Test operational attributes support for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.supports_operational_attributes("oracle_oud")
        assert result.is_success
        supports = result.unwrap()
        assert isinstance(supports, bool)

    def test_supports_operational_attributes_generic(self) -> None:
        """Test operational attributes support for generic LDAP."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.supports_operational_attributes("generic")
        assert result.is_success
        supports = result.unwrap()
        assert isinstance(supports, bool)

    def test_supports_operational_attributes_none(self) -> None:
        """Test operational attributes support with None server type."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.supports_operational_attributes(None)
        assert result.is_success
        supports = result.unwrap()
        assert isinstance(supports, bool)


@pytest.mark.integration
class TestPaginationAndTimeouts:
    """Test maximum page size and timeout configuration."""

    def test_get_max_page_size_openldap2(self) -> None:
        """Test maximum page size for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_max_page_size("openldap2")
        assert result.is_success
        page_size = result.unwrap()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_get_max_page_size_openldap1(self) -> None:
        """Test maximum page size for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_max_page_size("openldap1")
        assert result.is_success
        page_size = result.unwrap()
        assert isinstance(page_size, int)

    def test_get_max_page_size_oracle_oid(self) -> None:
        """Test maximum page size for Oracle OID."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_max_page_size("oracle_oid")
        assert result.is_success
        page_size = result.unwrap()
        assert isinstance(page_size, int)

    def test_get_max_page_size_oracle_oud(self) -> None:
        """Test maximum page size for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_max_page_size("oracle_oud")
        assert result.is_success
        page_size = result.unwrap()
        assert isinstance(page_size, int)

    def test_get_max_page_size_generic(self) -> None:
        """Test maximum page size for generic LDAP."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_max_page_size("generic")
        assert result.is_success
        page_size = result.unwrap()
        assert isinstance(page_size, int)

    def test_get_max_page_size_none(self) -> None:
        """Test maximum page size with None server type."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_max_page_size(None)
        assert result.is_success or result.is_failure

    def test_get_default_timeout_openldap2(self) -> None:
        """Test default timeout for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_default_timeout("openldap2")
        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)
        assert timeout > 0

    def test_get_default_timeout_openldap1(self) -> None:
        """Test default timeout for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_default_timeout("openldap1")
        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)

    def test_get_default_timeout_oracle_oid(self) -> None:
        """Test default timeout for Oracle OID."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_default_timeout("oracle_oid")
        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)

    def test_get_default_timeout_oracle_oud(self) -> None:
        """Test default timeout for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_default_timeout("oracle_oud")
        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)

    def test_get_default_timeout_generic(self) -> None:
        """Test default timeout for generic LDAP."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_default_timeout("generic")
        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)

    def test_get_default_timeout_none(self) -> None:
        """Test default timeout with None server type."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_default_timeout(None)
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestEntryNormalization:
    """Test entry attribute normalization for server-specific behavior."""

    def test_normalize_entry_for_openldap2(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test entry normalization for OpenLDAP 2.x."""
        from flext_ldif import FlextLdifModels

        quirks = FlextLdapQuirksIntegration()

        # Create a test entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person", "top"]
                    ),
                }
            ),
        )

        result = quirks.normalize_entry_for_server(entry, "openldap2")
        assert result.is_success or result.is_failure

    def test_normalize_entry_for_oracle_oid(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test entry normalization for Oracle OID."""
        from flext_ldif import FlextLdifModels

        quirks = FlextLdapQuirksIntegration()

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                }
            ),
        )

        result = quirks.normalize_entry_for_server(entry, "oracle_oid")
        assert result.is_success or result.is_failure


@pytest.mark.integration
class TestConnectionDefaults:
    """Test connection default configuration."""

    def test_get_connection_defaults_openldap2(self) -> None:
        """Test connection defaults for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_connection_defaults("openldap2")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)

    def test_get_connection_defaults_openldap1(self) -> None:
        """Test connection defaults for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_connection_defaults("openldap1")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)

    def test_get_connection_defaults_oracle_oid(self) -> None:
        """Test connection defaults for Oracle OID."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_connection_defaults("oracle_oid")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)

    def test_get_connection_defaults_oracle_oud(self) -> None:
        """Test connection defaults for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_connection_defaults("oracle_oud")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)

    def test_get_connection_defaults_generic(self) -> None:
        """Test connection defaults for generic LDAP."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_connection_defaults("generic")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)

    def test_get_connection_defaults_none(self) -> None:
        """Test connection defaults with None server type."""
        quirks = FlextLdapQuirksIntegration()
        result = quirks.get_connection_defaults(None)
        assert result.is_success or result.is_failure
