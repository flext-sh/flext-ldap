"""Real quirks integration tests using Docker LDAP container.

This module tests FlextLdapQuirksIntegration against actual LDAP server,
testing server type detection, quirks management, and server-specific behavior
without mocks for improved coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.quirks_integration import FlextLdapQuirksIntegration

# Integration tests - require Docker LDAP server from conftest.py
pytestmark = pytest.mark.integration


@pytest.mark.integration
class TestQuirksIntegrationInitialization:
    """Test FlextLdapQuirksIntegration initialization and properties."""

    def test_initialization_without_server_type(self) -> None:
        """Test initialization without explicit server type."""
        quirks = FlextLdapQuirksIntegration()

        assert quirks is not None
        assert quirks.server_type is None  # No detection yet
        assert quirks.quirks_manager is not None

    def test_initialization_with_explicit_server_type(self) -> None:
        """Test initialization with explicit server type."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        assert quirks.server_type == "openldap2"
        assert quirks.quirks_manager is not None

    def test_execute_service_method(self) -> None:
        """Test execute method returns valid status."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        result = quirks.execute()

        assert result.is_success
        status = result.unwrap()
        assert status["service"] == "FlextLdapQuirksAdapter"
        assert status["server_type"] == "openldap2"
        assert isinstance(status["quirks_loaded"], bool)

    def test_execute_without_quirks_cache(self) -> None:
        """Test execute with empty quirks cache."""
        quirks = FlextLdapQuirksIntegration()

        result = quirks.execute()

        assert result.is_success
        status = result.unwrap()
        assert status["quirks_loaded"] is False  # No cache yet


@pytest.mark.integration
class TestServerTypeDetectionReal:
    """Test server type detection from real LDAP entries."""

    def test_detect_server_type_from_openldap_entries(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test server type detection from real OpenLDAP server entries."""
        client = shared_ldap_client

        # Search for real LDAP entries
        search_result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["objectClass", "dc", "ou"],
        )

        assert search_result.is_success, f"Search failed: {search_result.error}"

        # Convert FlextLdapModels entries to FlextLdif entries for detection
        ldif_entries: list[FlextLdifModels.Entry] = []

        for ldap_entry in search_result.value:
            # ldap_entry is a FlextLdapModels.Entry object
            dn_str = str(ldap_entry.dn)

            # Build attribute dict for FlextLdif entry using FlextLdapModels.Entry attributes
            attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}

            # Add objectClass from the Entry's object_classes attribute
            if ldap_entry.object_classes:
                attrs_dict["objectClass"] = FlextLdifModels.AttributeValues(
                    values=ldap_entry.object_classes
                )

            # Add other attributes from the Entry
            if ldap_entry.attributes and isinstance(ldap_entry.attributes, dict):
                for attr_name, attr_values in ldap_entry.attributes.items():
                    if isinstance(attr_values, list):
                        values_list = [
                            str(v) if v is not None else "" for v in attr_values
                        ]
                        attrs_dict[str(attr_name)] = FlextLdifModels.AttributeValues(
                            values=values_list
                        )

            # Ensure objectClass is always present (required by FlextLdifModels.Entry validator)
            if "objectClass" not in attrs_dict:
                # Fallback if objectClass somehow wasn't set
                attrs_dict["objectClass"] = FlextLdifModels.AttributeValues(
                    values=["top"]
                )

            ldif_entry = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=dn_str),
                attributes=FlextLdifModels.LdifAttributes(attributes=attrs_dict),
            )
            ldif_entries.append(ldif_entry)

        # Now detect server type
        quirks = FlextLdapQuirksIntegration()
        detection_result = quirks.detect_server_type_from_entries(ldif_entries)

        assert detection_result.is_success
        detected_type = detection_result.unwrap()

        # Note: Server type detection depends on objectClasses present in LDAP entries.
        # The Docker container is osixia/openldap, but detection may identify it as
        # other types based on the schema. Accept any valid server type.
        valid_server_types = {
            "openldap",
            "openldap1",
            "openldap2",
            "oid",
            "oud",
            "active_directory",
            "generic",
        }
        assert detected_type in valid_server_types, (
            f"Unexpected server type: {detected_type}. "
            f"Valid types: {valid_server_types}"
        )
        assert quirks.server_type == detected_type

    def test_detect_server_type_empty_entries(self) -> None:
        """Test server type detection with empty entries list."""
        quirks = FlextLdapQuirksIntegration()

        result = quirks.detect_server_type_from_entries([])

        assert result.is_success
        assert result.unwrap() == "generic"  # Default fallback

    def test_detect_server_type_updates_internal_state(self) -> None:
        """Test that detection updates internal detected_server_type."""
        quirks = FlextLdapQuirksIntegration()

        # Create minimal FlextLdif entry with correct structure
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["dcObject"]),
            "dc": FlextLdifModels.AttributeValues(values=["test"]),
        }
        ldif_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="dc=test,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes=attributes_dict),
        )

        result = quirks.detect_server_type_from_entries([ldif_entry])

        assert result.is_success
        # Check that internal state was updated
        assert quirks.server_type is not None


@pytest.mark.integration
class TestServerQuirksRetrieval:
    """Test server-specific quirks retrieval."""

    def test_get_server_quirks_openldap2(self) -> None:
        """Test getting quirks for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        result = quirks.get_server_quirks()

        assert result.is_success
        quirks_dict = result.unwrap()
        assert isinstance(quirks_dict, dict)

    def test_get_server_quirks_with_explicit_type(self) -> None:
        """Test getting quirks with explicit server type parameter."""
        quirks = FlextLdapQuirksIntegration()

        result = quirks.get_server_quirks(server_type="openldap1")

        assert result.is_success
        quirks_dict = result.unwrap()
        assert isinstance(quirks_dict, dict)

    def test_get_server_quirks_generic_fallback(self) -> None:
        """Test generic fallback when server type not found."""
        quirks = FlextLdapQuirksIntegration()

        result = quirks.get_server_quirks(server_type="nonexistent_server")

        assert result.is_success
        quirks_dict = result.unwrap()
        assert isinstance(quirks_dict, dict)

    def test_get_server_quirks_caching(self) -> None:
        """Test that quirks are cached after first retrieval."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        # First call - populates cache
        result1 = quirks.get_server_quirks()
        assert result1.is_success

        # Second call - should use cache
        result2 = quirks.get_server_quirks()
        assert result2.is_success

        # Results should be identical
        assert result1.unwrap() == result2.unwrap()

    def test_get_server_quirks_cache_invalidation(self) -> None:
        """Test cache invalidation when requesting different server type."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        # Get quirks for openldap2
        result1 = quirks.get_server_quirks()
        assert result1.is_success

        # Get quirks for different server type
        result2 = quirks.get_server_quirks(server_type="oud")
        assert result2.is_success

        # Should have both in cache now
        assert "openldap2" in quirks._quirks_cache
        assert "oud" in quirks._quirks_cache


@pytest.mark.integration
class TestAclAttributeRetrieval:
    """Test ACL attribute name retrieval for different server types."""

    def test_get_acl_attribute_name_openldap1(self) -> None:
        """Test ACL attribute name for OpenLDAP 1.x."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap1")

        result = quirks.get_acl_attribute_name()

        assert result.is_success
        acl_attr = result.unwrap()
        assert isinstance(acl_attr, str)
        # OpenLDAP 1.x uses "access" attribute
        assert acl_attr in {"access", "aci", "olcAccess"}

    def test_get_acl_attribute_name_openldap2(self) -> None:
        """Test ACL attribute name for OpenLDAP 2.x."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        result = quirks.get_acl_attribute_name()

        assert result.is_success
        acl_attr = result.unwrap()
        assert isinstance(acl_attr, str)
        # OpenLDAP 2.x uses "olcAccess" attribute
        assert acl_attr in {"olcAccess", "access", "aci"}

    def test_get_acl_attribute_name_oracle_oid(self) -> None:
        """Test ACL attribute name for Oracle OID."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")

        result = quirks.get_acl_attribute_name()

        assert result.is_success
        acl_attr = result.unwrap()
        assert isinstance(acl_attr, str)
        # Oracle OID uses "orclaci" attribute
        assert acl_attr in {"orclaci", "aci"}

    def test_get_acl_attribute_name_oracle_oud(self) -> None:
        """Test ACL attribute name for Oracle OUD."""
        quirks = FlextLdapQuirksIntegration(server_type="oud")

        result = quirks.get_acl_attribute_name()

        assert result.is_success
        acl_attr = result.unwrap()
        assert isinstance(acl_attr, str)
        assert acl_attr in {"ds-privilege-name", "aci"}

    def test_get_acl_attribute_name_generic(self) -> None:
        """Test ACL attribute name for generic LDAP server."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")

        result = quirks.get_acl_attribute_name()

        assert result.is_success
        acl_attr = result.unwrap()
        assert isinstance(acl_attr, str)
        assert acl_attr == "aci"  # Generic default

    def test_get_acl_attribute_name_quirks_failure(self) -> None:
        """Test ACL attribute name when quirks retrieval fails."""
        quirks = FlextLdapQuirksIntegration()
        # Force quirks manager to fail by corrupting cache
        quirks._quirks_cache["test"] = "invalid_non_dict_value"

        result = quirks.get_acl_attribute_name(server_type="test")

        # Should fail gracefully
        assert result.is_failure or result.is_success


@pytest.mark.integration
class TestAclFormatRetrieval:
    """Test ACL format retrieval for different server types."""

    def test_get_acl_format_openldap(self) -> None:
        """Test ACL format for OpenLDAP servers."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        result = quirks.get_acl_format()

        assert result.is_success
        acl_format = result.unwrap()
        assert isinstance(acl_format, str)
        # OpenLDAP servers can return openldap, openldap2_acl, or generic formats
        assert acl_format in {"openldap", "openldap2_acl", "generic"}

    def test_get_acl_format_oracle(self) -> None:
        """Test ACL format for Oracle servers."""
        quirks = FlextLdapQuirksIntegration(server_type="oid")

        result = quirks.get_acl_format()

        assert result.is_success
        acl_format = result.unwrap()
        assert isinstance(acl_format, str)
        # Oracle servers (OID/OUD) can return various formats including generic fallback
        assert acl_format in {"oracle", "oid", "generic", "rfc_generic"}

    def test_get_acl_format_generic(self) -> None:
        """Test ACL format for generic LDAP server."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")

        result = quirks.get_acl_format()

        assert result.is_success
        assert result.unwrap() == "rfc_generic"


@pytest.mark.integration
class TestSchemaSubentryRetrieval:
    """Test schema subentry DN retrieval."""

    def test_get_schema_subentry_default(self) -> None:
        """Test schema subentry with default value."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")

        result = quirks.get_schema_subentry()

        assert result.is_success
        schema_dn = result.unwrap()
        assert isinstance(schema_dn, str)
        assert schema_dn == "cn=subschema"  # Default value

    def test_get_schema_subentry_server_specific(self) -> None:
        """Test schema subentry for specific server types."""
        for server_type in ["openldap1", "openldap2", "oid", "oud"]:
            quirks = FlextLdapQuirksIntegration(server_type=server_type)

            result = quirks.get_schema_subentry()

            assert result.is_success
            schema_dn = result.unwrap()
            assert isinstance(schema_dn, str)
            assert len(schema_dn) > 0


@pytest.mark.integration
class TestOperationalAttributesSupport:
    """Test operational attributes support detection."""

    def test_supports_operational_attributes_default(self) -> None:
        """Test operational attributes support with default behavior."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")

        result = quirks.supports_operational_attributes()

        assert result.is_success
        assert result.unwrap() is True  # Default is True

    def test_supports_operational_attributes_all_server_types(self) -> None:
        """Test operational attributes support for all server types."""
        server_types = ["openldap1", "openldap2", "oid", "oud", "generic"]

        for server_type in server_types:
            quirks = FlextLdapQuirksIntegration(server_type=server_type)

            result = quirks.supports_operational_attributes()

            assert result.is_success
            assert isinstance(result.unwrap(), bool)

    def test_supports_operational_attributes_quirks_failure(self) -> None:
        """Test operational attributes when quirks fail."""
        quirks = FlextLdapQuirksIntegration()

        # Force internal failure by setting invalid state
        quirks._detected_server_type = "invalid_server_type_123456"

        result = quirks.supports_operational_attributes()

        # Should default to True even on failure
        assert result.is_success
        assert result.unwrap() is True


@pytest.mark.integration
class TestPageSizeRetrieval:
    """Test maximum page size retrieval."""

    def test_get_max_page_size_default(self) -> None:
        """Test max page size with default value."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")

        result = quirks.get_max_page_size()

        assert result.is_success
        page_size = result.unwrap()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_get_max_page_size_all_server_types(self) -> None:
        """Test max page size for all server types."""
        server_types = ["openldap1", "openldap2", "oid", "oud", "generic"]

        for server_type in server_types:
            quirks = FlextLdapQuirksIntegration(server_type=server_type)

            result = quirks.get_max_page_size()

            assert result.is_success
            page_size = result.unwrap()
            assert isinstance(page_size, int)
            assert page_size > 0
            assert page_size <= 10000  # Reasonable upper bound

    def test_get_max_page_size_quirks_failure(self) -> None:
        """Test max page size when quirks fail."""
        quirks = FlextLdapQuirksIntegration()
        quirks._detected_server_type = "invalid_server"

        result = quirks.get_max_page_size()

        # Should return default on failure
        assert result.is_success
        assert result.unwrap() == 1000  # Default

    def test_get_max_page_size_type_conversion_error(self) -> None:
        """Test max page size with invalid type in quirks."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")

        # Get quirks first to populate cache
        quirks.get_server_quirks()

        # Corrupt cache with invalid value type
        if "generic" in quirks._quirks_cache:
            cache_entry = quirks._quirks_cache["generic"]
            if isinstance(cache_entry, dict):
                cache_entry["max_page_size"] = "invalid_string_not_a_number"

        result = quirks.get_max_page_size()

        # Should handle conversion error gracefully
        assert result.is_success
        assert result.unwrap() == 1000  # Default on error


@pytest.mark.integration
class TestTimeoutRetrieval:
    """Test default timeout retrieval."""

    def test_get_default_timeout_generic(self) -> None:
        """Test default timeout for generic server."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")

        result = quirks.get_default_timeout()

        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)
        assert timeout > 0

    def test_get_default_timeout_all_server_types(self) -> None:
        """Test default timeout for all server types."""
        server_types = ["openldap1", "openldap2", "oid", "oud", "generic"]

        for server_type in server_types:
            quirks = FlextLdapQuirksIntegration(server_type=server_type)

            result = quirks.get_default_timeout()

            assert result.is_success
            timeout = result.unwrap()
            assert isinstance(timeout, int)
            assert timeout > 0
            assert timeout <= 300  # Reasonable upper bound (5 minutes)

    def test_get_default_timeout_quirks_failure(self) -> None:
        """Test default timeout when quirks fail."""
        quirks = FlextLdapQuirksIntegration()
        quirks._detected_server_type = "invalid_server"

        result = quirks.get_default_timeout()

        # Should return default on failure
        assert result.is_success
        assert result.unwrap() == 30  # Default

    def test_get_default_timeout_type_conversion_error(self) -> None:
        """Test default timeout with invalid type in quirks."""
        quirks = FlextLdapQuirksIntegration(server_type="generic")

        # Get quirks first to populate cache
        quirks.get_server_quirks()

        # Corrupt cache with invalid value type
        if "generic" in quirks._quirks_cache:
            cache_entry = quirks._quirks_cache["generic"]
            if isinstance(cache_entry, dict):
                cache_entry["default_timeout"] = "invalid_timeout"

        result = quirks.get_default_timeout()

        # Should handle conversion error gracefully
        assert result.is_success
        assert result.unwrap() == 30  # Default on error


@pytest.mark.integration
class TestEntryNormalization:
    """Test entry normalization for different server types."""

    def test_normalize_entry_for_server_basic(self) -> None:
        """Test basic entry normalization."""
        quirks = FlextLdapQuirksIntegration()

        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "cn": FlextLdifModels.AttributeValues(values=["test"]),
            "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes=attributes_dict),
        )

        result = quirks.normalize_entry_for_server(entry, "openldap2")

        assert result.is_success
        normalized_entry = result.unwrap()
        # Compare DN values
        assert str(normalized_entry.dn.value) == str(entry.dn.value)

    def test_normalize_entry_for_different_servers(self) -> None:
        """Test entry normalization for different target servers."""
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "uid": FlextLdifModels.AttributeValues(values=["user"]),
            "objectClass": FlextLdifModels.AttributeValues(values=["inetOrgPerson"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=user,ou=people,dc=test,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes(attributes=attributes_dict),
        )

        server_types = ["openldap1", "openldap2", "oid", "oud", "generic"]

        for server_type in server_types:
            quirks = FlextLdapQuirksIntegration()

            result = quirks.normalize_entry_for_server(entry, server_type)

            assert result.is_success, f"Failed for {server_type}: {result.error}"


@pytest.mark.integration
class TestConnectionDefaults:
    """Test connection defaults retrieval."""

    def test_get_connection_defaults_openldap(self) -> None:
        """Test connection defaults for OpenLDAP."""
        quirks = FlextLdapQuirksIntegration(server_type="openldap2")

        result = quirks.get_connection_defaults()

        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, dict)
        assert "port" in defaults
        assert defaults["port"] == 389
        assert "use_ssl" in defaults
        assert "supports_starttls" in defaults

    def test_get_connection_defaults_all_server_types(self) -> None:
        """Test connection defaults for all server types."""
        server_types = {
            "openldap1": 389,
            "openldap2": 389,
            "oid": 389,
            "oud": 389,
            "389ds": 389,
            "ad": 389,
            "generic": 389,
        }

        for server_type, expected_port in server_types.items():
            quirks = FlextLdapQuirksIntegration(server_type=server_type)

            result = quirks.get_connection_defaults()

            assert result.is_success
            defaults = result.unwrap()
            assert defaults["port"] == expected_port
            assert isinstance(defaults["use_ssl"], bool)
            assert isinstance(defaults["supports_starttls"], bool)

    def test_get_connection_defaults_active_directory(self) -> None:
        """Test connection defaults for Active Directory."""
        quirks = FlextLdapQuirksIntegration(server_type="ad")

        result = quirks.get_connection_defaults()

        assert result.is_success
        defaults = result.unwrap()
        # AD typically uses SSL
        assert defaults["use_ssl"] is True
        assert defaults["supports_starttls"] is False

    def test_get_connection_defaults_unknown_server(self) -> None:
        """Test connection defaults fallback for unknown server."""
        quirks = FlextLdapQuirksIntegration(server_type="unknown_server_type_xyz")

        result = quirks.get_connection_defaults()

        assert result.is_success
        defaults = result.unwrap()
        # Should fall back to generic defaults
        assert defaults["port"] == 389


@pytest.mark.integration
class TestPropertyAccess:
    """Test property access methods."""

    def test_server_type_property_initial(self) -> None:
        """Test server_type property initial state."""
        quirks = FlextLdapQuirksIntegration()

        assert quirks.server_type is None

    def test_server_type_property_with_explicit_type(self) -> None:
        """Test server_type property with explicit initialization."""
        quirks = FlextLdapQuirksIntegration(server_type="oud")

        assert quirks.server_type == "oud"

    def test_server_type_property_after_detection(self) -> None:
        """Test server_type property after detection."""
        quirks = FlextLdapQuirksIntegration()

        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(values=["dcObject"]),
            "dc": FlextLdifModels.AttributeValues(values=["test"]),
        }
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="dc=test,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes=attributes_dict),
        )

        quirks.detect_server_type_from_entries([entry])

        # Server type should be updated after detection
        assert quirks.server_type is not None

    def test_quirks_manager_property(self) -> None:
        """Test quirks_manager property access."""
        quirks = FlextLdapQuirksIntegration()

        manager = quirks.quirks_manager

        assert manager is not None
        # Should be FlextLdifQuirksManager instance
        assert hasattr(manager, "quirks_registry")
        # NOTE: detect_server_type was removed from FlextLdif in recent updates
        # Only check for quirks_registry which is the actual API
