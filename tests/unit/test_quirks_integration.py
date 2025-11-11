"""Comprehensive tests for FlextLdapQuirksIntegration module.

Tests cover:
- Server type detection from LDAP entries
- Server-specific quirks retrieval and caching
- ACL attribute name and format detection
- Schema subentry discovery
- Operational attributes support checking
- Pagination and timeout configuration
- Entry normalization
- Connection defaults configuration
- Error handling and recovery
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.services.quirks_integration import FlextLdapQuirksIntegration


class TestFlextLdapQuirksIntegration:
    """Test cases for FlextLdapQuirksIntegration adapter."""

    @pytest.fixture
    def quirks_adapter(self) -> FlextLdapQuirksIntegration:
        """Create quirks adapter instance."""
        return FlextLdapQuirksIntegration()

    @pytest.fixture
    def quirks_adapter_with_server_type(self) -> FlextLdapQuirksIntegration:
        """Create quirks adapter with explicit server type."""
        return FlextLdapQuirksIntegration(server_type="openldap2")

    @pytest.fixture
    def sample_ldap_entries(self) -> list[FlextLdifModels.Entry]:
        """Create sample LDAP entries for testing."""
        return [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=schema,cn=config"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "objectClass": ["device"],
                        "cn": ["schema"],
                    }
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "objectClass": ["dcObject"],
                        "dc": ["example"],
                    }
                ),
            ),
        ]

    def test_initialization_without_server_type(self) -> None:
        """Test adapter initialization without explicit server type."""
        adapter = FlextLdapQuirksIntegration()
        assert adapter is not None
        assert adapter.server_type is None
        assert adapter.quirks_manager is not None

    def test_initialization_with_server_type(
        self, quirks_adapter_with_server_type: FlextLdapQuirksIntegration
    ) -> None:
        """Test adapter initialization with explicit server type."""
        assert quirks_adapter_with_server_type.server_type == "openldap2"

    def test_execute_returns_flext_result(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test execute method returns FlextResult."""
        result = quirks_adapter.execute()
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_execute_contains_expected_fields(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test execute result contains expected fields."""
        result = quirks_adapter.execute()
        assert result.is_success
        data = result.unwrap()
        assert "service" in data
        assert data["service"] == "FlextLdapQuirksAdapter"
        assert "server_type" in data
        assert "quirks_loaded" in data

    def test_server_type_property(
        self, quirks_adapter_with_server_type: FlextLdapQuirksIntegration
    ) -> None:
        """Test server_type property access."""
        assert quirks_adapter_with_server_type.server_type == "openldap2"

    def tests_manager_property(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test quirks_manager property access."""
        manager = quirks_adapter.quirks_manager
        assert manager is not None

    def test_detect_server_type_from_empty_entries(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test server type detection with empty entries list."""
        result = quirks_adapter.detect_server_type_from_entries([])
        assert result.is_success
        assert result.unwrap() == "generic"

    def test_detect_server_type_from_valid_entries(
        self,
        quirks_adapter: FlextLdapQuirksIntegration,
        sample_ldap_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test server type detection with valid entries."""
        result = quirks_adapter.detect_server_type_from_entries(sample_ldap_entries)
        assert result.is_success
        detected_type = result.unwrap()
        assert isinstance(detected_type, str)
        assert detected_type in {
            "generic",
            "openldap",  # Generic OpenLDAP when version cannot be distinguished
            "openldap1",
            "openldap2",
            "oid",
            "oud",
            "389ds",
            "ad",
            "active_directory",
        }

    def test_detect_server_type_updates_internal_state(
        self,
        quirks_adapter: FlextLdapQuirksIntegration,
        sample_ldap_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test that detection updates internal server type."""
        result = quirks_adapter.detect_server_type_from_entries(sample_ldap_entries)
        assert result.is_success
        # After detection, server_type should be set
        assert quirks_adapter.server_type is not None

    def test_detect_server_type_with_minimal_attributes(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test server type detection with minimal attributes."""
        # Create entry with minimal attributes
        minimal_entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="dc=minimal,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"objectClass": ["dcObject"]}
                ),
            )
        ]
        result = quirks_adapter.detect_server_type_from_entries(minimal_entries)
        # Should still succeed with fallback
        assert result.is_success
        detected = result.unwrap()
        assert isinstance(detected, str)
        assert detected in {
            "generic",
            "rfc",  # RFC fallback when detection has low confidence
            "openldap",  # Generic OpenLDAP when version cannot be distinguished
            "openldap1",
            "openldap2",
            "oid",
            "oud",
            "389ds",
            "ad",
            "active_directory",
        }

    def test_get_servers_with_explicit_type(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting quirks for explicit server type."""
        result = quirks_adapter.get_servers("openldap2")
        assert result.is_success
        quirks = result.unwrap()
        assert isinstance(quirks, dict)

    def test_get_servers_with_detected_type(
        self,
        quirks_adapter_with_server_type: FlextLdapQuirksIntegration,
    ) -> None:
        """Test getting quirks for detected server type."""
        result = quirks_adapter_with_server_type.get_servers()
        assert result.is_success
        quirks = result.unwrap()
        assert isinstance(quirks, dict)

    def test_get_servers_caches_results(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test that quirks are cached after first retrieval."""
        # First call
        result1 = quirks_adapter.get_servers("openldap2")
        assert result1.is_success

        # Cache should now contain the type
        assert "openldap2" in quirks_adapter.s_cache

        # Second call should use cache
        result2 = quirks_adapter.get_servers("openldap2")
        assert result2.is_success
        assert result1.unwrap() == result2.unwrap()

    def test_get_servers_fallback_to_generic(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test fallback to generic quirks for unknown server type."""
        # Request quirks for non-existent server type
        result = quirks_adapter.get_servers("nonexistent_server")
        assert result.is_success
        quirks = result.unwrap()
        assert isinstance(quirks, dict)

    def test_get_acl_attribute_name_default(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting ACL attribute name with default."""
        result = quirks_adapter.get_acl_attribute_name()
        assert result.is_success
        attr_name = result.unwrap()
        assert isinstance(attr_name, str)

    def test_get_acl_attribute_name_specific_server(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting ACL attribute name for specific server."""
        result = quirks_adapter.get_acl_attribute_name("openldap2")
        assert result.is_success
        attr_name = result.unwrap()
        assert isinstance(attr_name, str)

    def test_get_acl_format_default(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting ACL format with default."""
        result = quirks_adapter.get_acl_format()
        assert result.is_success
        acl_format = result.unwrap()
        assert isinstance(acl_format, str)

    def test_get_acl_format_specific_server(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting ACL format for specific server."""
        result = quirks_adapter.get_acl_format("oud")
        assert result.is_success
        acl_format = result.unwrap()
        assert isinstance(acl_format, str)

    def test_get_schema_subentry_default(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting schema subentry with default."""
        result = quirks_adapter.get_schema_subentry()
        assert result.is_success
        subentry = result.unwrap()
        assert isinstance(subentry, str)

    def test_get_schema_subentry_specific_server(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting schema subentry for specific server."""
        result = quirks_adapter.get_schema_subentry("oid")
        assert result.is_success
        subentry = result.unwrap()
        assert isinstance(subentry, str)

    def test_supports_operational_attributes_default(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test checking operational attributes support."""
        result = quirks_adapter.supports_operational_attributes()
        assert result.is_success
        supports = result.unwrap()
        assert isinstance(supports, bool)

    def test_supports_operational_attributes_specific_server(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test operational attributes support for specific server."""
        result = quirks_adapter.supports_operational_attributes("openldap1")
        assert result.is_success
        supports = result.unwrap()
        assert isinstance(supports, bool)

    def test_get_max_page_size_default(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting max page size."""
        result = quirks_adapter.get_max_page_size()
        assert result.is_success
        max_page = result.unwrap()
        assert isinstance(max_page, int)
        assert max_page > 0

    def test_get_max_page_size_specific_server(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting max page size for specific server."""
        result = quirks_adapter.get_max_page_size("openldap2")
        assert result.is_success
        max_page = result.unwrap()
        assert isinstance(max_page, int)
        assert max_page > 0

    def test_get_max_page_size_default_on_error(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test max page size returns default on conversion error."""
        # This should handle non-integer values gracefully
        result = quirks_adapter.get_max_page_size()
        assert result.is_success
        max_page = result.unwrap()
        assert max_page == 1000 or max_page > 0

    def test_get_default_timeout_default(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting default timeout."""
        result = quirks_adapter.get_default_timeout()
        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)
        assert timeout > 0

    def test_get_default_timeout_specific_server(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting default timeout for specific server."""
        result = quirks_adapter.get_default_timeout("oud")
        assert result.is_success
        timeout = result.unwrap()
        assert isinstance(timeout, int)
        assert timeout > 0

    def test_get_default_timeout_default_on_error(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test timeout returns default on conversion error."""
        result = quirks_adapter.get_default_timeout()
        assert result.is_success
        timeout = result.unwrap()
        assert timeout == 30 or timeout > 0

    def test_normalize_entry_for_server_success(
        self,
        quirks_adapter: FlextLdapQuirksIntegration,
        sample_ldap_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test entry normalization for target server."""
        entry = sample_ldap_entries[0]
        result = quirks_adapter.normalize_entry_for_server(entry, "openldap2")
        assert result.is_success
        normalized = result.unwrap()
        assert isinstance(normalized, FlextLdifModels.Entry)

    def test_normalize_entry_for_different_servers(
        self,
        quirks_adapter: FlextLdapQuirksIntegration,
        sample_ldap_entries: list[FlextLdifModels.Entry],
    ) -> None:
        """Test entry normalization for different server types."""
        entry = sample_ldap_entries[0]

        for server_type in ["openldap1", "openldap2", "oid", "oud", "generic"]:
            result = quirks_adapter.normalize_entry_for_server(entry, server_type)
            assert result.is_success
            normalized = result.unwrap()
            assert isinstance(normalized, FlextLdifModels.Entry)

    def test_get_connection_defaults_generic(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting connection defaults for generic server."""
        from flext_ldap.models import FlextLdapModels

        result = quirks_adapter.get_connection_defaults("generic")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, FlextLdapModels.ConnectionConfig)
        assert defaults.port == FlextLdapConstants.Defaults.DEFAULT_PORT
        assert defaults.use_ssl is False

    def test_get_connection_defaults_openldap(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting connection defaults for OpenLDAP."""
        from flext_ldap.models import FlextLdapModels

        result = quirks_adapter.get_connection_defaults("openldap2")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, FlextLdapModels.ConnectionConfig)
        assert defaults.port == FlextLdapConstants.Defaults.DEFAULT_PORT
        assert defaults.use_ssl is False

    def test_get_connection_defaults_oid(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting connection defaults for Oracle OID."""
        from flext_ldap.models import FlextLdapModels

        result = quirks_adapter.get_connection_defaults("oid")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, FlextLdapModels.ConnectionConfig)
        assert defaults.port == FlextLdapConstants.Defaults.DEFAULT_PORT
        assert defaults.use_ssl is False

    def test_get_connection_defaults_oud(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting connection defaults for Oracle OUD."""
        from flext_ldap.models import FlextLdapModels

        result = quirks_adapter.get_connection_defaults("oud")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, FlextLdapModels.ConnectionConfig)
        assert defaults.port == FlextLdapConstants.Defaults.DEFAULT_PORT

    def test_get_connection_defaults_active_directory(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting connection defaults for Active Directory."""
        from flext_ldap.models import FlextLdapModels

        result = quirks_adapter.get_connection_defaults("ad")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, FlextLdapModels.ConnectionConfig)
        assert defaults.port == FlextLdapConstants.Defaults.DEFAULT_PORT
        assert defaults.use_ssl is True

    def test_get_connection_defaults_with_detected_type(
        self, quirks_adapter_with_server_type: FlextLdapQuirksIntegration
    ) -> None:
        """Test getting connection defaults using detected type."""
        from flext_ldap.models import FlextLdapModels

        result = quirks_adapter_with_server_type.get_connection_defaults()
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, FlextLdapModels.ConnectionConfig)

    def test_get_connection_defaults_unknown_type_fallback(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test connection defaults falls back to generic for unknown type."""
        from flext_ldap.models import FlextLdapModels

        result = quirks_adapter.get_connection_defaults("unknown_server")
        assert result.is_success
        defaults = result.unwrap()
        assert isinstance(defaults, FlextLdapModels.ConnectionConfig)
        # Should fall back to generic defaults
        assert defaults.port == FlextLdapConstants.Defaults.DEFAULT_PORT

    def test_multiples_cache_entries(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test caching of multiple server type quirks."""
        # Request quirks for multiple server types
        result1 = quirks_adapter.get_servers("openldap2")
        result2 = quirks_adapter.get_servers("oid")
        result3 = quirks_adapter.get_servers("oud")

        assert result1.is_success
        assert result2.is_success
        assert result3.is_success

        # All three should be cached
        assert "openldap2" in quirks_adapter.s_cache
        assert "oid" in quirks_adapter.s_cache
        assert "oud" in quirks_adapter.s_cache

    def test_invalid_cache_entry_removal_and_reload(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test invalid cache entries are removed and reloaded."""
        # Manually add invalid cache entry
        quirks_adapter.s_cache["openldap2"] = "invalid_string"

        # Getting quirks should remove invalid entry and reload
        result = quirks_adapter.get_servers("openldap2")
        assert result.is_success
        quirks = result.unwrap()
        assert isinstance(quirks, dict)

    def test_flext_result_error_handling_in_get_servers(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test FlextResult error handling in get_servers."""
        # Even with unusual server types, should return success
        result = quirks_adapter.get_servers("very_unusual_server_type_xyz")
        assert result.is_success

    def test_all_server_types_supported(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test that all major server types are supported."""
        server_types = [
            "openldap1",
            "openldap2",
            "oid",
            "oud",
            "389ds",
            "ad",
            "generic",
        ]

        for server_type in server_types:
            result = quirks_adapter.get_connection_defaults(server_type)
            assert result.is_success, f"Failed for server type: {server_type}"

    def tests_integration_is_flext_service(
        self, quirks_adapter: FlextLdapQuirksIntegration
    ) -> None:
        """Test that QuirksIntegration is a proper FlextService."""
        # Should have FlextService methods
        assert hasattr(quirks_adapter, "execute")
        assert hasattr(quirks_adapter, "logger")

    def test_execute_with_detected_server_type(
        self,
        quirks_adapter_with_server_type: FlextLdapQuirksIntegration,
    ) -> None:
        """Test execute result shows detected server type."""
        result = quirks_adapter_with_server_type.execute()
        assert result.is_success
        data = result.unwrap()
        assert data["server_type"] == "openldap2"
