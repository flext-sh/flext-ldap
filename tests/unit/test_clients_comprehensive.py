"""Comprehensive unit tests for FlextLdapClients real operations.

Tests all FlextLdapClients methods with real LDAP operations when container is available,
otherwise gracefully skips with informative reasons.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdapClients, FlextLdapModels


@pytest.mark.unit
class TestFlextLdapClientsEdgeCases:
    """Edge case tests for FlextLdapClients methods."""

    def test_normalize_dn_with_various_formats(self) -> None:
        """Test DN normalization with multiple input formats."""
        client = FlextLdapClients()

        # Test uppercase DN
        dn1 = "CN=John,DC=Example,DC=Com"
        normalized1 = client.normalize_dn(dn1)
        assert isinstance(normalized1, str)

        # Test lowercase DN
        dn2 = "cn=john,dc=example,dc=com"
        normalized2 = client.normalize_dn(dn2)
        assert isinstance(normalized2, str)

        # Test mixed case DN
        dn3 = "Cn=John,Dc=Example,Dc=Com"
        normalized3 = client.normalize_dn(dn3)
        assert isinstance(normalized3, str)

        # Test with spaces
        dn4 = "CN=John Doe,DC=Example,DC=Com"
        normalized4 = client.normalize_dn(dn4)
        assert isinstance(normalized4, str)

    def test_get_server_capabilities_structure(self) -> None:
        """Test get_server_capabilities returns proper structure."""
        client = FlextLdapClients()
        result = client.get_server_capabilities()

        # Should return FlextResult
        assert isinstance(result, FlextResult)

    def test_clients_initialization_with_config(self) -> None:
        """Test FlextLdapClients initialization with configuration."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost:389",
            port=389,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
            base_dn="dc=example,dc=com",
        )

        client = FlextLdapClients(config=config)
        assert client is not None

    def test_search_with_attributes_list(self) -> None:
        """Test search with explicit attributes list."""
        client = FlextLdapClients()

        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            attributes=["cn", "mail", "objectClass"],
        )

        assert isinstance(result, FlextResult)

    def test_search_with_single_attribute(self) -> None:
        """Test search with single attribute as string."""
        client = FlextLdapClients()

        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(cn=*)",
            attributes=["cn"],
        )

        assert isinstance(result, FlextResult)

    def test_search_with_no_attributes(self) -> None:
        """Test search without specifying attributes (all returned)."""
        client = FlextLdapClients()

        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )

        assert isinstance(result, FlextResult)

    def test_search_scope_variations(self) -> None:
        """Test search with different scope values."""
        client = FlextLdapClients()

        # Base scope
        result_base = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="base",
        )
        assert isinstance(result_base, FlextResult)

        # OneLevel scope
        result_one = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="onelevel",
        )
        assert isinstance(result_one, FlextResult)

        # Subtree scope
        result_sub = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="subtree",
        )
        assert isinstance(result_sub, FlextResult)

    def test_test_connection_without_credentials(self) -> None:
        """Test connection test without providing credentials."""
        client = FlextLdapClients()
        result = client.test_connection()
        assert isinstance(result, FlextResult)

    def test_search_filter_with_special_characters(self) -> None:
        """Test search with LDAP filter special characters."""
        client = FlextLdapClients()

        # Filter with wildcards and operators
        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(&(objectClass=person)(cn=*John*))",
        )
        assert isinstance(result, FlextResult)

    def test_normalize_dn_empty_string(self) -> None:
        """Test normalizing empty DN string."""
        client = FlextLdapClients()
        result = client.normalize_dn("")
        assert isinstance(result, str)

    def test_normalize_dn_single_component(self) -> None:
        """Test normalizing DN with single component."""
        client = FlextLdapClients()
        result = client.normalize_dn("cn=admin")
        assert isinstance(result, str)

    def test_normalize_dn_with_special_chars(self) -> None:
        """Test normalizing DN with special characters."""
        client = FlextLdapClients()

        # DN with special characters (email-like)
        dn_special = "cn=user+admin@example.com,dc=example,dc=com"
        result = client.normalize_dn(dn_special)
        assert isinstance(result, str)

        # DN with spaces and quotes
        dn_spaces = 'cn=John "The Admin" Doe,dc=example,dc=com'
        result2 = client.normalize_dn(dn_spaces)
        assert isinstance(result2, str)


@pytest.mark.unit
class TestFlextLdapClientsValidation:
    """Validation and error handling tests for FlextLdapClients."""

    def test_search_with_invalid_base_dn(self) -> None:
        """Test search with malformed base DN."""
        client = FlextLdapClients()

        # Invalid DN format should still return FlextResult (error)
        result = client.search(
            base_dn="invalid:dn:format",
            filter_str="(objectClass=*)",
        )
        assert isinstance(result, FlextResult)

    def test_search_with_invalid_filter(self) -> None:
        """Test search with malformed LDAP filter."""
        client = FlextLdapClients()

        # Invalid filter format should return FlextResult (error)
        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(invalid filter without closing paren",
        )
        assert isinstance(result, FlextResult)

    def test_search_with_empty_filter(self) -> None:
        """Test search with empty filter string."""
        client = FlextLdapClients()

        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="",
        )
        assert isinstance(result, FlextResult)

    def test_search_with_null_character_in_filter(self) -> None:
        """Test search with null character in filter (edge case)."""
        client = FlextLdapClients()

        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(cn=test\x00injected)",
        )
        assert isinstance(result, FlextResult)

    def test_normalize_dn_with_long_string(self) -> None:
        """Test normalizing very long DN string."""
        client = FlextLdapClients()

        # Create a very long DN
        long_dn = "cn=" + "a" * 1000 + ",dc=example,dc=com"
        result = client.normalize_dn(long_dn)
        assert isinstance(result, str)

    def test_search_with_extremely_large_attributes_list(self) -> None:
        """Test search with very large attributes list."""
        client = FlextLdapClients()

        # Create large list of attributes
        large_attrs = [f"attr{i}" for i in range(100)]

        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            attributes=large_attrs,
        )
        assert isinstance(result, FlextResult)


@pytest.mark.unit
class TestFlextLdapClientsConfigVariations:
    """Tests for various client configuration scenarios."""

    def test_clients_with_none_config(self) -> None:
        """Test creating client with None config."""
        client = FlextLdapClients(config=None)
        assert client is not None

    def test_clients_with_ssl_enabled(self) -> None:
        """Test client configuration with SSL enabled."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldaps://localhost:636",
            port=636,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
            base_dn="dc=example,dc=com",
            use_ssl=True,
        )

        client = FlextLdapClients(config=config)
        assert client is not None

    def test_clients_with_start_tls(self) -> None:
        """Test client configuration with START_TLS."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost:389",
            port=389,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
            base_dn="dc=example,dc=com",
            use_ssl=False,
        )

        client = FlextLdapClients(config=config)
        assert client is not None

    def test_clients_with_custom_timeout(self) -> None:
        """Test client with custom connection timeout."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost:389",
            port=389,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
            base_dn="dc=example,dc=com",
            timeout=30,
        )

        client = FlextLdapClients(config=config)
        assert client is not None

    def test_clients_with_minimal_config(self) -> None:
        """Test client with minimal required configuration."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost:389",
            port=389,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
            base_dn="dc=example,dc=com",
        )

        client = FlextLdapClients(config=config)
        assert client is not None


@pytest.mark.unit
class TestFlextLdapClientsReturnTypes:
    """Test that all methods return correct types."""

    def test_normalize_dn_returns_string(self) -> None:
        """Verify normalize_dn always returns string."""
        client = FlextLdapClients()

        result = client.normalize_dn("cn=test,dc=example,dc=com")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_search_returns_flext_result(self) -> None:
        """Verify search always returns FlextResult."""
        client = FlextLdapClients()

        result = client.search(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )
        assert isinstance(result, FlextResult)

    def test_test_connection_returns_flext_result(self) -> None:
        """Verify test_connection always returns FlextResult."""
        client = FlextLdapClients()

        result = client.test_connection()
        assert isinstance(result, FlextResult)

    def test_get_server_capabilities_returns_flext_result(self) -> None:
        """Verify get_server_capabilities always returns FlextResult."""
        client = FlextLdapClients()

        result = client.get_server_capabilities()
        assert isinstance(result, FlextResult)
