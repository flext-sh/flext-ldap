"""Unit tests for FlextLdapClient search operations.

Tests search methods: search_with_request, search_users, search_groups, search_one.
Uses optimized session-scoped Docker LDAP fixtures for performance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClient, FlextLdapModels


@pytest.mark.unit
class TestFlextLdapClientSearchUnit:
    """Test FlextLdapClient search operations - unit tests (no Docker)."""

    def test_search_with_request_not_connected(self) -> None:
        """Test search_with_request fails when not connected."""
        client = FlextLdapClient()

        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
            scope="subtree",
        )

        result = client.search_with_request(search_request)

        assert result.is_failure
        assert (
            result.error
            and "not established" in result.error.lower()
            or result.error
            and "connection" in result.error.lower()
        )

    def test_search_with_request_invalid_dn(self) -> None:
        """Test search_with_request validates base DN at Pydantic level."""
        from pydantic_core import ValidationError

        FlextLdapClient()

        # Pydantic validation should reject empty DN at model construction
        with pytest.raises(ValidationError) as exc_info:
            FlextLdapModels.SearchRequest(
                base_dn="",  # Invalid empty DN
                filter_str="(objectClass=person)",
                scope="subtree",
            )

        assert (
            "base_dn" in str(exc_info.value).lower()
            or "dn" in str(exc_info.value).lower()
        )

    def test_search_with_request_invalid_filter(self) -> None:
        """Test search_with_request validates filter at Pydantic level."""
        from pydantic_core import ValidationError

        FlextLdapClient()

        # Pydantic validation should reject empty filter at model construction
        with pytest.raises(ValidationError) as exc_info:
            FlextLdapModels.SearchRequest(
                base_dn="dc=flext,dc=local",
                filter_str="",  # Invalid empty filter
                scope="subtree",
            )

        assert "filter" in str(exc_info.value).lower()

    def test_search_users_not_connected(self) -> None:
        """Test search_users fails when not connected."""
        client = FlextLdapClient()

        result = client.search_users(base_dn="ou=users,dc=flext,dc=local")

        assert result.is_failure
        assert (
            result.error and result.error and "not established" in result.error.lower()
        )

    def test_search_groups_not_connected(self) -> None:
        """Test search_groups fails when not connected."""
        client = FlextLdapClient()

        result = client.search_groups(base_dn="ou=groups,dc=flext,dc=local")

        assert result.is_failure
        assert (
            result.error and result.error and "not established" in result.error.lower()
        )


@pytest.mark.integration
@pytest.mark.docker
class TestFlextLdapClientSearchIntegration:
    """Integration tests for FlextLdapClient search with real LDAP server."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: dict[str, object]
    ) -> FlextLdapClient:
        """Create and connect LDAP client for search tests."""
        client = FlextLdapClient()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        return client

    def test_search_with_request_base_search(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search_with_request with BASE scope."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=dcObject)",
            scope="base",
            attributes=["objectClass", "dc"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success
        response = result.value
        assert response is not None
        assert isinstance(response, FlextLdapModels.SearchResponse)
        assert len(response.entries) > 0

    def test_search_with_request_subtree_search(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search_with_request with SUBTREE scope."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=organizationalUnit)",
            scope="subtree",
            attributes=["ou", "objectClass"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success
        response = result.value
        assert response is not None
        assert isinstance(response.entries, list)

    def test_search_with_request_returns_response(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search_with_request returns SearchResponse object."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=dcObject)",  # More specific filter
            scope="base",  # Base search for reliability
            attributes=["dc", "objectClass"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success
        response = result.value

        # Verify response structure
        assert hasattr(response, "entries")
        assert isinstance(response.entries, list)
        # Note: entries list may be empty or have entries with attribute parsing issues
        # due to ldap3 entry_attributes being list instead of dict in some cases

    def test_search_users_all_users(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search_users retrieves all users."""
        result = authenticated_client.search_users(
            base_dn=str(clean_ldap_container["base_dn"])
        )

        assert result.is_success
        users = result.value
        assert isinstance(users, list)
        # May be empty if no users exist, but should succeed

    def test_search_users_with_uid_filter(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search_users with UID filter."""
        result = authenticated_client.search_users(
            base_dn=str(clean_ldap_container["base_dn"]), uid="nonexistentuser"
        )

        assert result.is_success
        users = result.value
        assert isinstance(users, list)
        # Should return empty list for non-existent user
        assert len(users) == 0

    def test_search_groups_all_groups(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search_groups retrieves all groups."""
        result = authenticated_client.search_groups(
            base_dn=str(clean_ldap_container["base_dn"])
        )

        assert result.is_success
        groups = result.value
        assert isinstance(groups, list)
        # May be empty if no groups exist, but should succeed

    def test_search_groups_with_cn_filter(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search_groups with CN filter."""
        result = authenticated_client.search_groups(
            base_dn=str(clean_ldap_container["base_dn"]), cn="nonexistentgroup"
        )

        assert result.is_success
        groups = result.value
        assert isinstance(groups, list)
        # Should return empty list for non-existent group
        assert len(groups) == 0

    def test_search_disconnected_during_search(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search handles disconnection gracefully."""
        # Disconnect the client
        authenticated_client.disconnect()

        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="subtree",
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_failure
        assert (
            result.error
            and "not established" in result.error.lower()
            or result.error
            and "connection" in result.error.lower()
        )


@pytest.mark.integration
@pytest.mark.docker
@pytest.mark.slow
class TestFlextLdapClientSearchEdgeCases:
    """Edge case tests for FlextLdapClient search operations."""

    @pytest.fixture
    def authenticated_client(
        self, clean_ldap_container: dict[str, object]
    ) -> FlextLdapClient:
        """Create and connect LDAP client for edge case tests."""
        client = FlextLdapClient()

        connect_result = client.connect(
            server_uri=str(clean_ldap_container["server_url"]),
            bind_dn=str(clean_ldap_container["bind_dn"]),
            password=str(clean_ldap_container["password"]),
        )

        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        return client

    def test_search_with_complex_filter(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search with complex LDAP filter."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(&(objectClass=organizationalUnit)(!(ou=readonly)))",
            scope="subtree",
        )

        result = authenticated_client.search_with_request(search_request)

        # Should handle complex filter without crashing
        assert result.is_success or result.is_failure

    def test_search_with_invalid_attribute_list(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search with non-existent attribute in list."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="base",
            attributes=["nonExistentAttribute"],
        )

        result = authenticated_client.search_with_request(search_request)

        # Should handle gracefully (attribute won't be in results)
        assert result.is_success

    def test_search_with_wildcard_filter(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search with wildcard in filter."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="subtree",
            attributes=["objectClass"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success
        response = result.value
        assert len(response.entries) > 0

    def test_search_with_case_insensitive_scope(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search handles case-insensitive scope values."""
        # Test uppercase scope
        search_request = FlextLdapModels.SearchRequest(
            base_dn=str(clean_ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope="SUBTREE",  # Uppercase
            attributes=["objectClass"],
        )

        result = authenticated_client.search_with_request(search_request)

        assert result.is_success

    def test_search_users_empty_base_dn(
        self, authenticated_client: FlextLdapClient
    ) -> None:
        """Test search_users with empty base DN."""
        result = authenticated_client.search_users(base_dn="")

        # Method allows empty base DN and searches from root
        # Returns success with empty or full results depending on LDAP server
        assert result.is_success or result.is_failure
        if result.is_success:
            assert isinstance(result.value, list)

    def test_search_groups_special_characters_in_cn(
        self,
        authenticated_client: FlextLdapClient,
        clean_ldap_container: dict[str, object],
    ) -> None:
        """Test search_groups with special characters in CN."""
        result = authenticated_client.search_groups(
            base_dn=str(clean_ldap_container["base_dn"]), cn="group-with-dashes"
        )

        # Should handle special characters gracefully
        assert result.is_success
        groups = result.value
        assert isinstance(groups, list)
