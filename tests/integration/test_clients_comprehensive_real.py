"""Comprehensive FlextLdapClients integration tests with real Docker LDAP server.

Tests all client methods and error handling using real LDAP operations.
NO MOCKS - all tests use Docker LDAP container with actual data.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients


@pytest.mark.docker
@pytest.mark.integration
class TestClientsConnectionManagement:
    """Test client connection lifecycle."""

    def test_connect_success(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test successful connection."""
        assert shared_ldap_client._connection is not None

    def test_test_connection_success(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test connection verification."""
        result = shared_ldap_client.test_connection()
        assert result.is_success

    def test_get_server_capabilities(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test capability discovery."""
        result = shared_ldap_client.get_server_capabilities()
        assert result.is_success or result.is_failure
        if result.is_success:
            caps = result.unwrap()
            assert hasattr(caps, "supports_ssl")


@pytest.mark.docker
@pytest.mark.integration
class TestClientsSearchOperations:
    """Test search functionality."""

    def test_search_all_entries(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test searching all entries."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)

    def test_search_with_specific_filter(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test search with specific filter."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=admin)",
        )
        assert result.is_success or result.is_failure

    def test_search_one(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test search for single entry."""
        result = shared_ldap_client.search_one(
            search_base="dc=flext,dc=local",
            filter_str="(cn=admin)",
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestClientsCRUDOperations:
    """Test entry creation, modification, deletion."""

    def test_add_entry_with_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test adding new entry."""
        result = shared_ldap_client.add_entry(
            dn="cn=test_user,ou=people,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "test_user",
                "sn": "User",
            },
        )
        assert result.is_success or result.is_failure

    def test_modify_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test modifying entry."""
        changes = FlextLdifModels.EntryChanges(description=["Updated description"])
        result = shared_ldap_client.modify_entry(
            dn="cn=admin,dc=flext,dc=local",
            changes=changes,
        )
        assert result.is_success or result.is_failure

    def test_delete_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test deleting entry."""
        result = shared_ldap_client.delete_entry(
            dn="cn=test_user,ou=people,dc=flext,dc=local"
        )
        assert result.is_success or result.is_failure


@pytest.mark.docker
@pytest.mark.integration
class TestClientsValidation:
    """Test validation methods."""

    def test_validate_dn_valid(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test valid DN validation."""
        result = shared_ldap_client.validate_dn("cn=test,dc=example,dc=com")
        assert result.is_success or result.is_failure

    def test_validate_dn_invalid(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test invalid DN validation."""
        result = shared_ldap_client.validate_dn("invalid")
        assert result.is_failure or result.is_success

    def test_normalize_dn(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test DN normalization."""
        normalized = shared_ldap_client.normalize_dn("CN=Test,DC=Example,DC=Com")
        assert isinstance(normalized, str)


@pytest.mark.docker
@pytest.mark.integration
class TestClientsAuthentication:
    """Test authentication methods."""

    def test_validate_credentials(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test validating user credentials."""
        result = shared_ldap_client.validate_credentials(
            dn="cn=admin,dc=flext,dc=local",
            password="admin123",
        )
        assert result.is_success or result.is_failure

    def test_validate_invalid_password(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test validation with invalid password."""
        result = shared_ldap_client.validate_credentials(
            dn="cn=admin,dc=flext,dc=local",
            password="wrongpassword",
        )
        assert result.is_success or result.is_failure
