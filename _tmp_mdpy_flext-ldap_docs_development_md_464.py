# from flext-ldap_docs/development.md:464
from __future__ import annotations

import pytest
from flext_ldap import FlextLdapEntities
from flext_ldap.api import ldap


@pytest.mark.integration
@pytest.mark.io
class TestLdapOperations:
    """Integration tests with real LDAP server."""

    def test_user_authentication_success(self, ldap_server):
        """Test successful user authentication."""
        api = ldap

        # Create test user first
        create_request = FlextLdapEntities.CreateUserRequest(
            dn="cn=test.user,ou=users,dc=flext,dc=local",
            uid="test.user",
            cn="Test User",
            sn="User",
            password="test123",
        )

        create_result = api.create_user(create_request)
        assert create_result.success

        # Test authentication
        auth_result = api.authenticate_user("test.user", "test123")
        assert auth_result.success

        user = auth_result.unwrap()
        assert user.uid == "test.user"
        assert user.cn == "Test User"

    def test_user_search(self, ldap_server):
        """Test user search functionality."""
        api = ldap

        search_request = FlextLdapEntities.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["uid", "cn", "mail"],
        )

        result = api.search_entries(search_request)
        assert result.success

        entries = result.unwrap()
        assert isinstance(entries, list)```
### Test Fixtures

