"""Test configuration for pytest."""

import pytest

from flext_ldap.config import FlextLDAPSettings


@pytest.fixture
def ldap_settings():
    """Provide test LDAP settings."""
    return FlextLDAPSettings(
        connection__server="ldap://test.example.com",
        connection__port=389,
        auth__bind_dn="cn=test,dc=test,dc=com",
        search__base_dn="dc=test,dc=com",
    )
