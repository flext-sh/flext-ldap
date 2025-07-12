"""Test configuration for pytest."""

import pytest

from flext_ldap.config import FlextLDAPSettings


@pytest.fixture
def ldap_settings() -> FlextLDAPSettings:
    """Provide test LDAP settings."""
    return FlextLDAPSettings()  # Use defaults for testing
