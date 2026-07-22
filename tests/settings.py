"""Runtime settings for flext-ldap tests."""

from __future__ import annotations

from flext_ldap import FlextLdapSettings
from flext_tests import FlextTestsSettings


class TestsFlextLdapSettings(FlextLdapSettings, FlextTestsSettings):
    """LDAP settings extended with the shared test namespace."""


__all__: list[str] = ["TestsFlextLdapSettings"]
