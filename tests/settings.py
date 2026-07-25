"""Runtime settings for flext-ldap tests."""

from __future__ import annotations

from flext_tests.settings import FlextTestsSettings

from flext_ldap import FlextLdapSettings


class TestsFlextLdapSettings(FlextLdapSettings, FlextTestsSettings):
    """LDAP settings extended with the shared test namespace."""


__all__: list[str] = ["TestsFlextLdapSettings"]
