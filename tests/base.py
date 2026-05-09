"""Service base for flext-ldap tests."""

from __future__ import annotations

from typing import override

from flext_tests import s as tests_s

from flext_ldap import m, t
from tests.settings import TestsFlextLdapSettings


class TestsFlextLdapServiceBase[
    TResult: t.JsonPayload | t.SequenceOf[t.JsonPayload] = t.JsonPayload
    | t.SequenceOf[t.JsonPayload],
](tests_s[TResult]):
    """LDAP test service base with source and test settings namespaces."""

    @classmethod
    @override
    def fetch_settings(cls) -> TestsFlextLdapSettings:
        """Return the typed LDAP+LDIF+CLI+Tests settings singleton."""
        return TestsFlextLdapSettings.fetch_global()

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        return m.RuntimeBootstrapOptions(settings_type=TestsFlextLdapSettings)


s = TestsFlextLdapServiceBase

__all__: list[str] = ["TestsFlextLdapServiceBase", "s"]
