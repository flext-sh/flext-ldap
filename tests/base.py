"""Service base for flext-ldap tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from flext_ldap import m
from flext_tests import s as tests_s
from tests.settings import TestsFlextLdapSettings

if TYPE_CHECKING:
    from tests import p


class TestsFlextLdapServiceBase[TDomainResult: p.Base = p.Base](tests_s[TDomainResult]):
    """LDAP test service base with source and test settings namespaces."""

    # NOTE (multi-agent): flext-tests owns fetch_settings; this project
    # declares only its more-specific bootstrap settings type.
    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        return m.RuntimeBootstrapOptions(settings_type=TestsFlextLdapSettings)


s = TestsFlextLdapServiceBase

__all__: list[str] = ["TestsFlextLdapServiceBase", "s"]
