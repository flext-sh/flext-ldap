from __future__ import annotations

from collections.abc import Callable

import pytest

from flext_ldap import FlextLdapSettings

pytest_plugins = ["flext_tests.conftest_plugin"]


@pytest.fixture
def ldap_settings(
    settings_factory: Callable[..., FlextLdapSettings],
) -> FlextLdapSettings:
    """Provide clean FlextLdapSettings for tests."""
    return settings_factory(FlextLdapSettings)
