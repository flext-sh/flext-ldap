"""Runtime settings for flext-ldap tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsSettings

from flext_ldap._settings import FlextLdapSettings


class TestsFlextLdapSettings(FlextLdapSettings, FlextTestsSettings):
    """LDAP settings extended with the shared test namespace."""

    # A ``Tests*``-named non-test helper: without this marker pytest attempts
    # to collect it from every test-module namespace that imports it.
    __test__: bool = False


__all__: list[str] = ["TestsFlextLdapSettings"]
