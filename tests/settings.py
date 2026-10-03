"""Runtime settings for flext-ldap tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsSettings

from flext_ldap import FlextLdapSettings


class TestsFlextLdapSettings(FlextLdapSettings, FlextTestsSettings):
    """LDAP settings extended with the shared test namespace."""


__all__: list[str] = ["TestsFlextLdapSettings"]
