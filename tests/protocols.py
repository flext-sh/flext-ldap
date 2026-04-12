"""Protocol definitions for flext-ldap tests.

Provides TestsFlextLdapProtocols, extending TestsFlextProtocols with flext-ldap-specific
protocols. All generic test protocols come from flext_tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsProtocols

from flext_ldap import p


class TestsFlextLdapProtocols(FlextTestsProtocols, p):
    """Protocol definitions for flext-ldap tests."""

    class Ldap(p.Ldap):
        """Flext-ldap-specific test protocols."""

        class Tests:
            """Project-specific test protocols.

            Extends TestsFlextProtocols.Tests with flext-ldap-specific protocols.
            """


p = TestsFlextLdapProtocols

__all__: list[str] = ["TestsFlextLdapProtocols", "p"]
