"""Protocol definitions for flext-ldap tests.

Provides TestsFlextLdapProtocols, extending TestsFlextProtocols with flext-ldap-specific
protocols. All generic test protocols come from flext_tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsProtocols

from tests import FlextLdapProtocols


class TestsFlextLdapProtocols(FlextTestsProtocols, FlextLdapProtocols):
    """Protocol definitions for flext-ldap tests."""

    class Tests(FlextTestsProtocols.Tests):
        """Project-specific test protocols.

        Extends TestsFlextProtocols.Tests with flext-ldap-specific protocols.
        """


p = TestsFlextLdapProtocols

__all__: list[str] = ["TestsFlextLdapProtocols", "p"]
