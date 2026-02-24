"""Protocol definitions for flext-ldap tests.

Provides TestsFlextLdapProtocols, extending FlextTestsProtocols with flext-ldap-specific
protocols. All generic test protocols come from flext_tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.protocols import FlextLdapProtocols
from flext_tests.protocols import FlextTestsProtocols


class TestsFlextLdapProtocols(FlextTestsProtocols, FlextLdapProtocols):
    """Protocol definitions for flext-ldap tests.

    Extends both FlextTestsProtocols and FlextLdapProtocols with flext-ldap-specific
    protocol definitions.

    Provides access to:
    - tp.Tests.Docker.* (from FlextTestsProtocols)
    - tp.Tests.Factory.* (from FlextTestsProtocols)
    - tp.Ldap.* (from FlextLdapProtocols)

    Rules:
    - NEVER redeclare protocols from parent classes
    - Only flext-ldap-specific test protocols allowed
    """

    class Tests:
        """Project-specific test protocols.

        Extends FlextTestsProtocols.Tests with flext-ldap-specific protocols.
        """

        class Ldap:
            """Flext-ldap-specific test protocols."""


# Runtime aliases
p = TestsFlextLdapProtocols
tp = TestsFlextLdapProtocols

__all__ = [
    "TestsFlextLdapProtocols",
    "p",
    "tp",
]
