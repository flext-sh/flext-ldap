"""Protocol definitions for flext-ldap tests.

Provides TestsFlextLdapProtocols, extending p with flext-ldap-specific
protocols. All generic test protocols come from flext_tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import p

from flext_ldap import FlextLdapProtocols


class TestsFlextLdapProtocols(p, FlextLdapProtocols):
    """Protocol definitions for flext-ldap tests.

    Extends both p and FlextLdapProtocols with flext-ldap-specific
    protocol definitions.

    Provides access to:
    - p.Tests.Docker.* (from p)
    - p.Tests.Factory.* (from p)
    - p.Ldap.* (from FlextLdapProtocols)

    Rules:
    - NEVER redeclare protocols from parent classes
    - Only flext-ldap-specific test protocols allowed
    """

    class Tests(p.Tests):
        """Project-specific test protocols.

        Extends p.Tests with flext-ldap-specific protocols.
        """

        class Ldap:
            """Flext-ldap-specific test protocols."""


p = TestsFlextLdapProtocols
__all__ = ["TestsFlextLdapProtocols", "p"]
