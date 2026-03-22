"""Protocol definitions for flext-ldap tests.

Provides FlextLdapTestProtocols, extending FlextTestsProtocols with flext-ldap-specific
protocols. All generic test protocols come from flext_tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsProtocols

from flext_ldap import FlextLdapProtocols


class FlextLdapTestProtocols(FlextTestsProtocols, FlextLdapProtocols):
    """Protocol definitions for flext-ldap tests.

    Extends both FlextTestsProtocols and FlextLdapProtocols with flext-ldap-specific
    protocol definitions.

    Provides access to:
    - p.Tests.Docker.* (from FlextTestsProtocols)
    - p.Tests.Factory.* (from FlextTestsProtocols)
    - p.Ldap.* (from FlextLdapProtocols)

    Rules:
    - NEVER redeclare protocols from parent classes
    - Only flext-ldap-specific test protocols allowed
    """

    class Ldap(FlextLdapProtocols.Ldap):
        """Flext-ldap-specific test protocols."""

        class Tests:
            """Project-specific test protocols.

            Extends FlextTestsProtocols.Tests with flext-ldap-specific protocols.
            """


p = FlextLdapTestProtocols
__all__ = ["FlextLdapTestProtocols", "p"]
