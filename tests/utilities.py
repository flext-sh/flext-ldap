"""Utilities for flext-ldap tests.

Provides TestsFlextLdapUtilities, extending u with flext-ldap-specific utilities.
All generic test utilities come from flext_tests.

Architecture:
- u (flext_tests) = Generic utilities for all FLEXT projects
- TestsFlextLdapUtilities (tests/) = flext-ldap-specific utilities extending u

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsUtilities

from flext_ldap import FlextLdapUtilities


class TestsFlextLdapUtilities(FlextTestsUtilities, FlextLdapUtilities):
    """Utilities for flext-ldap tests - extends u and FlextLdapUtilities.

    Architecture: Extends both u and FlextLdapUtilities with flext-ldap-specific utility methods.
    All generic utilities from u and production utilities from FlextLdapUtilities are available through inheritance.

    Rules:
    - NEVER redeclare utilities from u or FlextLdapUtilities
    - Only flext-ldap-specific utilities allowed
    - All generic utilities come from u
    - All production utilities come from FlextLdapUtilities
    """

    class Ldap(FlextLdapUtilities.Ldap):
        """LDAP test utilities."""

        class Tests:
            """flext-ldap-specific test utilities definitions namespace.

            Use t.Tests.* for generic test types from t.
            """


__all__ = ["TestsFlextLdapUtilities", "u"]
u = TestsFlextLdapUtilities
