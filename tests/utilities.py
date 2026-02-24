"""Utilities for flext-ldap tests.

Provides TestsFlextLdapUtilities, extending FlextTestsUtilities with flext-ldap-specific utilities.
All generic test utilities come from flext_tests.

Architecture:
- FlextTestsUtilities (flext_tests) = Generic utilities for all FLEXT projects
- TestsFlextLdapUtilities (tests/) = flext-ldap-specific utilities extending FlextTestsUtilities

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.utilities import FlextLdapUtilities
from flext_tests.utilities import FlextTestsUtilities


class TestsFlextLdapUtilities(FlextTestsUtilities, FlextLdapUtilities):
    """Utilities for flext-ldap tests - extends FlextTestsUtilities and FlextLdapUtilities.

    Architecture: Extends both FlextTestsUtilities and FlextLdapUtilities with flext-ldap-specific utility methods.
    All generic utilities from FlextTestsUtilities and production utilities from FlextLdapUtilities are available through inheritance.

    Rules:
    - NEVER redeclare utilities from FlextTestsUtilities or FlextLdapUtilities
    - Only flext-ldap-specific utilities allowed
    - All generic utilities come from FlextTestsUtilities
    - All production utilities come from FlextLdapUtilities
    """


__all__ = ["TestsFlextLdapUtilities", "u"]

# Alias for simplified usage
u = TestsFlextLdapUtilities
