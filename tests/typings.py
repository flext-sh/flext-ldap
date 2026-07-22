"""Type system foundation for flext-ldap tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import t
from flext_tests import FlextTestsTypes


class TestsFlextLdapTypes(FlextTestsTypes, t):
    """Type system foundation for flext-ldap tests - extends TestsFlextTypes and t."""

    class Ldap(t.Ldap):
        """LDAP test types."""

        class Tests:
            """flext-ldap-specific test type definitions namespace.

            Consolidates all test types from helpers/typings.py and inline locations.
            Use t.Ldap.Tests.* for all flext-ldap test types.
            """

            type LdapContainerDict = t.MappingKV[str, t.Scalar]


t = TestsFlextLdapTypes

__all__: list[str] = ["TestsFlextLdapTypes", "t"]
