"""Type system foundation for flext-ldap tests."""

from __future__ import annotations

from flext_tests import FlextTestsTypes

from flext_ldap import t


class TestsFlextLdapTypes(FlextTestsTypes, t):
    """Type system foundation for flext-ldap tests - extends TestsFlextTypes and t.

    Architecture: Extends both TestsFlextTypes and t with flext-ldap-specific
    type definitions. All generic types from TestsFlextTypes and production
    types from t are available through inheritance.

    Hierarchy:
    - t.Ldap.Tests.* (generic test types from flext_tests)
    - t.Ldap.* (source types from flext_ldap)
    - TestsFlextLdapTypes.Tests.* (flext-ldap-specific test types)

    Rules:
    - NEVER redeclare types from TestsFlextTypes or t
    - Only flext-ldap-specific types allowed (not generic for other projects)
    - All generic types come from TestsFlextTypes
    - All production types come from t
    """

    class Ldap(t.Ldap):
        """LDAP test types."""

        class Tests:
            """flext-ldap-specific test type definitions namespace.

            Consolidates all test types from helpers/typings.py and inline locations.
            Use t.Ldap.Tests.* for all flext-ldap test types.
            """

            type LdapContainerDict = t.MappingKV[
                str,
                t.Scalar,
            ]


t = TestsFlextLdapTypes

__all__: list[str] = ["TestsFlextLdapTypes", "t"]
