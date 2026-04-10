"""Type system foundation for flext-ldap tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from flext_tests import FlextTestsTypes

from flext_ldap import t
from tests import r

if TYPE_CHECKING:
    from tests import m


class TestsFlextLdapTypes(FlextTestsTypes, t):
    """Type system foundation for flext-ldap tests - extends TestsFlextTypes and t.

    Architecture: Extends both TestsFlextTypes and t with flext-ldap-specific type definitions.
    All generic types from TestsFlextTypes and production types from t are available through inheritance.

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

            # Core operation result types (from helpers/typings.py)
            type OperationResultType = r[m.Ldap.OperationResult]
            type SearchResultType = r[m.Ldap.SearchResult]

            # Test data dictionary types
            type GenericFieldsDict = Mapping[
                str,
                TestsFlextLdapTypes.Scalar
                | TestsFlextLdapTypes.StrSequence
                | Mapping[str, TestsFlextLdapTypes.StrSequence],
            ]
            type LdapContainerDict = TestsFlextLdapTypes.ScalarMapping
            type LdapConnectionConfigDict = Mapping[
                str,
                TestsFlextLdapTypes.OptionalScalar,
            ]
            type LdapSearchOptionsDict = TestsFlextLdapTypes.ScalarMapping
            type LdapEntryDataDict = Mapping[
                str,
                TestsFlextLdapTypes.Scalar | TestsFlextLdapTypes.StrSequence,
            ]
            type LdapSchemaAttributeDict = Mapping[
                str,
                str | TestsFlextLdapTypes.StrSequence | bool,
            ]
            type LdapSchemaObjectClassDict = Mapping[
                str,
                str | TestsFlextLdapTypes.StrSequence | bool,
            ]
            type LdapModifyOperationDict = Mapping[
                str,
                TestsFlextLdapTypes.Scalar | TestsFlextLdapTypes.StrSequence,
            ]
            type LdapSearchResultDict = Mapping[
                str,
                TestsFlextLdapTypes.Scalar | TestsFlextLdapTypes.StrSequence,
            ]
            type LdapTestScenarioDict = TestsFlextLdapTypes.ScalarMapping
            type GenericTestCaseDict = TestsFlextLdapTypes.ScalarMapping
            type GenericCallableParameterDict = TestsFlextLdapTypes.ScalarMapping
            type LdapConnectionResultDict = TestsFlextLdapTypes.ScalarMapping


t = TestsFlextLdapTypes

__all__ = ["TestsFlextLdapTypes", "t"]
