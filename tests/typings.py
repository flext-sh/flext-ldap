"""Type system foundation for flext-ldap tests."""

from __future__ import annotations

from collections.abc import Mapping

from flext_tests import FlextTestsTypes

from flext_core.result import r
from flext_ldap import FlextLdapModels, FlextLdapTypes


class TestsFlextLdapTypes(FlextTestsTypes, FlextLdapTypes):
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

    class Ldap(FlextLdapTypes.Ldap):
        """LDAP test types."""

        class Tests:
            """flext-ldap-specific test type definitions namespace.

            Consolidates all test types from helpers/typings.py and inline locations.
            Use t.Ldap.Tests.* for all flext-ldap test types.
            """

            # Core operation result types (from helpers/typings.py)
            type OperationResultType = r[FlextLdapModels.Ldap.OperationResult]
            type SearchResultType = r[FlextLdapModels.Ldap.SearchResult]

            # Test data dictionary types
            type GenericFieldsDict = Mapping[
                str,
                FlextLdapTypes.Scalar
                | FlextLdapTypes.StrSequence
                | Mapping[str, FlextLdapTypes.StrSequence],
            ]
            type LdapContainerDict = FlextLdapTypes.ScalarMapping
            type LdapConnectionConfigDict = Mapping[
                str,
                FlextLdapTypes.OptionalScalar,
            ]
            type LdapSearchOptionsDict = FlextLdapTypes.ScalarMapping
            type LdapEntryDataDict = Mapping[
                str,
                FlextLdapTypes.Scalar | FlextLdapTypes.StrSequence,
            ]
            type LdapSchemaAttributeDict = Mapping[
                str,
                str | FlextLdapTypes.StrSequence | bool,
            ]
            type LdapSchemaObjectClassDict = Mapping[
                str,
                str | FlextLdapTypes.StrSequence | bool,
            ]
            type LdapModifyOperationDict = Mapping[
                str,
                FlextLdapTypes.Scalar | FlextLdapTypes.StrSequence,
            ]
            type LdapSearchResultDict = Mapping[
                str,
                FlextLdapTypes.Scalar | FlextLdapTypes.StrSequence,
            ]
            type LdapTestScenarioDict = FlextLdapTypes.ScalarMapping
            type GenericTestCaseDict = FlextLdapTypes.ScalarMapping
            type GenericCallableParameterDict = FlextLdapTypes.ScalarMapping
            type LdapConnectionResultDict = FlextLdapTypes.ScalarMapping


t = TestsFlextLdapTypes

__all__ = ["TestsFlextLdapTypes", "t"]
