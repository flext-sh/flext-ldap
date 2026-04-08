"""Type system foundation for flext-ldap tests.

Provides TestsFlextLdapTypes, extending TestsFlextTypes with flext-ldap-specific types.
All generic test types come from flext_tests, only flext-ldap-specific additions here.

Architecture:
- TestsFlextTypes (flext_tests) = Generic types for all FLEXT projects
- TestsFlextLdapTypes (tests/) = flext-ldap-specific types extending TestsFlextTypes

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_tests import FlextTestsTypes

from flext_core import FlextTypes, r
from flext_ldap import FlextLdapModels, FlextLdapTypes


class TestsFlextLdapTypes(FlextTestsTypes, FlextLdapTypes):
    """Type system foundation for flext-ldap tests - extends TestsFlextTypes and FlextLdapTypes.

    Architecture: Extends both TestsFlextTypes and FlextLdapTypes with flext-ldap-specific type definitions.
    All generic types from TestsFlextTypes and production types from FlextLdapTypes are available through inheritance.

    Hierarchy:
    - t.Tests.* (generic test types from flext_tests)
    - FlextLdapTypes.Ldap.* (source types from flext_ldap)
    - TestsFlextLdapTypes.Tests.* (flext-ldap-specific test types)

    Rules:
    - NEVER redeclare types from TestsFlextTypes or FlextLdapTypes
    - Only flext-ldap-specific types allowed (not generic for other projects)
    - All generic types come from TestsFlextTypes
    - All production types come from FlextLdapTypes
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
                FlextTypes.Scalar
                | FlextTypes.StrSequence
                | Mapping[str, FlextTypes.StrSequence],
            ]
            type LdapContainerDict = FlextTypes.ScalarMapping
            type LdapConnectionConfigDict = Mapping[str, FlextTypes.OptionalScalar]
            type LdapSearchOptionsDict = FlextTypes.ScalarMapping
            type LdapEntryDataDict = Mapping[
                str, FlextTypes.Scalar | FlextTypes.StrSequence
            ]
            type LdapSchemaAttributeDict = Mapping[
                str, str | FlextTypes.StrSequence | bool
            ]
            type LdapSchemaObjectClassDict = Mapping[
                str, str | FlextTypes.StrSequence | bool
            ]
            type LdapModifyOperationDict = Mapping[
                str, FlextTypes.Scalar | FlextTypes.StrSequence
            ]
            type LdapSearchResultDict = Mapping[
                str, FlextTypes.Scalar | FlextTypes.StrSequence
            ]
            type LdapTestScenarioDict = FlextTypes.ScalarMapping
            type GenericTestCaseDict = FlextTypes.ScalarMapping
            type GenericCallableParameterDict = FlextTypes.ScalarMapping
            type LdapConnectionResultDict = FlextTypes.ScalarMapping


t = TestsFlextLdapTypes

__all__ = ["TestsFlextLdapTypes", "t"]
