"""Type system foundation for flext-ldap tests.

Provides FlextLdapTestTypes, extending FlextTestsTypes with flext-ldap-specific types.
All generic test types come from flext_tests, only flext-ldap-specific additions here.

Architecture:
- FlextTestsTypes (flext_tests) = Generic types for all FLEXT projects
- FlextLdapTestTypes (tests/) = flext-ldap-specific types extending FlextTestsTypes

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_tests import FlextTestsTypes

from flext_core import r
from flext_ldap import FlextLdapTypes
from tests import m, t as _t


class FlextLdapTestTypes(FlextTestsTypes, FlextLdapTypes):
    """Type system foundation for flext-ldap tests - extends FlextTestsTypes and FlextLdapTypes.

    Architecture: Extends both FlextTestsTypes and FlextLdapTypes with flext-ldap-specific type definitions.
    All generic types from FlextTestsTypes and production types from FlextLdapTypes are available through inheritance.

    Hierarchy:
    - t.Tests.* (generic test types from flext_tests)
    - FlextLdapTypes.Ldap.* (source types from flext_ldap)
    - FlextLdapTestTypes.Tests.* (flext-ldap-specific test types)

    Rules:
    - NEVER redeclare types from FlextTestsTypes or FlextLdapTypes
    - Only flext-ldap-specific types allowed (not generic for other projects)
    - All generic types come from FlextTestsTypes
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
            type OperationResultType = r[m.Ldap.OperationResult]
            type SearchResultType = r[m.Ldap.SearchResult]

            # Test data dictionary types
            type GenericFieldsDict = Mapping[
                str,
                _t.Scalar | _t.StrSequence | Mapping[str, _t.StrSequence],
            ]
            type LdapContainerDict = _t.ScalarMapping
            type LdapConnectionConfigDict = Mapping[str, _t.OptionalScalar]
            type LdapSearchOptionsDict = _t.ScalarMapping
            type LdapEntryDataDict = Mapping[str, _t.Scalar | _t.StrSequence]
            type LdapSchemaAttributeDict = Mapping[str, str | _t.StrSequence | bool]
            type LdapSchemaObjectClassDict = Mapping[str, str | _t.StrSequence | bool]
            type LdapModifyOperationDict = Mapping[str, _t.Scalar | _t.StrSequence]
            type LdapSearchResultDict = Mapping[str, _t.Scalar | _t.StrSequence]
            type LdapTestScenarioDict = _t.ScalarMapping
            type GenericTestCaseDict = _t.ScalarMapping
            type GenericCallableParameterDict = _t.ScalarMapping
            type LdapConnectionResultDict = _t.ScalarMapping


t = FlextLdapTestTypes

__all__ = ["FlextLdapTestTypes", "t"]
