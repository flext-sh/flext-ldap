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

from collections.abc import Mapping, Sequence

from flext_core import r
from flext_tests import FlextTestsTypes

from flext_ldap import FlextLdapTypes
from tests import FlextLdapTestModels as _m


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
            type OperationResultType = r[_m.Ldap.OperationResult]
            type SearchResultType = r[_m.Ldap.SearchResult]
            type LdapEntry = _m.Ldif.Entry

            # Test data dictionary types
            type GenericFieldsDict = Mapping[
                str, t.Scalar | Sequence[str] | Mapping[str, Sequence[str]]
            ]
            type LdapContainerDict = Mapping[str, t.Scalar]
            type LdapConnectionConfigDict = Mapping[str, t.Scalar | None]
            type LdapSearchOptionsDict = Mapping[str, t.Scalar]
            type LdapEntryDataDict = Mapping[str, t.Scalar | Sequence[str]]
            type LdapSchemaAttributeDict = Mapping[str, str | Sequence[str] | bool]
            type LdapSchemaObjectClassDict = Mapping[str, str | Sequence[str] | bool]
            type LdapModifyOperationDict = Mapping[str, t.Scalar | Sequence[str]]
            type LdapSearchResultDict = Mapping[str, t.Scalar | Sequence[str]]
            type LdapTestScenarioDict = Mapping[str, t.Scalar]
            type GenericTestCaseDict = Mapping[str, t.Scalar]
            type GenericCallableParameterDict = Mapping[str, t.Scalar]
            type LdapConnectionResultDict = Mapping[str, t.Scalar]


t = FlextLdapTestTypes

__all__ = ["FlextLdapTestTypes", "t"]
