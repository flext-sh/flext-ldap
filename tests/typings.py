"""Type system foundation for flext-ldap tests.

Provides TestsLdapTypes, extending t with flext-ldap-specific types.
All generic test types come from flext_tests, only flext-ldap-specific additions here.

Architecture:
- t (flext_tests) = Generic types for all FLEXT projects
- TestsLdapTypes (tests/) = flext-ldap-specific types extending t

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import T, T_co, T_contra
from flext_tests import t

from flext_ldap import FlextLdapTypes


class TestsFlextLdapTypes(t, FlextLdapTypes):
    """Type system foundation for flext-ldap tests - extends t and FlextLdapTypes.

    Architecture: Extends both t and FlextLdapTypes with flext-ldap-specific type definitions.
    All generic types from t and production types from FlextLdapTypes are available through inheritance.

    Hierarchy:
    - t.Tests.* (generic test types from flext_tests)
    - FlextLdapTypes.Ldap.* (source types from flext_ldap)
    - TestsFlextLdapTypes.Tests.* (flext-ldap-specific test types)

    Rules:
    - NEVER redeclare types from t or FlextLdapTypes
    - Only flext-ldap-specific types allowed (not generic for other projects)
    - All generic types come from t
    - All production types come from FlextLdapTypes
    """

    class Tests(t.Tests):
        """flext-ldap-specific test type definitions namespace.

        Use tt.Tests.* for flext-ldap-specific test types.
        Use t.Tests.* for generic test types from t.
        """

        class Fixtures:
            """TypedDict definitions for LDAP test fixtures."""


type GenericFieldsDict = dict[str, str | int | bool | list[str]]
type LdapContainerDict = dict[str, str | int | bool]
type LdapConnectionConfigDict = dict[str, str | int | bool | None]
type LdapSearchOptionsDict = dict[str, str | int | bool]
type LdapEntryDataDict = dict[str, str | int | bool | list[str]]
type LdapSchemaAttributeDict = dict[str, str | list[str] | bool]
type LdapSchemaObjectClassDict = dict[str, str | list[str] | bool]
type LdapModifyOperationDict = dict[str, str | int | bool | list[str]]
type LdapSearchResultDict = dict[str, str | int | bool | list[str]]
type LdapTestScenarioDict = dict[str, str | int | bool]
type GenericTestCaseDict = dict[str, str | int | bool]
type GenericCallableParameterDict = dict[str, str | int | bool]
type LdapConnectionResultDict = dict[str, str | int | bool]
t = TestsFlextLdapTypes
tt = TestsFlextLdapTypes
__all__ = [
    "GenericCallableParameterDict",
    "GenericFieldsDict",
    "GenericTestCaseDict",
    "LdapConnectionConfigDict",
    "LdapConnectionResultDict",
    "LdapContainerDict",
    "LdapEntryDataDict",
    "LdapModifyOperationDict",
    "LdapSchemaAttributeDict",
    "LdapSchemaObjectClassDict",
    "LdapSearchOptionsDict",
    "LdapSearchResultDict",
    "LdapTestScenarioDict",
    "T",
    "T_co",
    "T_contra",
    "TestsFlextLdapTypes",
    "t",
    "tt",
]
