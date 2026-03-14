"""Type system foundation for flext-ldap tests.

Provides TestsLdapTypes, extending FlextTestsTypes with flext-ldap-specific types.
All generic test types come from flext_tests, only flext-ldap-specific additions here.

Architecture:
- FlextTestsTypes (flext_tests) = Generic types for all FLEXT projects
- TestsLdapTypes (tests/) = flext-ldap-specific types extending FlextTestsTypes

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeAlias

from flext_core import T, T_co, T_contra
from flext_tests import FlextTestsTypes

from flext_ldap import FlextLdapTypes


class TestsFlextLdapTypes(FlextTestsTypes, FlextLdapTypes):
    """Type system foundation for flext-ldap tests - extends FlextTestsTypes and FlextLdapTypes.

    Architecture: Extends both FlextTestsTypes and FlextLdapTypes with flext-ldap-specific type definitions.
    All generic types from FlextTestsTypes and production types from FlextLdapTypes are available through inheritance.

    Hierarchy:
    - FlextTestsTypes.Tests.* (generic test types from flext_tests)
    - FlextLdapTypes.Ldap.* (source types from flext_ldap)
    - TestsFlextLdapTypes.Tests.* (flext-ldap-specific test types)

    Rules:
    - NEVER redeclare types from FlextTestsTypes or FlextLdapTypes
    - Only flext-ldap-specific types allowed (not generic for other projects)
    - All generic types come from FlextTestsTypes
    - All production types come from FlextLdapTypes
    """

    class Tests(FlextTestsTypes.Tests):
        """flext-ldap-specific test type definitions namespace.

        Use tt.Tests.* for flext-ldap-specific test types.
        Use t.Tests.* for generic test types from FlextTestsTypes.
        """

        class Fixtures:
            """TypedDict definitions for LDAP test fixtures."""


GenericFieldsDict: TypeAlias = dict[str, str | int | bool | list[str]]
LdapContainerDict: TypeAlias = dict[str, str | int | bool]
LdapConnectionConfigDict: TypeAlias = dict[str, str | int | bool | None]
LdapSearchOptionsDict: TypeAlias = dict[str, str | int | bool]
LdapEntryDataDict: TypeAlias = dict[str, str | int | bool | list[str]]
LdapSchemaAttributeDict: TypeAlias = dict[str, str | list[str] | bool]
LdapSchemaObjectClassDict: TypeAlias = dict[str, str | list[str] | bool]
LdapModifyOperationDict: TypeAlias = dict[str, str | int | bool | list[str]]
LdapSearchResultDict: TypeAlias = dict[str, str | int | bool | list[str]]
LdapTestScenarioDict: TypeAlias = dict[str, str | int | bool]
GenericTestCaseDict: TypeAlias = dict[str, str | int | bool]
GenericCallableParameterDict: TypeAlias = dict[str, str | int | bool]
LdapConnectionResultDict: TypeAlias = dict[str, str | int | bool]
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
