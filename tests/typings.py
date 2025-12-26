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

from typing import TypedDict

from flext_core.typings import T, T_co, T_contra
from flext_tests.typings import FlextTestsTypes

from flext_ldap.typings import FlextLdapTypes


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

    class Tests:
        """flext-ldap-specific test type definitions namespace.

        Use tt.Tests.* for flext-ldap-specific test types.
        Use t.Tests.* for generic test types from FlextTestsTypes.
        """

        class Fixtures:
            """TypedDict definitions for LDAP test fixtures."""

            class LdapContainerDict(TypedDict):
                """LDAP container fixture configuration."""

                server_url: str
                host: str
                bind_dn: str
                password: str
                base_dn: str
                port: int
                use_ssl: bool
                worker_id: str

            class LdapConnectionConfigDict(TypedDict, total=False):
                """LDAP connection configuration."""

                host: str
                port: int
                bind_dn: str
                password: str
                use_ssl: bool
                start_tls: bool
                timeout: int

            class LdapSearchOptionsDict(TypedDict, total=False):
                """LDAP search operation options."""

                base_dn: str
                search_filter: str
                scope: str
                attributes: list[str]
                size_limit: int
                time_limit: int
                page_size: int

            class LdapEntryDataDict(TypedDict, total=False):
                """Test LDAP entry data."""

                dn: str
                objectClass: list[str]
                cn: list[str]
                mail: list[str]
                uid: list[str]
                ou: list[str]
                dc: list[str]
                description: list[str]
                sn: list[str]
                givenName: list[str]
                memberOf: list[str]
                member: list[str]

            class LdapSchemaAttributeDict(TypedDict, total=False):
                """LDAP schema attribute definition."""

                oid: str
                name: str
                syntax: str
                description: str
                equality_match: str
                ordering_match: str
                substr_match: str
                single_value: bool

            class LdapSchemaObjectClassDict(TypedDict, total=False):
                """LDAP schema object class definition."""

                oid: str
                name: str
                sup: str
                description: str
                structural: bool
                auxiliary: bool
                abstract: bool
                must: list[str]
                may: list[str]

            class LdapModifyOperationDict(TypedDict, total=False):
                """LDAP modify operation data."""

                dn: str
                operation: str
                attribute: str
                values: list[str] | None

            class LdapSearchResultDict(TypedDict, total=False):
                """LDAP search result data."""

                dn: str
                attributes: dict[str, object]
                entry_uuid: str
                modifyTimestamp: str
                createTimestamp: str

            class LdapTestScenarioDict(TypedDict, total=False):
                """Generic test scenario for LDAP testing."""

                scenario_name: str
                input_data: dict[str, object]
                expected_output: dict[str, object]
                error_expected: bool
                error_message: str

            class GenericFieldsDict(TypedDict, total=False):
                """Generic dictionary for field validation in helpers.

                Used by helper methods for validating, comparing, and transforming
                flexible field dictionaries with any key-value pairs.
                """

                # Common fields that may be present
                dn: str
                attributes: dict[str, list[str]]

            class GenericTestCaseDict(TypedDict, total=False):
                """Generic test case dictionary for helper deduplication.

                Provides type-safe wrapper for test cases passed to deduplication
                helpers while maintaining flexibility for different test scenarios.
                """

            class GenericCallableParameterDict(TypedDict, total=False):
                """Generic dictionary parameter for callable operations in helpers.

                Used for operations passed to helper methods that need flexible
                dictionary input with any key-value combination.
                """

            class LdapConnectionResultDict(TypedDict, total=False):
                """LDAP connection test result."""

                success: bool
                connection_id: str
                bind_dn: str
                server_type: str
                version: str


# Export TypedDict classes for direct import (backward compatibility)
GenericFieldsDict = TestsFlextLdapTypes.Tests.Fixtures.GenericFieldsDict
LdapContainerDict = TestsFlextLdapTypes.Tests.Fixtures.LdapContainerDict
LdapConnectionConfigDict = TestsFlextLdapTypes.Tests.Fixtures.LdapConnectionConfigDict
LdapSearchOptionsDict = TestsFlextLdapTypes.Tests.Fixtures.LdapSearchOptionsDict
LdapEntryDataDict = TestsFlextLdapTypes.Tests.Fixtures.LdapEntryDataDict
LdapSchemaAttributeDict = TestsFlextLdapTypes.Tests.Fixtures.LdapSchemaAttributeDict
LdapSchemaObjectClassDict = TestsFlextLdapTypes.Tests.Fixtures.LdapSchemaObjectClassDict
LdapModifyOperationDict = TestsFlextLdapTypes.Tests.Fixtures.LdapModifyOperationDict
LdapSearchResultDict = TestsFlextLdapTypes.Tests.Fixtures.LdapSearchResultDict
LdapTestScenarioDict = TestsFlextLdapTypes.Tests.Fixtures.LdapTestScenarioDict
GenericTestCaseDict = TestsFlextLdapTypes.Tests.Fixtures.GenericTestCaseDict
GenericCallableParameterDict = (
    TestsFlextLdapTypes.Tests.Fixtures.GenericCallableParameterDict
)
LdapConnectionResultDict = TestsFlextLdapTypes.Tests.Fixtures.LdapConnectionResultDict

# Short aliases
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
