"""Type definitions for flext-ldap test fixtures using Python 3.13 patterns.

Module functionality: Centralized TypedDict definitions for test fixtures.
Provides type-safe configuration dictionaries replacing generic dict[str, object].

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypedDict


class LdapContainerDict(TypedDict, total=False):
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
    attributes: GenericFieldsDict
    entry_uuid: str
    modifyTimestamp: str
    createTimestamp: str


class LdapTestScenarioDict(TypedDict, total=False):
    """Generic test scenario for LDAP testing."""

    scenario_name: str
    input_data: GenericFieldsDict
    expected_output: GenericFieldsDict
    error_expected: bool
    error_message: str


class GenericFieldsDict(TypedDict, total=False):
    """Generic dictionary for field validation in helpers.

    Used by helper methods for validating, comparing, and transforming
    flexible field dictionaries with any key-value pairs.
    """

    # Allow any additional keys for maximum flexibility
    __extra_items__: dict[str, object]


class GenericTestCaseDict(TypedDict, total=False):
    """Generic test case dictionary for helper deduplication.

    Provides type-safe wrapper for test cases passed to deduplication
    helpers while maintaining flexibility for different test scenarios.
    """

    # Total flexibility - any keys/values allowed via cast


class GenericCallableParameterDict(TypedDict, total=False):
    """Generic dictionary parameter for callable operations in helpers.

    Used for operations passed to helper methods that need flexible
    dictionary input with any key-value combination.
    """

    # Total flexibility - any keys/values allowed via cast


class LdapConnectionResultDict(TypedDict, total=False):
    """LDAP connection test result."""

    success: bool
    connection_id: str
    bind_dn: str
    server_type: str
    version: str


# =========================================================================
# TYPE ALIASES FOR FLEXIBLE ATTRIBUTES (Python 3.13+ PEP 695)
# =========================================================================

type LdapAttributeValue = str | int | float | bool | list[str] | None
"""Type alias for LDAP attribute values used in **extra_attributes kwargs.

Covers common LDAP attribute value types for flexible test attribute passing.
"""

__all__ = [
    "GenericCallableParameterDict",
    "GenericFieldsDict",
    "GenericTestCaseDict",
    "LdapAttributeValue",
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
]
