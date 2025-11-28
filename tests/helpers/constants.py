"""Test constants for flext-ldap tests.

Centralized constants for test fixtures, factories, and test data.
Does NOT duplicate src/flext_ldap/constants.py - only test-specific constants.
Reuses production constants from FlextLdapConstants when appropriate.

Python 3.13+ strict features:
- PEP 695 type aliases (type keyword) - no TypeAlias
- collections.abc for type hints (preferred over typing)
- StrEnum for type-safe string enums
- Literal types derived from StrEnum values
- No backward compatibility with Python < 3.13

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Final

from flext_ldap.constants import FlextLdapConstants

# =========================================================================
# DOMAIN-SPECIFIC SERVER CONSTANTS
# =========================================================================
# These classes provide server-specific test constants for different LDAP
# server implementations. They reuse production StrEnum values for consistency.


class RFC:
    """RFC-compliant server test constants."""

    SERVER_TYPE: Final[str] = FlextLdapConstants.ServerTypes.RFC.value
    DEFAULT_HOST: Final[str] = "localhost"
    DEFAULT_PORT: Final[int] = 3390
    DEFAULT_BASE_DN: Final[str] = "dc=flext,dc=local"
    DEFAULT_BIND_DN: Final[str] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
    DEFAULT_BIND_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"
    DEFAULT_FILTER: Final[str] = FlextLdapConstants.Filters.ALL_ENTRIES_FILTER.value
    DEFAULT_SCOPE: Final[str] = FlextLdapConstants.SearchScope.SUBTREE.value
    DEFAULT_ATTRIBUTES: Final[tuple[str, ...]] = ("objectClass", "cn")
    TEST_USER_CN: Final[str] = "testuser"
    TEST_USER_DN: Final[str] = f"uid={TEST_USER_CN},ou=people,{DEFAULT_BASE_DN}"
    TEST_GROUP_CN: Final[str] = "testgroup"
    TEST_GROUP_DN: Final[str] = f"cn={TEST_GROUP_CN},ou=groups,{DEFAULT_BASE_DN}"
    OU_PEOPLE: Final[str] = "ou=people"
    OU_GROUPS: Final[str] = "ou=groups"
    OU_SYSTEM: Final[str] = "ou=system"
    OU_PEOPLE_DN: Final[str] = f"{OU_PEOPLE},{DEFAULT_BASE_DN}"
    OU_GROUPS_DN: Final[str] = f"{OU_GROUPS},{DEFAULT_BASE_DN}"
    OU_SYSTEM_DN: Final[str] = f"{OU_SYSTEM},{DEFAULT_BASE_DN}"


class OID:
    """Oracle Internet Directory server test constants."""

    SERVER_TYPE: Final[str] = FlextLdapConstants.ServerTypes.OID.value
    DEFAULT_HOST: Final[str] = "localhost"
    DEFAULT_PORT: Final[int] = 3060
    DEFAULT_BASE_DN: Final[str] = "dc=example,dc=com"
    DEFAULT_BIND_DN: Final[str] = "cn=orclREDACTED_LDAP_BIND_PASSWORD"
    DEFAULT_BIND_PASSWORD: Final[str] = "password"
    DEFAULT_FILTER: Final[str] = FlextLdapConstants.Filters.ALL_ENTRIES_FILTER.value
    DEFAULT_SCOPE: Final[str] = FlextLdapConstants.SearchScope.SUBTREE.value
    DEFAULT_ATTRIBUTES: Final[tuple[str, ...]] = ("objectClass", "cn")
    TEST_USER_CN: Final[str] = "testuser"
    TEST_USER_DN: Final[str] = f"uid={TEST_USER_CN},ou=people,{DEFAULT_BASE_DN}"
    TEST_GROUP_CN: Final[str] = "testgroup"
    TEST_GROUP_DN: Final[str] = f"cn={TEST_GROUP_CN},ou=groups,{DEFAULT_BASE_DN}"
    OU_PEOPLE: Final[str] = "ou=people"
    OU_GROUPS: Final[str] = "ou=groups"
    OU_SYSTEM: Final[str] = "ou=system"
    OU_PEOPLE_DN: Final[str] = f"{OU_PEOPLE},{DEFAULT_BASE_DN}"
    OU_GROUPS_DN: Final[str] = f"{OU_GROUPS},{DEFAULT_BASE_DN}"
    OU_SYSTEM_DN: Final[str] = f"{OU_SYSTEM},{DEFAULT_BASE_DN}"


class OUD:
    """Oracle Unified Directory server test constants."""

    SERVER_TYPE: Final[str] = FlextLdapConstants.ServerTypes.OUD.value
    DEFAULT_HOST: Final[str] = "localhost"
    DEFAULT_PORT: Final[int] = 1389
    DEFAULT_BASE_DN: Final[str] = "dc=example,dc=com"
    DEFAULT_BIND_DN: Final[str] = "cn=Directory Manager"
    DEFAULT_BIND_PASSWORD: Final[str] = "password"
    DEFAULT_FILTER: Final[str] = FlextLdapConstants.Filters.ALL_ENTRIES_FILTER.value
    DEFAULT_SCOPE: Final[str] = FlextLdapConstants.SearchScope.SUBTREE.value
    DEFAULT_ATTRIBUTES: Final[tuple[str, ...]] = ("objectClass", "cn")
    TEST_USER_CN: Final[str] = "testuser"
    TEST_USER_DN: Final[str] = f"uid={TEST_USER_CN},ou=people,{DEFAULT_BASE_DN}"
    TEST_GROUP_CN: Final[str] = "testgroup"
    TEST_GROUP_DN: Final[str] = f"cn={TEST_GROUP_CN},ou=groups,{DEFAULT_BASE_DN}"
    OU_PEOPLE: Final[str] = "ou=people"
    OU_GROUPS: Final[str] = "ou=groups"
    OU_SYSTEM: Final[str] = "ou=system"
    OU_PEOPLE_DN: Final[str] = f"{OU_PEOPLE},{DEFAULT_BASE_DN}"
    OU_GROUPS_DN: Final[str] = f"{OU_GROUPS},{DEFAULT_BASE_DN}"
    OU_SYSTEM_DN: Final[str] = f"{OU_SYSTEM},{DEFAULT_BASE_DN}"


class OpenLDAP2:
    """OpenLDAP 2 server test constants."""

    SERVER_TYPE: Final[str] = FlextLdapConstants.ServerTypes.OPENLDAP2.value
    DEFAULT_HOST: Final[str] = "localhost"
    DEFAULT_PORT: Final[int] = 389
    DEFAULT_BASE_DN: Final[str] = "dc=example,dc=com"
    DEFAULT_BIND_DN: Final[str] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
    DEFAULT_BIND_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD"
    DEFAULT_FILTER: Final[str] = FlextLdapConstants.Filters.ALL_ENTRIES_FILTER.value
    DEFAULT_SCOPE: Final[str] = FlextLdapConstants.SearchScope.SUBTREE.value
    DEFAULT_ATTRIBUTES: Final[tuple[str, ...]] = ("objectClass", "cn")
    TEST_USER_CN: Final[str] = "testuser"
    TEST_USER_DN: Final[str] = f"uid={TEST_USER_CN},ou=people,{DEFAULT_BASE_DN}"
    TEST_GROUP_CN: Final[str] = "testgroup"
    TEST_GROUP_DN: Final[str] = f"cn={TEST_GROUP_CN},ou=groups,{DEFAULT_BASE_DN}"
    OU_PEOPLE: Final[str] = "ou=people"
    OU_GROUPS: Final[str] = "ou=groups"
    OU_SYSTEM: Final[str] = "ou=system"
    OU_PEOPLE_DN: Final[str] = f"{OU_PEOPLE},{DEFAULT_BASE_DN}"
    OU_GROUPS_DN: Final[str] = f"{OU_GROUPS},{DEFAULT_BASE_DN}"
    OU_SYSTEM_DN: Final[str] = f"{OU_SYSTEM},{DEFAULT_BASE_DN}"


class General:
    """General test constants used across all server types."""

    # Common OIDs
    OID_CN: Final[str] = "2.5.4.3"
    OID_SN: Final[str] = "2.5.4.4"
    OID_OBJECTCLASS: Final[str] = "2.5.4.0"
    OID_PERSON: Final[str] = "2.5.6.6"

    # Common names
    NAME_CN: Final[str] = "cn"
    NAME_SN: Final[str] = "sn"
    NAME_OBJECTCLASS: Final[str] = "objectClass"
    NAME_PERSON: Final[str] = "person"

    # Common DNs
    DN_TEST: Final[str] = "cn=test,dc=example,dc=com"
    DN_EXAMPLE: Final[str] = "dc=example,dc=com"
    DN_SCHEMA: Final[str] = "cn=schema"

    # Common syntax OIDs
    SYNTAX_DIRECTORY_STRING: Final[str] = "1.3.6.1.4.1.1466.115.115.121.1.15"
    SYNTAX_BOOLEAN: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
    SYNTAX_INTEGER: Final[str] = "1.3.6.1.4.1.1466.115.121.1.27"

    # Test values
    VALUE_TEST: Final[str] = "test"
    VALUE_USER: Final[str] = "user"
    VALUE_USER1: Final[str] = "user1"
    VALUE_USER2: Final[str] = "user2"

    # Error messages
    ERROR_MISSING_OID: Final[str] = "Missing OID"
    ERROR_INVALID_FORMAT: Final[str] = "Invalid format"
    ERROR_PARSE_FAILED: Final[str] = "Parse failed"

    # Version validation constants
    VERSION_MIN_LENGTH: Final[int] = 5
    VERSION_MAX_LENGTH: Final[int] = 50
    VERSION_MIN_PARTS: Final[int] = 2
    VERSION_MAX_PARTS: Final[int] = 3
    VERSION_MIN_COMPONENTS: Final[int] = 2


# =========================================================================
# MAIN TEST CONSTANTS CLASS
# =========================================================================
# Hierarchical namespace structure for reusable constants across all test modules.
# Organized by domain with nested classes for better organization and reuse.


class TestConstants:
    """Hierarchical test constants for flext-ldap tests with domain-based organization.

    Centralized test constants following flext-core nested class pattern.
    Reuses production constants from FlextLdapConstants when appropriate.
    """

    # Top-level shortcuts for common constants (using RFC as default)
    DEFAULT_BASE_DN: ClassVar[str] = RFC.DEFAULT_BASE_DN
    DEFAULT_HOST: ClassVar[str] = RFC.DEFAULT_HOST
    DEFAULT_PORT: ClassVar[int] = RFC.DEFAULT_PORT
    DEFAULT_BIND_DN: ClassVar[str] = RFC.DEFAULT_BIND_DN
    DEFAULT_BIND_PASSWORD: ClassVar[str] = RFC.DEFAULT_BIND_PASSWORD
    DEFAULT_FILTER: ClassVar[str] = RFC.DEFAULT_FILTER
    DEFAULT_SCOPE: ClassVar[str] = RFC.DEFAULT_SCOPE
    DEFAULT_ATTRIBUTES: ClassVar[tuple[str, ...]] = RFC.DEFAULT_ATTRIBUTES
    TEST_USER_CN: ClassVar[str] = RFC.TEST_USER_CN
    TEST_USER_DN: ClassVar[str] = RFC.TEST_USER_DN
    TEST_GROUP_CN: ClassVar[str] = RFC.TEST_GROUP_CN
    TEST_GROUP_DN: ClassVar[str] = RFC.TEST_GROUP_DN

    class ServerTypes:
        """Server type constants for LDAP server variants.

        Reuses production StrEnum values from FlextLdapConstants.ServerTypes.
        """

        RFC: Final[str] = FlextLdapConstants.ServerTypes.RFC.value
        GENERIC: Final[str] = FlextLdapConstants.ServerTypes.GENERIC.value
        OID: Final[str] = FlextLdapConstants.ServerTypes.OID.value
        OUD: Final[str] = FlextLdapConstants.ServerTypes.OUD.value
        OPENLDAP2: Final[str] = FlextLdapConstants.ServerTypes.OPENLDAP2.value

        # Valid server types for testing (only those registered in quirks)
        VALID: Final[tuple[str, ...]] = (RFC, GENERIC)

    class Connection:
        """LDAP connection-related constants."""

        DEFAULT_HOST: Final[str] = RFC.DEFAULT_HOST
        DEFAULT_PORT: Final[int] = RFC.DEFAULT_PORT
        DEFAULT_BIND_DN: Final[str] = RFC.DEFAULT_BIND_DN
        DEFAULT_BIND_PASSWORD: Final[str] = RFC.DEFAULT_BIND_PASSWORD

        # SSL/TLS configurations
        SSL_ENABLED: Final[bool] = True
        SSL_DISABLED: Final[bool] = False
        TLS_ENABLED: Final[bool] = True
        TLS_DISABLED: Final[bool] = False

        # Connection timeouts
        FAST_TIMEOUT: Final[int] = 5
        NORMAL_TIMEOUT: Final[int] = 30
        SLOW_TIMEOUT: Final[int] = 300

        # Connection service test constants
        INVALID_HOST: Final[str] = "invalid.host"
        TEST_BIND_DN: Final[str] = "cn=test,dc=example,dc=com"

    class Directory:
        """Directory structure and DN constants."""

        BASE_DN: Final[str] = RFC.DEFAULT_BASE_DN
        FILTER_ALL: Final[str] = RFC.DEFAULT_FILTER
        SCOPE_SUBTREE: Final[str] = RFC.DEFAULT_SCOPE
        SCOPE_ONELEVEL: Final[str] = FlextLdapConstants.SearchScope.ONELEVEL.value
        SCOPE_BASE: Final[str] = FlextLdapConstants.SearchScope.BASE.value

        class OrganizationalUnits:
            """Organizational unit constants."""

            PEOPLE: Final[str] = RFC.OU_PEOPLE
            GROUPS: Final[str] = RFC.OU_GROUPS
            SYSTEM: Final[str] = RFC.OU_SYSTEM

            PEOPLE_DN: Final[str] = RFC.OU_PEOPLE_DN
            GROUPS_DN: Final[str] = RFC.OU_GROUPS_DN
            SYSTEM_DN: Final[str] = RFC.OU_SYSTEM_DN

        class TestEntries:
            """Test entry constants."""

            USER_CN: Final[str] = RFC.TEST_USER_CN
            USER_DN: Final[str] = RFC.TEST_USER_DN
            GROUP_CN: Final[str] = RFC.TEST_GROUP_CN
            GROUP_DN: Final[str] = RFC.TEST_GROUP_DN

    class Attributes:
        """LDAP attribute constants."""

        COMMON: ClassVar[list[str]] = list(RFC.DEFAULT_ATTRIBUTES)
        USER_ATTRIBUTES: ClassVar[list[str]] = [
            "cn",
            "sn",
            "givenName",
            "uid",
            "mail",
            "userPassword",
        ]
        GROUP_ATTRIBUTES: ClassVar[list[str]] = ["cn", "member", "description"]
        SYSTEM_ATTRIBUTES: ClassVar[list[str]] = ["cn", "description", "objectClass"]

    class Operations:
        """LDAP operation constants.

        Reuses production StrEnum values from FlextLdapConstants.OperationType.
        """

        ADD: Final[str] = FlextLdapConstants.OperationType.ADD.value
        MODIFY: Final[str] = FlextLdapConstants.OperationType.MODIFY.value
        DELETE: Final[str] = FlextLdapConstants.OperationType.DELETE.value
        SEARCH: Final[str] = FlextLdapConstants.OperationType.SEARCH.value
        BIND: Final[str] = FlextLdapConstants.OperationType.BIND.value
        UNBIND: Final[str] = FlextLdapConstants.OperationType.UNBIND.value

        # Operation result codes
        SUCCESS: Final[int] = 0
        FAILURE: Final[int] = 1
        PARTIAL_SUCCESS: Final[int] = 2

        # Operations service test constants
        TEST_DN: Final[str] = "cn=test,dc=example,dc=com"
        TEST_DN_1: Final[str] = "cn=test1,dc=example,dc=com"
        TEST_DN_2: Final[str] = "cn=test2,dc=example,dc=com"
        BASE_DN: Final[str] = "dc=example,dc=com"
        DEFAULT_FILTER: Final[str] = FlextLdapConstants.Filters.ALL_ENTRIES_FILTER.value

    class Adapter:
        """Entry adapter test constants."""

        TEST_DN: Final[str] = "cn=test,dc=example,dc=com"
        STANDARD_ATTRIBUTES: ClassVar[dict[str, list[str]]] = {
            "cn": ["test"],
            "objectClass": ["top", "person"],
        }
        EMPTY_ATTRIBUTES: ClassVar[dict[str, list[str]]] = {}
        SERVER_TYPE_OPENLDAP: Final[str] = FlextLdapConstants.ServerTypes.OPENLDAP.value
        SERVER_TYPE_OPENLDAP2: Final[str] = (
            FlextLdapConstants.ServerTypes.OPENLDAP2.value
        )
        ERROR_NO_ATTRIBUTES: Final[str] = "no attributes"

    class Singleton:
        """Singleton pattern test constants."""

        DIFFERENT_HOST: Final[str] = "different.example.com"
        TEST_HOST: Final[str] = "test.example.com"
        TEST_PORT: Final[int] = 389

    class Base:
        """Base service test constants."""

        CONFIG_NAMESPACES: Final[tuple[str, ...]] = ("ldap", "ldif")

    class Paths:
        """Test path constants."""

        TEST_INPUT_DIR: Final[str] = "tests/fixtures/data/input"
        TEST_OUTPUT_DIR: Final[str] = "tests/fixtures/data/output"
        TEST_TEMP_PREFIX: Final[str] = "flext_ldap_test_"

    class LDAP:
        """LDAP test server constants.

        Reuses production constants from FlextLdapConstants.ConnectionDefaults
        where appropriate, only defines test-specific values.
        """

        DEFAULT_HOST: Final[str] = "localhost"
        DEFAULT_PORT: Final[int] = FlextLdapConstants.ConnectionDefaults.PORT
        DEFAULT_PORT_SSL: Final[int] = FlextLdapConstants.ConnectionDefaults.PORT_SSL
        DEFAULT_BASE_DN: Final[str] = "dc=example,dc=com"
        DEFAULT_BIND_DN: Final[str] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        DEFAULT_BIND_PASSWORD: Final[str] = "TestPassword123"
        CONNECTION_TIMEOUT: Final[int] = FlextLdapConstants.ConnectionDefaults.TIMEOUT
        OPERATION_TIMEOUT: Final[int] = 60

    class Files:
        """Test file name constants."""

        SCHEMA_FILE: Final[str] = "schema.ldif"
        TEST_ENTRY_FILE: Final[str] = "test_entry.ldif"
        TEST_ENTRIES_FILE: Final[str] = "test_entries.ldif"

    class TestData:
        """Test data constants."""

        SAMPLE_USER_DN: Final[str] = "cn=testuser,ou=users,dc=example,dc=com"
        SAMPLE_GROUP_DN: Final[str] = "cn=testgroup,ou=groups,dc=example,dc=com"
        SAMPLE_OU_DN: Final[str] = "ou=test,dc=example,dc=com"
        SAMPLE_CN: Final[str] = "testuser"
        SAMPLE_UID: Final[str] = "testuser"
        SAMPLE_MAIL: Final[str] = "testuser@example.com"

    class Fixtures:
        """Test fixture constants."""

        MINIMAL_ENTRY_FIXTURE: Final[str] = "minimal_entry"
        FULL_ENTRY_FIXTURE: Final[str] = "full_entry"
        MULTI_ENTRY_FIXTURE: Final[str] = "multi_entry"

    class Ldap3Adapter:
        """Ldap3Adapter test constants."""

        INVALID_HOSTS: Final[tuple[str, ...]] = (
            "192.0.2.1",
            "invalid-host-that-does-not-exist",
        )
        INVALID_BASE_DN: Final[str] = "invalid=base,dn=invalid"
        FAST_TIMEOUT: Final[int] = 1

    # =========================================================================
    # TYPE ALIASES (reusing production Literal types for test type hints)
    # =========================================================================
    # Python 3.13+ PEP 695: Using `type` keyword for type aliases
    # These reference production Literals for use in test type hints.
    # Always prefer using FlextLdapConstants.LiteralTypes directly when possible.

    class TestLiteralTypes:
        """Test-specific Literal type aliases (reusing production types).

        These type aliases reference production Literals for use in test type hints.
        Always prefer using FlextLdapConstants.LiteralTypes directly when possible.

        Uses PEP 695 type aliases (Python 3.13+ strict).
        """

        # Server type literal (reusing production type)
        type ServerTypeLiteral = FlextLdapConstants.LiteralTypes.ServerTypeLiteral

        # Search scope literal (reusing production type)
        type SearchScopeLiteral = FlextLdapConstants.LiteralTypes.SearchScopeLiteral

        # Operation type literal (reusing production type)
        type OperationTypeLiteral = FlextLdapConstants.LiteralTypes.OperationTypeLiteral


__all__ = [
    "OID",
    "OUD",
    "RFC",
    "General",
    "OpenLDAP2",
    "TestConstants",
]
