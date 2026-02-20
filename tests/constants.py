"""Constants for flext-ldap tests.

Provides TestsLdapConstants, extending FlextTestsConstants with flext-ldap-specific
constants. All generic test constants come from flext_tests.

Architecture:
- FlextTestsConstants (flext_tests) = Generic constants for all FLEXT projects
- TestsLdapConstants (tests/) = flext-ldap-specific constants extending FlextTestsConstants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Final

from flext_ldap.constants import FlextLdapConstants
from flext_ldif.constants import FlextLdifConstants
from flext_tests.constants import FlextTestsConstants


class TestsFlextLdapConstants(FlextTestsConstants, FlextLdapConstants):
    """Constants for flext-ldap tests - extends FlextTestsConstants and FlextLdapConstants.

    Architecture: Extends both FlextTestsConstants and FlextLdapConstants with flext-ldap-specific constants.
    All generic constants from FlextTestsConstants and production constants from FlextLdapConstants are available through inheritance.

    Rules:
    - NEVER duplicate constants from FlextTestsConstants or FlextLdapConstants
    - Only flext-ldap-specific constants allowed (not generic for other projects)
    - All generic constants come from FlextTestsConstants
    - All production constants come from FlextLdapConstants
    """

    class Fixtures:
        """Fixture-related test constants.

        Test-specific fixture constants that complement production constants.
        """

        SAMPLE_DN: Final[str] = "cn=test,dc=example,dc=com"
        SAMPLE_UID: Final[str] = "testuser"
        DEFAULT_STATUS: Final[str] = "completed"

    class Mocks:
        """Mock-related test constants.

        Test-specific mock constants for test fixtures and mocks.
        """

        MOCK_SERVER_RESPONSE: Final[dict[str, str]] = {
            "status": "ok",
            "code": "200",
        }

    class Servers:
        """Server-specific test constants (para quirks).

        Test-specific server constants for quirks testing.
        """

        class OUD:
            """OUD server test constants."""

            SAMPLE_ACL: Final[str] = "access to * by * read"

        class OID:
            """OID server test constants."""

            SAMPLE_ACL: Final[str] = "aci: (target=*)"

    class RFC:
        """RFC server test constants - flat namespace for backward compatibility."""

        # Server type - use production StrEnum from flext-ldif directly
        # Use TestsFlextLdapConstants.Ldif.ServerTypes.RFC.value - no aliases

        # LDAP connection defaults
        DEFAULT_HOST: Final[str] = "localhost"
        DEFAULT_PORT: Final[int] = 3390
        DEFAULT_BASE_DN: Final[str] = "dc=flext,dc=local"
        DEFAULT_BIND_DN: Final[str] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        DEFAULT_BIND_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"

        # Search defaults - use production StrEnum directly
        DEFAULT_FILTER: Final[str] = "(objectClass=*)"
        # Use TestsFlextLdapConstants.Ldap.SearchScope.SUBTREE.value - no aliases
        DEFAULT_ATTRIBUTES: Final[tuple[str, ...]] = ("objectClass", "cn")

        # Test entry defaults
        TEST_USER_CN: Final[str] = "testuser"
        TEST_USER_DN: Final[str] = f"uid={TEST_USER_CN},ou=people,{DEFAULT_BASE_DN}"
        TEST_GROUP_CN: Final[str] = "testgroup"
        TEST_GROUP_DN: Final[str] = f"cn={TEST_GROUP_CN},ou=groups,{DEFAULT_BASE_DN}"

        # Organizational Units
        OU_PEOPLE: Final[str] = "ou=people"
        OU_GROUPS: Final[str] = "ou=groups"
        OU_SYSTEM: Final[str] = "ou=system"

        OU_PEOPLE_DN: Final[str] = f"{OU_PEOPLE},{DEFAULT_BASE_DN}"
        OU_GROUPS_DN: Final[str] = f"{OU_GROUPS},{DEFAULT_BASE_DN}"
        OU_SYSTEM_DN: Final[str] = f"{OU_SYSTEM},{DEFAULT_BASE_DN}"

    class General:
        """General test constants - flat namespace for backward compatibility."""

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

    class TestConstants:
        """Hierarchical test constants for flext-ldap tests with domain-based organization."""

        # Top-level shortcuts for common constants (reference RFC class directly)
        DEFAULT_BASE_DN: ClassVar[str] = "dc=flext,dc=local"
        DEFAULT_HOST: ClassVar[str] = "localhost"
        DEFAULT_PORT: ClassVar[int] = 3390
        DEFAULT_BIND_DN: ClassVar[str] = (
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        )
        DEFAULT_BIND_PASSWORD: ClassVar[str] = "REDACTED_LDAP_BIND_PASSWORD123"
        DEFAULT_FILTER: ClassVar[str] = "(objectClass=*)"
        # Use production StrEnum values directly - no aliases
        # Access via TestsFlextLdapConstants.Ldap.SearchScope.SUBTREE.value
        DEFAULT_ATTRIBUTES: ClassVar[tuple[str, ...]] = ("objectClass", "cn")
        TEST_USER_CN: ClassVar[str] = "testuser"
        TEST_USER_DN: ClassVar[str] = "uid=testuser,ou=people,dc=flext,dc=local"
        TEST_GROUP_CN: ClassVar[str] = "testgroup"
        TEST_GROUP_DN: ClassVar[str] = "cn=testgroup,ou=groups,dc=flext,dc=local"

        class ServerTypes:
            """Server type constants for LDAP server variants.

            Reuses production StrEnum values from FlextLdifConstants.ServerTypes.
            """

            # Use production StrEnum values directly - no aliases
            # Access via TestsFlextLdapConstants.Ldif.ServerTypes.RFC.value

            # Valid server types for testing (only those registered in quirks)
            # Use FlextLdifConstants.Ldif.ServerTypes.RFC.value directly - no aliases
            VALID = (FlextLdifConstants.Ldif.ServerTypes.RFC.value,)

        class Connection:
            """LDAP connection-related constants."""

            DEFAULT_HOST = "localhost"
            DEFAULT_PORT = 3390
            DEFAULT_BIND_DN = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
            DEFAULT_BIND_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD123"

            # SSL/TLS configurations
            SSL_ENABLED = True
            SSL_DISABLED = False
            TLS_ENABLED = True
            TLS_DISABLED = False

            # Connection timeouts
            FAST_TIMEOUT = 5
            NORMAL_TIMEOUT = 30
            SLOW_TIMEOUT = 300

            # Connection service test constants
            INVALID_HOST: ClassVar[str] = "invalid.host"
            TEST_BIND_DN: ClassVar[str] = "cn=test,dc=example,dc=com"

        class Directory:
            """Directory structure and DN constants."""

            BASE_DN = "dc=flext,dc=local"
            FILTER_ALL = "(objectClass=*)"
            # Use production StrEnum values directly - no aliases
            # Access via TestsFlextLdapConstants.Ldap.SearchScope.SUBTREE.value

            class OrganizationalUnits:
                """Organizational unit constants."""

                PEOPLE = "ou=people"
                GROUPS = "ou=groups"
                SYSTEM = "ou=system"

                PEOPLE_DN = "ou=people,dc=flext,dc=local"
                GROUPS_DN = "ou=groups,dc=flext,dc=local"
                SYSTEM_DN = "ou=system,dc=flext,dc=local"

            class TestEntries:
                """Test entry constants."""

                USER_CN = "testuser"
                USER_DN = "uid=testuser,ou=people,dc=flext,dc=local"
                GROUP_CN = "testgroup"
                GROUP_DN = "cn=testgroup,ou=groups,dc=flext,dc=local"

        class Attributes:
            """LDAP attribute constants."""

            COMMON: ClassVar[list[str]] = ["objectClass", "cn"]
            USER_ATTRIBUTES: ClassVar[list[str]] = [
                "cn",
                "sn",
                "givenName",
                "uid",
                "mail",
                "userPassword",
            ]
            GROUP_ATTRIBUTES: ClassVar[list[str]] = ["cn", "member", "description"]
            SYSTEM_ATTRIBUTES: ClassVar[list[str]] = [
                "cn",
                "description",
                "objectClass",
            ]

        class Operations:
            """LDAP operation constants."""

            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"
            SEARCH = "search"
            BIND = "bind"
            UNBIND = "unbind"

            # Operation result codes
            SUCCESS = 0
            FAILURE = 1
            PARTIAL_SUCCESS = 2

            # Operations service test constants
            TEST_DN: ClassVar[str] = "cn=test,dc=example,dc=com"
            TEST_DN_1: ClassVar[str] = "cn=test1,dc=example,dc=com"
            TEST_DN_2: ClassVar[str] = "cn=test2,dc=example,dc=com"
            BASE_DN: ClassVar[str] = "dc=example,dc=com"
            DEFAULT_FILTER: ClassVar[str] = "(objectClass=*)"

        class Adapter:
            """Entry adapter test constants."""

            TEST_DN: ClassVar[str] = "cn=test,dc=example,dc=com"
            STANDARD_ATTRIBUTES: ClassVar[dict[str, list[str]]] = {
                "cn": ["test"],
                "objectClass": ["top", "person"],
            }
            EMPTY_ATTRIBUTES: ClassVar[dict[str, list[str]]] = {}
            SERVER_TYPE_OPENLDAP: ClassVar[str] = (
                FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value
            )
            SERVER_TYPE_OPENLDAP2: ClassVar[str] = (
                FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value
            )
            ERROR_NO_ATTRIBUTES: ClassVar[str] = "no attributes"

        class Singleton:
            """Singleton pattern test constants."""

            DIFFERENT_HOST: ClassVar[str] = "different.example.com"
            TEST_HOST: ClassVar[str] = "test.example.com"
            TEST_PORT: ClassVar[int] = 389

        class Base:
            """Base service test constants."""

            CONFIG_NAMESPACES: ClassVar[tuple[str, ...]] = ("ldap", "ldif")

        class Ldap3Adapter:
            """Ldap3Adapter test constants."""

            INVALID_HOSTS: ClassVar[tuple[str, ...]] = (
                "192.0.2.1",
                "invalid-host-that-does-not-exist",
            )
            INVALID_BASE_DN: ClassVar[str] = "invalid=base,dn=invalid"
            FAST_TIMEOUT: ClassVar[int] = 1


# Short aliases per FLEXT convention
tc = TestsFlextLdapConstants  # Primary test constants alias
c = TestsFlextLdapConstants  # Alternative alias for compatibility

__all__ = [
    "TestsFlextLdapConstants",
    "c",
    "tc",
]
