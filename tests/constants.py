"""Constants for flext-ldap tests.

Provides FlextLdapTestConstants, extending FlextTestsConstants with flext-ldap-specific
constants. All generic test constants come from flext_tests.

Architecture:
- FlextTestsConstants (flext_tests) = Generic constants for all FLEXT projects
- FlextLdapTestConstants (tests/) = flext-ldap-specific constants extending FlextTestsConstants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import ClassVar, Final

from flext_tests import FlextTestsConstants

from flext_ldap import FlextLdapConstants


class FlextLdapTestConstants(FlextTestsConstants, FlextLdapConstants):
    """Constants for flext-ldap tests - extends FlextTestsConstants and FlextLdapConstants.

    Architecture: Extends both FlextTestsConstants and FlextLdapConstants with flext-ldap-specific constants.
    All generic constants from FlextTestsConstants and production constants from FlextLdapConstants are available through inheritance.

    Rules:
    - NEVER duplicate constants from FlextTestsConstants or FlextLdapConstants
    - Only flext-ldap-specific constants allowed (not generic for other projects)
    - All generic constants come from FlextTestsConstants
    - All production constants come from FlextLdapConstants
    """

    class Ldap(FlextLdapConstants.Ldap):
        """LDAP test constants."""

        class Tests:
            """LDAP test-specific constants."""

            class RFC:
                """RFC server test constants."""

                DEFAULT_HOST: Final[str] = "localhost"
                DEFAULT_PORT: Final[int] = 3390
                DEFAULT_BASE_DN: Final[str] = "dc=flext,dc=local"
                DEFAULT_BIND_DN: Final[str] = (
                    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
                )
                DEFAULT_BIND_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"
                DEFAULT_FILTER: Final[str] = "(objectClass=*)"
                DEFAULT_ATTRIBUTES: Final[tuple[str, ...]] = ("objectClass", "cn")
                TEST_USER_CN: Final[str] = "testuser"
                TEST_USER_DN: Final[str] = (
                    f"uid={TEST_USER_CN},ou=people,{DEFAULT_BASE_DN}"
                )
                TEST_GROUP_CN: Final[str] = "testgroup"
                TEST_GROUP_DN: Final[str] = (
                    f"cn={TEST_GROUP_CN},ou=groups,{DEFAULT_BASE_DN}"
                )
                OU_PEOPLE: Final[str] = "ou=people"
                OU_GROUPS: Final[str] = "ou=groups"
                OU_SYSTEM: Final[str] = "ou=system"
                OU_PEOPLE_DN: Final[str] = f"{OU_PEOPLE},{DEFAULT_BASE_DN}"
                OU_GROUPS_DN: Final[str] = f"{OU_GROUPS},{DEFAULT_BASE_DN}"
                OU_SYSTEM_DN: Final[str] = f"{OU_SYSTEM},{DEFAULT_BASE_DN}"

            class Docker:
                """Docker container infrastructure constants for integration tests."""

                CONTAINER_NAME: Final[str] = "flext-openldap-test"
                COMPOSE_FILE_REL: Final[str] = "docker/docker-compose.openldap.yml"
                SERVICE_NAME: Final[str] = "openldap"
                PORT: Final[int] = 3390
                BASE_DN: Final[str] = "dc=flext,dc=local"
                ADMIN_DN: Final[str] = "cn=admin,dc=flext,dc=local"
                ADMIN_PASSWORD: Final[str] = "admin123"
                LEGACY_ADMIN_DN: Final[str] = (
                    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
                )
                LEGACY_ADMIN_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"

            class SampleData:
                """Static sample entries for tests."""

                USER_ENTRY: ClassVar[
                    Mapping[str, str | Mapping[str, Sequence[str]]]
                ] = {
                    "dn": "cn=testuser,ou=people,dc=flext,dc=local",
                    "attributes": {
                        "cn": ["testuser"],
                        "sn": ["User"],
                        "givenName": ["Test"],
                        "uid": ["testuser"],
                        "mail": ["testuser@internal.invalid"],
                        "objectClass": [
                            "inetOrgPerson",
                            "organizationalPerson",
                            "person",
                            "top",
                        ],
                        "userPassword": ["test123"],
                    },
                }
                GROUP_ENTRY: ClassVar[
                    Mapping[str, str | Mapping[str, Sequence[str]]]
                ] = {
                    "dn": "cn=testgroup,ou=groups,dc=flext,dc=local",
                    "attributes": {
                        "cn": ["testgroup"],
                        "objectClass": ["groupOfNames", "top"],
                        "member": ["cn=testuser,ou=people,dc=flext,dc=local"],
                    },
                }


c = FlextLdapTestConstants

__all__ = ["FlextLdapTestConstants", "c"]
