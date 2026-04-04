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

from flext_ldap import FlextLdapConstants, FlextLdapTypes


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

            class Api:
                """API facade test constants."""

                EXPECTED_METHODS: ClassVar[Sequence[str]] = [
                    "connect",
                    "disconnect",
                    "search",
                    "add",
                    "modify",
                    "delete",
                    "upsert",
                    "batch_upsert",
                    "sync_phase_entries",
                    "sync_multiple_phases",
                ]

            class Base:
                """FlextLdapServiceBase test constants."""

                FAIL_ERROR_MESSAGE: Final[str] = "nope"
                EXPORT_ALIAS: Final[str] = "s"

            class Config:
                """Settings test constants."""

                EXAMPLE_HOST: Final[str] = "example.com"
                ORIGINAL_HOST: Final[str] = "original.com"
                FIRST_HOST: Final[str] = "first.com"
                SECOND_HOST: Final[str] = "second.com"
                IP_HOST: Final[str] = "192.168.1.1"
                LDAPS_PORT: Final[int] = 636
                PORT_MIN: Final[int] = 1
                PORT_MAX: Final[int] = 65535
                ENV_PREFIX: Final[str] = "FLEXT_"
                VALID_PORTS: ClassVar[Sequence[int]] = [1, 389, 636, 65535]
                SSL_TLS_COMBOS: ClassVar[Sequence[tuple[bool, bool]]] = [
                    (False, False),
                    (True, False),
                    (False, True),
                    (True, True),
                ]
                HOST_VARIANTS: ClassVar[Sequence[str]] = [
                    "localhost",
                    "example.com",
                    "192.168.1.1",
                    "",
                ]

            class FieldNames:
                """Pydantic field name constants used in assertions."""

                HOST: Final[str] = "host"
                PORT: Final[str] = "port"
                BIND_DN: Final[str] = "bind_dn"
                BIND_PASSWORD: Final[str] = "bind_password"
                BASE_DN: Final[str] = "base_dn"
                SCOPE: Final[str] = "scope"
                PROPERTIES: Final[str] = "properties"
                TYPE: Final[str] = "type"

            class ApiModelConfig:
                """Expected model_config values for the ldap API facade."""

                FROZEN: Final[bool] = False
                EXTRA: Final[str] = "ignore"
                ARBITRARY_TYPES_ALLOWED: Final[bool] = True

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

            class ErrorPatterns:
                """Error classification patterns for test infrastructure."""

                INFRASTRUCTURE_ERRORS: frozenset[str] = frozenset({
                    "ldapsessionterminatedbyservererror",
                    "ldapserverdownerror",
                    "ldap server is not responding",
                    "broken pipe",
                    "session terminated by server",
                    "ldapoperationresult",
                })
                TRANSIENT_ERRORS: frozenset[str] = frozenset({
                    "connection refused",
                    "connection reset by peer",
                    "cannot connect to ldap",
                    "ldapsocketopenerror",
                    "ldapcommunicationerror",
                    "ldap bind failed",
                    "timeout",
                })

            class EntryDN:
                """Test DN constants used across adapter/entry/sync tests."""

                USER_EXAMPLE: Final[str] = "cn=user,dc=example,dc=com"
                TEST_EXAMPLE: Final[str] = "cn=test,dc=example,dc=com"
                ADMIN_EXAMPLE: Final[str] = (
                    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
                )
                USER_NEW: Final[str] = "cn=user,dc=new,dc=com"

            class BindCredentials:
                """Test bind DN/password pairs for settings/config tests."""

                ADMIN_DN: Final[str] = "cn=admin,dc=x,dc=y"
                ADMIN_PASSWORD: Final[str] = "secret"

            class Detection:
                """Scenarios and constants for server type detection tests."""

                EXECUTE_SCENARIOS: ClassVar[
                    Sequence[
                        tuple[
                            Mapping[str, bool | float | str | None] | None,
                            bool,
                            str,
                        ]
                    ]
                ] = [
                    ({}, True, "connection parameter required"),
                    (
                        {"connection": "invalid"},
                        True,
                        "connection must be ldap3.Connection",
                    ),
                ]

                GET_FIRST_VALUE_SCENARIOS: ClassVar[
                    Sequence[
                        tuple[
                            Mapping[str, Sequence[str]],
                            str,
                            str | None,
                        ]
                    ]
                ] = [
                    (
                        {"vendorName": ["Oracle Corporation", "Version 2"]},
                        "vendorName",
                        "Oracle Corporation",
                    ),
                    ({"vendorName": ["OpenLDAP"]}, "vendorName", "OpenLDAP"),
                    ({"otherKey": ["value"]}, "vendorName", None),
                    ({"vendorName": []}, "vendorName", None),
                ]

                DETECT_FROM_ATTRIBUTES_SCENARIOS: ClassVar[
                    Sequence[tuple[str | None, str | None, Sequence[str], str]]
                ] = [
                    ("Oracle Corporation", "12.2.1.4.0", [], "oid"),
                    ("Oracle Unified Directory", "12.2.1.4.0", [], "oud"),
                    ("OpenLDAP", "2.4.57", [], "openldap"),
                    (
                        "Microsoft Corporation",
                        None,
                        ["1.2.840.113556.1.4.319"],
                        "ad",
                    ),
                    ("389 Project", "2.0.0", [], "ds389"),
                    (None, None, [], "rfc"),
                    ("oracle corporation", "12.2.1.4.0", [], "oid"),
                    ("Oracle", None, [], "oid"),
                ]

            class Operations:
                """Test data for operations tests."""

                ERROR_DETECTION_SCENARIOS: ClassVar[Mapping[str, bool]] = {
                    "Entry already exists": True,
                    "already exists": True,
                    "ALREADY EXISTS": True,
                    "entryAlreadyExists": True,
                    "Connection failed": False,
                    "": False,
                }

            class ModelConfig:
                """Expected Pydantic model_config values for base service tests."""

                SERVICE_BASE_CONFIG: ClassVar[Sequence[tuple[str, str | bool]]] = [
                    ("arbitrary_types_allowed", True),
                    ("extra", "forbid"),
                    ("use_enum_values", True),
                    ("validate_assignment", True),
                ]

            class EntryScenarios:
                """Entry attribute scenarios for comparison tests."""

                IDENTICAL: ClassVar[Mapping[str, Sequence[str]]] = {
                    "cn": ["test"],
                    "sn": ["User"],
                }
                DIFFERENT: ClassVar[Mapping[str, Sequence[str]]] = {
                    "cn": ["test"],
                    "sn": ["Different"],
                }

            class SearchResultScenarios:
                """Search result count scenarios."""

                COUNTS: ClassVar[Mapping[str, tuple[int, int]]] = {
                    "empty": (0, 0),
                    "single": (1, 1),
                    "multiple": (5, 5),
                }

            class StringValues:
                """String test data for utility tests."""

                SIMPLE: Final[str] = "test"
                SIMPLE_UPPER: Final[str] = "TEST"
                EMPTY: Final[str] = ""
                WHITESPACE: Final[str] = "  test  "
                UNICODE: Final[str] = "café"
                DEFAULT_CUSTOM: Final[str] = "default"

            class ListValues:
                """List/sequence test data for utility tests."""

                ABC: ClassVar[Sequence[str]] = ["a", "b", "c"]
                ABC_UPPER: ClassVar[Sequence[str]] = ["A", "B", "C"]
                SINGLE: Final[str] = "single"

            class FilterTruthyData:
                """Test data for filter_truthy tests."""

                INPUT: ClassVar[Mapping[str, str]] = {
                    "a": "value",
                    "b": "",
                    "c": "none_str",
                    "d": "value2",
                }
                EXPECTED_KEYS: ClassVar[Sequence[str]] = ["a", "c", "d"]

            class NormData:
                """Test data for norm_str/norm_join tests."""

                JOIN_INPUT: ClassVar[Sequence[str]] = ["A", "B", "C"]
                JOIN_EXPECTED: Final[str] = "a b c"

            class CallableHandlers:
                """Handler names for find_callable tests."""

                FOUND_KEY: Final[str] = "handler1"

            class SampleData:
                """Static sample entries for tests."""

                USER_ENTRY: ClassVar[
                    Mapping[str, str | Mapping[str, FlextLdapTypes.StrSequence]]
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
                    Mapping[str, str | Mapping[str, FlextLdapTypes.StrSequence]]
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
