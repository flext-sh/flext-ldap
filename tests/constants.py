"""Canonical test constants for flext-ldap.

This module provides a single flat namespace of typed constants (c.Ldap.Tests.*),
organized for data-driven testing, maximum reuse, and composition.

**Design Patterns:**

1. **Enums for Closed Sets**: Use StrEnum/unique for scenarios and case tags that
   are complete, fixed domains (e.g., CallbackGuardCase, Ldap3ServerCase,
   PhaseName, AttrToStrListCase).

2. **Composable Mappings**: MappingProxyType + Final ensure immutability and type
   clarity. Keyed by enum values for composable, well-named test parameters.
   Example: CALLBACK_GUARD_EXPECTED[case] -> (multi_bool, single_bool)

3. **Flat & Reusable**: All constants live at c.Ldap.Tests.* — no sub-namespaces.
   Tests @parametrize directly over Enums or iterate tuples/mappings.

4. **Sequence & Set Constants**: Tuple and frozenset for ordered/unordered collections
   that are fixed. Support pytest.mark.parametrize and data-driven assertions.

**Usage Examples:**

    @pytest.mark.parametrize("case", c.Ldap.Tests.CallbackGuardCase)
    def test_callback_guard(case):
        expected, _ = c.Ldap.Tests.CALLBACK_GUARD_EXPECTED[case]
        assert check_multi_phase(callback[case]) == expected

    @pytest.mark.parametrize(
        "attrs,str_list",
        c.Ldap.Tests.LDAP3_VALUE_TO_STRINGS_SCENARIOS.items()
    )
    def test_ldap_value_to_strings(attrs, str_list):
        assert ldap_value_to_strings(attrs) == str_list

    for count, affected in c.Ldap.Tests.SEARCH_RESULT_TOTAL_COUNT_CASES:
        assert process_result(count) == affected
"""

from __future__ import annotations

import math
from collections.abc import (
    Mapping,
    Sequence,
)
from enum import StrEnum, unique
from types import MappingProxyType
from typing import Final

from flext_cli import t
from flext_tests import FlextTestsConstants

from flext_ldap import c


class TestsFlextLdapConstants(FlextTestsConstants, c):
    """Flat test constants for flext-ldap."""

    class Ldap(c.Ldap):
        """LDAP test constants."""

        class Tests:
            """Direct `c.Ldap.Tests.*` constants with no extra subnamespace."""

            @unique
            class FieldName(StrEnum):
                HOST = "host"
                PORT = "port"
                BIND_DN = "bind_dn"
                BIND_PASSWORD = "bind_password"
                BASE_DN = "base_dn"
                SCOPE = "scope"
                PROPERTIES = "properties"
                TYPE = "type"
                SUCCESS_RATE = "success_rate"

            @unique
            class PhaseName(StrEnum):
                USERS = "users"
                GROUPS = "groups"

            @unique
            class FileName(StrEnum):
                USERS_LDIF = "users.ldif"

            @unique
            class CallbackGuardCase(StrEnum):
                NONE = "none"
                MULTI = "multi"
                SINGLE = "single"

            @unique
            class ConnectionSecurityCase(StrEnum):
                SSL_ONLY = "ssl_only"
                TLS_ONLY = "tls_only"

            @unique
            class Ldap3ServerCase(StrEnum):
                PLAIN = "plain"
                SSL = "ssl"
                TLS = "tls"

            @unique
            class AttrToStrListCase(StrEnum):
                EMPTY = "empty"
                BYTES = "bytes"
                LIST = "list"
                LIST_BYTES = "list_bytes"
                INT = "int"

            @unique
            class LdapValueCase(StrEnum):
                BYTES = "bytes"
                LIST = "list"
                LIST_BYTES = "list_bytes"
                TUPLE = "tuple"
                STR = "str"
                INT = "int"
                FLOAT = "float"

            @unique
            class SearchCategoryCase(StrEnum):
                EMPTY = "empty"
                PERSON = "person"

            RFC_DEFAULT_BASE_DN: Final[str] = "dc=flext,dc=local"
            RFC_DEFAULT_FILTER: Final[str] = "(objectClass=*)"

            BASE_FAIL_ERROR_MESSAGE: Final[str] = "nope"

            CONFIG_EXAMPLE_HOST: Final[str] = "example.com"
            CONFIG_ORIGINAL_HOST: Final[str] = "original.com"
            CONFIG_FIRST_HOST: Final[str] = "first.com"
            CONFIG_SECOND_HOST: Final[str] = "second.com"
            CONFIG_LDAPS_PORT: Final[int] = 636
            CONFIG_PORT_MIN: Final[int] = 1
            CONFIG_PORT_MAX: Final[int] = 65535
            CONFIG_SSL_TLS_COMBOS: Final[tuple[tuple[bool, bool], ...]] = (
                (False, False),
                (True, False),
                (False, True),
                (True, True),
            )
            CONFIG_VALID_PORTS: Final[tuple[int, ...]] = (
                CONFIG_PORT_MIN,
                c.Ldap.PORT,
                CONFIG_LDAPS_PORT,
                CONFIG_PORT_MAX,
            )
            CONFIG_HOST_CASES: Final[tuple[str, ...]] = (
                c.LOCALHOST,
                CONFIG_EXAMPLE_HOST,
                "192.168.1.1",
                "",
            )
            CALLBACK_GUARD_EXPECTED: Final[
                Mapping[CallbackGuardCase, tuple[bool, bool]]
            ] = MappingProxyType({
                CallbackGuardCase.NONE: (False, False),
                CallbackGuardCase.MULTI: (True, False),
                CallbackGuardCase.SINGLE: (False, True),
            })

            FIELD_HOST: Final[FieldName] = FieldName.HOST
            FIELD_PORT: Final[FieldName] = FieldName.PORT
            FIELD_BIND_DN: Final[FieldName] = FieldName.BIND_DN
            FIELD_BIND_PASSWORD: Final[FieldName] = FieldName.BIND_PASSWORD
            FIELD_BASE_DN: Final[FieldName] = FieldName.BASE_DN
            FIELD_SCOPE: Final[FieldName] = FieldName.SCOPE
            FIELD_PROPERTIES: Final[FieldName] = FieldName.PROPERTIES
            FIELD_TYPE: Final[FieldName] = FieldName.TYPE
            FIELD_SUCCESS_RATE: Final[FieldName] = FieldName.SUCCESS_RATE

            DOCKER_CONTAINER_NAME: Final[str] = "flext-openldap-test"
            DOCKER_COMPOSE_FILE_REL: Final[str] = "docker/docker-compose.openldap.yml"
            DOCKER_SERVICE_NAME: Final[str] = "openldap"
            DOCKER_PORT: Final[int] = 3390
            DOCKER_BASE_DN: Final[str] = "dc=flext,dc=local"
            DOCKER_ADMIN_DN: Final[str] = "cn=admin,dc=flext,dc=local"
            DOCKER_ADMIN_PASSWORD: Final[str] = "admin123"
            DOCKER_LEGACY_ADMIN_DN: Final[str] = (
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
            )
            DOCKER_LEGACY_ADMIN_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"
            DOCKER_STARTUP_TIMEOUT: Final[int] = 90
            DOCKER_BIND_READY_TIMEOUT: Final[int] = 60
            DOCKER_DEFAULT_WORKER_ID: Final[str] = "master"
            DOCKER_OU_NAMES: Final[tuple[str, ...]] = (
                "people",
                "groups",
                "services",
            )

            ERROR_INFRASTRUCTURE_PATTERNS: Final[frozenset[str]] = frozenset(
                {
                    "ldapsessionterminatedbyservererror",
                    "ldapserverdownerror",
                    "ldap server is not responding",
                    "broken pipe",
                    "session terminated by server",
                    "ldapoperationresult",
                },
            )
            ERROR_TRANSIENT_PATTERNS: Final[frozenset[str]] = frozenset(
                {
                    "connection refused",
                    "connection reset by peer",
                    "cannot connect to ldap",
                    "ldapsocketopenerror",
                    "ldapcommunicationerror",
                    "ldap bind failed",
                    "timeout",
                },
            )

            ENTRY_DN_USER_EXAMPLE: Final[str] = "cn=user,dc=example,dc=com"
            ENTRY_DN_TEST_EXAMPLE: Final[str] = "cn=test,dc=example,dc=com"
            ENTRY_DN_ADMIN_EXAMPLE: Final[str] = (
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            )
            ENTRY_DN_USER_NEW: Final[str] = "cn=user,dc=new,dc=com"

            BIND_ADMIN_DN: Final[str] = "cn=admin,dc=x,dc=y"
            BIND_ADMIN_PASSWORD: Final[str] = "secret"

            DETECTION_EXECUTE_SCENARIOS: Final[
                Sequence[
                    tuple[
                        Mapping[str, bool | float | str | None] | None,
                        bool,
                        str,
                    ]
                ]
            ] = (
                # Substrings match the centralized flext-core error format —
                # ``ERR_SERVICE_TYPE_MISMATCH`` and the validate-connection
                # wrapper. Keep these aligned with the canonical messages.
                ({}, True, "parameter required"),
                (
                    {"connection": "invalid"},
                    True,
                    "ldap3.Connection",
                ),
            )
            DETECTION_GET_FIRST_VALUE_SCENARIOS: Final[
                Sequence[tuple[Mapping[str, t.StrSequence], str, str | None]]
            ] = (
                (
                    MappingProxyType(
                        {"vendorName": ("Oracle Corporation", "Version 2")},
                    ),
                    "vendorName",
                    "Oracle Corporation",
                ),
                (
                    MappingProxyType({"vendorName": ("OpenLDAP",)}),
                    "vendorName",
                    "OpenLDAP",
                ),
                (MappingProxyType({"otherKey": ("value",)}), "vendorName", None),
                (MappingProxyType({"vendorName": ()}), "vendorName", None),
            )
            DETECTION_FROM_ATTRIBUTES_SCENARIOS: Final[
                Sequence[tuple[str | None, str | None, t.StrSequence, str]]
            ] = (
                ("Oracle Corporation", "12.2.1.4.0", (), "oid"),
                ("Oracle Unified Directory", "12.2.1.4.0", (), "oud"),
                ("OpenLDAP", "2.4.57", (), "openldap"),
                (
                    "Microsoft Corporation",
                    None,
                    ("1.2.840.113556.1.4.319",),
                    "ad",
                ),
                ("389 Project", "2.0.0", (), "ds389"),
                (None, None, (), "rfc"),
                ("oracle corporation", "12.2.1.4.0", (), "oid"),
                ("Oracle", None, (), "oid"),
            )

            OPERATIONS_ERROR_DETECTION_SCENARIOS: Final[t.BoolMapping] = (
                MappingProxyType(
                    {
                        "Entry already exists": True,
                        "already exists": True,
                        "ALREADY EXISTS": True,
                        "entryAlreadyExists": True,
                        "Connection failed": False,
                        "": False,
                    },
                )
            )
            OPERATIONS_BATCH_STOP_FRAGMENT: Final[str] = "stopped on error"
            OPERATIONS_BATCH_ALL_FAILED_FRAGMENT: Final[str] = "entries failed"

            SEARCH_RESULT_TOTAL_COUNT_CASES: Final[tuple[tuple[int, int], ...]] = (
                (0, 0),
                (1, 1),
                (5, 5),
                (10, 10),
            )

            STRING_SIMPLE: Final[str] = "test"
            STRING_SIMPLE_UPPER: Final[str] = "TEST"
            STRING_EMPTY: Final[str] = ""
            STRING_DEFAULT_CUSTOM: Final[str] = "default"

            LIST_ABC: Final[tuple[str, ...]] = ("a", "b", "c")
            LIST_ABC_UPPER: Final[tuple[str, ...]] = ("A", "B", "C")
            LIST_SINGLE: Final[str] = "single"

            FILTER_TRUTHY_INPUT: Final[t.StrMapping] = MappingProxyType(
                {
                    "a": "value",
                    "b": "",
                    "c": "none_str",
                    "d": "value2",
                },
            )
            FILTER_TRUTHY_EXPECTED_KEYS: Final[tuple[str, ...]] = ("a", "c", "d")

            NORM_JOIN_INPUT: Final[tuple[str, ...]] = ("A", "B", "C")
            NORM_JOIN_EXPECTED: Final[str] = "a b c"
            CONSTANT_INVALID_STATUS: Final[str] = "invalid"
            ENTRY_ADAPTER_SAMPLE_ATTRIBUTES: Final[Mapping[str, t.StrSequence]] = (
                MappingProxyType(
                    {
                        "cn": ("user",),
                        "sn": ("Doe",),
                    },
                )
            )
            # Substring matches the centralized validation error
            # ("Failed to validate entry.attributes: empty"). Update with the
            # canonical message rather than re-introducing custom wording.
            ENTRY_ADAPTER_NO_ATTRIBUTES_ERROR: Final[str] = "empty"
            LDAP3_ADAPTER_DEFAULT_TIMEOUT: Final[int] = 5
            LDAP3_ADAPTER_NOT_CONNECTED_ERROR: Final[str] = "Not connected"
            LDAP3_SERVER_SCENARIOS: Final[
                Mapping[Ldap3ServerCase, tuple[int, bool, bool]]
            ] = MappingProxyType({
                Ldap3ServerCase.PLAIN: (c.Ldap.PORT, False, False),
                Ldap3ServerCase.SSL: (CONFIG_LDAPS_PORT, True, False),
                Ldap3ServerCase.TLS: (c.Ldap.PORT, False, True),
            })
            ATTR_TO_STR_LIST_SCENARIOS: Final[
                Mapping[AttrToStrListCase, Mapping[str, tuple[str, ...]]]
            ] = MappingProxyType({
                AttrToStrListCase.EMPTY: MappingProxyType({}),
                AttrToStrListCase.BYTES: MappingProxyType({"key": ("hello",)}),
                AttrToStrListCase.LIST: MappingProxyType({"cn": LIST_ABC}),
                AttrToStrListCase.LIST_BYTES: MappingProxyType({
                    "key": ("bytes", "str")
                }),
                AttrToStrListCase.INT: MappingProxyType({"num": ("42",)}),
            })
            LDAP3_VALUE_TO_STRINGS_SCENARIOS: Final[
                Mapping[
                    LdapValueCase,
                    tuple[
                        bytes | int | float | str | Sequence[bytes | str],
                        tuple[str, ...],
                    ],
                ]
            ] = MappingProxyType({
                LdapValueCase.BYTES: (b"hello", ("hello",)),
                LdapValueCase.LIST: (list(LIST_ABC), LIST_ABC),
                LdapValueCase.LIST_BYTES: ((b"hello", "world"), ("hello", "world")),
                LdapValueCase.TUPLE: (LIST_ABC, LIST_ABC),
                LdapValueCase.STR: ("hello", ("hello",)),
                LdapValueCase.INT: (42, ("42",)),
                LdapValueCase.FLOAT: (math.pi, (str(math.pi),)),
            })

            MODELS_LDAP_EXAMPLE_HOST: Final[str] = "ldap.example.com"
            MODELS_CUSTOM_TIMEOUT: Final[int] = 60
            MODELS_INVALID_DN_FORMAT: Final[str] = "invalid-dn-format"
            MODELS_ALLOWED_SECURITY_COMBOS: Final[
                Mapping[ConnectionSecurityCase, tuple[bool, bool]]
            ] = MappingProxyType({
                ConnectionSecurityCase.SSL_ONLY: (True, False),
                ConnectionSecurityCase.TLS_ONLY: (False, True),
            })
            MODELS_INVALID_PORTS: Final[tuple[int, ...]] = (0, 65536)

            SEARCH_SCOPE_BASE: Final[str] = "BASE"
            SEARCH_SCOPE_SUBTREE_LOWER: Final[str] = "subtree"
            SEARCH_FILTER_CN: Final[str] = "(cn=*)"
            SEARCH_FILTER_UID: Final[str] = "(uid=*)"
            SEARCH_ATTRIBUTES: Final[tuple[str, ...]] = ("cn", "mail")
            SEARCH_SIZE_LIMIT_CUSTOM: Final[int] = 100
            SEARCH_TIME_LIMIT_CUSTOM: Final[int] = 30
            SEARCH_NORMALIZED_SIZE_LIMIT: Final[int] = 50
            SEARCH_ENTRY_ADDED_MESSAGE: Final[str] = "Entry added successfully"
            SEARCH_DEFAULT_LIMIT_ZERO: Final[int] = 0
            SEARCH_OBJECTCLASS_PERSON_TOP: Final[Mapping[str, t.StrSequence]] = (
                MappingProxyType({"objectClass": ("person", "top")})
            )
            SEARCH_CATEGORY_EXPECTED: Final[Mapping[SearchCategoryCase, str]] = (
                MappingProxyType({
                    SearchCategoryCase.EMPTY: c.Ldap.UNKNOWN_CATEGORY,
                    SearchCategoryCase.PERSON: "person",
                })
            )
            SEARCH_ENTRIES_AFFECTED_ONE: Final[int] = 1
            SEARCH_SYNC_COUNTERS_SYNCED: Final[int] = 80
            SEARCH_SYNC_COUNTERS_SKIPPED: Final[int] = 10
            SEARCH_SYNC_COUNTERS_FAILED: Final[int] = 10
            SEARCH_EXPECTED_SUCCESS_RATE_90: Final[float] = 0.9

            SYNC_PHASE_NAME: Final[str] = "01-users"
            SYNC_ENTRY_ALREADY_EXISTS: Final[str] = "Entry already exists"
            SYNC_DEFAULT_ZERO_COUNT: Final[int] = 0
            SYNC_DEFAULT_EMPTY_SOURCE_DN: Final[str] = ""

            SYNC_FROM_COUNTERS_SYNCED: Final[int] = 50
            SYNC_FROM_COUNTERS_SKIPPED: Final[int] = 30
            SYNC_FROM_COUNTERS_FAILED: Final[int] = 20
            SYNC_FROM_COUNTERS_TOTAL: Final[int] = 100
            SYNC_FROM_COUNTERS_DURATION: Final[float] = 10.5
            SYNC_FROM_COUNTERS_SUCCESS_RATE: Final[float] = 0.8

            SYNC_SERIALIZATION_SYNCED: Final[int] = 9
            SYNC_SERIALIZATION_SKIPPED: Final[int] = 1
            SYNC_SERIALIZATION_FAILED: Final[int] = 0

            SYNC_UPSERT_BATCH_TOTAL: Final[int] = 100
            SYNC_UPSERT_BATCH_SUCCESSFUL: Final[int] = 90
            SYNC_UPSERT_BATCH_FAILED: Final[int] = 10

            SYNC_METADATA_SOURCE_ATTRIBUTES: Final[tuple[str, ...]] = (
                "cn",
                "mail",
                "telephoneNumber",
            )
            SYNC_METADATA_REMOVED_ATTRIBUTES: Final[tuple[str, ...]] = ("userPassword",)

            SYNC_PHASE_TOTAL_ENTRIES: Final[int] = 100
            SYNC_PHASE_SYNCED: Final[int] = 90
            SYNC_PHASE_FAILED: Final[int] = 5
            SYNC_PHASE_SKIPPED: Final[int] = 5
            SYNC_PHASE_DURATION: Final[float] = 30.0
            SYNC_PHASE_SUCCESS_RATE: Final[float] = 95.0

            SYNC_MULTI_PHASE_TOTAL_ENTRIES: Final[int] = 500
            SYNC_MULTI_PHASE_TOTAL_SYNCED: Final[int] = 450
            SYNC_MULTI_PHASE_TOTAL_FAILED: Final[int] = 25
            SYNC_MULTI_PHASE_TOTAL_SKIPPED: Final[int] = 25
            SYNC_MULTI_PHASE_OVERALL_SUCCESS_RATE: Final[float] = 95.0
            SYNC_MULTI_PHASE_TOTAL_DURATION: Final[float] = 120.0

            SYNC_PHASE_RESULTS_SYNCED: Final[int] = 95
            SYNC_PHASE_RESULTS_FAILED: Final[int] = 5
            SYNC_PHASE_RESULTS_SKIPPED: Final[int] = 0
            SYNC_PHASE_RESULTS_DURATION: Final[float] = 10.0
            SYNC_PHASE_RESULTS_SUCCESS_RATE: Final[float] = 95.0

            SYNC_BATCH_STATS_SYNCED: Final[int] = 80
            SYNC_BATCH_STATS_FAILED: Final[int] = 10
            SYNC_BATCH_STATS_SKIPPED: Final[int] = 10

            SYNC_FACADE_MISSING_LDIF_PATH: Final[str] = (
                "/tmp/flext-ldap-sync-missing.ldif"
            )
            SYNC_FACADE_PHASE_NAME_USERS: Final[PhaseName] = PhaseName.USERS
            SYNC_FACADE_MISSING_FILE_PHASES: Final[tuple[PhaseName, ...]] = (
                PhaseName.USERS,
                PhaseName.GROUPS,
            )
            SYNC_FACADE_TEST_USER_DN: Final[str] = (
                "cn=syncuser,ou=people,dc=flext,dc=local"
            )
            CONNECTION_INVALID_PASSWORDS: Final[tuple[str, ...]] = (
                "invalid-password",
                "wrong-password",
            )
            SYNC_FACADE_SINGLE_ENTRY_LDIF: Final[str] = (
                "version: 1\n\n"
                "dn: cn=syncuser,ou=people,dc=flext,dc=local\n"
                "changetype: add\n"
                "objectClass: inetOrgPerson\n"
                "objectClass: organizationalPerson\n"
                "objectClass: person\n"
                "objectClass: top\n"
                "cn: syncuser\n"
                "sn: user\n"
                "uid: syncuser\n"
                "mail: syncuser@flext.local\n"
            )
            SYNC_FACADE_USERS_LDIF_FILENAME: Final[FileName] = FileName.USERS_LDIF


c = TestsFlextLdapConstants

__all__: list[str] = ["TestsFlextLdapConstants", "c"]
