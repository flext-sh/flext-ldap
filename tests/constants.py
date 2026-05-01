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

            @unique
            class OperationScenarioCase(StrEnum):
                ADD_SUCCESS = "add_success"
                ADD_EXISTS = "add_exists"
                DELETE_SUCCESS = "delete_success"
                DELETE_MISSING = "delete_missing"
                MODIFY_SUCCESS = "modify_success"
                MODIFY_MISSING = "modify_missing"
                SEARCH_FOUND = "search_found"
                SEARCH_EMPTY = "search_empty"
                BATCH_ALL_PASS = "batch_all_pass"
                BATCH_MIXED = "batch_mixed"
                BATCH_ALL_FAIL = "batch_all_fail"

            @unique
            class AttributeTransformCase(StrEnum):
                BYTES_SINGLE = "bytes_single"
                STR_SINGLE = "str_single"
                STR_LIST = "str_list"
                BYTES_LIST = "bytes_list"
                NUMERIC = "numeric"
                EMPTY = "empty"
                MIXED = "mixed"

            @unique
            class SecurityModeCase(StrEnum):
                PLAIN = "plain"
                SSL = "ssl"
                TLS = "tls"
                SSL_AND_TLS = "ssl_and_tls"

            @unique
            class EntryOperationCase(StrEnum):
                VALID_DN = "valid_dn"
                EMPTY_DN = "empty_dn"
                INVALID_DN = "invalid_dn"
                SPECIAL_CHARS_DN = "special_chars_dn"

            @unique
            class AddOperationVariationCase(StrEnum):
                SIMPLE_ENTRY = "simple_entry"
                MISSING_DN = "missing_dn"
                DUPLICATE_DN = "duplicate_dn"
                INVALID_SCHEMA = "invalid_schema"
                PERMISSION_DENIED = "permission_denied"
                EMPTY_ATTRIBUTES = "empty_attributes"

            @unique
            class DeleteOperationVariationCase(StrEnum):
                EXISTING_ENTRY = "existing_entry"
                MISSING_ENTRY = "missing_entry"
                WITH_CHILDREN = "with_children"
                NO_PERMISSION = "no_permission"
                INVALID_DN_FORMAT = "invalid_dn_format"
                LAST_ENTRY = "last_entry"

            @unique
            class ModifyOperationVariationCase(StrEnum):
                REPLACE_ATTR = "replace_attr"
                ADD_ATTR = "add_attr"
                DELETE_ATTR = "delete_attr"
                MISSING_ENTRY = "missing_entry"
                SCHEMA_VIOLATION = "schema_violation"
                INVALID_MODIFICATION = "invalid_modification"
                MULTI_ATTRIBUTE = "multi_attribute"

            @unique
            class BatchUpsertVariationCase(StrEnum):
                ALL_SUCCESS = "all_success"
                MIXED_SUCCESS = "mixed_success"
                ALL_FAIL = "all_fail"
                STOP_ON_ERROR = "stop_on_error"
                PARTIAL_SUCCESS = "partial_success"
                EMPTY_BATCH = "empty_batch"

            @unique
            class PortVariationCase(StrEnum):
                STANDARD_389 = "standard_389"
                LDAPS_636 = "ldaps_636"
                CUSTOM_VALID = "custom_valid"
                ZERO_PORT = "zero_port"
                EXCEED_RANGE = "exceed_range"
                PRIVILEGED_PORT = "privileged_port"

            @unique
            class HostVariationCase(StrEnum):
                LOCALHOST = "localhost"
                DNS_NAME = "dns_name"
                IPV4_ADDRESS = "ipv4_address"
                FQDN = "fqdn"
                INVALID_HOST = "invalid_host"
                EMPTY_HOST = "empty_host"
                NUMERIC_HOST = "numeric_host"

            @unique
            class ConnectionTimeoutCase(StrEnum):
                ZERO_TIMEOUT = "zero_timeout"
                CUSTOM_TIMEOUT = "custom_timeout"
                EXCEED_MAX = "exceed_max"
                FRACTIONAL_TIMEOUT = "fractional_timeout"

            @unique
            class ConnectionStateCase(StrEnum):
                NOT_CONNECTED = "not_connected"
                CONNECTED = "connected"
                BINDING = "binding"
                BOUND = "bound"
                CLOSED = "closed"
                ERROR_STATE = "error_state"

            @unique
            class AttributeTransformVariationCase(StrEnum):
                BYTES_VALUE = "bytes_value"
                STRING_VALUE = "string_value"
                INTEGER_VALUE = "integer_value"
                FLOAT_VALUE = "float_value"
                LIST_BYTES = "list_bytes"
                LIST_STRINGS = "list_strings"
                MIXED_LIST = "mixed_list"
                EMPTY_VALUE = "empty_value"
                NULL_BYTES_IN_VALUE = "null_bytes_in_value"
                SPECIAL_CHARS = "special_chars"

            @unique
            class EntryConversionCase(StrEnum):
                SIMPLE_ENTRY = "simple_entry"
                NESTED_OBJECTCLASS = "nested_objectclass"
                COMPLEX_ATTRIBUTES = "complex_attributes"
                SCHEMA_ATTRIBUTES = "schema_attributes"
                OPERATIONAL_ATTRS = "operational_attrs"
                BINARY_DATA = "binary_data"

            @unique
            class SearchFilterCase(StrEnum):
                PRESENT = "present"
                EQUALITY = "equality"
                SUBSTRING = "substring"
                GREATER_EQUAL = "greater_equal"
                LESS_EQUAL = "less_equal"
                OR_COMPOUND = "or_compound"
                AND_COMPOUND = "and_compound"
                COMPLEX_NESTED = "complex_nested"

            @unique
            class SearchSizeCase(StrEnum):
                SIZE_ZERO = "size_zero"
                SIZE_ONE = "size_one"
                SIZE_SMALL = "size_small"
                SIZE_MEDIUM = "size_medium"
                SIZE_LARGE = "size_large"

            @unique
            class SearchScopeCase(StrEnum):
                BASE = "base"
                ONE_LEVEL = "one_level"
                SUBTREE = "subtree"
                SUBORDINATE = "subordinate"

            OPERATION_SCENARIOS: Final[
                Mapping[OperationScenarioCase, Mapping[str, t.StrSequence | str]]
            ] = MappingProxyType({
                OperationScenarioCase.ADD_SUCCESS: MappingProxyType({
                    "action": ("add",),
                    "state": ("success",),
                    "expected": ("dn created",),
                }),
                OperationScenarioCase.ADD_EXISTS: MappingProxyType({
                    "action": ("add",),
                    "state": ("exists",),
                    "expected": ("already exists",),
                }),
                OperationScenarioCase.DELETE_SUCCESS: MappingProxyType({
                    "action": ("delete",),
                    "state": ("success",),
                    "expected": ("deleted",),
                }),
                OperationScenarioCase.DELETE_MISSING: MappingProxyType({
                    "action": ("delete",),
                    "state": ("missing",),
                    "expected": ("not found",),
                }),
                OperationScenarioCase.MODIFY_SUCCESS: MappingProxyType({
                    "action": ("modify",),
                    "state": ("success",),
                    "expected": ("modified",),
                }),
                OperationScenarioCase.MODIFY_MISSING: MappingProxyType({
                    "action": ("modify",),
                    "state": ("missing",),
                    "expected": ("not found",),
                }),
                OperationScenarioCase.SEARCH_FOUND: MappingProxyType({
                    "action": ("search",),
                    "state": ("found",),
                    "expected": ("entries",),
                }),
                OperationScenarioCase.SEARCH_EMPTY: MappingProxyType({
                    "action": ("search",),
                    "state": ("empty",),
                    "expected": ("no results",),
                }),
            })

            ATTRIBUTE_TRANSFORMS: Final[
                Mapping[AttributeTransformCase, tuple[str, type, int]]
            ] = MappingProxyType({
                AttributeTransformCase.BYTES_SINGLE: ("bytes", bytes, 1),
                AttributeTransformCase.STR_SINGLE: ("string", str, 1),
                AttributeTransformCase.STR_LIST: ("list", list, 3),
                AttributeTransformCase.BYTES_LIST: ("bytes_list", bytes, 3),
                AttributeTransformCase.NUMERIC: ("num", int, 1),
                AttributeTransformCase.EMPTY: ("empty", str, 0),
                AttributeTransformCase.MIXED: ("mixed", object, 5),
            })

            SECURITY_SCENARIOS: Final[Mapping[SecurityModeCase, tuple[bool, bool]]] = (
                MappingProxyType({
                    SecurityModeCase.PLAIN: (False, False),
                    SecurityModeCase.SSL: (True, False),
                    SecurityModeCase.TLS: (False, True),
                    SecurityModeCase.SSL_AND_TLS: (True, True),
                })
            )

            ENTRY_DN_SCENARIOS: Final[Mapping[EntryOperationCase, str]] = (
                MappingProxyType({
                    EntryOperationCase.VALID_DN: "cn=test,ou=people,dc=example,dc=com",
                    EntryOperationCase.EMPTY_DN: "",
                    EntryOperationCase.INVALID_DN: "not-a-valid-dn",
                    EntryOperationCase.SPECIAL_CHARS_DN: (
                        "cn=test\\,user,ou=people,dc=example,dc=com"
                    ),
                })
            )

            ADD_OPERATION_SCENARIOS: Final[
                Mapping[AddOperationVariationCase, Mapping[str, object]]
            ] = MappingProxyType({
                AddOperationVariationCase.SIMPLE_ENTRY: MappingProxyType({
                    "dn": ("cn=newuser,ou=people,dc=example,dc=com",),
                    "attributes": ("cn", "sn", "objectClass"),
                    "should_succeed": (True,),
                }),
                AddOperationVariationCase.MISSING_DN: MappingProxyType({
                    "dn": ("",),
                    "attributes": ("cn", "sn"),
                    "should_succeed": (False,),
                }),
                AddOperationVariationCase.DUPLICATE_DN: MappingProxyType({
                    "dn": ("cn=existing,ou=people,dc=example,dc=com",),
                    "attributes": ("cn", "sn"),
                    "should_succeed": (False,),
                    "error": ("Entry already exists",),
                }),
                AddOperationVariationCase.INVALID_SCHEMA: MappingProxyType({
                    "dn": ("cn=test,ou=people,dc=example,dc=com",),
                    "attributes": ("invalidAttr",),
                    "should_succeed": (False,),
                    "error": ("Schema violation",),
                }),
                AddOperationVariationCase.PERMISSION_DENIED: MappingProxyType({
                    "dn": ("cn=test,ou=people,dc=example,dc=com",),
                    "attributes": ("cn", "sn"),
                    "should_succeed": (False,),
                    "error": ("Permission denied",),
                }),
                AddOperationVariationCase.EMPTY_ATTRIBUTES: MappingProxyType({
                    "dn": ("cn=test,ou=people,dc=example,dc=com",),
                    "attributes": (),
                    "should_succeed": (False,),
                }),
            })

            DELETE_OPERATION_SCENARIOS: Final[
                Mapping[DeleteOperationVariationCase, Mapping[str, object]]
            ] = MappingProxyType({
                DeleteOperationVariationCase.EXISTING_ENTRY: MappingProxyType({
                    "dn": ("cn=existinguser,ou=people,dc=example,dc=com",),
                    "should_succeed": (True,),
                }),
                DeleteOperationVariationCase.MISSING_ENTRY: MappingProxyType({
                    "dn": ("cn=nonexistent,ou=people,dc=example,dc=com",),
                    "should_succeed": (False,),
                    "error": ("Not found",),
                }),
                DeleteOperationVariationCase.WITH_CHILDREN: MappingProxyType({
                    "dn": ("ou=people,dc=example,dc=com",),
                    "should_succeed": (False,),
                    "error": ("Has children",),
                }),
                DeleteOperationVariationCase.NO_PERMISSION: MappingProxyType({
                    "dn": ("cn=restricted,ou=people,dc=example,dc=com",),
                    "should_succeed": (False,),
                    "error": ("Permission denied",),
                }),
                DeleteOperationVariationCase.INVALID_DN_FORMAT: MappingProxyType({
                    "dn": ("not-a-valid-dn",),
                    "should_succeed": (False,),
                    "error": ("Invalid DN",),
                }),
                DeleteOperationVariationCase.LAST_ENTRY: MappingProxyType({
                    "dn": ("cn=lastuser,ou=people,dc=example,dc=com",),
                    "should_succeed": (True,),
                }),
            })

            MODIFY_OPERATION_SCENARIOS: Final[
                Mapping[ModifyOperationVariationCase, Mapping[str, object]]
            ] = MappingProxyType({
                ModifyOperationVariationCase.REPLACE_ATTR: MappingProxyType({
                    "dn": ("cn=user,ou=people,dc=example,dc=com",),
                    "operation": ("replace",),
                    "should_succeed": (True,),
                }),
                ModifyOperationVariationCase.ADD_ATTR: MappingProxyType({
                    "dn": ("cn=user,ou=people,dc=example,dc=com",),
                    "operation": ("add",),
                    "should_succeed": (True,),
                }),
                ModifyOperationVariationCase.DELETE_ATTR: MappingProxyType({
                    "dn": ("cn=user,ou=people,dc=example,dc=com",),
                    "operation": ("delete",),
                    "should_succeed": (True,),
                }),
                ModifyOperationVariationCase.MISSING_ENTRY: MappingProxyType({
                    "dn": ("cn=nonexistent,ou=people,dc=example,dc=com",),
                    "operation": ("replace",),
                    "should_succeed": (False,),
                }),
                ModifyOperationVariationCase.SCHEMA_VIOLATION: MappingProxyType({
                    "dn": ("cn=user,ou=people,dc=example,dc=com",),
                    "operation": ("replace",),
                    "attribute": ("invalidAttr",),
                    "should_succeed": (False,),
                }),
                ModifyOperationVariationCase.INVALID_MODIFICATION: MappingProxyType({
                    "dn": ("cn=user,ou=people,dc=example,dc=com",),
                    "operation": ("invalid",),
                    "should_succeed": (False,),
                }),
                ModifyOperationVariationCase.MULTI_ATTRIBUTE: MappingProxyType({
                    "dn": ("cn=user,ou=people,dc=example,dc=com",),
                    "operation": ("replace",),
                    "attributes": ("cn", "mail", "telephoneNumber"),
                    "should_succeed": (True,),
                }),
            })

            BATCH_UPSERT_SCENARIOS: Final[
                Mapping[BatchUpsertVariationCase, Mapping[str, object]]
            ] = MappingProxyType({
                BatchUpsertVariationCase.ALL_SUCCESS: MappingProxyType({
                    "count": (10,),
                    "success_count": (10,),
                    "fail_count": (0,),
                    "should_succeed": (True,),
                }),
                BatchUpsertVariationCase.MIXED_SUCCESS: MappingProxyType({
                    "count": (10,),
                    "success_count": (7,),
                    "fail_count": (3,),
                    "should_succeed": (True,),
                }),
                BatchUpsertVariationCase.ALL_FAIL: MappingProxyType({
                    "count": (10,),
                    "success_count": (0,),
                    "fail_count": (10,),
                    "should_succeed": (False,),
                }),
                BatchUpsertVariationCase.STOP_ON_ERROR: MappingProxyType({
                    "count": (10,),
                    "success_count": (3,),
                    "fail_count": (1,),
                    "stop_on_error": (True,),
                    "should_succeed": (False,),
                }),
                BatchUpsertVariationCase.PARTIAL_SUCCESS: MappingProxyType({
                    "count": (20,),
                    "success_count": (15,),
                    "fail_count": (5,),
                    "should_succeed": (True,),
                }),
                BatchUpsertVariationCase.EMPTY_BATCH: MappingProxyType({
                    "count": (0,),
                    "success_count": (0,),
                    "fail_count": (0,),
                    "should_succeed": (True,),
                }),
            })

            PORT_SCENARIOS: Final[Mapping[PortVariationCase, int]] = MappingProxyType({
                PortVariationCase.STANDARD_389: c.Ldap.PORT,
                PortVariationCase.LDAPS_636: CONFIG_LDAPS_PORT,
                PortVariationCase.CUSTOM_VALID: 10389,
                PortVariationCase.ZERO_PORT: 0,
                PortVariationCase.EXCEED_RANGE: 99999,
                PortVariationCase.PRIVILEGED_PORT: 22,
            })

            HOST_SCENARIOS: Final[Mapping[HostVariationCase, str]] = MappingProxyType({
                HostVariationCase.LOCALHOST: c.LOCALHOST,
                HostVariationCase.DNS_NAME: "ldap.example.com",
                HostVariationCase.IPV4_ADDRESS: "192.168.1.1",
                HostVariationCase.FQDN: "ldap.company.internal.example.com",
                HostVariationCase.INVALID_HOST: "invalid..host..",
                HostVariationCase.EMPTY_HOST: "",
                HostVariationCase.NUMERIC_HOST: "999.999.999.999",
            })

            TIMEOUT_SCENARIOS: Final[Mapping[ConnectionTimeoutCase, int | float]] = (
                MappingProxyType({
                    ConnectionTimeoutCase.ZERO_TIMEOUT: 0,
                    ConnectionTimeoutCase.CUSTOM_TIMEOUT: 60,
                    ConnectionTimeoutCase.EXCEED_MAX: 999999,
                    ConnectionTimeoutCase.FRACTIONAL_TIMEOUT: 5,
                })
            )

            CONNECTION_STATE_SCENARIOS: Final[Mapping[ConnectionStateCase, bool]] = (
                MappingProxyType({
                    ConnectionStateCase.NOT_CONNECTED: False,
                    ConnectionStateCase.CONNECTED: True,
                    ConnectionStateCase.BINDING: False,
                    ConnectionStateCase.BOUND: True,
                    ConnectionStateCase.CLOSED: False,
                    ConnectionStateCase.ERROR_STATE: False,
                })
            )

            ATTRIBUTE_TRANSFORM_SCENARIOS: Final[
                Mapping[AttributeTransformVariationCase, Mapping[str, object]]
            ] = MappingProxyType({
                AttributeTransformVariationCase.BYTES_VALUE: MappingProxyType({
                    "value": (b"hello",),
                    "expected_type": (str,),
                }),
                AttributeTransformVariationCase.STRING_VALUE: MappingProxyType({
                    "value": ("hello",),
                    "expected_type": (str,),
                }),
                AttributeTransformVariationCase.INTEGER_VALUE: MappingProxyType({
                    "value": (42,),
                    "expected_type": (str,),
                }),
                AttributeTransformVariationCase.FLOAT_VALUE: MappingProxyType({
                    "value": (math.pi,),
                    "expected_type": (str,),
                }),
                AttributeTransformVariationCase.LIST_BYTES: MappingProxyType({
                    "value": ((b"hello", b"world"),),
                    "expected_type": (tuple,),
                }),
                AttributeTransformVariationCase.LIST_STRINGS: MappingProxyType({
                    "value": (("hello", "world"),),
                    "expected_type": (tuple,),
                }),
                AttributeTransformVariationCase.MIXED_LIST: MappingProxyType({
                    "value": ((b"hello", "world", 42),),
                    "expected_type": (tuple,),
                }),
                AttributeTransformVariationCase.EMPTY_VALUE: MappingProxyType({
                    "value": ((),),
                    "expected_type": (tuple,),
                }),
                AttributeTransformVariationCase.NULL_BYTES_IN_VALUE: MappingProxyType({
                    "value": (b"hello\x00world",),
                    "expected_type": (str,),
                }),
                AttributeTransformVariationCase.SPECIAL_CHARS: MappingProxyType({
                    "value": ("hello\\nworld\\t!@#$%",),
                    "expected_type": (str,),
                }),
            })

            ENTRY_CONVERSION_SCENARIOS: Final[
                Mapping[EntryConversionCase, Mapping[str, object]]
            ] = MappingProxyType({
                EntryConversionCase.SIMPLE_ENTRY: MappingProxyType({
                    "cn": ("John",),
                    "sn": ("Doe",),
                    "mail": ("john@example.com",),
                }),
                EntryConversionCase.NESTED_OBJECTCLASS: MappingProxyType({
                    "objectClass": ("top", "person", "inetOrgPerson"),
                    "cn": ("John",),
                    "sn": ("Doe",),
                }),
                EntryConversionCase.COMPLEX_ATTRIBUTES: MappingProxyType({
                    "cn": ("John", "Johnny"),
                    "mail": ("john@example.com", "john.doe@example.com"),
                    "telephoneNumber": ("+1234567890", "+0987654321"),
                }),
                EntryConversionCase.SCHEMA_ATTRIBUTES: MappingProxyType({
                    "cn": ("User",),
                    "uid": ("user123",),
                    "uidNumber": ("1001",),
                    "gidNumber": ("100",),
                }),
                EntryConversionCase.OPERATIONAL_ATTRS: MappingProxyType({
                    "modifyTimestamp": ("20240101120000Z",),
                    "createTimestamp": ("20240101100000Z",),
                    "modifiersName": ("cn=admin,dc=example,dc=com",),
                }),
                EntryConversionCase.BINARY_DATA: MappingProxyType({
                    "jpegPhoto": (b"\xff\xd8\xff\xe0",),
                    "cn": ("User",),
                }),
            })

            SEARCH_FILTER_SCENARIOS_ADVANCED: Final[Mapping[SearchFilterCase, str]] = (
                MappingProxyType({
                    SearchFilterCase.PRESENT: "(cn=*)",
                    SearchFilterCase.EQUALITY: "(uid=john)",
                    SearchFilterCase.SUBSTRING: "(mail=*@example.com)",
                    SearchFilterCase.GREATER_EQUAL: "(uidNumber>=1000)",
                    SearchFilterCase.LESS_EQUAL: "(uidNumber<=2000)",
                    SearchFilterCase.OR_COMPOUND: "(|(cn=John)(cn=Jane))",
                    SearchFilterCase.AND_COMPOUND: "(&(objectClass=person)(cn=John))",
                    SearchFilterCase.COMPLEX_NESTED: (
                        "(&(|(cn=John)(cn=Jane))(&(mail=*@example.com)(objectClass=person)))"
                    ),
                })
            )

            SEARCH_SIZE_SCENARIOS: Final[Mapping[SearchSizeCase, int]] = (
                MappingProxyType({
                    SearchSizeCase.SIZE_ZERO: 0,
                    SearchSizeCase.SIZE_ONE: 1,
                    SearchSizeCase.SIZE_SMALL: 10,
                    SearchSizeCase.SIZE_MEDIUM: 100,
                    SearchSizeCase.SIZE_LARGE: 10000,
                })
            )

            SEARCH_SCOPE_SCENARIOS: Final[Mapping[SearchScopeCase, str]] = (
                MappingProxyType({
                    SearchScopeCase.BASE: "BASE",
                    SearchScopeCase.ONE_LEVEL: "LEVEL(1)",
                    SearchScopeCase.SUBTREE: "SUBTREE",
                    SearchScopeCase.SUBORDINATE: "SUBORDINATE",
                })
            )

            OPERATION_BATCH_SCENARIOS: Final[frozenset[OperationScenarioCase]] = (
                frozenset({
                    OperationScenarioCase.BATCH_ALL_PASS,
                    OperationScenarioCase.BATCH_MIXED,
                    OperationScenarioCase.BATCH_ALL_FAIL,
                })
            )

            SEARCH_FILTER_SCENARIOS: Final[frozenset[str]] = frozenset({
                "(objectClass=*)",
                "(cn=*)",
                "(uid=*)",
                "(mail=user@*)",
                "(|(cn=*)(uid=*))",
                "(&(objectClass=person)(cn=test))",
            })

            ATTRIBUTE_NAMES_STANDARD: Final[frozenset[str]] = frozenset({
                "cn",
                "mail",
                "uid",
                "objectClass",
                "sn",
                "givenName",
                "telephoneNumber",
            })


c = TestsFlextLdapConstants

__all__: list[str] = ["TestsFlextLdapConstants", "c"]
