"""Canonical test constants for flext-ldap."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    Sequence,
)
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

            RFC_DEFAULT_HOST: Final[str] = "localhost"
            RFC_DEFAULT_PORT: Final[int] = 3390
            RFC_DEFAULT_BASE_DN: Final[str] = "dc=flext,dc=local"
            RFC_DEFAULT_BIND_DN: Final[str] = (
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
            )
            RFC_DEFAULT_BIND_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"
            RFC_DEFAULT_FILTER: Final[str] = "(objectClass=*)"
            RFC_DEFAULT_ATTRIBUTES: Final[tuple[str, ...]] = ("objectClass", "cn")

            API_EXPECTED_METHODS: Final[tuple[str, ...]] = (
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
            )

            BASE_FAIL_ERROR_MESSAGE: Final[str] = "nope"
            BASE_EXPORT_ALIAS: Final[str] = "s"

            CONFIG_EXAMPLE_HOST: Final[str] = "example.com"
            CONFIG_ORIGINAL_HOST: Final[str] = "original.com"
            CONFIG_FIRST_HOST: Final[str] = "first.com"
            CONFIG_SECOND_HOST: Final[str] = "second.com"
            CONFIG_IP_HOST: Final[str] = "192.168.1.1"
            CONFIG_LDAPS_PORT: Final[int] = 636
            CONFIG_PORT_MIN: Final[int] = 1
            CONFIG_PORT_MAX: Final[int] = 65535
            CONFIG_ENV_PREFIX: Final[str] = "FLEXT_LDAP_"
            CONFIG_SSL_TLS_COMBOS: Final[tuple[tuple[bool, bool], ...]] = (
                (False, False),
                (True, False),
                (False, True),
                (True, True),
            )

            FIELD_HOST: Final[str] = "host"
            FIELD_PORT: Final[str] = "port"
            FIELD_BIND_DN: Final[str] = "bind_dn"
            FIELD_BIND_PASSWORD: Final[str] = "bind_password"
            FIELD_BASE_DN: Final[str] = "base_dn"
            FIELD_SCOPE: Final[str] = "scope"
            FIELD_PROPERTIES: Final[str] = "properties"
            FIELD_TYPE: Final[str] = "type"
            FIELD_SUCCESS_RATE: Final[str] = "success_rate"

            API_MODEL_CONFIG_FROZEN: Final[bool] = False
            API_MODEL_CONFIG_EXTRA: Final[str] = "forbid"
            API_MODEL_CONFIG_ARBITRARY_TYPES_ALLOWED: Final[bool] = True

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
            DOCKER_OU_NAMES: Final[tuple[str, ...]] = ("people", "groups", "services")
            DOCKER_OU_SEARCH_ATTRS: Final[tuple[str, ...]] = ("ou",)

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

            MODEL_CONFIG_SERVICE_BASE_CONFIG: Final[
                Sequence[tuple[str, str | bool]]
            ] = (
                ("arbitrary_types_allowed", True),
                ("extra", "forbid"),
                ("use_enum_values", True),
                ("validate_assignment", True),
            )

            SEARCH_RESULT_SCENARIO_COUNTS: Final[Mapping[str, tuple[int, int]]] = (
                MappingProxyType(
                    {
                        "empty": (0, 0),
                        "single": (1, 1),
                        "multiple": (5, 5),
                    },
                )
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

            CALLABLE_HANDLER_FOUND_KEY: Final[str] = "handler1"

            CONSTANT_STATUS_SCENARIOS: Final[Sequence[tuple[str, str]]] = (
                ("PENDING", "pending"),
                ("RUNNING", "running"),
                ("COMPLETED", "completed"),
                ("FAILED", "failed"),
            )
            CONSTANT_SCOPE_SCENARIOS: Final[Sequence[tuple[str, str]]] = (
                ("BASE", "BASE"),
                ("ONELEVEL", "ONELEVEL"),
                ("SUBTREE", "SUBTREE"),
            )
            CONSTANT_OPERATION_TYPE_SCENARIOS: Final[Sequence[tuple[str, str]]] = (
                ("ADD", "add"),
                ("MODIFY", "modify"),
                ("DELETE", "delete"),
                ("SEARCH", "search"),
            )
            CONSTANT_INVALID_STATUS: Final[str] = "invalid"
            CONSTANT_EXPECTED_CORE_NAME: Final[str] = "FLEXT_LDAP"
            CONSTANT_EXPECTED_ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"
            CONSTANT_EXPECTED_VENDOR_STRING_MAX_TOKENS: Final[int] = 2

            ENTRY_ADAPTER_BASE64_MARKER_VALUE: Final[str] = "::dGVzdA=="
            ENTRY_ADAPTER_NON_ASCII_VALUE: Final[str] = "testÿ"
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

            LDAP3_ADAPTER_INNER_CLASS_CONNECTION_MANAGER: Final[str] = (
                "ConnectionManager"
            )
            LDAP3_ADAPTER_INNER_CLASS_RESULT_CONVERTER: Final[str] = "ResultConverter"
            LDAP3_ADAPTER_CREATE_SERVER_METHOD: Final[str] = "create_server"
            LDAP3_ADAPTER_DEFAULT_TIMEOUT: Final[int] = 5
            LDAP3_ADAPTER_NOT_CONNECTED_ERROR: Final[str] = "Not connected"

            MODELS_LDAP_EXAMPLE_HOST: Final[str] = "ldap.example.com"
            MODELS_CUSTOM_TIMEOUT: Final[int] = 60
            MODELS_INVALID_PORT_BELOW_MIN: Final[int] = 0
            MODELS_INVALID_PORT_ABOVE_MAX: Final[int] = 65536
            MODELS_INVALID_DN_FORMAT: Final[str] = "invalid-dn-format"

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
            SEARCH_EXPECTED_CATEGORY_PERSON: Final[str] = "person"
            SEARCH_ENTRIES_AFFECTED_ONE: Final[int] = 1
            SEARCH_SYNC_COUNTERS_SYNCED: Final[int] = 80
            SEARCH_SYNC_COUNTERS_SKIPPED: Final[int] = 10
            SEARCH_SYNC_COUNTERS_FAILED: Final[int] = 10
            SEARCH_EXPECTED_SUCCESS_RATE_90: Final[float] = 0.9

            SYNC_PHASE_NAME: Final[str] = "01-users"
            SYNC_ENTRY_ALREADY_EXISTS: Final[str] = "Entry already exists"
            SYNC_DEFAULT_AUTO_CREATE_PARENTS: Final[bool] = True
            SYNC_DEFAULT_ALLOW_DELETES: Final[bool] = False
            SYNC_DEFAULT_ZERO_COUNT: Final[int] = 0
            SYNC_DEFAULT_STOP_ON_ERROR: Final[bool] = False
            SYNC_DEFAULT_DN_CHANGED: Final[bool] = False
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

            SYNC_SUCCESS_RATE_90_KWARGS: Final[t.IntMapping] = MappingProxyType(
                {
                    "synced": 70,
                    "skipped": 20,
                    "failed": 10,
                    "total": 100,
                },
            )
            SYNC_SUCCESS_RATE_90_EXPECTED: Final[float] = 0.9

            SYNC_SUCCESS_RATE_BATCH_85_KWARGS: Final[t.IntMapping] = MappingProxyType(
                {
                    "total_processed": 100,
                    "successful": 85,
                    "failed": 15,
                },
            )
            SYNC_SUCCESS_RATE_BATCH_85_EXPECTED: Final[float] = 0.85

            SYNC_SUCCESS_RATE_BATCH_ZERO_KWARGS: Final[t.IntMapping] = MappingProxyType(
                {
                    "total_processed": 0,
                    "successful": 0,
                    "failed": 0,
                },
            )
            SYNC_SUCCESS_RATE_BATCH_ZERO_EXPECTED: Final[float] = 0.0

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
            SYNC_FACADE_PHASE_NAME_USERS: Final[str] = "users"
            SYNC_FACADE_ZERO_COUNT: Final[int] = 0


c = TestsFlextLdapConstants

__all__: list[str] = ["TestsFlextLdapConstants", "c"]
