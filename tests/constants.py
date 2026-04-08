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

from flext_ldap import c, t


class FlextLdapTestConstants(FlextTestsConstants, c):
    """Constants for flext-ldap tests - extends FlextTestsConstants and c.

    Architecture: Extends both FlextTestsConstants and c with flext-ldap-specific constants.
    All generic constants from FlextTestsConstants and production constants from c are available through inheritance.

    Rules:
    - NEVER duplicate constants from FlextTestsConstants or c
    - Only flext-ldap-specific constants allowed (not generic for other projects)
    - All generic constants come from FlextTestsConstants
    - All production constants come from c
    """

    class Ldap(c.Ldap):
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
                ENV_PREFIX: Final[str] = "FLEXT_LDAP_"
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
                USE_SSL: Final[str] = "use_ssl"
                SUCCESS_RATE: Final[str] = "success_rate"

            class ApiModelConfig:
                """Expected model_config values for the ldap API facade."""

                FROZEN: Final[bool] = False
                EXTRA: Final[str] = "forbid"
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
                STARTUP_TIMEOUT: Final[int] = 90
                BIND_READY_TIMEOUT: Final[int] = 60
                DEFAULT_WORKER_ID: Final[str] = "master"
                OU_NAMES: ClassVar[Sequence[str]] = ["people", "groups", "services"]
                OU_SEARCH_ATTRS: ClassVar[Sequence[str]] = ["ou"]

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
                        t.Triple[
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
                        t.Triple[
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
                    Sequence[
                        t.Quad[
                            str | None,
                            str | None,
                            Sequence[str],
                            str,
                        ]
                    ]
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
                SECOND_KEY: Final[str] = "handler2"
                THIRD_KEY: Final[str] = "handler3"
                FOUND_RETURN_VALUE: Final[str] = "value1"

            class SampleData:
                """Static sample entries for tests."""

                USER_ENTRY: ClassVar[
                    Mapping[str, str | Mapping[str, t.StrSequence]]
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
                    Mapping[str, str | Mapping[str, t.StrSequence]]
                ] = {
                    "dn": "cn=testgroup,ou=groups,dc=flext,dc=local",
                    "attributes": {
                        "cn": ["testgroup"],
                        "objectClass": ["groupOfNames", "top"],
                        "member": ["cn=testuser,ou=people,dc=flext,dc=local"],
                    },
                }

            # ── Contract verification (test_constants.py) ────────────────

            class ConstantVerification:
                """Expected enum/constant values for contract tests."""

                STATUS_SCENARIOS: ClassVar[Sequence[tuple[str, str]]] = [
                    ("PENDING", "pending"),
                    ("RUNNING", "running"),
                    ("COMPLETED", "completed"),
                    ("FAILED", "failed"),
                ]
                SCOPE_SCENARIOS: ClassVar[Sequence[tuple[str, str]]] = [
                    ("BASE", "BASE"),
                    ("ONELEVEL", "ONELEVEL"),
                    ("SUBTREE", "SUBTREE"),
                ]
                OPERATION_TYPE_SCENARIOS: ClassVar[Sequence[tuple[str, str]]] = [
                    ("ADD", "add"),
                    ("MODIFY", "modify"),
                    ("DELETE", "delete"),
                    ("SEARCH", "search"),
                ]
                INVALID_STATUS: Final[str] = "invalid"
                EXPECTED_CORE_NAME: Final[str] = "FLEXT_LDAP"
                EXPECTED_ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"
                EXPECTED_VENDOR_STRING_MAX_TOKENS: Final[int] = 2

            # ── Entry adapter (test_entry_adapter.py) ────────────────────

            class EntryAdapter:
                """Entry adapter test data."""

                BASE64_MARKER_VALUE: Final[str] = "::dGVzdA=="
                NON_ASCII_VALUE: Final[str] = "testÿ"
                SAMPLE_ATTRIBUTES: ClassVar[Mapping[str, Sequence[str]]] = {
                    "cn": ["user"],
                    "sn": ["Doe"],
                }
                NO_ATTRIBUTES_ERROR: Final[str] = "no attributes"

            # ── Ldap3 adapter (test_ldap3_adapter.py) ────────────────────

            class Ldap3Adapter:
                """Ldap3 adapter test data."""

                INNER_CLASS_CONNECTION_MANAGER: Final[str] = "ConnectionManager"
                INNER_CLASS_RESULT_CONVERTER: Final[str] = "ResultConverter"
                CREATE_SERVER_METHOD: Final[str] = "create_server"
                DEFAULT_TIMEOUT: Final[int] = 5
                NOT_CONNECTED_ERROR: Final[str] = "Not connected"

            # ── Model tests (test_models.py) ─────────────────────────────

            class Models:
                """Model test data."""

                LDAP_EXAMPLE_HOST: Final[str] = "ldap.example.com"
                CUSTOM_TIMEOUT: Final[int] = 60
                MUTUALLY_EXCLUSIVE_ERROR: Final[str] = "mutually exclusive"
                INVALID_PORT_BELOW_MIN: Final[int] = 0
                INVALID_PORT_ABOVE_MAX: Final[int] = 65536
                INVALID_DN_FORMAT: Final[str] = "invalid-dn-format"

            # ── Search model tests (test_models_search.py) ───────────────

            class Search:
                """Search model test data."""

                SCOPE_BASE: Final[str] = "BASE"
                SCOPE_SUBTREE_LOWER: Final[str] = "subtree"
                FILTER_CN: Final[str] = "(cn=*)"
                FILTER_UID: Final[str] = "(uid=*)"
                SEARCH_ATTRIBUTES: ClassVar[Sequence[str]] = ["cn", "mail"]
                SIZE_LIMIT_CUSTOM: Final[int] = 100
                TIME_LIMIT_CUSTOM: Final[int] = 30
                NORMALIZED_SIZE_LIMIT: Final[int] = 50
                ENTRY_ADDED_MESSAGE: Final[str] = "Entry added successfully"
                DEFAULT_LIMIT_ZERO: Final[int] = 0
                OBJECTCLASS_PERSON_TOP: ClassVar[Mapping[str, Sequence[str]]] = {
                    "objectClass": ["person", "top"],
                }
                EXPECTED_CATEGORY_PERSON: Final[str] = "person"
                EXTRA_RESULT_COUNT: Final[int] = 10
                ENTRIES_AFFECTED_ONE: Final[int] = 1
                SYNC_COUNTERS_SYNCED: Final[int] = 80
                SYNC_COUNTERS_SKIPPED: Final[int] = 10
                SYNC_COUNTERS_FAILED: Final[int] = 10
                EXPECTED_SUCCESS_RATE_90: Final[float] = 0.9

            # ── Sync model tests (test_models_sync.py) ───────────────────

            class Sync:
                """Sync model test data."""

                PHASE_NAME: Final[str] = "01-users"
                ENTRY_ALREADY_EXISTS: Final[str] = "Entry already exists"
                ZERO_BATCH_SIZE: Final[int] = 0

                class Defaults:
                    """Expected default values for sync models."""

                    AUTO_CREATE_PARENTS: Final[bool] = True
                    ALLOW_DELETES: Final[bool] = False
                    ZERO_COUNT: Final[int] = 0
                    STOP_ON_ERROR: Final[bool] = False
                    DN_CHANGED: Final[bool] = False
                    EMPTY_SOURCE_DN: Final[str] = ""

                class FromCounters:
                    """from_counters factory test data."""

                    SYNCED: Final[int] = 50
                    SKIPPED: Final[int] = 30
                    FAILED: Final[int] = 20
                    TOTAL: Final[int] = 100
                    DURATION: Final[float] = 10.5
                    SUCCESS_RATE: Final[float] = 0.8

                class Serialization:
                    """Serialization round-trip data."""

                    SYNCED: Final[int] = 9
                    SKIPPED: Final[int] = 1
                    FAILED: Final[int] = 0

                class SuccessRate90:
                    """SyncStats 90% success rate scenario."""

                    KWARGS: ClassVar[Mapping[str, int]] = {
                        "synced": 70,
                        "skipped": 20,
                        "failed": 10,
                        "total": 100,
                    }
                    EXPECTED: Final[float] = 0.9

                class SuccessRateBatch85:
                    """BatchUpsertResult 85% scenario."""

                    KWARGS: ClassVar[Mapping[str, int]] = {
                        "total_processed": 100,
                        "successful": 85,
                        "failed": 15,
                    }
                    EXPECTED: Final[float] = 0.85

                class SuccessRateBatchZero:
                    """BatchUpsertResult 0% scenario."""

                    KWARGS: ClassVar[Mapping[str, int]] = {
                        "total_processed": 0,
                        "successful": 0,
                        "failed": 0,
                    }
                    EXPECTED: Final[float] = 0.0

                class Upsert:
                    """Batch upsert test data."""

                    BATCH_TOTAL: Final[int] = 100
                    BATCH_SUCCESSFUL: Final[int] = 90
                    BATCH_FAILED: Final[int] = 10

                class Metadata:
                    """ConversionMetadata test data."""

                    SOURCE_ATTRIBUTES: ClassVar[Sequence[str]] = [
                        "cn",
                        "mail",
                        "telephoneNumber",
                    ]
                    REMOVED_ATTRIBUTES: ClassVar[Sequence[str]] = ["userPassword"]

                class Phase:
                    """PhaseSyncResult test data."""

                    TOTAL_ENTRIES: Final[int] = 100
                    SYNCED: Final[int] = 90
                    FAILED: Final[int] = 5
                    SKIPPED: Final[int] = 5
                    DURATION: Final[float] = 30.0
                    SUCCESS_RATE: Final[float] = 95.0

                class MultiPhase:
                    """MultiPhaseSyncResult test data."""

                    TOTAL_ENTRIES: Final[int] = 500
                    TOTAL_SYNCED: Final[int] = 450
                    TOTAL_FAILED: Final[int] = 25
                    TOTAL_SKIPPED: Final[int] = 25
                    OVERALL_SUCCESS_RATE: Final[float] = 95.0
                    TOTAL_DURATION: Final[float] = 120.0

                class PhaseResults:
                    """Phase results dict scenario."""

                    SYNCED: Final[int] = 95
                    FAILED: Final[int] = 5
                    SKIPPED: Final[int] = 0
                    DURATION: Final[float] = 10.0
                    SUCCESS_RATE: Final[float] = 95.0

                class BatchStats:
                    """LdapBatchStats test data."""

                    SYNCED: Final[int] = 80
                    FAILED: Final[int] = 10
                    SKIPPED: Final[int] = 10

            # ── Sync facade (test_sync.py) ───────────────────────────────

            class SyncFacade:
                """Sync facade test data."""

                MISSING_LDIF_PATH: Final[str] = "/tmp/flext-ldap-sync-missing.ldif"
                PHASE_NAME_USERS: Final[str] = "users"
                ZERO_COUNT: Final[int] = 0

            # ── Smoke tests (test_smoke.py) ──────────────────────────────

            class Smoke:
                """Smoke test categorization constants."""

                CONTAINER_HEALTH: Final[str] = "container_health"
                API_IMPORTS: Final[str] = "api_imports"
                BASIC_CONNECTION: Final[str] = "basic_connection"


c = FlextLdapTestConstants

__all__ = ["FlextLdapTestConstants", "c"]
