"""FlextLdap constants module.

This module provides constants for LDAP operations, extending c.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import IntEnum, StrEnum, unique
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final

from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

from flext_ldif import c

if TYPE_CHECKING:
    from flext_ldap import t


class FlextLdapConstants(c):
    """FlextLdap domain constants extending c.

    Hierarchy:
    FlextConstants (flext-core)
    -> c (flext-ldif)
    -> FlextLdapConstants (this module)

    Access patterns:
    - c.Ldap.* (LDAP-specific constants)
    - c.Ldif.* (inherited from c - do NOT override)
    - c.* (inherited from FlextConstants via c)

    NOTE: Ldif namespace is inherited from parent - do NOT override.
    """

    class Ldap:
        """LDAP-related constants."""

        NAME: Final[str] = "FLEXT_LDAP"
        VERSION: Final[str] = "0.10.0"
        VENDOR_STRING_MAX_TOKENS: Final[int] = 2
        DEFAULT_MAX_RETRIES: Final[int] = 5
        DEFAULT_RETRY_DELAY: Final[float] = 1.0
        PORT: Final[int] = 389
        TIMEOUT: Final[int] = c.DEFAULT_TIMEOUT_SECONDS
        AUTO_BIND: Final[bool] = True
        AUTO_RANGE: Final[bool] = True
        POOL_SIZE: Final[int] = 10
        POOL_LIFETIME: Final[int] = 3600
        DEFAULT_BIND_DN: Final[str] = ""
        DEFAULT_BIND_PASSWORD: Final[str] = ""
        DEFAULT_USE_SSL: Final[bool] = False
        DEFAULT_USE_TLS: Final[bool] = False
        ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"
        UNKNOWN_CATEGORY: Final[str] = "unknown"
        EXAMPLE_BASE_DN: Final[str] = "dc=example,dc=com"
        MULTI_PHASE_PARAM_COUNT: Final[int] = 5
        SINGLE_PHASE_PARAM_COUNT: Final[int] = 4
        DN_TRUNCATION_LENGTH: Final[int] = 100
        BATCH_SIZE: Final[int] = 100

        @unique
        class Status(StrEnum):
            """LDAP operation status values."""

            PENDING = "pending"
            RUNNING = "running"
            COMPLETED = "completed"
            FAILED = "failed"

        VALID_STATUSES: Final[frozenset[Status]] = frozenset({
            Status.PENDING,
            Status.RUNNING,
            Status.COMPLETED,
            Status.FAILED,
        })

        @unique
        class OperationName(StrEnum):
            """LDAP operation name constants."""

            CONNECT = "connect"
            DETECT_FROM_CONNECTION = "detect_from_connection"
            LDAP3_TO_LDIF_ENTRY = "ldap3_to_ldif_entry"
            LDIF_ENTRY_TO_LDAP3 = "ldif_entry_to_ldap3"
            LDIF_ENTRY_TO_LDAP3_ATTRIBUTES = "ldif_entry_to_ldap3_attributes"
            BIND = "bind"
            UNBIND = "unbind"
            SYNC = "sync"
            BATCH_UPSERT = "batch_upsert"

        @unique
        class ResultCode(IntEnum):
            """LDAP result codes."""

            SUCCESS = 0
            OPERATIONS_ERROR = 1
            PROTOCOL_ERROR = 2
            REFERRAL = 10
            NO_SUCH_OBJECT = 32

        PARTIAL_SUCCESS_CODES: Final[frozenset[ResultCode]] = frozenset({
            ResultCode.SUCCESS,
            ResultCode.REFERRAL,
        })

        @unique
        class ErrorMessage(StrEnum):
            """Closed-set LDAP error message constants."""

            NOT_CONNECTED = "Not connected to LDAP server"
            CONNECTION_FAILED = "Connection failed"
            AUTHENTICATION_FAILED = "Authentication failed"
            SEARCH_FAILED = "Search failed"
            OPERATION_FAILED = "Operation failed"
            UNKNOWN_ERROR = "unknown error"

        ENTRY_ALREADY_EXISTS_RE: Final[re.Pattern[str]] = re.compile(
            r"entry already exists|already exists|entryalreadyexists|ldap_already_exists",
            re.IGNORECASE,
        )

        @unique
        class AttributeName(StrEnum):
            """LDAP protocol-level attribute names."""

            ALL_ATTRIBUTES = "*"
            OBJECT_CLASS = "objectClass"
            DN = "dn"
            CHANGETYPE = "changetype"
            COMMON_NAME = "cn"

        @unique
        class OperationType(StrEnum):
            """LDAP operation types."""

            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"
            SEARCH = "search"

        OPERATION_SUCCESS_MESSAGES: ClassVar[
            Mapping[FlextLdapConstants.Ldap.OperationType, str]
        ] = MappingProxyType({
            OperationType.ADD: "Entry added successfully",
            OperationType.MODIFY: "Entry modified successfully",
            OperationType.DELETE: "Entry deleted successfully",
            OperationType.SEARCH: "Search completed successfully",
        })
        "Per-operation success messages used by ``OperationExecutor``."

        OPERATION_FAILURE_PREFIXES: ClassVar[
            Mapping[FlextLdapConstants.Ldap.OperationType, str]
        ] = MappingProxyType({
            OperationType.ADD: "Add failed",
            OperationType.MODIFY: "Modify failed",
            OperationType.DELETE: "Delete failed",
            OperationType.SEARCH: "Search failed",
        })
        "Per-operation error message prefixes used by ``OperationExecutor``."

        EXC_CONNECTION: Final[tuple[type[Exception], ...]] = (
            *c.EXC_BROAD_IO_TYPE,
            _Ldap3LDAPException,
        )
        "Boundary catch for ldap3 connect/bind: c.EXC_BROAD_IO_TYPE plus LDAPException."

        @unique
        class UpsertOperation(StrEnum):
            """Upsert operation types."""

            ADD = "add"
            MODIFY = "modify"
            SKIPPED = "skipped"
            ADDED = "added"
            MODIFIED = "modified"

        @unique
        class SearchScope(StrEnum):
            """LDAP search scopes."""

            BASE = "BASE"
            ONELEVEL = "ONELEVEL"
            SUBTREE = "SUBTREE"

        DEFAULT_SCOPE: Final[SearchScope] = SearchScope.SUBTREE

        @unique
        class SearchScopeValue(IntEnum):
            """ldap3-compatible search scope integer values."""

            BASE = 0
            LEVEL = 1
            SUBTREE = 2

        LDAP3_SCOPE_BY_SEARCH_SCOPE: Final[
            t.MappingKV[SearchScope, SearchScopeValue]
        ] = MappingProxyType({
            SearchScope.BASE: SearchScopeValue.BASE,
            SearchScope.ONELEVEL: SearchScopeValue.LEVEL,
            SearchScope.SUBTREE: SearchScopeValue.SUBTREE,
        })

        @unique
        class ModifyOperation(IntEnum):
            """ldap3-compatible modify operation integer values."""

            ADD = 0
            DELETE = 1
            REPLACE = 2

        @unique
        class Ldap3SearchScope(StrEnum):
            """ldap3-compatible search scope string values."""

            BASE = "BASE"
            LEVEL = "LEVEL"
            SUBTREE = "SUBTREE"

        @unique
        class Ldap3GetInfo(StrEnum):
            """ldap3-compatible get-info option string values."""

            ALL = "ALL"
            DSA = "DSA"
            NO_INFO = "NO_INFO"
            SCHEMA = "SCHEMA"

        DEFAULT_TYPE: Final[c.Ldif.ServerTypes] = c.Ldif.ServerTypes.RFC

        @unique
        class RootDseAttribute(StrEnum):
            """rootDSE query attribute names for server type detection."""

            VENDOR_NAME = "vendorName"
            VENDOR_VERSION = "vendorVersion"
            NAMING_CONTEXTS = "namingContexts"
            SUPPORTED_CONTROLS = "supportedControl"
            SUPPORTED_EXTENSIONS = "supportedExtension"

        ROOT_DSE_DETECTION_ORDER: Final[tuple[str, ...]] = (
            c.Ldif.ServerTypes.OPENLDAP.value,
            c.Ldif.ServerTypes.OID.value,
            c.Ldif.ServerTypes.OUD.value,
            c.Ldif.ServerTypes.AD.value,
            c.Ldif.ServerTypes.DS389.value,
        )

        ROOT_DSE_EXTENSION_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
            MappingProxyType({
                c.Ldif.ServerTypes.OPENLDAP.value: frozenset({"openldap"}),
                c.Ldif.ServerTypes.OID.value: frozenset({"oracle", "oid"}),
                c.Ldif.ServerTypes.OUD.value: frozenset({"oud"}),
                c.Ldif.ServerTypes.AD.value: frozenset({"microsoft", "windows"}),
                c.Ldif.ServerTypes.DS389.value: frozenset({"389", "dirsrv"}),
            })
        )

        ROOT_DSE_CONTEXT_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
            MappingProxyType({
                c.Ldif.ServerTypes.OID.value: frozenset({"oracle"}),
                c.Ldif.ServerTypes.AD.value: frozenset({"microsoft", "windows"}),
            })
        )

        ROOT_DSE_VENDOR_REQUIRED_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
            MappingProxyType({
                c.Ldif.ServerTypes.OUD.value: frozenset({
                    "oracle",
                    "unified directory",
                }),
                c.Ldif.ServerTypes.OID.value: frozenset({"oracle"}),
                c.Ldif.ServerTypes.OPENLDAP.value: frozenset(),
                c.Ldif.ServerTypes.AD.value: frozenset(),
                c.Ldif.ServerTypes.DS389.value: frozenset(),
            })
        )

        ROOT_DSE_VENDOR_ANY_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
            MappingProxyType({
                c.Ldif.ServerTypes.OID.value: frozenset({
                    "internet directory",
                    "oid",
                    "corporation",
                }),
                c.Ldif.ServerTypes.OPENLDAP.value: frozenset({"openldap"}),
                c.Ldif.ServerTypes.AD.value: frozenset({
                    "microsoft",
                    "active directory",
                }),
                c.Ldif.ServerTypes.DS389.value: frozenset({"389", "dirsrv"}),
            })
        )

        ROOT_DSE_VENDOR_EXCLUDED_MARKERS: Final[t.MappingKV[str, frozenset[str]]] = (
            MappingProxyType({
                c.Ldif.ServerTypes.OID.value: frozenset({"unified directory"}),
            })
        )

        ROOT_DSE_VENDOR_MAX_TOKENS: Final[t.MappingKV[str, int]] = MappingProxyType({
            c.Ldif.ServerTypes.OID.value: VENDOR_STRING_MAX_TOKENS,
        })

        RETRY_ERROR_PATTERNS: Final[frozenset[str]] = frozenset({
            "session terminated",
            "not connected",
            "invalid messageid",
            "socket",
        })


c = FlextLdapConstants

__all__: list[str] = ["FlextLdapConstants", "c"]
