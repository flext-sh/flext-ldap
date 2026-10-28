"""Private constants base for flext-ldap.

Owns every LDAP constant value so the public ``constants.py`` facade module
declares no constant directly (ENFORCE-079); the facade re-exports them via
``c.Ldap.*`` through inheritance.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from enum import IntEnum, StrEnum, unique
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final

from flext_ldif import FlextLdifConstants
from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

if TYPE_CHECKING:
    from flext_ldap import t


class FlextLdapConstantsBase:
    """Private constants owner for LDAP defaults, sets, and lookup tables."""

    @unique
    class Status(StrEnum):
        """LDAP operation status values."""

        PENDING = "pending"
        RUNNING = "running"
        COMPLETED = "completed"
        FAILED = "failed"

    @unique
    class OperationName(StrEnum):
        """LDAP operation name constants."""

        CONNECT = "connect"
        DETECT_FROM_CONNECTION = "detect_from_connection"
        LDAP3_TO_LDIF_ENTRY = "ldap3_to_ldif_entry"
        LDIF_ENTRY_TO_LDAP3_ATTRIBUTES = "ldif_entry_to_ldap3_attributes"
        BIND = "bind"
        UNBIND = "unbind"
        SYNC = "sync"
        BATCH_UPSERT = "batch_upsert"
        PLAN_UPSERT = "plan_upsert"
        SUBTREE_DELETE = "subtree_delete"

    @unique
    class ResultCode(IntEnum):
        """LDAP result codes."""

        SUCCESS = 0
        OPERATIONS_ERROR = 1
        PROTOCOL_ERROR = 2
        REFERRAL = 10
        NO_SUCH_OBJECT = 32

    @unique
    class ErrorMessage(StrEnum):
        """Closed-set LDAP error message constants."""

        NOT_CONNECTED = "Not connected to LDAP server"
        CONNECTION_FAILED = "Connection failed"
        UNKNOWN_ERROR = "unknown error"
        MODIFY_ENTRY_WITHOUT_ADDITIONS = "Schema modify entry missing add operations"

    @unique
    class AttributeName(StrEnum):
        """LDAP protocol-level attribute names."""

        ALL_ATTRIBUTES = "*"
        NO_ATTRIBUTES = "1.1"
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

    @unique
    class SearchScopeValue(IntEnum):
        """ldap3-compatible search scope integer values."""

        BASE = 0
        LEVEL = 1
        SUBTREE = 2

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

    @unique
    class RootDseAttribute(StrEnum):
        """rootDSE query attribute names for server type detection."""

        VENDOR_NAME = "vendorName"
        VENDOR_VERSION = "vendorVersion"
        NAMING_CONTEXTS = "namingContexts"
        SUPPORTED_EXTENSIONS = "supportedExtension"

    NAME: ClassVar[str] = "FLEXT_LDAP"
    VENDOR_STRING_MAX_TOKENS: Final[int] = 2
    DEFAULT_MAX_RETRIES: Final[int] = 5
    DEFAULT_RETRY_DELAY: Final[float] = 1.0
    PORT: Final[int] = 389
    TIMEOUT: Final[int] = FlextLdifConstants.DEFAULT_TIMEOUT_SECONDS
    AUTO_BIND: Final[bool] = True
    AUTO_RANGE: Final[bool] = True
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

    VALID_STATUSES: Final[frozenset[Status]] = frozenset({
        Status.PENDING,
        Status.RUNNING,
        Status.COMPLETED,
        Status.FAILED,
    })

    PARTIAL_SUCCESS_CODES: Final[frozenset[ResultCode]] = frozenset({
        ResultCode.SUCCESS,
        ResultCode.REFERRAL,
    })

    ENTRY_ALREADY_EXISTS_RE: Final[t.RegexPattern] = re.compile(
        r"entry already exists|already exists|entryalreadyexists|ldap_already_exists",
        re.IGNORECASE,
    )

    NO_SUCH_OBJECT_RE: Final[t.RegexPattern] = re.compile(
        r"nosuchobject|no such object",
        re.IGNORECASE,
    )

    OPERATION_SUCCESS_MESSAGES: ClassVar[Mapping[OperationType, str]] = (
        MappingProxyType({
            OperationType.ADD: "Entry added successfully",
            OperationType.MODIFY: "Entry modified successfully",
            OperationType.DELETE: "Entry deleted successfully",
            OperationType.SEARCH: "Search completed successfully",
        })
    )
    "Per-operation success messages used by the ldap3 operation executor."

    OPERATION_FAILURE_PREFIXES: ClassVar[Mapping[OperationType, str]] = (
        MappingProxyType({
            OperationType.ADD: "Add failed",
            OperationType.MODIFY: "Modify failed",
            OperationType.DELETE: "Delete failed",
            OperationType.SEARCH: "Search failed",
        })
    )
    "Per-operation error message prefixes used by the ldap3 operation executor."

    EXC_CONNECTION: Final[tuple[type[Exception], ...]] = (
        *FlextLdifConstants.EXC_BROAD_IO_TYPE,
        _Ldap3LDAPException,
    )
    "Boundary catch for ldap3 connect/bind: c.EXC_BROAD_IO_TYPE plus LDAPException."

    DEFAULT_SCOPE: Final[SearchScope] = SearchScope.SUBTREE

    LDAP3_SCOPE_BY_SEARCH_SCOPE: Final[
        Mapping[
            SearchScope,
            SearchScopeValue,
        ]
    ] = MappingProxyType({
        SearchScope.BASE: (SearchScopeValue.BASE),
        SearchScope.ONELEVEL: (SearchScopeValue.LEVEL),
        SearchScope.SUBTREE: (SearchScopeValue.SUBTREE),
    })

    DEFAULT_TYPE: Final[FlextLdifConstants.Ldif.ServerTypes] = (
        FlextLdifConstants.Ldif.ServerTypes.RFC
    )

    ROOT_DSE_DETECTION_ORDER: Final[Sequence[str]] = (
        FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value,
        FlextLdifConstants.Ldif.ServerTypes.OID.value,
        FlextLdifConstants.Ldif.ServerTypes.OUD.value,
        FlextLdifConstants.Ldif.ServerTypes.AD.value,
        FlextLdifConstants.Ldif.ServerTypes.DS389.value,
    )

    ROOT_DSE_EXTENSION_MARKERS: Final[Mapping[str, frozenset[str]]] = MappingProxyType({
        FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value: frozenset({"openldap"}),
        FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({"oracle", "oid"}),
        FlextLdifConstants.Ldif.ServerTypes.OUD.value: frozenset({"oud"}),
        FlextLdifConstants.Ldif.ServerTypes.AD.value: frozenset({
            "microsoft",
            "windows",
        }),
        FlextLdifConstants.Ldif.ServerTypes.DS389.value: frozenset({
            "389",
            "dirsrv",
        }),
    })

    ROOT_DSE_CONTEXT_MARKERS: Final[Mapping[str, frozenset[str]]] = MappingProxyType({
        FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({"oracle"}),
        FlextLdifConstants.Ldif.ServerTypes.AD.value: frozenset({
            "microsoft",
            "windows",
        }),
    })

    ROOT_DSE_VENDOR_REQUIRED_MARKERS: Final[Mapping[str, frozenset[str]]] = (
        MappingProxyType({
            FlextLdifConstants.Ldif.ServerTypes.OUD.value: frozenset({
                "oracle",
                "unified directory",
            }),
            FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({"oracle"}),
            FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value: frozenset(),
            FlextLdifConstants.Ldif.ServerTypes.AD.value: frozenset(),
            FlextLdifConstants.Ldif.ServerTypes.DS389.value: frozenset(),
        })
    )

    ROOT_DSE_VENDOR_ANY_MARKERS: Final[Mapping[str, frozenset[str]]] = (
        MappingProxyType({
            FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({
                "internet directory",
                "oid",
                "corporation",
            }),
            FlextLdifConstants.Ldif.ServerTypes.OPENLDAP.value: frozenset({"openldap"}),
            FlextLdifConstants.Ldif.ServerTypes.AD.value: frozenset({
                "microsoft",
                "active directory",
            }),
            FlextLdifConstants.Ldif.ServerTypes.DS389.value: frozenset({
                "389",
                "dirsrv",
            }),
        })
    )

    ROOT_DSE_VENDOR_EXCLUDED_MARKERS: Final[Mapping[str, frozenset[str]]] = (
        MappingProxyType({
            FlextLdifConstants.Ldif.ServerTypes.OID.value: frozenset({
                "unified directory",
            }),
        })
    )

    ROOT_DSE_VENDOR_MAX_TOKENS: Final[Mapping[str, int]] = MappingProxyType({
        FlextLdifConstants.Ldif.ServerTypes.OID.value: VENDOR_STRING_MAX_TOKENS,
    })


__all__: list[str] = ["FlextLdapConstantsBase"]
