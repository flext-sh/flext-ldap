"""Private LDAP enumerations owned by the ``_constants`` tier.

Closed-set LDAP vocabularies re-exported through ``c.Ldap.*`` by MRO
(ENFORCE-079).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import IntEnum, StrEnum, unique


class FlextLdapConstantsEnums:
    """Private owner of LDAP closed-set enumerations."""

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


__all__: list[str] = ["FlextLdapConstantsEnums"]
