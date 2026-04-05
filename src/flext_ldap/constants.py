"""FlextLdap constants module.

This module provides constants for LDAP operations, extending FlextLdifConstants.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum, unique
from typing import ClassVar, Final

from flext_ldif import FlextLdifConstants


class FlextLdapConstants(FlextLdifConstants):
    """FlextLdap domain constants extending FlextLdifConstants.

    Hierarchy:
    FlextConstants (flext-core)
    -> FlextLdifConstants (flext-ldif)
    -> FlextLdapConstants (this module)

    Access patterns:
    - c.Ldap.* (LDAP-specific constants)
    - c.Ldif.* (inherited from FlextLdifConstants - do NOT override)
    - c.* (inherited from FlextConstants via FlextLdifConstants)

    NOTE: Ldif namespace is inherited from parent - do NOT override.
    """

    class Ldap:
        """LDAP-related constants."""

        class Core:
            """Core FLEXT-LDAP constants."""

            NAME = "FLEXT_LDAP"
            VERSION = "0.10.0"

        class ServerTypeMappings:
            """Server type mappings and limits."""

            VENDOR_STRING_MAX_TOKENS = 2

        class ConnectionDefaults:
            """Connection default values."""

            DEFAULT_MAX_RETRIES = 5
            DEFAULT_RETRY_DELAY = 1.0
            PORT = 389
            TIMEOUT = 30
            AUTO_BIND: Final[bool] = True
            AUTO_RANGE: Final[bool] = True
            POOL_SIZE = 10
            POOL_LIFETIME = 3600

        class SearchDefaults:
            """Search operation default values."""

            DEFAULT_SCOPE = "SUBTREE"

        class ServerDefaults:
            """Server configuration default values."""

            DEFAULT_TYPE = "rfc"

        class LdapCqrs:
            """LDAP CQRS constants."""

            @unique
            class Status(StrEnum):
                """LDAP operation status values."""

                PENDING = "pending"
                RUNNING = "running"
                COMPLETED = "completed"
                FAILED = "failed"

        class LdapOperationNames:
            """LDAP operation name constants."""

            CONNECT = "connect"
            DETECT_FROM_CONNECTION = "detect_from_connection"
            LDAP3_TO_LDIF_ENTRY = "ldap3_to_ldif_entry"
            LDIF_ENTRY_TO_LDAP3 = "ldif_entry_to_ldap3"
            LDIF_ENTRY_TO_LDAP3_ATTRIBUTES = "ldif_entry_to_ldap3_attributes"
            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"
            SEARCH = "search"
            BIND = "bind"
            UNBIND = "unbind"
            SYNC = "sync"
            BATCH_UPSERT = "batch_upsert"

        class LdapResultCodes:
            """LDAP result code constants."""

            SUCCESS = 0
            OPERATIONS_ERROR = 1
            PROTOCOL_ERROR = 2
            NO_SUCH_OBJECT = 32
            REFERRAL = 10
            PARTIAL_SUCCESS_CODES: ClassVar[Sequence[int]] = (0, 10)

        class ErrorStrings:
            """Error message string constants."""

            NOT_CONNECTED = "Not connected to LDAP server"
            CONNECTION_FAILED = "Connection failed"
            AUTHENTICATION_FAILED = "Authentication failed"
            SEARCH_FAILED = "Search failed"
            OPERATION_FAILED = "Operation failed"
            ENTRY_ALREADY_EXISTS = "entry already exists"
            ENTRY_ALREADY_EXISTS_ALT = "already exists"
            ENTRY_ALREADY_EXISTS_LDAP = "entryalreadyexists"
            ENTRY_ALREADY_EXISTS_SNAKE = "ldap_already_exists"
            UNKNOWN_ERROR = "unknown error"

        class LdapAttributeNames:
            """LDAP protocol control attributes — only protocol-level constants.

            Domain-specific attributes (department, manager, telephoneNumber, etc.)
            are potentially hundreds and vary per LDAP schema/deployment. They belong
            in consumer Pydantic settings models, NOT as hardcoded constants.

            Only attributes required by the LDAP protocol operations themselves
            (objectClass for filtering, dn for entry identity, changetype for
            LDIF operations, * for search-all) live here.
            """

            ALL_ATTRIBUTES: Final[str] = "*"
            OBJECT_CLASS: Final[str] = "objectClass"
            DN: Final[str] = "dn"
            CHANGETYPE: Final[str] = "changetype"
            COMMON_NAME: Final[str] = "cn"

        class Filters:
            """LDAP protocol filter constants.

            Only the universal protocol-level filter lives here.
            Domain-specific filters (user, group, membership) are
            deployment-specific and belong in consumer Pydantic settings.
            """

            ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"

        @unique
        class OperationType(StrEnum):
            """LDAP operation types."""

            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"
            SEARCH = "search"

        class UpsertOperations:
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

        class SearchScopeValue:
            """ldap3-compatible search scope integer values."""

            BASE = 0
            LEVEL = 1
            SUBTREE = 2

        class ModifyOperation:
            """ldap3-compatible modify operation integer values."""

            ADD = 0
            DELETE = 1
            REPLACE = 2

        class Defaults:
            """Domain default values."""

            UNKNOWN_CATEGORY: Final[str] = "unknown"
            EXAMPLE_BASE_DN: Final[str] = "dc=example,dc=com"

        class RootDseAttributes:
            """rootDSE query attribute names for server type detection."""

            VENDOR_NAME: Final[str] = "vendorName"
            VENDOR_VERSION: Final[str] = "vendorVersion"
            NAMING_CONTEXTS: Final[str] = "namingContexts"
            SUPPORTED_CONTROLS: Final[str] = "supportedControl"
            SUPPORTED_EXTENSIONS: Final[str] = "supportedExtension"

        class Callback:
            """Callback protocol constants."""

            MULTI_PHASE_PARAM_COUNT: Final[int] = 5
            SINGLE_PHASE_PARAM_COUNT: Final[int] = 4

        class Logging:
            """Logging-related constants."""

            DN_TRUNCATION_LENGTH: Final[int] = 100

        class SyncDefaults:
            """Sync operation default values."""

            BATCH_SIZE: Final[int] = 100
            DEFAULT_RETRY_ERROR_PATTERNS: ClassVar[tuple[str, ...]] = (
                "session terminated",
                "not connected",
                "invalid messageid",
                "socket",
            )


c = FlextLdapConstants
