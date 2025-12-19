"""FlextLdap constants module.

This module provides constants for LDAP operations, extending FlextLdifConstants.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from flext_ldif.constants import FlextLdifConstants


class FlextLdapConstants(FlextLdifConstants):
    """FlextLdap domain constants extending FlextLdifConstants.

    Hierarchy:
    FlextConstants (flext-core)
    -> FlextLdifConstants (flext-ldif)
    -> FlextLdapConstants (this module)

    Access patterns:
    - c.Ldap.* (LDAP-specific constants)
    - c.Ldif.* (inherited from FlextLdifConstants)
    - c.Platform.* (inherited from FlextConstants via FlextLdifConstants)
    """

    class Ldif:
        """LDIF-related constants."""

        # Expose Categories from parent FlextLdifConstants.Ldif
        Categories = FlextLdifConstants.Ldif.Categories

        class ServerTypes(StrEnum):
            """Server type constants."""

            RFC = "rfc"
            OUD = "oud"
            OID = "oid"
            OPENLDAP = "openldap"
            OPENLDAP1 = "openldap1"
            APACHE = "apache"
            DS389 = "ds389"
            NOVELL = "novell"
            IBM_TIVOLI = "ibm_tivoli"
            AD = "ad"
            RELAXED = "relaxed"

        class SpaceHandlingOption:
            """Space handling options."""

            PRESERVE = "preserve"
            NORMALIZE = "normalize"
            STRIP = "strip"

        class EscapeHandlingOption:
            """Escape handling options."""

            PRESERVE = "preserve"
            ESCAPE = "escape"
            UNESCAPE = "unescape"

        class SortOption:
            """Sort options."""

            DN = "dn"
            ATTR = "attr"
            NONE = "none"

        class LiteralTypes:
            """Literal type definitions for LDIF."""

            ServerTypeLiteral = Literal[
                "rfc",
                "oud",
                "oid",
                "openldap",
                "openldap1",
                "apache",
                "ds389",
                "novell",
                "ibm_tivoli",
                "ad",
                "relaxed",
            ]

    class Ldap:
        """LDAP-related constants."""

        class Core:
            """Core FLEXT-LDAP constants."""

            NAME = "FLEXT_LDAP"
            VERSION = "0.10.0"

        class ServerTypeMappings:
            """Server type mappings and limits."""

            VENDOR_STRING_MAX_TOKENS = 100

        class ConnectionDefaults:
            """Connection default values."""

            PORT = 389
            TIMEOUT = 30
            AUTO_BIND = True
            AUTO_RANGE = True
            POOL_SIZE = 10
            POOL_LIFETIME = 3600

        class LdapCqrs:
            """LDAP CQRS constants."""

            class Status(StrEnum):
                """LDAP operation status values."""

                PENDING = "pending"
                RUNNING = "running"
                COMPLETED = "completed"
                FAILED = "failed"

            StatusLiteral = Literal["pending", "running", "completed", "failed"]

        class LdapOperationNames:
            """LDAP operation name constants."""

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
            PARTIAL_SUCCESS_CODES = [0, 10]

        class ErrorStrings:
            """Error message string constants."""

            NOT_CONNECTED = "Not connected to LDAP server"
            CONNECTION_FAILED = "Connection failed"
            AUTHENTICATION_FAILED = "Authentication failed"
            SEARCH_FAILED = "Search failed"
            OPERATION_FAILED = "Operation failed"
            ENTRY_ALREADY_EXISTS = "entry already exists"
            ENTRY_ALREADY_EXISTS_ALT = "already exists"
            ENTRY_ALREADY_EXISTS_LDAP = "no such object"
            UNKNOWN_ERROR = "unknown error"

        class LdapAttributeNames:
            """Common LDAP attribute name constants."""

            ALL_ATTRIBUTES = "*"
            COMMON_NAME = "cn"
            SURNAME = "sn"
            MAIL = "mail"
            OBJECT_CLASS = "objectClass"

        class Filters:
            """LDAP filter constants."""

            ALL_ENTRIES_FILTER = "(objectClass=*)"

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

        class ChangeTypeOperations:
            """Change type operations."""

            ADD = "add"
            MODIFY = "modify"
            DELETE = "delete"

        class SearchScope(StrEnum):
            """LDAP search scopes."""

            BASE = "BASE"
            ONELEVEL = "ONELEVEL"
            SUBTREE = "SUBTREE"

        class LiteralTypes:
            """Literal type definitions."""

            class ServerTypeLiteral:
                """Server type literals."""


c = FlextLdapConstants()
