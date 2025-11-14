"""LDAP constants and enumerations.

This module defines constant values and enumerations used throughout the
LDAP library. Minimal constants - reuses flext-ldif when possible.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from flext_core import FlextConstants


class FlextLdapConstants(FlextConstants):
    """LDAP domain constants extending flext-core FlextConstants.

    Contains ONLY constant values specific to LDAP operations.
    Reuses flext-ldif constants for Entry, DN, and Schema operations.
    """

    # =========================================================================
    # LDAP SEARCH SCOPE ENUMS
    # =========================================================================

    class SearchScope(StrEnum):
        """LDAP search scope types (RFC 4511)."""

        BASE = "BASE"
        ONELEVEL = "ONELEVEL"
        SUBTREE = "SUBTREE"

    # =========================================================================
    # LDAP OPERATION TYPES
    # =========================================================================

    class OperationType(StrEnum):
        """LDAP operation types."""

        SEARCH = "search"
        ADD = "add"
        MODIFY = "modify"
        DELETE = "delete"
        MODIFY_DN = "modify_dn"
        COMPARE = "compare"
        BIND = "bind"
        UNBIND = "unbind"

    # =========================================================================
    # LDAP CONNECTION DEFAULTS
    # =========================================================================

    class ConnectionDefaults:
        """Default values for LDAP connections."""

        PORT: Final[int] = 389
        PORT_SSL: Final[int] = 636
        TIMEOUT: Final[int] = 30
        AUTO_BIND: Final[bool] = True
        AUTO_RANGE: Final[bool] = True
        POOL_SIZE: Final[int] = 10
        POOL_LIFETIME: Final[int] = 3600

    # =========================================================================
    # LITERAL TYPES
    # =========================================================================

    class LiteralTypes:
        """Type-safe literal types for LDAP operations."""

        SearchScope = Literal["BASE", "ONELEVEL", "SUBTREE"]
        OperationType = Literal[
            "search",
            "add",
            "modify",
            "delete",
            "modify_dn",
            "compare",
            "bind",
            "unbind",
        ]

    # =========================================================================
    # DEFAULT VALUES
    # =========================================================================

    class Defaults:
        """LDAP-specific default values."""

        SERVER_TYPE: Final[str] = "generic"
        OBJECT_CLASS_TOP: Final[str] = "top"
        SCHEMA_SUBENTRY: Final[str] = "cn=subschema"
        DEFAULT_SEARCH_FILTER: Final[str] = "(objectClass=*)"

    # =========================================================================
    # SEARCH FILTERS
    # =========================================================================

    class Filters:
        """Default LDAP search filters."""

        ALL_ENTRIES_FILTER: Final[str] = "(objectClass=*)"
        ALL_USERS_FILTER: Final[str] = "(objectClass=person)"
        DEFAULT_USER_FILTER: Final[str] = "(objectClass=inetOrgPerson)"
        DEFAULT_GROUP_FILTER: Final[str] = "(objectClass=groupOfNames)"

    # =========================================================================
    # LDAP ATTRIBUTE NAMES
    # =========================================================================

    class LdapAttributeNames:
        """LDAP attribute names."""

        DN: Final[str] = "dn"
        OBJECT_CLASS: Final[str] = "objectClass"
        CN: Final[str] = "cn"
        UID: Final[str] = "uid"
        MAIL: Final[str] = "mail"

    # =========================================================================
    # ERROR STRINGS
    # =========================================================================

    class ErrorStrings:
        """Error/status string constants."""

        UNKNOWN_ERROR: Final[str] = "Unknown error"
        NOT_CONNECTED: Final[str] = "Not connected to LDAP server"

    # =========================================================================
    # ACL ATTRIBUTES
    # =========================================================================

    class AclAttributes:
        """ACL-related attribute names."""

        RAW: Final[str] = "raw"
        TARGET: Final[str] = "target"
        TARGET_ATTRIBUTES: Final[str] = "targetAttributes"
        SUBJECT: Final[str] = "subject"
        PERMISSIONS: Final[str] = "permissions"

    # =========================================================================
    # ACL FORMAT
    # =========================================================================

    class AclFormat:
        """Supported ACL format identifiers."""

        GENERIC: Final[str] = "generic"
        OPENLDAP2: Final[str] = "openldap2"
        OPENLDAP1: Final[str] = "openldap1"
        ORACLE: Final[str] = "oracle"

    # =========================================================================
    # SYNTHETIC DNS
    # =========================================================================

    class SyntheticDns:
        """Synthetic DN constants for internal operations."""

        ACL_RULE: Final[str] = "cn=acl-rule"
        OBJECT_CLASS_DEFINITION: Final[str] = "cn=objectclass-definition"
        ATTRIBUTE_TYPE_DEFINITION: Final[str] = "cn=attributetype-definition"

    # =========================================================================
    # LDAP DICT KEYS
    # =========================================================================

    class LdapDictKeys:
        """LDAP dictionary key names."""

        DESCRIPTION: Final[str] = "description"

    # =========================================================================
    # SASL MECHANISMS
    # =========================================================================

    class SaslMechanisms:
        """SASL authentication mechanism constants."""

        SIMPLE: Final[str] = "SIMPLE"
        SASL_EXTERNAL: Final[str] = "SASL/EXTERNAL"
        SASL_DIGEST_MD5: Final[str] = "SASL/DIGEST-MD5"
        SASL_GSSAPI: Final[str] = "SASL/GSSAPI"

    # =========================================================================
    # SCOPES
    # =========================================================================

    class Scopes:
        """LDAP search scope constants for ldap3."""

        BASE_LDAP3: Final[int] = 0  # BASE scope
        LEVEL_LDAP3: Final[int] = 1  # ONELEVEL scope
        SUBTREE_LDAP3: Final[int] = 2  # SUBTREE scope

    # =========================================================================
    # ROOT DSE ATTRIBUTES
    # =========================================================================

    class RootDseAttributes:
        """Root DSE attribute name constants."""

        VENDOR_NAME: Final[str] = "vendorName"
        VENDOR_VERSION: Final[str] = "vendorVersion"
        CONFIG_CONTEXT: Final[str] = "configContext"
        ROOT_DOMAIN_NAMING_CONTEXT: Final[str] = "rootDomainNamingContext"
        DEFAULT_NAMING_CONTEXT: Final[str] = "defaultNamingContext"

    # =========================================================================
    # VENDOR NAMES
    # =========================================================================

    class VendorNames:
        """Vendor name constants for server detection."""

        ORACLE: Final[str] = "oracle"
        OPENLDAP: Final[str] = "openldap"
        MICROSOFT: Final[str] = "microsoft"
        WINDOWS: Final[str] = "windows"
        NOVELL: Final[str] = "novell"
        EDIR: Final[str] = "edir"
        IBM: Final[str] = "ibm"
        UNBOUNDID: Final[str] = "unboundid"
        FORGEROCK: Final[str] = "forgerock"

    # =========================================================================
    # SERVER TYPES
    # =========================================================================

    class ServerTypes:
        """LDAP server type identifiers."""

        GENERIC: Final[str] = "generic"
        OPENLDAP: Final[str] = "openldap"
        OPENLDAP1: Final[str] = "openldap1"
        OPENLDAP2: Final[str] = "openldap2"
        OID: Final[str] = "oid"
        OUD: Final[str] = "oud"
        AD: Final[str] = "ad"
        AD_SHORT: Final[str] = "ad"
