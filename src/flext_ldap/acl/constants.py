"""ACL Constants for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_core import FlextConstants


class FlextLdapAclConstants(FlextConstants):
    """Unified constants for LDAP ACL management across different server types."""

    class AclFormat:
        """Supported ACL format identifiers."""

        OPENLDAP: Final[str] = "openldap"
        ORACLE: Final[str] = "oracle"
        ACI: Final[str] = "aci"  # 389 DS / Apache DS
        ACTIVE_DIRECTORY: Final[str] = "active_directory"
        UNIFIED: Final[str] = "unified"

    class Permission:
        """Standard ACL permissions mapped across formats."""

        READ: Final[str] = "read"
        WRITE: Final[str] = "write"
        ADD: Final[str] = "add"
        DELETE: Final[str] = "delete"
        SEARCH: Final[str] = "search"
        COMPARE: Final[str] = "compare"
        BROWSE: Final[str] = "browse"
        PROXY: Final[str] = "proxy"
        AUTH: Final[str] = "auth"
        ALL: Final[str] = "all"
        NONE: Final[str] = "none"

    class SubjectType:
        """ACL subject types."""

        USER: Final[str] = "user"
        GROUP: Final[str] = "group"
        DN: Final[str] = "dn"
        SELF: Final[str] = "self"
        ANONYMOUS: Final[str] = "anonymous"
        AUTHENTICATED: Final[str] = "authenticated"
        ANYONE: Final[str] = "anyone"

    class TargetType:
        """ACL target types."""

        DN: Final[str] = "dn"
        ATTRIBUTES: Final[str] = "attributes"
        ENTRY: Final[str] = "entry"
        FILTER: Final[str] = "filter"

    class OpenLdapKeywords:
        """OpenLDAP ACL keywords."""

        ACCESS_TO: Final[str] = "access to"
        BY: Final[str] = "by"
        ATTRS: Final[str] = "attrs="
        DN_EXACT: Final[str] = "dn.exact="
        DN_REGEX: Final[str] = "dn.regex="
        FILTER: Final[str] = "filter="

    class OracleKeywords:
        """Oracle Directory ACL keywords."""

        ACCESS_TO: Final[str] = "access to"
        ATTR: Final[str] = "attr="
        ENTRY: Final[str] = "entry"
        BY: Final[str] = "by"
        GROUP: Final[str] = "group="
        USER: Final[str] = "user="

    class AciKeywords:
        """389 DS/Apache DS ACI keywords."""

        TARGET: Final[str] = "target"
        TARGETATTR: Final[str] = "targetattr"
        TARGETFILTER: Final[str] = "targetfilter"
        VERSION: Final[str] = "version 3.0"
        ACL: Final[str] = "acl"
        ALLOW: Final[str] = "allow"
        DENY: Final[str] = "deny"
        USERDN: Final[str] = "userdn"
        GROUPDN: Final[str] = "groupdn"

    class ConversionWarnings:
        """Warning messages for ACL conversion."""

        PERMISSION_NOT_SUPPORTED: Final[str] = (
            "Permission '{permission}' not supported in {format}, using closest match"
        )
        FEATURE_LOSS: Final[str] = (
            "Feature '{feature}' cannot be preserved in {format} conversion"
        )
        SYNTAX_MISMATCH: Final[str] = (
            "Syntax pattern not directly translatable between formats"
        )

    class Parsing:
        """ACL parsing constants."""

        MIN_ACL_PARTS: Final[int] = 4  # Minimum parts for valid ACL (OpenLDAP format)


__all__ = ["FlextLdapAclConstants"]
