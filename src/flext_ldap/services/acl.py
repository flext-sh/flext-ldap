"""LDAP ACL (Access Control List) operations and management.

Provides ACL-specific operations, format detection, and server-specific
ACL handling for various LDAP server types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService


class FlextLdapAclService(FlextService[None]):
    """LDAP ACL (Access Control List) operations and management.

    Provides:
    - ACL format detection and handling
    - Server-specific ACL operations
    - ACL parsing and manipulation
    - ACL information retrieval
    """

    # ACL format constants
    ACL_FORMAT_ACI: str = "aci"  # Oracle OID/OUD format
    ACL_FORMAT_OLCACCESS: str = "olcaccess"  # OpenLDAP format
    ACL_FORMAT_NTSD: str = "ntsd"  # AD format

    def __init__(self) -> None:
        """Initialize ACL operations."""
        super().__init__()

    def execute(self) -> FlextResult[None]:
        """Execute ACL operations."""
        return FlextResult[None].ok(None)

    def get_acl_format(self) -> str:
        """Get default ACL format.

        Returns:
            The default ACL format string (typically "aci" for Oracle, "olcaccess" for OpenLDAP).

        """
        return self.ACL_FORMAT_ACI

    def supports_acl_format(self, acl_format: str) -> bool:
        """Check if ACL format is supported.

        Args:
            acl_format: ACL format to check (e.g., "aci", "olcaccess", "ntsd")

        Returns:
            True if format is supported, False otherwise.

        """
        return acl_format in {
            self.ACL_FORMAT_ACI,
            self.ACL_FORMAT_OLCACCESS,
            self.ACL_FORMAT_NTSD,
        }

    def get_acl_attribute_name(self, server_type: str | None = None) -> str:
        """Get ACL attribute name for server type.

        Args:
            server_type: LDAP server type. If None, returns default.

        Returns:
            The attribute name used for ACLs on this server type.

        """
        if server_type in {"openldap1", "openldap2"}:
            return "olcAccess"
        if server_type in {"oid", "oud"}:
            return "aci"
        if server_type == "ad":
            return "nTSecurityDescriptor"
        return "aci"  # Default
