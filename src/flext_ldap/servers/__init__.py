"""Unified LDAP server operations for flext-ldap domain.

This module provides a single FlextLdapServers class that consolidates all
server-specific LDAP operations into one unified interface following FLEXT
single-class-per-module pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations


class FlextLdapServers(FlextService[None]):
    """Unified LDAP server operations class consolidating all server-specific implementations.

    This class provides a single interface for all LDAP server operations across
    different server types (OpenLDAP, Oracle OID/OUD, Active Directory, etc.)
    following FLEXT single-class-per-module pattern.

    **UNIFIED SERVER OPERATIONS**: One class handles all server types through
    internal factory pattern and server-specific implementations.

    **PROTOCOL COMPLIANCE**: Implements server-specific protocols through
    structural subtyping and factory-based delegation.
    """

    # Server type constants - using centralized constants (ClassVar to avoid Pydantic field detection)
    SERVER_OPENLDAP1: ClassVar[str] = FlextLdapConstants.Servers.OPENLDAP1
    SERVER_OPENLDAP2: ClassVar[str] = FlextLdapConstants.Servers.OPENLDAP2
    SERVER_OID: ClassVar[str] = FlextLdapConstants.Servers.OID
    SERVER_OUD: ClassVar[str] = FlextLdapConstants.Servers.OUD
    SERVER_AD: ClassVar[str] = FlextLdapConstants.Servers.AD
    SERVER_GENERIC: ClassVar[str] = FlextLdapConstants.Servers.GENERIC

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize unified server operations with Phase 1 context enrichment.

        Args:
            server_type: LDAP server type (openldap1, openldap2, oid, oud, ad, generic)

        """
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._server_type = server_type or self.SERVER_GENERIC
        self._operations: object | None = None

    def execute(self) -> FlextResult[None]:
        """Execute method required by FlextService."""
        return FlextResult[None].ok(None)

    @property
    def server_type(self) -> str:
        """Get current server type."""
        return self._server_type

    @property
    def operations(self) -> FlextLdapServersBaseOperations | None:
        """Get current server operations instance."""
        if self._operations is None:
            self._operations = self._create_operations_for_server(self._server_type)
        return self._operations

    def _create_operations_for_server(self, server_type: str) -> object:
        """Factory method to create operations instance for server type.

        Args:
            server_type: Server type identifier

        Returns:
            Server operations instance

        """
        # Import here to avoid circular imports
        from flext_ldap.servers.factory import FlextLdapServersFactory

        factory = FlextLdapServersFactory()
        result = factory.create_from_server_type(server_type)

        if result.is_failure:
            # Fallback to generic operations
            self.logger.warning(
                f"Failed to create operations for server type {server_type}, using generic",
                error=result.error,
            )
            result = factory.create_from_server_type(self.SERVER_GENERIC)

        return result.unwrap()

    # =========================================================================
    # DELEGATED METHODS - All server operations delegate to internal operations
    # =========================================================================

    def get_acl_format(self) -> str:
        """Get ACL format for current server type."""
        ops = self.operations
        return ops.get_acl_format() if ops else "unknown"

    def get_acl_attribute_name(self) -> str:
        """Get ACL attribute name for current server type."""
        ops = self.operations
        return ops.get_acl_attribute_name() if ops else "aci"

    def get_schema_dn(self) -> str:
        """Get schema DN for current server type."""
        ops = self.operations
        return ops.get_schema_dn() if ops else "cn=schema"

    def get_default_port(self, use_ssl: bool = False) -> int:
        """Get default port for current server type."""
        ops = self.operations
        return ops.get_default_port(use_ssl) if ops else (636 if use_ssl else 389)

    def supports_start_tls(self) -> bool:
        """Check if server supports STARTTLS."""
        ops = self.operations
        return ops.supports_start_tls() if ops else False

    def get_bind_mechanisms(self) -> list[str]:
        """Get supported bind mechanisms."""
        ops = self.operations
        return ops.get_bind_mechanisms() if ops else ["SIMPLE"]

    def get_max_page_size(self) -> int:
        """Get maximum page size for paged results."""
        ops = self.operations
        return ops.get_max_page_size() if ops else 1000

    def supports_paged_results(self) -> bool:
        """Check if server supports paged results."""
        ops = self.operations
        return ops.supports_paged_results() if ops else True

    def supports_vlv(self) -> bool:
        """Check if server supports VLV (Virtual List View)."""
        ops = self.operations
        return ops.supports_vlv() if ops else False

    def search_with_paging(
        self,
        connection: Connection,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Perform paged search operation."""
        ops = self.operations
        if not ops:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "No server operations available"
            )
        return ops.search_with_paging(
            connection, base_dn, search_filter, attributes, page_size
        )

    def get_root_dse_attributes(
        self, connection: Connection
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes."""
        ops = self.operations
        if not ops:
            return FlextResult[dict[str, object]].fail(
                FlextLdapConstants.LdapMessages.NO_SERVER_OPERATIONS_AVAILABLE
            )
        return ops.get_root_dse_attributes(connection)

    def detect_server_type_from_root_dse(self, root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE."""
        ops = self.operations
        return (
            ops.detect_server_type_from_root_dse(root_dse)
            if ops
            else self.SERVER_GENERIC
        )

    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported controls."""
        ops = self.operations
        if not ops:
            return FlextResult[list[str]].fail(
                FlextLdapConstants.LdapMessages.NO_SERVER_OPERATIONS_AVAILABLE
            )
        return ops.get_supported_controls(connection)

    def normalize_entry_for_server(
        self, entry: FlextLdifModels.Entry, target_server_type: str | None = None
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for target server type."""
        ops = self.operations
        if not ops:
            return FlextResult[FlextLdifModels.Entry].fail(
                "No server operations available"
            )
        return ops.normalize_entry_for_server(entry, target_server_type)

    def validate_entry_for_server(
        self, entry: FlextLdifModels.Entry, server_type: str | None = None
    ) -> FlextResult[bool]:
        """Validate entry compatibility with server."""
        ops = self.operations
        if not ops:
            return FlextResult[bool].fail(
                FlextLdapConstants.LdapMessages.NO_SERVER_OPERATIONS_AVAILABLE
            )
        return ops.validate_entry_for_server(entry, server_type)

    # =========================================================================
    # FACTORY METHODS - Create operations for specific server types
    # =========================================================================

    @classmethod
    def for_openldap1(cls) -> FlextLdapServers:
        """Create operations for OpenLDAP 1.x."""
        return cls(cls.SERVER_OPENLDAP1)

    @classmethod
    def for_openldap2(cls) -> FlextLdapServers:
        """Create operations for OpenLDAP 2.x."""
        return cls(cls.SERVER_OPENLDAP2)

    @classmethod
    def for_oracle_oid(cls) -> FlextLdapServers:
        """Create operations for Oracle Internet Directory."""
        return cls(cls.SERVER_OID)

    @classmethod
    def for_oracle_oud(cls) -> FlextLdapServers:
        """Create operations for Oracle Unified Directory."""
        return cls(cls.SERVER_OUD)

    @classmethod
    def for_active_directory(cls) -> FlextLdapServers:
        """Create operations for Active Directory."""
        return cls(cls.SERVER_AD)

    @classmethod
    def generic(cls) -> FlextLdapServers:
        """Create generic operations."""
        return cls(cls.SERVER_GENERIC)


__all__ = [
    "FlextLdapServers",
]
