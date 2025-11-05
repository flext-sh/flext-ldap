"""Unified LDAP server operations consolidation.

Single FlextLdapServers class consolidating all server-specific LDAP
operations with unified interface following FLEXT patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.servers.factory import FlextLdapServersFactory


class FlextLdapServers(FlextService[None]):
    """Unified LDAP server operations facade for multiple implementations.

    This class provides a single interface for all LDAP server operations across
    different server types (OpenLDAP, Oracle OID/OUD, Active Directory, etc.)
    following FLEXT single-class-per-module pattern.

    UNIFIED SERVER OPERATIONS: One class handles all server types through
    internal factory pattern and server-specific implementations.

    PROTOCOL COMPLIANCE: Implements server-specific protocols through
    structural subtyping and factory-based delegation.
    """

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize unified server operations with Phase 1 context enrichment.

        Args:
        server_type: LDAP server type (openldap1, openldap2, oid, oud, ad, generic)

        """
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._server_type = server_type or FlextLdapConstants.ServerTypes.GENERIC
        self._operations: FlextLdapServersBaseOperations | None = None

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

    def _create_operations_for_server(
        self,
        server_type: str,
    ) -> FlextLdapServersBaseOperations | None:
        """Factory method to create operations instance for server type.

        Args:
        server_type: Server type identifier

        Returns:
        Server operations instance

        """
        factory = FlextLdapServersFactory()
        result = factory.create_from_server_type(server_type)

        if result.is_failure:
            # Fallback to generic operations
            self.logger.warning(
                "Failed to create operations for server type %s, using generic",
                server_type,
                error=result.error,
            )
            result = factory.create_from_server_type(
                FlextLdapConstants.ServerTypes.GENERIC,
            )

        if result.is_failure:
            # Even generic operations failed - this shouldn't happen
            self.logger.error(
                "Failed to create even generic operations for server type %s",
                server_type,
                error=result.error,
            )
            return None

        return result.unwrap()

    # =========================================================================
    # DELEGATED METHODS - All server operations delegate to internal operations
    # =========================================================================

    def get_acl_format(self) -> str:
        """Get ACL format for current server type."""
        ops = self.operations
        return ops.get_acl_format() if ops else FlextLdapConstants.ErrorStrings.UNKNOWN

    def get_acl_attribute_name(self) -> str:
        """Get ACL attribute name for current server type."""
        ops = self.operations
        return ops.get_acl_attribute_name() if ops else "aci"

    def get_schema_dn(self) -> str:
        """Get schema DN for current server type."""
        ops = self.operations
        return ops.get_schema_dn() if ops else FlextLdapConstants.SchemaDns.SCHEMA

    def get_default_port(self, *, use_ssl: bool = False) -> int:
        """Get default port for current server type."""
        ops = self.operations
        return (
            ops.get_default_port(use_ssl=use_ssl) if ops else (636 if use_ssl else 389)
        )

    def supports_start_tls(self) -> bool:
        """Check if server supports STARTTLS."""
        ops = self.operations
        return ops.supports_start_tls() if ops else False

    def get_bind_mechanisms(self) -> list[str]:
        """Get supported bind mechanisms."""
        ops = self.operations
        return (
            ops.get_bind_mechanisms()
            if ops
            else [FlextLdapConstants.SaslMechanisms.SIMPLE]
        )

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
        scope: str = "subtree",
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Perform paged search operation."""
        ops = self.operations
        if not ops:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "No server operations available",
            )
        return ops.search_with_paging(
            connection,
            base_dn,
            search_filter,
            attributes,
            scope,
            page_size,
        )

    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes."""
        ops = self.operations
        if not ops:
            return FlextResult[dict[str, object]].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.get_root_dse_attributes(connection)

    def detect_server_type_from_root_dse(self, root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE."""
        ops = self.operations
        return (
            ops.detect_server_type_from_root_dse(root_dse)
            if ops
            else FlextLdapConstants.ServerTypes.GENERIC
        )

    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported controls."""
        ops = self.operations
        if not ops:
            return FlextResult[list[str]].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.get_supported_controls(connection)

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for target server type."""
        ops = self.operations
        if not ops:
            return FlextResult[FlextLdifModels.Entry].fail(
                "No server operations available",
            )
        return ops.normalize_entry_for_server(entry, target_server_type)

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry compatibility with server."""
        ops = self.operations
        if not ops:
            return FlextResult[bool].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.validate_entry_for_server(entry, server_type)

    def add_entry(
        self,
        connection: Connection,
        entry: FlextLdifModels.Entry,
        *,
        should_normalize: bool = True,
    ) -> FlextResult[bool]:
        """Add entry to LDAP server."""
        ops = self.operations
        if not ops:
            return FlextResult[bool].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.add_entry(connection, entry, should_normalize=should_normalize)

    def modify_entry(
        self,
        connection: Connection,
        dn: str,
        modifications: dict[str, object],
    ) -> FlextResult[bool]:
        """Modify entry on LDAP server."""
        ops = self.operations
        if not ops:
            return FlextResult[bool].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.modify_entry(connection, dn, modifications)

    def delete_entry(self, connection: Connection, dn: str) -> FlextResult[bool]:
        """Delete entry from LDAP server."""
        ops = self.operations
        if not ops:
            return FlextResult[bool].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.delete_entry(connection, dn)

    def get_acls(
        self,
        connection: Connection,
        dn: str,
    ) -> FlextResult[list[FlextLdifModels.Acl]]:
        """Get ACLs for entry."""
        ops = self.operations
        if not ops:
            return FlextResult[list[FlextLdifModels.Acl]].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.get_acls(connection, dn)

    def set_acls(
        self,
        connection: Connection,
        dn: str,
        acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set ACLs for entry."""
        ops = self.operations
        if not ops:
            return FlextResult[bool].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.set_acls(connection, dn, acls)

    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
        """Parse ACL string to Entry."""
        ops = self.operations
        if not ops:
            return FlextResult[FlextLdifModels.Entry].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.parse(acl_string)

    def format_acl(self, acl_entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Format ACL Entry to string."""
        ops = self.operations
        if not ops:
            return FlextResult[str].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.format_acl(acl_entry)

    def discover_schema(
        self,
        connection: Connection,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Discover schema from server."""
        ops = self.operations
        if not ops:
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.discover_schema(connection)

    def parse_object_class(
        self,
        object_class_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse objectClass definition."""
        ops = self.operations
        if not ops:
            return FlextResult[FlextLdifModels.Entry].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.parse_object_class(object_class_def)

    def parse_attribute_type(
        self,
        attribute_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse attributeType definition."""
        ops = self.operations
        if not ops:
            return FlextResult[FlextLdifModels.Entry].fail(
                FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE,
            )
        return ops.parse_attribute_type(attribute_def)

    # =========================================================================
    # FACTORY METHODS - Create operations for specific server types
    # =========================================================================

    @classmethod
    def for_openldap1(cls) -> FlextLdapServers:
        """Create operations for OpenLDAP 1.x."""
        return cls(FlextLdapConstants.ServerTypes.OPENLDAP1)

    @classmethod
    def for_openldap2(cls) -> FlextLdapServers:
        """Create operations for OpenLDAP 2.x."""
        return cls(FlextLdapConstants.ServerTypes.OPENLDAP2)

    @classmethod
    def for_oracle_oid(cls) -> FlextLdapServers:
        """Create operations for Oracle Internet Directory."""
        return cls(FlextLdapConstants.ServerTypes.OID)

    @classmethod
    def for_oracle_oud(cls) -> FlextLdapServers:
        """Create operations for Oracle Unified Directory."""
        return cls(FlextLdapConstants.ServerTypes.OUD)

    @classmethod
    def for_active_directory(cls) -> FlextLdapServers:
        """Create operations for Active Directory."""
        return cls(FlextLdapConstants.ServerTypes.AD)

    @classmethod
    def generic(cls) -> FlextLdapServers:
        """Create generic operations."""
        return cls(FlextLdapConstants.ServerTypes.GENERIC)


__all__ = ["FlextLdapServers"]
