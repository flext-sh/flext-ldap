"""Generic LDAP server operations.

Implementation for generic/unknown LDAP servers with standard RFC-compliant operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations


class FlextLdapServersGenericOperations(FlextLdapServersBaseOperations):
    """Generic LDAP server operations implementation.

    Provides LDAP operations for unknown/generic servers using standard LDAP
    conventions and RFC-compliant operations.
    """

    def __init__(self) -> None:
        """Initialize generic server operations."""
        super().__init__(server_type=FlextLdapConstants.Defaults.SERVER_TYPE)

    # --------------------------------------------------------------------- #
    # INHERITED METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods are used directly from the base class without override:
    # - get_default_port(): Returns 389 (standard LDAP port)
    # - supports_start_tls(): Returns True (standard LDAP feature)
    # - discover_schema(): Generic schema discovery implementation
    # - parse_object_class(): Generic objectClass parsing
    # - parse_attribute_type(): Generic attributeType parsing
    # - get_acls(): Generic ACL retrieval
    # - set_acls(): Generic ACL setting
    # - parse(): Generic ACL parsing
    # - format_acl(): Generic ACL formatting
    # - add_entry(): Generic entry addition
    # - modify_entry(): Generic entry modification
    # - delete_entry(): Generic entry deletion
    # - normalize_entry(): Generic entry normalization
    # - get_max_page_size(): Returns 1000 (standard page size)
    # - supports_paged_results(): Returns True (standard LDAP feature)
    # - supports_vlv(): Returns False (not widely supported)
    # - search_with_paging(): Generic paged search implementation
    # - get_root_dse_attributes(): Generic Root DSE retrieval
    # - get_supported_controls(): Generic supported controls
    # - normalize_entry_for_server(): Generic entry normalization
    #
    # --------------------------------------------------------------------- #
    # OVERRIDDEN METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods override the base class with generic/server-specific logic:
    # - get_schema_dn(): Returns "cn=subschema" (RFC 4512 standard)
    # - get_acl_attribute_name(): Returns "aci" (RFC 4512 standard)
    # - get_acl_format(): Returns "generic" (standard format)
    # - detect_server_type_from_root_dse(): Generic server detection
    # - validate_entry_for_server(): Generic entry validation

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """Generic LDAP uses cn=subschema (RFC 4512)."""
        return FlextLdapConstants.Defaults.SCHEMA_SUBENTRY

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @override
    def get_acl_attribute_name(self) -> str:
        """Generic LDAP uses aci attribute."""
        return "aci"

    @override
    def get_acl_format(self) -> str:
        """Generic LDAP ACL format identifier."""
        return FlextLdapConstants.AclFormat.GENERIC

    @override
    def _format_acls(self, acls: list[dict[str, object]]) -> FlextResult[list[str]]:
        """Format ACLs for generic LDAP server."""
        try:
            formatted_acls = []
            for acl in acls:
                # Generic ACL formatting - convert dict to string
                acl_str = str(acl)
                formatted_acls.append(acl_str)
            return FlextResult.ok(formatted_acls)
        except Exception as e:
            return FlextResult.fail(
                f"Failed to format ACLs: {e}",
                error_code=FlextLdapConstants.Errors.PROCESSING_ERROR,
            )

    @override
    def _get_acl_attribute(self) -> str:
        """Get ACL attribute name for generic LDAP."""
        return "aci"  # Generic default

    # get_acls(), set_acls() - Use base implementations

    # parse() - Use base implementation

    # format_acl() - Use base implementation

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @override
    def add_entry(
        self,
        connection: Connection,
        entry: FlextLdifModels.Entry,
        *,
        should_normalize: bool = True,
    ) -> FlextResult[bool]:
        """Add entry to generic LDAP server - uses base with no normalization."""
        return super().add_entry(connection, entry, should_normalize=False)

    # modify_entry(), delete_entry() - Use base implementations

    # normalize_entry() - Use base implementation (returns entry as-is)

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    # get_max_page_size(), supports_paged_results(), supports_vlv() - Use base defaults

    # search_with_paging() - Use base implementation

    # =========================================================================
    # Root DSE OPERATIONS
    # =========================================================================

    # get_root_dse_attributes() - Use base implementation

    @override
    def detect_server_type_from_root_dse(self, _root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE attributes."""
        # Check for common vendor identifiers
        if FlextLdapConstants.RootDseAttributes.VENDOR_NAME in _root_dse:
            vendor = str(
                _root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_NAME],
            ).lower()
            if FlextLdapConstants.VendorNames.ORACLE in vendor:
                return "oracle-oid"  # Legacy format - keep for compatibility
            if FlextLdapConstants.VendorNames.OPENLDAP in vendor:
                return FlextLdapConstants.ServerTypes.OPENLDAP2
            if (
                FlextLdapConstants.VendorNames.MICROSOFT in vendor
                or FlextLdapConstants.VendorNames.WINDOWS in vendor
            ):
                return "active-directory"  # Legacy format - keep for compatibility
            if (
                FlextLdapConstants.VendorNames.NOVELL in vendor
                or FlextLdapConstants.VendorNames.EDIR in vendor
            ):
                return FlextLdapConstants.VendorNames.EDIR
            if FlextLdapConstants.VendorNames.IBM in vendor:
                return "ibm-tivoli"  # Legacy format - keep for compatibility
            if FlextLdapConstants.VendorNames.UNBOUNDID in vendor:
                return FlextLdapConstants.VendorNames.UNBOUNDID
            if FlextLdapConstants.VendorNames.FORGEROCK in vendor:
                return FlextLdapConstants.VendorNames.FORGEROCK

        # Check for specific attributes
        if FlextLdapConstants.RootDseAttributes.CONFIG_CONTEXT in _root_dse:
            return "oracle-oid"  # Legacy format - keep for compatibility

        # Default to generic
        return FlextLdapConstants.AclFormat.GENERIC

    # get_supported_controls() - Use base implementation (standard controls)

    # normalize_entry_for_server() - Use base implementation (delegates to normalize_entry)

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for generic LDAP server using shared service."""
        # Use shared FlextLdapEntryAdapter service for validation
        adapter = FlextLdapEntryAdapter(server_type=self.server_type)
        return adapter.validate_entry_for_server(entry, self.server_type)
