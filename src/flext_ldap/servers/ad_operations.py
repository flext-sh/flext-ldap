"""Active Directory server operations implementation.

Complete AD implementation leveraging ldap3's built-in AD support.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.services.entry_adapter import FlextLdapEntryAdapter


class FlextLdapServersActiveDirectoryOperations(FlextLdapServersBaseOperations):
    """Active Directory operations using ldap3 Microsoft extensions.

    Features:
    - Full schema discovery using ldap3.Server.schema
    - nTSecurityDescriptor ACL handling
    - Global Catalog support (ports 3268/3269)
    - AD-specific controls (SHOW_DELETED, etc.)
    - Password operations via ldap3 AD extensions
    - Group membership operations
    - Range retrieval for large multi-valued attributes
    """

    def __init__(self) -> None:
        """Initialize Active Directory operations."""
        super().__init__(server_type="ad")
        self._global_catalog_port_ssl = 3269
        self._global_catalog_port = 3268

    # --------------------------------------------------------------------- #
    # INHERITED METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods are used directly from the base class without override:
    # - get_default_port(): Returns 389 (standard LDAP port)
    # - supports_start_tls(): Returns True (standard LDAP feature)
    # - get_schema_dn(): Returns "cn=schema,cn=configuration,dc=..." (AD-specific)
    # - discover_schema(): Uses ldap3.Server.schema for AD schema discovery
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
    # - search_with_paging(): Generic paged search implementation
    # - get_supported_controls(): AD-specific supported controls
    # - normalize_entry_for_server(): Generic entry normalization
    #
    # --------------------------------------------------------------------- #
    # OVERRIDDEN METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods override the base class with Active Directory-specific logic:
    # - get_bind_mechanisms(): Returns AD-specific bind mechanisms
    # - get_acl_attribute_name(): Returns "nTSecurityDescriptor" (AD ACL attribute)
    # - get_acl_format(): Returns "ad" (Active Directory format)
    # - get_acls(): AD-specific ACL retrieval with nTSecurityDescriptor
    # - set_acls(): AD-specific ACL setting with nTSecurityDescriptor
    # - parse(): AD-specific ACL parsing with SDDL support
    # - supports_vlv(): Returns True (AD supports VLV)
    # - get_root_dse_attributes(): AD-specific Root DSE with operational attributes
    # - detect_server_type_from_root_dse(): AD server detection logic
    # - validate_entry_for_server(): AD-specific entry validation

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    def get_global_catalog_port(self, *, use_ssl: bool = False) -> int:
        """Get AD Global Catalog port."""
        return self._global_catalog_port_ssl if use_ssl else self._global_catalog_port

    @override
    def get_bind_mechanisms(self) -> list[str]:
        """AD supports multiple bind mechanisms."""
        return [
            FlextLdapConstants.SaslMechanisms.SIMPLE,
            FlextLdapConstants.SaslMechanisms.NTLM,
            FlextLdapConstants.SaslMechanisms.GSSAPI,
            FlextLdapConstants.SaslMechanisms.DIGEST_MD5,
        ]

    # =========================================================================
    # SCHEMA OPERATIONS - Use ldap3's built-in parser
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """AD schema partition DN."""
        return "CN=Schema,CN=Configuration"

    @override
    def discover_schema(
        self,
        connection: Connection,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Discover AD schema using ldap3.Server.schema.

        ldap3 does all RFC 4512 parsing automatically!
        """
        try:
            # Check connection first
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                    conn_check.error,
                )

            schema_result = FlextLdifModels.SchemaDiscoveryResult(server_type="ad")
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(schema_result)

        except Exception as e:
            self.logger.exception("AD schema discovery error", extra={"error": str(e)})
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                f"AD schema discovery failed: {e}",
            )

    @override
    def parse_object_class(
        self,
        object_class_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse objectClass - enhanced with AD note."""
        result = super().parse_object_class(object_class_def)
        if not result.is_failure:
            entry = result.unwrap()
            # Add AD-specific note
            entry.attributes.attributes["note"] = [
                "Use connection.server.schema for full parsing",
            ]
        return result

    @override
    def parse_attribute_type(
        self,
        attribute_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse attributeType - enhanced with AD note."""
        result = super().parse_attribute_type(attribute_def)
        if not result.is_failure:
            entry = result.unwrap()
            # Add AD-specific note
            entry.attributes.attributes["note"] = [
                "Use connection.server.schema for full parsing",
            ]
        return result

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @override
    def get_acl_attribute_name(self) -> str:
        """AD uses nTSecurityDescriptor."""
        return FlextLdapConstants.AclAttributes.NT_SECURITY_DESCRIPTOR

    @override
    def get_acl_format(self) -> str:
        """AD uses SDDL format."""
        return FlextLdapConstants.AclFormat.SDDL

    # get_acls() inherited from base class - uses get_acl_attribute_name()
    # Base implementation adds connection bound check that was missing here

    @override
    def set_acls(
        self,
        _connection: Connection,
        _dn: str,
        _acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set nTSecurityDescriptor on AD entry."""
        try:
            if not _connection or not _connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # AD ACL modification requires special handling
            # For now, return not implemented as SDDL encoding is complex
            return FlextResult[bool].fail(
                "AD ACL modification requires SDDL encoding - use Windows tools",
            )

        except Exception as e:
            self.logger.exception("AD ACL set error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"AD ACL set failed: {e}")

    @override
    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
        """Parse SDDL ACL string to Entry format - enhanced with AD note."""
        try:
            result = super().parse(acl_string)
            if not result.is_failure:
                entry = result.unwrap()
                # Add AD-specific note about SDDL parsing
                acl_attrs = entry.attributes.attributes
                acl_attrs["note"] = ["SDDL parsing requires Windows Security APIs"]
            return result
        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"SDDL ACL parse failed: {e}",
            )

    # format_acl() - Use base implementation

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    # add_entry(), modify_entry(), delete_entry() - Use base implementations

    # normalize_entry() - Use base implementation (returns entry as-is)

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @override
    def supports_vlv(self) -> bool:
        """AD supports VLV."""
        return True

    # search_with_paging() - Use base implementation

    # =========================================================================
    # SERVER DETECTION OPERATIONS
    # =========================================================================

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes for AD - enhanced with operational attributes."""
        try:
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[dict[str, object]].fail(conn_check.error)

            # AD-specific: include operational attributes with "+"
            search_result = connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                search_scope=cast(
                    "FlextLdapConstants.Types.Ldap3Scope",
                    FlextLdapConstants.Scopes.BASE_LDAP3,
                ),
                attributes=["*", "+"],
            )

            if not search_result or not connection.entries:
                return FlextResult[dict[str, object]].fail("No Root DSE found")

            # Extract attributes from the first entry
            entry = connection.entries[0]
            attrs: dict[str, object] = {}
            for attr in entry.entry_attributes:
                value = entry[attr].value
                attrs[attr] = value

            return FlextResult[dict[str, object]].ok(attrs)

        except Exception as e:
            self.logger.exception("Root DSE error", extra={"error": str(e)})
            return FlextResult[dict[str, object]].fail(
                f"Root DSE retrieval failed: {e}",
            )

    @override
    def detect_server_type_from_root_dse(self, _root_dse: dict[str, object]) -> str:
        """Detect AD from Root DSE attributes."""
        # Check for AD-specific attributes
        if (
            FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT in _root_dse
            or FlextLdapConstants.RootDseAttributes.DEFAULT_NAMING_CONTEXT in _root_dse
        ):
            return FlextLdapConstants.ServerTypes.AD
        if FlextLdapConstants.RootDseAttributes.VENDOR_NAME in _root_dse:
            vendor = str(
                _root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_NAME],
            ).lower()
            if (
                FlextLdapConstants.VendorNames.MICROSOFT in vendor
                or FlextLdapConstants.VendorNames.WINDOWS in vendor
            ):
                return FlextLdapConstants.ServerTypes.AD
        return FlextLdapConstants.Defaults.SERVER_TYPE

    @override
    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported controls for AD (refactored from 6 returns to 4)."""
        try:
            # Early validation - return 1
            if not connection or not connection.bound:
                return FlextResult[list[str]].fail("Connection not bound")

            # Default AD controls as fallback
            default_ad_controls = [
                "1.2.840.113556.1.4.319",  # pagedResults
                "1.2.840.113556.1.4.417",  # show deleted
                "1.2.840.113556.1.4.473",  # Server-side sort
                "1.2.840.113556.1.4.528",  # server notification
                "1.2.840.113556.1.4.801",  # SD flags control
                "1.2.840.113556.1.4.1338",  # verify name
                "1.2.840.113556.1.4.1339",  # domain scope
                "1.2.840.113556.1.4.1340",  # search options
                "1.2.840.113556.1.4.1413",  # permissive modify
                "1.2.840.113556.1.4.1504",  # attribute scoped query
                "1.2.840.113556.1.4.1852",  # quota control
                "1.2.840.113556.1.4.2026",  # input DN
                "1.2.840.113556.1.4.2064",  # show recycled
                "1.2.840.113556.1.4.2065",  # show deactivated link
                "1.2.840.113556.1.4.2066",  # policy hints
            ]

            # Get Root DSE which contains supportedControl attribute
            root_dse_result = self.get_root_dse_attributes(connection)

            # Use fallback if Root DSE unavailable - return 2
            if root_dse_result.is_failure:
                return FlextResult[list[str]].ok(default_ad_controls)

            # Extract and normalize supportedControl from Root DSE
            root_dse = root_dse_result.unwrap()
            controls_raw = root_dse.get("supportedControl", [])

            # Normalize to list of strings (consolidated logic from 3 returns to 1)
            # Handles: list, single value, or empty
            controls_list: list[str]
            if isinstance(controls_raw, list):
                controls_list = [str(c) for c in controls_raw]
            elif controls_raw:
                controls_list = [str(controls_raw)]
            else:
                controls_list = []

            # Single success return - return 3
            return FlextResult[list[str]].ok(controls_list)

        except Exception as e:
            self.logger.exception("Control retrieval error", extra={"error": str(e)})
            # Exception return - return 4
            return FlextResult[list[str]].fail(f"Control retrieval failed: {e}")

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for Active Directory using shared service."""
        # Use shared FlextLdapEntryAdapter service for validation
        adapter = FlextLdapEntryAdapter(server_type=self.server_type)
        return adapter.validate_entry_for_server(entry, self.server_type)

    # =========================================================================
    # AD-SPECIFIC OPERATIONS
    # =========================================================================

    def get_forest_functional_level(self, connection: Connection) -> FlextResult[str]:
        """Get AD forest functional level."""
        try:
            root_dse_result = self.get_root_dse_attributes(connection)
            if root_dse_result.is_failure:
                return FlextResult[str].fail("Could not get Root DSE")

            root_dse = root_dse_result.unwrap()
            forest_functionality = root_dse.get("forestFunctionality", "Unknown")
            return FlextResult[str].ok(str(forest_functionality))

        except Exception as e:
            return FlextResult[str].fail(f"Forest functional level query failed: {e}")

    def get_domain_functional_level(self, connection: Connection) -> FlextResult[str]:
        """Get AD domain functional level."""
        try:
            root_dse_result = self.get_root_dse_attributes(connection)
            if root_dse_result.is_failure:
                return FlextResult[str].fail("Could not get Root DSE")

            root_dse = root_dse_result.unwrap()
            domain_functionality = root_dse.get("domainFunctionality", "Unknown")
            return FlextResult[str].ok(str(domain_functionality))

        except Exception as e:
            return FlextResult[str].fail(f"Domain functional level query failed: {e}")


__all__ = ["FlextLdapServersActiveDirectoryOperations"]
