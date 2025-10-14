"""Generic LDAP server operations stub.

Stub implementation for generic/unknown LDAP servers - basic operations only.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextCore
from flext_ldif import FlextLdifModels
from ldap3 import BASE, LEVEL, MODIFY_REPLACE, SUBTREE, Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.models import FlextLdapModels
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations


class FlextLdapServersGenericOperations(FlextLdapServersBaseOperations):
    """Generic LDAP server operations stub.

    This provides basic LDAP operations for unknown/generic servers.
    Uses standard LDAP conventions and RFC-compliant operations.

    For better server support, implement a specific server operations class.
    """

    def __init__(self) -> None:
        """Initialize generic server operations."""
        super().__init__(server_type="generic")
        self.logger.info("Using generic LDAP server operations")

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    @override
    def get_default_port(self, *, use_ssl: bool = False) -> int:
        """Get default port for generic LDAP."""
        return 636 if use_ssl else 389

    @override
    def supports_start_tls(self) -> bool:
        """Assume generic LDAP supports START_TLS."""
        return True

    @override
    def get_bind_mechanisms(self) -> FlextCore.Types.StringList:
        """Get supported BIND mechanisms for generic LDAP."""
        return ["SIMPLE"]

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """Generic LDAP uses cn=subschema (RFC 4512)."""
        return "cn=subschema"

    @override
    def discover_schema(
        self,
        connection: Connection,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Discover schema from generic LDAP server."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Connection not bound"
                )

            success = connection.search(
                search_base=self.get_schema_dn(),
                search_filter="(objectClass=*)",
                attributes=["objectClasses", "attributeTypes"],
            )

            if not success or not connection.entries:
                self.logger.warning("Generic schema discovery failed - using defaults")
                return FlextCore.Result[FlextCore.Types.Dict].ok({
                    "object_classes": [],
                    "attribute_types": [],
                    "server_type": "generic",
                })

            entry = connection.entries[0]
            schema_data: FlextCore.Types.Dict = {
                "object_classes": (
                    entry.objectClasses.values
                    if hasattr(entry, "objectClasses")
                    else []
                ),
                "attribute_types": (
                    entry.attributeTypes.values
                    if hasattr(entry, "attributeTypes")
                    else []
                ),
                "server_type": "generic",
            }

            return FlextCore.Result[FlextCore.Types.Dict].ok(schema_data)

        except Exception as e:
            self.logger.warning(
                "Generic schema discovery error",
                extra={"error": str(e)},
            )
            return FlextCore.Result[FlextCore.Types.Dict].ok({
                "object_classes": [],
                "attribute_types": [],
                "server_type": "generic",
            })

    @override
    def parse_object_class(
        self, object_class_def: str
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Parse generic objectClass definition."""
        return FlextCore.Result[FlextCore.Types.Dict].ok({
            "definition": object_class_def,
            "server_type": "generic",
        })

    @override
    def parse_attribute_type(
        self, attribute_def: str
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Parse generic attributeType definition."""
        return FlextCore.Result[FlextCore.Types.Dict].ok({
            "definition": attribute_def,
            "server_type": "generic",
        })

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
        return "generic"

    @override
    def get_acls(
        self,
        connection: Connection,
        dn: str,
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Get ACLs from generic LDAP server."""
        self.logger.warning("Generic ACL retrieval - may not work on all servers")
        return FlextCore.Result[list[FlextCore.Types.Dict]].ok([])

    @override
    def set_acls(
        self,
        connection: Connection,
        dn: str,
        acls: list[FlextCore.Types.Dict],
    ) -> FlextCore.Result[bool]:
        """Set ACLs on generic LDAP server."""
        return FlextCore.Result[bool].fail(
            "Generic LDAP ACL setting not supported - implement server-specific operations",
        )

    @override
    def parse_acl(self, acl_string: str) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Parse generic ACL string."""
        return FlextCore.Result[FlextCore.Types.Dict].ok({
            "raw": acl_string,
            "format": "generic",
            "server_type": "generic",
        })

    @override
    def format_acl(self, acl_dict: FlextCore.Types.Dict) -> FlextCore.Result[str]:
        """Format ACL dict[str, object] to generic string."""
        if "raw" in acl_dict:
            return FlextCore.Result[str].ok(str(acl_dict["raw"]))
        return FlextCore.Result[str].fail(
            "Generic ACL formatting requires raw ACL string"
        )

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @override
    def add_entry(
        self,
        connection: Connection,
        entry: FlextLdifModels.Entry,
    ) -> FlextCore.Result[bool]:
        """Add entry to generic LDAP server."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[bool].fail("Connection not bound")

            success = connection.add(
                str(entry.dn),
                attributes=entry.attributes,
            )

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.DictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextCore.Result[bool].fail(f"Add entry failed: {error_msg}")

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            self.logger.exception("Add entry error", extra={"error": str(e)})
            return FlextCore.Result[bool].fail(f"Add entry failed: {e}")

    @override
    def modify_entry(
        self,
        connection: Connection,
        dn: str,
        modifications: FlextCore.Types.Dict,
    ) -> FlextCore.Result[bool]:
        """Modify entry in generic LDAP server."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[bool].fail("Connection not bound")

            ldap3_mods: dict[str, list[tuple[str, FlextCore.Types.List]]] = {}
            for attr, value in modifications.items():
                values = value if isinstance(value, list) else [value]
                ldap3_mods[attr] = [(MODIFY_REPLACE, values)]

            success = connection.modify(dn, ldap3_mods)

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.DictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextCore.Result[bool].fail(f"Modify entry failed: {error_msg}")

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            self.logger.exception("Modify entry error", extra={"error": str(e)})
            return FlextCore.Result[bool].fail(f"Modify entry failed: {e}")

    @override
    def delete_entry(
        self,
        connection: Connection,
        dn: str,
    ) -> FlextCore.Result[bool]:
        """Delete entry from generic LDAP server."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[bool].fail("Connection not bound")

            success = connection.delete(dn)

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.DictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextCore.Result[bool].fail(f"Delete entry failed: {error_msg}")

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            self.logger.exception("Delete entry error", extra={"error": str(e)})
            return FlextCore.Result[bool].fail(f"Delete entry failed: {e}")

    @override
    def normalize_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Normalize entry for generic LDAP server."""
        return FlextCore.Result[FlextLdifModels.Entry].ok(entry)

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @override
    def get_max_page_size(self) -> int:
        """Generic LDAP max page size."""
        return 1000

    @override
    def supports_paged_results(self) -> bool:
        """Assume generic LDAP supports paged results."""
        return True

    @override
    def supports_vlv(self) -> bool:
        """Generic LDAP does not typically support VLV."""
        return False

    @override
    def search_with_paging(
        self,
        connection: Connection,
        base_dn: str,
        search_filter: str,
        attributes: FlextCore.Types.StringList | None = None,
        scope: str = "subtree",
        page_size: int = 100,
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Execute paged search on generic LDAP server.

        Args:
            connection: Active LDAP connection
            base_dn: Search base DN
            search_filter: LDAP search filter
            attributes: Attributes to retrieve
            scope: Search scope (base, level, or subtree)
            page_size: Page size for results

        Returns:
            FlextCore.Result containing list of entries

        """
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[list[FlextLdapModels.Entry]].fail(
                    "Connection not bound",
                )

            # Convert scope string to ldap3 constant
            scope_map = {
                "base": BASE,
                "level": LEVEL,
                "subtree": SUBTREE,
            }
            search_scope = scope_map.get(scope.lower(), SUBTREE)

            entry_generator = connection.extend.standard.paged_search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attributes or ["*"],
                paged_size=page_size,
                generator=True,
            )

            adapter = FlextLdapEntryAdapter()
            entries: list[FlextLdifModels.Entry] = []

            for ldap3_entry in entry_generator:
                if "dn" in ldap3_entry and "attributes" in ldap3_entry:
                    entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                    if entry_result.is_success:
                        entries.append(entry_result.unwrap())

            # Cast LDIF entries to LDAP entries - they have compatible structure
            return FlextCore.Result[list[FlextLdapModels.Entry]].ok(
                cast("list[FlextLdapModels.Entry]", entries),
            )

        except Exception as e:
            self.logger.exception("Paged search error", extra={"error": str(e)})
            return FlextCore.Result[list[FlextLdapModels.Entry]].fail(
                f"Paged search failed: {e}",
            )

    # =========================================================================
    # ROOT DSE OPERATIONS
    # =========================================================================

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Get Root DSE attributes for generic server."""
        try:
            # Use standard Root DSE search
            result = connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*"],
                size_limit=1,
            )

            if result:
                # Extract attributes from the single result
                if hasattr(result[0], "entry_attributes"):
                    attrs = dict[str, object](result[0].entry_attributes)
                else:
                    attrs = {}

                return FlextCore.Result[FlextCore.Types.Dict].ok(attrs)
            return FlextCore.Result[FlextCore.Types.Dict].fail("No Root DSE found")

        except Exception as e:
            self.logger.exception("Root DSE retrieval error", extra={"error": str(e)})
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Root DSE retrieval failed: {e}",
            )

    @override
    def detect_server_type_from_root_dse(self, root_dse: FlextCore.Types.Dict) -> str:
        """Detect server type from Root DSE attributes."""
        # Check for common vendor identifiers
        if "vendorName" in root_dse:
            vendor = str(root_dse["vendorName"]).lower()
            if "oracle" in vendor:
                return "oracle-oid"
            if "openldap" in vendor:
                return "openldap2"
            if "microsoft" in vendor or "windows" in vendor:
                return "active-directory"
            if "novell" in vendor or "edir" in vendor:
                return "edir"
            if "ibm" in vendor:
                return "ibm-tivoli"
            if "unboundid" in vendor:
                return "unboundid"
            if "forgerock" in vendor:
                return "forgerock"

        # Check for specific attributes
        if "configContext" in root_dse:
            return "oracle-oid"

        # Default to generic
        return "generic"

    @override
    def get_supported_controls(
        self,
        connection: Connection,
    ) -> FlextCore.Result[FlextCore.Types.StringList]:
        """Get supported controls for generic server."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[FlextCore.Types.StringList].fail(
                    "Connection not bound"
                )

            # For generic servers, return standard LDAP controls
            standard_controls = [
                "1.2.840.113556.1.4.319",  # pagedResults
                "1.2.840.113556.1.4.473",  # sortRequest/sortResponse
                "2.16.840.1.113730.3.4.2",  # ManageDsaIT
                "1.3.6.1.4.1.1466.20037",  # StartTLS
            ]

            return FlextCore.Result[FlextCore.Types.StringList].ok(standard_controls)

        except Exception as e:
            self.logger.exception("Control retrieval error", extra={"error": str(e)})
            return FlextCore.Result[FlextCore.Types.StringList].fail(
                f"Control retrieval failed: {e}"
            )

    @override
    def normalize_entry_for_server(
        self,
        entry: FlextLdapModels.Entry | FlextLdifModels.Entry,
        target_server_type: str | None = None,
    ) -> FlextCore.Result[FlextLdapModels.Entry]:
        """Normalize entry for generic server.

        Args:
            entry: Entry to normalize (accepts both LDAP and LDIF entry types)
            target_server_type: Target server type (unused for generic)

        Returns:
            FlextCore.Result containing normalized entry

        """
        try:
            # For generic server, just return the entry as-is
            # Cast to FlextLdapModels.Entry since both types have compatible structure
            return FlextCore.Result[FlextLdapModels.Entry].ok(
                cast("FlextLdapModels.Entry", entry),
            )

        except Exception as e:
            self.logger.exception("Entry normalization error", extra={"error": str(e)})
            return FlextCore.Result[FlextLdapModels.Entry].fail(
                f"Entry normalization failed: {e}",
            )

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str | None = None,
    ) -> FlextCore.Result[bool]:
        """Validate entry for generic server."""
        try:
            # For generic server, perform basic validation
            if not entry.dn:
                return FlextCore.Result[bool].fail("Entry must have a DN")

            if not entry.attributes:
                return FlextCore.Result[bool].fail("Entry must have attributes")

            # Check for required attributes based on object classes
            object_classes = entry.attributes.get("objectClass", [])
            if not object_classes:
                return FlextCore.Result[bool].fail(
                    "Entry must have objectClass attribute"
                )

            # For generic server, we assume the entry is valid if it has DN and attributes
            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            self.logger.exception("Entry validation error", extra={"error": str(e)})
            return FlextCore.Result[bool].fail(f"Entry validation failed: {e}")
