"""Generic LDAP server operations stub.

Stub implementation for generic/unknown LDAP servers - basic operations only.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult, FlextTypes
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
    def get_bind_mechanisms(self) -> FlextTypes.StringList:
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
    ) -> FlextResult[FlextTypes.Dict]:
        """Discover schema from generic LDAP server."""
        try:
            if not connection or not connection.bound:
                return FlextResult[FlextTypes.Dict].fail("Connection not bound")

            success = connection.search(
                search_base=self.get_schema_dn(),
                search_filter="(objectClass=*)",
                attributes=["objectClasses", "attributeTypes"],
            )

            if not success or not connection.entries:
                self.logger.warning("Generic schema discovery failed - using defaults")
                return FlextResult[FlextTypes.Dict].ok({
                    "object_classes": [],
                    "attribute_types": [],
                    "server_type": "generic",
                })

            entry = connection.entries[0]
            schema_data: FlextTypes.Dict = {
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

            return FlextResult[FlextTypes.Dict].ok(schema_data)

        except Exception as e:
            self.logger.warning(
                "Generic schema discovery error",
                extra={"error": str(e)},
            )
            return FlextResult[FlextTypes.Dict].ok({
                "object_classes": [],
                "attribute_types": [],
                "server_type": "generic",
            })

    @override
    def parse_object_class(self, object_class_def: str) -> FlextResult[FlextTypes.Dict]:
        """Parse generic objectClass definition."""
        return FlextResult[FlextTypes.Dict].ok({
            "definition": object_class_def,
            "server_type": "generic",
        })

    @override
    def parse_attribute_type(self, attribute_def: str) -> FlextResult[FlextTypes.Dict]:
        """Parse generic attributeType definition."""
        return FlextResult[FlextTypes.Dict].ok({
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
    ) -> FlextResult[list[FlextTypes.Dict]]:
        """Get ACLs from generic LDAP server."""
        self.logger.warning("Generic ACL retrieval - may not work on all servers")
        return FlextResult[list[FlextTypes.Dict]].ok([])

    @override
    def set_acls(
        self,
        connection: Connection,
        dn: str,
        acls: list[FlextTypes.Dict],
    ) -> FlextResult[bool]:
        """Set ACLs on generic LDAP server."""
        return FlextResult[bool].fail(
            "Generic LDAP ACL setting not supported - implement server-specific operations",
        )

    @override
    def parse_acl(self, acl_string: str) -> FlextResult[FlextTypes.Dict]:
        """Parse generic ACL string."""
        return FlextResult[FlextTypes.Dict].ok({
            "raw": acl_string,
            "format": "generic",
            "server_type": "generic",
        })

    @override
    def format_acl(self, acl_dict: FlextTypes.Dict) -> FlextResult[str]:
        """Format ACL dict[str, object] to generic string."""
        if "raw" in acl_dict:
            return FlextResult[str].ok(str(acl_dict["raw"]))
        return FlextResult[str].fail("Generic ACL formatting requires raw ACL string")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @override
    def add_entry(
        self,
        connection: Connection,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[bool]:
        """Add entry to generic LDAP server."""
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # Extract objectClass from entry
            attrs = entry.attributes.attributes
            object_class = (
                attrs["objectClass"].values if "objectClass" in attrs else ["top"]
            )

            # Convert attributes to dict format for ldap3
            ldap3_attrs: dict[str, list[str]] = {}
            for attr_name, attr_value in attrs.items():
                if attr_name != "objectClass":  # Skip objectClass (passed separately)
                    ldap3_attrs[attr_name] = [str(v) for v in attr_value.values]

            # ldap3 library has incomplete type stubs; external library limitation
            success = connection.add(
                str(entry.dn),
                object_class,
                attributes=ldap3_attrs or None,
            )

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.DictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextResult[bool].fail(f"Add entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Add entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    @override
    def modify_entry(
        self,
        connection: Connection,
        dn: str,
        modifications: FlextTypes.Dict,
    ) -> FlextResult[bool]:
        """Modify entry in generic LDAP server."""
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # Convert modifications to ldap3 format
            ldap3_mods: dict[str, list[tuple[object, list[str] | str]]] = {}
            for attr, value in modifications.items():
                values = value if isinstance(value, list) else [value]
                # Convert all values to strings
                str_values: list[str] | str = [str(v) for v in values]
                ldap3_mods[attr] = cast(
                    "list[tuple[object, list[str] | str]]",
                    [(MODIFY_REPLACE, str_values)],
                )

            # ldap3 library has incomplete type stubs; external library limitation
            success = connection.modify(
                dn, cast("dict[str, list[tuple[int, list[str] | str]]]", ldap3_mods)
            )

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.DictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextResult[bool].fail(f"Modify entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Modify entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    @override
    def delete_entry(
        self,
        connection: Connection,
        dn: str,
    ) -> FlextResult[bool]:
        """Delete entry from generic LDAP server."""
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # ldap3 library has incomplete type stubs; external library limitation
            success = connection.delete(dn)

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.DictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextResult[bool].fail(f"Delete entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Delete entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    @override
    def normalize_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for generic LDAP server."""
        return FlextResult[FlextLdifModels.Entry].ok(entry)

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
        attributes: FlextTypes.StringList | None = None,
        scope: str = "subtree",
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Execute paged search on generic LDAP server.

        Args:
            connection: Active LDAP connection
            base_dn: Search base DN
            search_filter: LDAP search filter
            attributes: Attributes to retrieve
            scope: Search scope (base, level, or subtree)
            page_size: Page size for results

        Returns:
            FlextResult containing list of entries

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
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
            return FlextResult[list[FlextLdapModels.Entry]].ok(
                cast("list[FlextLdapModels.Entry]", entries),
            )

        except Exception as e:
            self.logger.exception("Paged search error", extra={"error": str(e)})
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"Paged search failed: {e}",
            )

    # =========================================================================
    # ROOT DSE OPERATIONS
    # =========================================================================

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[FlextTypes.Dict]:
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

            if result and connection.entries:
                # Extract attributes from the single entry
                entry = connection.entries[0]
                attrs: FlextTypes.Dict = {}
                for attr in entry.entry_attributes:
                    attrs[attr] = entry[attr].value

                return FlextResult[FlextTypes.Dict].ok(attrs)
            return FlextResult[FlextTypes.Dict].fail("No Root DSE found")

        except Exception as e:
            self.logger.exception("Root DSE retrieval error", extra={"error": str(e)})
            return FlextResult[FlextTypes.Dict].fail(
                f"Root DSE retrieval failed: {e}",
            )

    @override
    def detect_server_type_from_root_dse(self, root_dse: FlextTypes.Dict) -> str:
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
    ) -> FlextResult[FlextTypes.StringList]:
        """Get supported controls for generic server."""
        try:
            if not connection or not connection.bound:
                return FlextResult[FlextTypes.StringList].fail("Connection not bound")

            # For generic servers, return standard LDAP controls
            standard_controls = [
                "1.2.840.113556.1.4.319",  # pagedResults
                "1.2.840.113556.1.4.473",  # sortRequest/sortResponse
                "2.16.840.1.113730.3.4.2",  # ManageDsaIT
                "1.3.6.1.4.1.1466.20037",  # StartTLS
            ]

            return FlextResult[FlextTypes.StringList].ok(standard_controls)

        except Exception as e:
            self.logger.exception("Control retrieval error", extra={"error": str(e)})
            return FlextResult[FlextTypes.StringList].fail(
                f"Control retrieval failed: {e}"
            )

    @override
    def normalize_entry_for_server(
        self,
        entry: FlextLdapModels.Entry | FlextLdifModels.Entry,
        target_server_type: str | None = None,
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Normalize entry for generic server.

        Args:
            entry: Entry to normalize (accepts both LDAP and LDIF entry types)
            target_server_type: Target server type (unused for generic)

        Returns:
            FlextResult containing normalized entry

        """
        try:
            # For generic server, just return the entry as-is
            # Cast to FlextLdapModels.Entry since both types have compatible structure
            return FlextResult[FlextLdapModels.Entry].ok(
                cast("FlextLdapModels.Entry", entry),
            )

        except Exception as e:
            self.logger.exception("Entry normalization error", extra={"error": str(e)})
            return FlextResult[FlextLdapModels.Entry].fail(
                f"Entry normalization failed: {e}",
            )

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for generic server."""
        try:
            # For generic server, perform basic validation
            if not entry.dn:
                return FlextResult[bool].fail("Entry must have a DN")

            if not entry.attributes:
                return FlextResult[bool].fail("Entry must have attributes")

            # Check for required attributes based on object classes
            object_classes = entry.attributes.get("objectClass", [])
            if not object_classes:
                return FlextResult[bool].fail("Entry must have objectClass attribute")

            # For generic server, we assume the entry is valid if it has DN and attributes
            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Entry validation error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Entry validation failed: {e}")
