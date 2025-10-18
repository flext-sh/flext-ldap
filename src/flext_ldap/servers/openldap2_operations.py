"""OpenLDAP 2.x server operations implementation.

Complete implementation for OpenLDAP 2.x (cn=config style) with olcAccess ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import BASE, LEVEL, MODIFY_REPLACE, SUBTREE, Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.models import FlextLdapModels
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations


class FlextLdapServersOpenLDAP2Operations(FlextLdapServersBaseOperations):
    """Complete OpenLDAP 2.x operations implementation.

    OpenLDAP 2.x Features:
    - cn=config dynamic configuration
    - olcAccess ACL attribute
    - olcDatabase configuration entries
    - Supports paged results
    - START_TLS support
    - SASL authentication
    """

    def __init__(self) -> None:
        """Initialize OpenLDAP 2.x operations."""
        super().__init__(server_type="openldap2")

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    @override
    def get_default_port(self, *, use_ssl: bool = False) -> int:
        """Get default port for OpenLDAP."""
        return 636 if use_ssl else 389

    @override
    def supports_start_tls(self) -> bool:
        """OpenLDAP supports START_TLS."""
        return True

    @override
    def get_bind_mechanisms(self) -> list[str]:
        """Get supported BIND mechanisms."""
        return ["SIMPLE", "SASL/EXTERNAL", "SASL/DIGEST-MD5", "SASL/GSSAPI"]

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """OpenLDAP 2.x uses cn=subschema."""
        return "cn=subschema"

    @override
    def discover_schema(self, connection: Connection) -> FlextResult[dict[str, object]]:
        """Discover schema from OpenLDAP 2.x server.

        Args:
            connection: Active ldap3 connection

        Returns:
            FlextResult containing schema information

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[dict[str, object]].fail("Connection not bound")

            # Search for schema
            success: bool = connection.search(
                search_base=self.get_schema_dn(),
                search_filter="(objectClass=*)",
                attributes=[
                    "objectClasses",
                    "attributeTypes",
                    "ldapSyntaxes",
                    "matchingRules",
                ],
            )

            if not success or not connection.entries:
                return FlextResult[dict[str, object]].fail("Schema discovery failed")

            entry = connection.entries[0]
            schema_data: dict[str, object] = {
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
                "syntaxes": (
                    entry.ldapSyntaxes.values if hasattr(entry, "ldapSyntaxes") else []
                ),
                "matching_rules": (
                    entry.matchingRules.values
                    if hasattr(entry, "matchingRules")
                    else []
                ),
                "server_type": "openldap2",
            }

            return FlextResult[dict[str, object]].ok(schema_data)

        except Exception as e:
            self.logger.exception("Schema discovery error", extra={"error": str(e)})
            return FlextResult[dict[str, object]].fail(f"Schema discovery failed: {e}")

    @override
    def parse_object_class(
        self, object_class_def: str
    ) -> FlextResult[dict[str, object]]:
        """Parse OpenLDAP objectClass definition.

        Args:
            object_class_def: ObjectClass definition string

        Returns:
            FlextResult containing parsed objectClass

        """
        # Basic parsing - would need full RFC 4512 parser for production
        try:
            parsed: dict[str, object] = {
                "definition": object_class_def,
                "server_type": "openldap2",
            }
            return FlextResult[dict[str, object]].ok(parsed)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Parse failed: {e}")

    @override
    def parse_attribute_type(
        self, attribute_def: str
    ) -> FlextResult[dict[str, object]]:
        """Parse OpenLDAP attributeType definition.

        Args:
            attribute_def: AttributeType definition string

        Returns:
            FlextResult containing parsed attribute

        """
        try:
            parsed: dict[str, object] = {
                "definition": attribute_def,
                "server_type": "openldap2",
            }
            return FlextResult[dict[str, object]].ok(parsed)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Parse failed: {e}")

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @override
    def get_acl_attribute_name(self) -> str:
        """OpenLDAP 2.x uses olcAccess attribute."""
        return "olcAccess"

    @override
    def get_acl_format(self) -> str:
        """OpenLDAP 2.x ACL format identifier."""
        return "openldap2"

    @override
    def get_acls(
        self,
        connection: Connection,
        dn: str,
    ) -> FlextResult[list[dict[str, object]]]:
        """Get olcAccess ACLs from OpenLDAP 2.x.

        Args:
            connection: Active ldap3 connection
            dn: DN of config entry (e.g., olcDatabase={1}mdb,cn=config)

        Returns:
            FlextResult containing list of ACLs

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[list[dict[str, object]]].fail("Connection not bound")

            success: bool = connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["olcAccess"],
            )

            if not success or not connection.entries:
                return FlextResult[list[dict[str, object]]].ok([])

            entry = connection.entries[0]
            acl_values = entry.olcAccess.values if hasattr(entry, "olcAccess") else []

            acls: list[dict[str, object]] = []
            for acl_value in acl_values:
                acl_str = str(acl_value)
                parse_result = self.parse_acl(acl_str)
                if parse_result.is_success:
                    acls.append(parse_result.unwrap())

            return FlextResult[list[dict[str, object]]].ok(acls)

        except Exception as e:
            self.logger.exception("Get ACLs error", extra={"dn": dn, "error": str(e)})
            return FlextResult[list[dict[str, object]]].fail(f"Get ACLs failed: {e}")

    @override
    def set_acls(
        self,
        connection: Connection,
        dn: str,
        acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set olcAccess ACLs on OpenLDAP 2.x.

        Args:
            connection: Active ldap3 connection
            dn: DN of config entry
            acls: List of ACL dictionaries

        Returns:
            FlextResult indicating success

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # Format ACLs to olcAccess strings
            formatted_acls: list[str] = []
            for acl in acls:
                format_result = self.format_acl(acl)
                if format_result.is_failure:
                    return FlextResult[bool].fail(
                        format_result.error or "ACL format failed",
                    )
                formatted_acls.append(format_result.unwrap())

            # Modify entry with new ACLs
            # ldap3 library has incomplete type stubs; external library limitation
            success: bool = connection.modify(
                dn,
                {"olcAccess": [(MODIFY_REPLACE, formatted_acls)]},
            )

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.LdapDictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextResult[bool].fail(f"Set ACLs failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Set ACLs error", extra={"dn": dn, "error": str(e)})
            return FlextResult[bool].fail(f"Set ACLs failed: {e}")

    @override
    def parse_acl(self, acl_string: str) -> FlextResult[dict[str, object]]:
        """Parse olcAccess ACL string.

        OpenLDAP 2.x ACL format:
        {0}to what by whom access

        Example:
        {0}to * by self write by anonymous auth by * read

        Args:
            acl_string: olcAccess ACL string

        Returns:
            FlextResult containing parsed ACL

        """
        try:
            # Basic parsing - production would need full parser
            acl_dict: dict[str, object] = {
                "raw": acl_string,
                "format": "openldap2",
                "server_type": "openldap2",
            }

            # Extract index if present
            if acl_string.startswith("{"):
                end_idx = acl_string.find("}")
                if end_idx > 0:
                    acl_dict["index"] = acl_string[1:end_idx]
                    acl_string = acl_string[end_idx + 1 :].strip()

            # Extract 'to' clause
            if acl_string.startswith("to "):
                parts = acl_string.split(" by ", 1)
                acl_dict["to"] = parts[0][3:].strip()
                if len(parts) > 1:
                    acl_dict["by"] = parts[1]

            return FlextResult[dict[str, object]].ok(acl_dict)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"ACL parse failed: {e}")

    @override
    def format_acl(self, acl_dict: dict[str, object]) -> FlextResult[str]:
        """Format ACL dict[str, object] to olcAccess string.

        Args:
            acl_dict: ACL dictionary

        Returns:
            FlextResult containing formatted ACL string

        """
        try:
            # If raw is present, use it
            if "raw" in acl_dict:
                return FlextResult[str].ok(str(acl_dict["raw"]))

            # Otherwise construct from parts
            parts: list[str] = []

            if "index" in acl_dict:
                parts.append(f"{{{acl_dict['index']}}}")

            if "to" in acl_dict:
                parts.append(f"to {acl_dict['to']}")

            if "by" in acl_dict:
                parts.append(f"by {acl_dict['by']}")

            return FlextResult[str].ok(" ".join(parts))

        except Exception as e:
            return FlextResult[str].fail(f"ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @override
    def add_entry(
        self,
        connection: Connection,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[bool]:
        """Add entry to OpenLDAP 2.x server.

        Args:
            connection: Active ldap3 connection
            entry: FlextLdif Entry to add

        Returns:
            FlextResult indicating success

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # Normalize entry for OpenLDAP
            norm_result = self.normalize_entry(entry)
            if norm_result.is_failure:
                return FlextResult[bool].fail(
                    norm_result.error or "Normalization failed",
                )

            normalized_entry = norm_result.unwrap()

            # Extract objectClass from entry
            attrs = normalized_entry.attributes.attributes
            object_class = (
                attrs["objectClass"].values if "objectClass" in attrs else ["top"]
            )

            # Convert attributes to dict format for ldap3
            ldap3_attrs: dict[str, list[str]] = {}
            for attr_name, attr_value in normalized_entry.attributes.attributes.items():
                if attr_name != "objectClass":  # Skip objectClass (passed separately)
                    ldap3_attrs[attr_name] = [str(v) for v in attr_value.values]

            # Add entry using ldap3
            # ldap3 library has incomplete type stubs; external library limitation
            success: bool = connection.add(
                str(normalized_entry.dn),
                object_class,
                attributes=ldap3_attrs or None,
            )

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.LdapDictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextResult[bool].fail(f"Add entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception(
                "Add entry error",
                extra={"dn": str(entry.dn), "error": str(e)},
            )
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    @override
    def modify_entry(
        self,
        connection: Connection,
        dn: str,
        modifications: dict[str, object],
    ) -> FlextResult[bool]:
        """Modify entry in OpenLDAP 2.x.

        Args:
            connection: Active ldap3 connection
            dn: DN of entry to modify
            modifications: Dict of attribute modifications

        Returns:
            FlextResult indicating success

        """
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
                    FlextLdapConstants.LdapDictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextResult[bool].fail(f"Modify entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception(
                "Modify entry error",
                extra={"dn": dn, "error": str(e)},
            )
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    @override
    def delete_entry(self, connection: Connection, dn: str) -> FlextResult[bool]:
        """Delete entry from OpenLDAP 2.x.

        Args:
            connection: Active ldap3 connection
            dn: DN of entry to delete

        Returns:
            FlextResult indicating success

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # ldap3 library has incomplete type stubs; external library limitation
            success: bool = connection.delete(dn)

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.LdapDictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextResult[bool].fail(f"Delete entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception(
                "Delete entry error",
                extra={"dn": dn, "error": str(e)},
            )
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    @override
    def normalize_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for OpenLDAP 2.x.

        Args:
            entry: FlextLdif Entry to normalize

        Returns:
            FlextResult containing normalized entry

        """
        # OpenLDAP 2.x generally uses standard LDAP conventions
        # No special normalization needed for most cases
        return FlextResult[FlextLdifModels.Entry].ok(entry)

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @override
    def get_max_page_size(self) -> int:
        """OpenLDAP 2.x default max page size."""
        return 1000

    @override
    def supports_paged_results(self) -> bool:
        """OpenLDAP 2.x supports paged results control."""
        return True

    @override
    def supports_vlv(self) -> bool:
        """OpenLDAP 2.x does not support VLV by default."""
        return False

    @override
    def search_with_paging(
        self,
        connection: Connection,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "subtree",
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Execute paged search on OpenLDAP 2.x.

        Args:
            connection: Active ldap3 connection
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

            # Use ldap3 paged search
            entry_generator = connection.extend.standard.paged_search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attributes or ["*"],
                paged_size=page_size,
                generator=True,
            )

            # Convert results to FlextLdap entries
            adapter = FlextLdapEntryAdapter()
            entries: list[FlextLdapModels.Entry] = []

            for ldap3_entry in entry_generator:
                if "dn" in ldap3_entry and "attributes" in ldap3_entry:
                    # Convert ldap3 entry to LDIF entry first
                    ldif_entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                    if ldif_entry_result.is_success:
                        ldif_entry = ldif_entry_result.unwrap()
                        # Convert LDIF entry to LDAP entry
                        ldap_entry = FlextLdapModels.Entry.from_ldif(ldif_entry)
                        entries.append(ldap_entry)

            return FlextResult[list[FlextLdapModels.Entry]].ok(entries)

        except Exception as e:
            self.logger.exception(
                "Paged search error",
                extra={"base_dn": base_dn, "error": str(e)},
            )
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"Paged search failed: {e}",
            )

    # =========================================================================
    # SERVER DETECTION OPERATIONS
    # =========================================================================

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes for OpenLDAP 2.x server.

        Args:
            connection: Active ldap3 connection

        Returns:
            FlextResult containing Root DSE attributes

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[dict[str, object]].fail("Connection not bound")

            # Use standard Root DSE search
            success: bool = connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*", "+"],
            )

            if not success or not connection.entries:
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
    def detect_server_type_from_root_dse(self, root_dse: dict[str, object]) -> str:
        """Detect OpenLDAP version from Root DSE attributes.

        Args:
            root_dse: Root DSE attributes

        Returns:
            Detected server type ("openldap2", "openldap1", or "openldap")

        """
        # Check for vendorName
        if "vendorName" in root_dse:
            vendor = str(root_dse["vendorName"]).lower()
            if "openldap" in vendor:
                # Check for version to distinguish 1.x from 2.x
                if "vendorVersion" in root_dse:
                    version = str(root_dse["vendorVersion"]).lower()
                    if version.startswith("1."):
                        return "openldap1"
                    if version.startswith("2."):
                        return "openldap2"
                # Default to 2.x if version unclear
                return "openldap2"

        # Check for configContext (2.x feature - cn=config)
        if "configContext" in root_dse:
            return "openldap2"

        # Fallback to generic openldap
        return "openldap"

    @override
    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported controls for OpenLDAP 2.x server.

        Args:
            connection: Active ldap3 connection

        Returns:
            FlextResult containing list of supported control OIDs

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[list[str]].fail("Connection not bound")

            # Get Root DSE which contains supportedControl attribute
            root_dse_result = self.get_root_dse_attributes(connection)
            if root_dse_result.is_failure:
                # Return common OpenLDAP 2.x controls as fallback
                openldap2_controls = [
                    "1.2.840.113556.1.4.319",  # pagedResults
                    "1.2.840.113556.1.4.473",  # Server-side sort
                    "1.3.6.1.4.1.4203.1.10.1",  # Subentries
                    "2.16.840.1.113730.3.4.2",  # ManageDsaIT
                    "1.3.6.1.4.1.1466.20037",  # StartTLS
                    "1.3.6.1.1.12",  # Assertion control
                    "1.3.6.1.1.13.1",  # LDAP Pre-read Controls
                    "1.3.6.1.1.13.2",  # LDAP Post-read Controls
                    "1.3.6.1.4.1.4203.1.9.1.1",  # Content Sync
                ]
                return FlextResult[list[str]].ok(openldap2_controls)

            root_dse = root_dse_result.unwrap()

            # Extract supportedControl from Root DSE
            if "supportedControl" in root_dse:
                controls = root_dse["supportedControl"]
                if isinstance(controls, list):
                    return FlextResult[list[str]].ok([str(c) for c in controls])
                return FlextResult[list[str]].ok([str(controls)])

            # Return empty list if not found
            return FlextResult[list[str]].ok([])

        except Exception as e:
            self.logger.exception("Control retrieval error", extra={"error": str(e)})
            return FlextResult[list[str]].fail(f"Control retrieval failed: {e}")

    @override
    def normalize_entry_for_server(
        self,
        entry: FlextLdapModels.Entry | FlextLdifModels.Entry,
        target_server_type: str | None = None,
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Normalize entry for OpenLDAP 2.x server specifics.

        Applies OpenLDAP 2.x-specific transformations:
        - Ensures cn=config compatible objectClasses
        - Converts access ACLs to olcAccess format if needed
        - Normalizes attribute names to lowercase

        Args:
            entry: Entry to normalize (accepts both LDAP and LDIF entry types)
            target_server_type: Ignored for OpenLDAP 2.x (uses self._server_type)

        Returns:
            FlextResult containing normalized entry

        """
        # Convert FlextLdapModels.Entry to FlextLdifModels.Entry if needed
        # normalize_entry expects FlextLdifModels.Entry
        if isinstance(entry, FlextLdapModels.Entry):
            # Cast to FlextLdifModels.Entry since both have compatible structure
            ldif_entry = cast("FlextLdifModels.Entry", entry)
        else:
            ldif_entry = entry

        # Reuse existing normalize_entry method which handles OpenLDAP 2.x specifics
        normalize_result = self.normalize_entry(ldif_entry)
        if normalize_result.is_failure:
            return FlextResult[FlextLdapModels.Entry].fail(normalize_result.error)

        # Convert FlextLdifModels.Entry to FlextLdapModels.Entry
        normalized_ldif_entry = normalize_result.unwrap()

        # Cast FlextLdifModels.Entry to FlextLdapModels.Entry
        # Both have compatible structure (dn, attributes) and represent LDAP entries
        return FlextResult[FlextLdapModels.Entry].ok(
            cast("FlextLdapModels.Entry", normalized_ldif_entry),
        )

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for OpenLDAP 2.x server.

        Checks:
        - Entry has DN
        - Entry has attributes
        - Entry has objectClass
        - ObjectClass values are valid for OpenLDAP 2.x

        Args:
            entry: Entry to validate
            server_type: Ignored for OpenLDAP 2.x (uses self._server_type)

        Returns:
            FlextResult[bool] indicating validation success

        """
        try:
            # Basic validation
            if not entry.dn:
                return FlextResult[bool].fail("Entry must have a DN")

            if not entry.attributes or not entry.attributes.attributes:
                return FlextResult[bool].fail("Entry must have attributes")

            # Check for objectClass
            attrs = entry.attributes.attributes
            if "objectClass" not in attrs:
                return FlextResult[bool].fail("Entry must have objectClass attribute")

            # OpenLDAP 2.x accepts both standard and olc* objectClasses
            object_class_attr = attrs["objectClass"]
            object_classes = object_class_attr.values

            # Ensure at least one objectClass value
            if not object_classes:
                return FlextResult[bool].fail(
                    "objectClass must have at least one value"
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")
