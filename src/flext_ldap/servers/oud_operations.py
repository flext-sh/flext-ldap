"""Oracle Unified Directory (OUD) server operations implementation.

Complete implementation for Oracle OUD with ds-privilege-name ACLs.

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


class FlextLdapServersOUDOperations(FlextLdapServersBaseOperations):
    """Complete Oracle OUD operations implementation.

    Oracle OUD Features:
    - Based on 389 Directory Server
    - ds-privilege-name ACL attribute
    - cn=schema for schema discovery
    - Modern LDAP features
    """

    def __init__(self) -> None:
        """Initialize Oracle OUD operations."""
        super().__init__(server_type="oud")

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    @override
    def get_default_port(self, *, use_ssl: bool = False) -> int:
        """Get default port for Oracle OUD."""
        return 636 if use_ssl else 389

    @override
    def supports_start_tls(self) -> bool:
        """Oracle OUD supports START_TLS."""
        return True

    @override
    def get_bind_mechanisms(self) -> list[str]:
        """Get supported BIND mechanisms."""
        return [
            "SIMPLE",
            "SASL/EXTERNAL",
            "SASL/DIGEST-MD5",
            "SASL/GSSAPI",
            "SASL/PLAIN",
        ]

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """Oracle OUD uses cn=schema."""
        return "cn=schema"

    @override
    def discover_schema(self, connection: Connection) -> FlextResult[dict[str, object]]:
        """Discover schema from Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[dict[str, object]].fail("Connection not bound")

            success = connection.search(
                search_base=self.get_schema_dn(),
                search_filter="(objectClass=*)",
                attributes=["objectClasses", "attributeTypes", "ldapSyntaxes"],
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
                "server_type": "oud",
            }

            return FlextResult[dict[str, object]].ok(schema_data)

        except Exception as e:
            self.logger.exception("Schema discovery error", extra={"error": str(e)})
            return FlextResult[dict[str, object]].fail(f"Schema discovery failed: {e}")

    @override
    def parse_object_class(
        self, object_class_def: str
    ) -> FlextResult[dict[str, object]]:
        """Parse Oracle OUD objectClass definition."""
        try:
            return FlextResult[dict[str, object]].ok({
                "definition": object_class_def,
                "server_type": "oud",
            })
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Parse failed: {e}")

    @override
    def parse_attribute_type(
        self, attribute_def: str
    ) -> FlextResult[dict[str, object]]:
        """Parse Oracle OUD attributeType definition."""
        try:
            return FlextResult[dict[str, object]].ok({
                "definition": attribute_def,
                "server_type": "oud",
            })
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Parse failed: {e}")

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @override
    def get_acl_attribute_name(self) -> str:
        """Oracle OUD uses ds-privilege-name attribute."""
        return "ds-privilege-name"

    @override
    def get_acl_format(self) -> str:
        """Oracle OUD ACL format identifier."""
        return "oracle"

    @override
    def get_acls(
        self,
        connection: Connection,
        dn: str,
    ) -> FlextResult[list[dict[str, object]]]:
        """Get ds-privilege-name ACLs from Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[list[dict[str, object]]].fail("Connection not bound")

            success = connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["ds-privilege-name"],
            )

            if not success or not connection.entries:
                return FlextResult[list[dict[str, object]]].ok([])

            entry = connection.entries[0]
            # Handle attribute with hyphen in name
            acl_attr = getattr(entry, "ds-privilege-name", None)
            acl_values = acl_attr.values if acl_attr else []

            acls: list[dict[str, object]] = []
            for acl_str in acl_values:
                parse_result = self.parse_acl(str(acl_str))
                if parse_result.is_success:
                    acls.append(parse_result.unwrap())

            return FlextResult[list[dict[str, object]]].ok(acls)

        except Exception as e:
            self.logger.exception("Get ACLs error", extra={"error": str(e)})
            return FlextResult[list[dict[str, object]]].fail(f"Get ACLs failed: {e}")

    @override
    def set_acls(
        self,
        connection: Connection,
        dn: str,
        acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set ds-privilege-name ACLs on Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            formatted_acls: list[str] = []
            for acl in acls:
                format_result = self.format_acl(acl)
                if format_result.is_failure:
                    return FlextResult[bool].fail(
                        format_result.error or "ACL format failed",
                    )
                formatted_acls.append(format_result.unwrap())

            # ldap3 library has incomplete type stubs; external library limitation
            success = connection.modify(
                dn,
                {"ds-privilege-name": [(MODIFY_REPLACE, formatted_acls)]},
            )

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.LdapDictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextResult[bool].fail(f"Set ACLs failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Set ACLs error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Set ACLs failed: {e}")

    @override
    def parse_acl(self, acl_string: str) -> FlextResult[dict[str, object]]:
        """Parse ds-privilege-name ACL string for Oracle OUD.

        Oracle OUD ACL format (ds-privilege-name):
        Privilege-based access control using named privileges.

        Common privileges:
        - config-read: Read configuration
        - config-write: Modify configuration
        - password-reset: Reset user passwords
        - privilege-change: Modify privileges
        - proxied-auth: Proxy authentication
        - bypass-acl: Bypass access control

        Args:
            acl_string: ds-privilege-name value

        Returns:
            FlextResult containing parsed ACL with structure:
            {
                "raw": original string,
                "format": "oracle",
                "server_type": "oud",
                "privilege": privilege name
            }

        """
        try:
            acl_dict: dict[str, object] = {
                "raw": acl_string,
                "format": "oracle",
                "server_type": "oud",
            }

            # ds-privilege-name contains privilege identifiers
            privilege_name = acl_string.strip()
            acl_dict["privilege"] = privilege_name

            # Map common privileges to categories
            if privilege_name in {"config-read", "config-write"}:
                acl_dict["category"] = "configuration"
            elif privilege_name in {"password-reset", "password-modify"}:
                acl_dict["category"] = "password"
            elif privilege_name in {"proxied-auth", "bypass-acl"}:
                acl_dict["category"] = "administrative"
            elif privilege_name in {"privilege-change", "update-schema"}:
                acl_dict["category"] = "management"
            else:
                acl_dict["category"] = "custom"

            return FlextResult[dict[str, object]].ok(acl_dict)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Oracle OUD ACL parse failed: {e}",
            )

    @override
    def format_acl(self, acl_dict: dict[str, object]) -> FlextResult[str]:
        """Format ACL dict[str, object] to ds-privilege-name string for Oracle OUD.

        Args:
            acl_dict: ACL dictionary with structure:
            {
                "privilege": privilege name,
                OR "raw": raw privilege string
            }

        Returns:
            FlextResult containing formatted privilege string

        Examples:
            - config-read
            - password-reset
            - bypass-acl

        """
        try:
            # Use raw if available
            if "raw" in acl_dict:
                return FlextResult[str].ok(str(acl_dict["raw"]))

            # Use privilege name if available
            if "privilege" in acl_dict:
                return FlextResult[str].ok(str(acl_dict["privilege"]))

            # Default fallback
            return FlextResult[str].fail(
                "Oracle OUD ACL formatting requires 'privilege' or 'raw' field",
            )

        except Exception as e:
            return FlextResult[str].fail(f"Oracle OUD ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @override
    def add_entry(
        self,
        connection: Connection,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[bool]:
        """Add entry to Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

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
            for attr_name, attr_value in attrs.items():
                if attr_name != "objectClass":  # Skip objectClass (passed separately)
                    ldap3_attrs[attr_name] = [str(v) for v in attr_value.values]

            # ldap3 library has incomplete type stubs; external library limitation
            success = connection.add(
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
            self.logger.exception("Add entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    @override
    def modify_entry(
        self,
        connection: Connection,
        dn: str,
        modifications: dict[str, object],
    ) -> FlextResult[bool]:
        """Modify entry in Oracle OUD."""
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
            self.logger.exception("Modify entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    @override
    def delete_entry(self, connection: Connection, dn: str) -> FlextResult[bool]:
        """Delete entry from Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # ldap3 library has incomplete type stubs; external library limitation
            success = connection.delete(dn)

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.LdapDictKeys.DESCRIPTION,
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
        """Normalize entry for Oracle OUD."""
        return FlextResult[FlextLdifModels.Entry].ok(entry)

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @override
    def get_max_page_size(self) -> int:
        """Oracle OUD max page size."""
        return 1000

    @override
    def supports_paged_results(self) -> bool:
        """Oracle OUD supports paged results."""
        return True

    @override
    def supports_vlv(self) -> bool:
        """Oracle OUD supports VLV."""
        return True

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
        """Execute paged search on Oracle OUD.

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
            self.logger.exception("Paged search error", extra={"error": str(e)})
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"Paged search failed: {e}",
            )

    # =========================================================================
    # ORACLE OUD-SPECIFIC OPERATIONS
    # =========================================================================

    def get_oud_version(self) -> str:
        """Get Oracle OUD version identifier.

        Returns:
            Oracle OUD version (e.g., "12c")

        """
        return "12c"  # Default to latest

    def is_based_on_389ds(self) -> bool:
        """Check if OUD is based on 389 Directory Server.

        Returns:
            True - OUD is based on 389 DS

        """
        return True

    def get_oud_privileges(self) -> list[str]:
        """Get Oracle OUD standard privileges.

        Returns:
            List of standard OUD privileges

        """
        return [
            "config-read",
            "config-write",
            "password-reset",
            "password-modify",
            "privilege-change",
            "proxied-auth",
            "bypass-acl",
            "update-schema",
            "ldif-import",
            "ldif-export",
            "backend-backup",
            "backend-restore",
        ]

    def get_privilege_category(self, privilege: str) -> str:
        """Get category for a privilege.

        Args:
            privilege: Privilege name

        Returns:
            Category name

        """
        if privilege in {"config-read", "config-write"}:
            return "configuration"
        if privilege in {"password-reset", "password-modify"}:
            return "password"
        if privilege in {"proxied-auth", "bypass-acl"}:
            return "administrative"
        if privilege in {"privilege-change", "update-schema"}:
            return "management"
        if privilege in {"ldif-import", "ldif-export"}:
            return "data-management"
        if privilege in {"backend-backup", "backend-restore"}:
            return "maintenance"
        return "custom"

    def supports_replication(self) -> bool:
        """Check if OUD supports replication.

        Returns:
            True - OUD supports multi-master replication

        """
        return True

    def get_replication_mechanism(self) -> str:
        """Get replication mechanism for Oracle OUD.

        Returns:
            "multi-master" - OUD uses multi-master replication

        """
        return "multi-master"

    @override
    def detect_server_type_from_root_dse(self, root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE for Oracle OUD."""
        # Oracle OUD specific detection logic
        if "vendorname" in root_dse:
            vendor = str(root_dse["vendorname"]).lower()
            if "oracle" in vendor or "oud" in vendor:
                return "oud"
        return "generic"

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes for Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[dict[str, object]].fail("Connection not established")

            root_dse = connection.server.info
            if not root_dse:
                return FlextResult[dict[str, object]].fail("Root DSE not available")

            return FlextResult[dict[str, object]].ok(dict(root_dse))
        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Failed to get Root DSE: {e}")

    @override
    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported LDAP controls for Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[list[str]].fail("Connection not established")

            controls = connection.server.info.supported_controls
            if controls is None:
                return FlextResult[list[str]].ok([])

            return FlextResult[list[str]].ok(list(controls))
        except Exception as e:
            return FlextResult[list[str]].fail(f"Failed to get supported controls: {e}")

    @override
    def normalize_entry_for_server(
        self,
        entry: FlextLdapModels.Entry | FlextLdifModels.Entry,
        target_server_type: str | None = None,
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Normalize entry for Oracle OUD server.

        Args:
            entry: Entry to normalize (accepts both LDAP and LDIF entry types)
            target_server_type: Ignored for OUD (uses self._server_type)

        Returns:
            FlextResult containing normalized entry

        """
        try:
            # Convert FlextLdapModels.Entry to FlextLdifModels.Entry if needed
            if isinstance(entry, FlextLdapModels.Entry):
                ldif_entry = cast("FlextLdifModels.Entry", entry)
            else:
                ldif_entry = entry

            # Oracle OUD specific normalization
            normalized_entry = ldif_entry.model_copy()

            # Ensure OUD-specific object classes are present
            if "objectClass" not in normalized_entry.attributes.attributes:
                normalized_entry.attributes.attributes["objectClass"] = (
                    FlextLdifModels.AttributeValues(values=["top", "person"])
                )

            # Cast back to FlextLdapModels.Entry for return type
            return FlextResult[FlextLdapModels.Entry].ok(
                cast("FlextLdapModels.Entry", normalized_entry),
            )
        except Exception as e:
            return FlextResult[FlextLdapModels.Entry].fail(
                f"Failed to normalize entry: {e}",
            )

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry compatibility with Oracle OUD."""
        try:
            # Oracle OUD specific validation
            # Convert DistinguishedName to string if needed before strip()
            dn_str = str(entry.dn) if entry.dn else ""
            if not dn_str or not dn_str.strip():
                return FlextResult[bool].fail("Entry DN cannot be empty")

            if not entry.attributes or not entry.attributes.attributes:
                return FlextResult[bool].fail("Entry must have attributes")

            # Check for required object classes
            object_classes = entry.attributes.get("objectClass")
            if not object_classes:
                return FlextResult[bool].fail("Entry must have objectClass attribute")

            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")
