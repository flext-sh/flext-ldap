"""Oracle Unified Directory (OUD) server operations implementation.

Complete implementation for Oracle OUD with ds-privilege-name ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any, override

from flext_core import FlextResult
from flext_ldap.servers.base_operations import BaseServerOperations
from flext_ldif import FlextLdifModels


class OracleOUDOperations(BaseServerOperations):
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
    def get_default_port(self, use_ssl: bool = False) -> int:
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
    def discover_schema(self, connection: Any) -> FlextResult[dict[str, Any]]:
        """Discover schema from Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[dict[str, Any]].fail("Connection not bound")

            success = connection.search(
                search_base=self.get_schema_dn(),
                search_filter="(objectClass=*)",
                attributes=["objectClasses", "attributeTypes", "ldapSyntaxes"],
            )

            if not success or not connection.entries:
                return FlextResult[dict[str, Any]].fail("Schema discovery failed")

            entry = connection.entries[0]
            schema_data: dict[str, Any] = {
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

            return FlextResult[dict[str, Any]].ok(schema_data)

        except Exception as e:
            self._logger.error("Schema discovery error", extra={"error": str(e)})
            return FlextResult[dict[str, Any]].fail(f"Schema discovery failed: {e}")

    @override
    def parse_object_class(self, object_class_def: str) -> FlextResult[dict[str, Any]]:
        """Parse Oracle OUD objectClass definition."""
        try:
            return FlextResult[dict[str, Any]].ok(
                {
                    "definition": object_class_def,
                    "server_type": "oud",
                }
            )
        except Exception as e:
            return FlextResult[dict[str, Any]].fail(f"Parse failed: {e}")

    @override
    def parse_attribute_type(self, attribute_def: str) -> FlextResult[dict[str, Any]]:
        """Parse Oracle OUD attributeType definition."""
        try:
            return FlextResult[dict[str, Any]].ok(
                {
                    "definition": attribute_def,
                    "server_type": "oud",
                }
            )
        except Exception as e:
            return FlextResult[dict[str, Any]].fail(f"Parse failed: {e}")

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
    def get_acls(self, connection: Any, dn: str) -> FlextResult[list[dict[str, Any]]]:
        """Get ds-privilege-name ACLs from Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[list[dict[str, Any]]].fail("Connection not bound")

            success = connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["ds-privilege-name"],
            )

            if not success or not connection.entries:
                return FlextResult[list[dict[str, Any]]].ok([])

            entry = connection.entries[0]
            # Handle attribute with hyphen in name
            acl_attr = getattr(entry, "ds-privilege-name", None)
            acl_values = acl_attr.values if acl_attr else []

            acls: list[dict[str, Any]] = []
            for acl_str in acl_values:
                parse_result = self.parse_acl(str(acl_str))
                if parse_result.is_success:
                    acls.append(parse_result.unwrap())

            return FlextResult[list[dict[str, Any]]].ok(acls)

        except Exception as e:
            self._logger.error("Get ACLs error", extra={"error": str(e)})
            return FlextResult[list[dict[str, Any]]].fail(f"Get ACLs failed: {e}")

    @override
    def set_acls(
        self, connection: Any, dn: str, acls: list[dict[str, Any]]
    ) -> FlextResult[bool]:
        """Set ds-privilege-name ACLs on Oracle OUD."""
        try:
            from ldap3 import MODIFY_REPLACE

            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            formatted_acls: list[str] = []
            for acl in acls:
                format_result = self.format_acl(acl)
                if format_result.is_failure:
                    return FlextResult[bool].fail(
                        format_result.error or "ACL format failed"
                    )
                formatted_acls.append(format_result.unwrap())

            success = connection.modify(
                dn,
                {"ds-privilege-name": [(MODIFY_REPLACE, formatted_acls)]},
            )

            if not success:
                error_msg = connection.result.get("description", "Unknown error")
                return FlextResult[bool].fail(f"Set ACLs failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.error("Set ACLs error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Set ACLs failed: {e}")

    @override
    def parse_acl(self, acl_string: str) -> FlextResult[dict[str, Any]]:
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
            acl_dict: dict[str, Any] = {
                "raw": acl_string,
                "format": "oracle",
                "server_type": "oud",
            }

            # ds-privilege-name contains privilege identifiers
            privilege_name = acl_string.strip()
            acl_dict["privilege"] = privilege_name

            # Map common privileges to categories
            if privilege_name in ("config-read", "config-write"):
                acl_dict["category"] = "configuration"
            elif privilege_name in ("password-reset", "password-modify"):
                acl_dict["category"] = "password"
            elif privilege_name in ("proxied-auth", "bypass-acl"):
                acl_dict["category"] = "administrative"
            elif privilege_name in ("privilege-change", "update-schema"):
                acl_dict["category"] = "management"
            else:
                acl_dict["category"] = "custom"

            return FlextResult[dict[str, Any]].ok(acl_dict)

        except Exception as e:
            return FlextResult[dict[str, Any]].fail(f"Oracle OUD ACL parse failed: {e}")

    @override
    def format_acl(self, acl_dict: dict[str, Any]) -> FlextResult[str]:
        """Format ACL dict to ds-privilege-name string for Oracle OUD.

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
                return FlextResult[str].ok(acl_dict["privilege"])

            # Default fallback
            return FlextResult[str].fail(
                "Oracle OUD ACL formatting requires 'privilege' or 'raw' field"
            )

        except Exception as e:
            return FlextResult[str].fail(f"Oracle OUD ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @override
    def add_entry(
        self, connection: Any, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Add entry to Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            norm_result = self.normalize_entry(entry)
            if norm_result.is_failure:
                return FlextResult[bool].fail(
                    norm_result.error or "Normalization failed"
                )

            normalized_entry = norm_result.unwrap()

            success = connection.add(
                str(normalized_entry.dn),
                attributes=normalized_entry.attributes,
            )

            if not success:
                error_msg = connection.result.get("description", "Unknown error")
                return FlextResult[bool].fail(f"Add entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.error("Add entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    @override
    def modify_entry(
        self, connection: Any, dn: str, modifications: dict[str, Any]
    ) -> FlextResult[bool]:
        """Modify entry in Oracle OUD."""
        try:
            from ldap3 import MODIFY_REPLACE

            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            ldap3_mods: dict[str, list[tuple[int, list[Any]]]] = {}
            for attr, value in modifications.items():
                values: list[Any] = value if isinstance(value, list) else [value]
                ldap3_mods[attr] = [(int(MODIFY_REPLACE), values)]

            success = connection.modify(dn, ldap3_mods)

            if not success:
                error_msg = connection.result.get("description", "Unknown error")
                return FlextResult[bool].fail(f"Modify entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.error("Modify entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    @override
    def delete_entry(self, connection: Any, dn: str) -> FlextResult[bool]:
        """Delete entry from Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            success = connection.delete(dn)

            if not success:
                error_msg = connection.result.get("description", "Unknown error")
                return FlextResult[bool].fail(f"Delete entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.error("Delete entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    @override
    def normalize_entry(
        self, entry: FlextLdifModels.Entry
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
        connection: Any,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute paged search on Oracle OUD."""
        try:
            if not connection or not connection.bound:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "Connection not bound"
                )

            from ldap3 import SUBTREE

            entry_generator = connection.extend.standard.paged_search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes or ["*"],
                paged_size=page_size,
                generator=True,
            )

            from flext_ldap.entry_adapter import FlextLdapEntryAdapter

            adapter = FlextLdapEntryAdapter()
            entries: list[FlextLdifModels.Entry] = []

            for ldap3_entry in entry_generator:
                if "dn" in ldap3_entry and "attributes" in ldap3_entry:
                    entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                    if entry_result.is_success:
                        entries.append(entry_result.unwrap())

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except Exception as e:
            self._logger.error("Paged search error", extra={"error": str(e)})
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Paged search failed: {e}"
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
        if privilege in ("config-read", "config-write"):
            return "configuration"
        elif privilege in ("password-reset", "password-modify"):
            return "password"
        elif privilege in ("proxied-auth", "bypass-acl"):
            return "administrative"
        elif privilege in ("privilege-change", "update-schema"):
            return "management"
        elif privilege in ("ldif-import", "ldif-export"):
            return "data-management"
        elif privilege in ("backend-backup", "backend-restore"):
            return "maintenance"
        else:
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
