"""Oracle Internet Directory (OID) server operations implementation.

Complete implementation for Oracle OID with orclaci ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from ldap3 import Connection
from flext_ldif import FlextLdifModels

from flext_core import FlextResult, FlextTypes
from flext_ldap.servers.base_operations import FlextLDAPServersBaseOperations


class FlextLDAPServersOIDOperations(FlextLDAPServersBaseOperations):
    """Complete Oracle OID operations implementation.

    Oracle OID Features:
    - orclaci ACL attribute
    - Oracle-specific object classes (orclUserV2, orclContainer)
    - cn=subschemasubentry for schema
    - Proprietary extensions
    """

    def __init__(self) -> None:
        """Initialize Oracle OID operations."""
        super().__init__(server_type="oid")

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    @override
    def get_default_port(self, use_ssl: bool = False) -> int:
        """Get default port for Oracle OID."""
        return 636 if use_ssl else 389

    @override
    def supports_start_tls(self) -> bool:
        """Oracle OID supports START_TLS."""
        return True

    @override
    def get_bind_mechanisms(self) -> FlextTypes.StringList:
        """Get supported BIND mechanisms."""
        return ["SIMPLE", "SASL/EXTERNAL", "SASL/DIGEST-MD5"]

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """Oracle OID uses cn=subschemasubentry."""
        return "cn=subschemasubentry"

    @override
    def discover_schema(self, connection: Connection) -> FlextResult[FlextTypes.Dict]:
        """Discover schema from Oracle OID.

        Args:
            connection: Active ldap3 connection

        Returns:
            FlextResult containing schema information

        """
        try:
            if not connection or not connection.bound:
                return FlextResult[FlextTypes.Dict].fail("Connection not bound")

            success = connection.search(
                search_base=self.get_schema_dn(),
                search_filter="(objectClass=*)",
                attributes=["objectClasses", "attributeTypes"],
            )

            if not success or not connection.entries:
                return FlextResult[FlextTypes.Dict].fail("Schema discovery failed")

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
                "server_type": "oid",
            }

            return FlextResult[FlextTypes.Dict].ok(schema_data)

        except Exception as e:
            self._logger.error("Schema discovery error", extra={"error": str(e)})
            return FlextResult[FlextTypes.Dict].fail(f"Schema discovery failed: {e}")

    @override
    def parse_object_class(self, object_class_def: str) -> FlextResult[FlextTypes.Dict]:
        """Parse Oracle OID objectClass definition."""
        try:
            return FlextResult[FlextTypes.Dict].ok(
                {
                    "definition": object_class_def,
                    "server_type": "oid",
                }
            )
        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Parse failed: {e}")

    @override
    def parse_attribute_type(self, attribute_def: str) -> FlextResult[FlextTypes.Dict]:
        """Parse Oracle OID attributeType definition."""
        try:
            return FlextResult[FlextTypes.Dict].ok(
                {
                    "definition": attribute_def,
                    "server_type": "oid",
                }
            )
        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Parse failed: {e}")

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @override
    def get_acl_attribute_name(self) -> str:
        """Oracle OID uses orclaci attribute."""
        return "orclaci"

    @override
    def get_acl_format(self) -> str:
        """Oracle OID ACL format identifier."""
        return "oracle"

    @override
    def get_acls(
        self, connection: Connection, dn: str
    ) -> FlextResult[list[FlextTypes.Dict]]:
        """Get orclaci ACLs from Oracle OID."""
        try:
            if not connection or not connection.bound:
                return FlextResult[list[FlextTypes.Dict]].fail("Connection not bound")

            success = connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["orclaci"],
            )

            if not success or not connection.entries:
                return FlextResult[list[FlextTypes.Dict]].ok([])

            entry = connection.entries[0]
            acl_values = entry.orclaci.values if hasattr(entry, "orclaci") else []

            acls: list[FlextTypes.Dict] = []
            for acl_str in acl_values:
                parse_result = self.parse_acl(str(acl_str))
                if parse_result.is_success:
                    acls.append(parse_result.unwrap())

            return FlextResult[list[FlextTypes.Dict]].ok(acls)

        except Exception as e:
            self._logger.error("Get ACLs error", extra={"error": str(e)})
            return FlextResult[list[FlextTypes.Dict]].fail(f"Get ACLs failed: {e}")

    @override
    def set_acls(
        self, connection: Connection, dn: str, acls: list[FlextTypes.Dict]
    ) -> FlextResult[bool]:
        """Set orclaci ACLs on Oracle OID."""
        try:
            from ldap3 import MODIFY_REPLACE

            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            formatted_acls: FlextTypes.StringList = []
            for acl in acls:
                format_result = self.format_acl(acl)
                if format_result.is_failure:
                    return FlextResult[bool].fail(
                        format_result.error or "ACL format failed"
                    )
                formatted_acls.append(format_result.unwrap())

            success = connection.modify(
                dn,
                {"orclaci": [(MODIFY_REPLACE, formatted_acls)]},
            )

            if not success:
                error_msg = connection.result.get("description", "Unknown error")
                return FlextResult[bool].fail(f"Set ACLs failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.error("Set ACLs error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Set ACLs failed: {e}")

    @override
    def parse_acl(self, acl_string: str) -> FlextResult[FlextTypes.Dict]:
        """Parse orclaci ACL string for Oracle OID.

        Oracle OID ACL format (orclaci):
        access to entry|attr:<target> by <subject>:<permissions>

        Examples:
        - access to entry by * : browse
        - access to attr:userPassword by self : write
        - access to entry by group="cn=admins,ou=groups" : add, delete, write

        Args:
            acl_string: orclaci ACL string

        Returns:
            FlextResult containing parsed ACL with structure:
            {
                "raw": original string,
                "format": "oracle",
                "server_type": "oid",
                "target_type": "entry" or "attr",
                "target": target specification,
                "subject": access subject,
                "permissions": list of permissions
            }

        """
        try:
            acl_dict: FlextTypes.Dict = {
                "raw": acl_string,
                "format": "oracle",
                "server_type": "oid",
            }

            # Parse Oracle OID syntax: access to <target> by <subject>:<permissions>
            if acl_string.startswith("access to "):
                remainder = acl_string[10:]  # Skip "access to "

                # Split into target and "by" clause
                by_split = remainder.split(" by ", 1)
                target_clause = by_split[0].strip()

                # Parse target (entry or attr:name)
                if target_clause.startswith("attr:"):
                    acl_dict["target_type"] = "attr"
                    acl_dict["target"] = target_clause[5:]  # Skip "attr:"
                elif target_clause == "entry":
                    acl_dict["target_type"] = "entry"
                    acl_dict["target"] = "*"
                else:
                    acl_dict["target_type"] = "entry"
                    acl_dict["target"] = target_clause

                if len(by_split) > 1:
                    # Parse "by <subject>:<permissions>"
                    by_clause = by_split[1].strip()

                    # Split subject and permissions by last ":"
                    if ":" in by_clause:
                        parts = by_clause.rsplit(":", 1)
                        acl_dict["subject"] = parts[0].strip()

                        # Parse permissions (comma-separated)
                        if len(parts) > 1:
                            perms_str = parts[1].strip()
                            permissions = [p.strip() for p in perms_str.split(",")]
                            acl_dict["permissions"] = permissions
                    else:
                        # No explicit permissions
                        acl_dict["subject"] = by_clause
                        acl_dict["permissions"] = ["read"]  # Default

            return FlextResult[FlextTypes.Dict].ok(acl_dict)

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"Oracle OID ACL parse failed: {e}"
            )

    @override
    def format_acl(self, acl_dict: FlextTypes.Dict) -> FlextResult[str]:
        """Format ACL dict to orclaci string for Oracle OID.

        Args:
            acl_dict: ACL dictionary with structure:
            {
                "target_type": "entry" or "attr",
                "target": target specification,
                "subject": access subject,
                "permissions": list of permissions,
                OR "raw": raw ACL string
            }

        Returns:
            FlextResult containing formatted ACL string

        Examples:
            - access to entry by * : browse
            - access to attr:userPassword by self : write

        """
        try:
            # Use raw if available
            if "raw" in acl_dict:
                return FlextResult[str].ok(str(acl_dict["raw"]))

            # Build structured ACL
            parts = ["access to"]

            # Add target
            target_type = acl_dict.get("target_type", "entry")
            target = str(acl_dict.get("target", "*"))

            if target_type == "attr":
                parts.append(f"attr:{target}")
            elif target == "*":
                parts.append("entry")
            else:
                parts.append(target)

            # Add "by" clause
            parts.append("by")

            subject = str(acl_dict.get("subject", "*"))
            parts.append(subject)

            # Add permissions
            permissions = acl_dict.get("permissions", ["read"])
            if permissions and isinstance(permissions, list):
                perms_str = ", ".join(str(p) for p in permissions)
                parts.append(f": {perms_str}")

            return FlextResult[str].ok(" ".join(parts))

        except Exception as e:
            return FlextResult[str].fail(f"Oracle OID ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @override
    def add_entry(
        self, connection: Connection, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Add entry to Oracle OID."""
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
        self, connection: Connection, dn: str, modifications: FlextTypes.Dict
    ) -> FlextResult[bool]:
        """Modify entry in Oracle OID."""
        try:
            from ldap3 import MODIFY_REPLACE

            if not connection or not connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            ldap3_mods: dict[str, list[tuple[int, FlextTypes.List]]] = {}
            for attr, value in modifications.items():
                values: FlextTypes.List = value if isinstance(value, list) else [value]
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
    def delete_entry(self, connection: Connection, dn: str) -> FlextResult[bool]:
        """Delete entry from Oracle OID."""
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
        """Normalize entry for Oracle OID.

        Oracle OID Considerations:
        - May need Oracle-specific object classes (orclUserV2, orclContainer)
        - Handles orclaci ACL attributes
        - Supports Oracle-specific attributes (orclPassword, orclCommonAttribute)

        Args:
            entry: FlextLdif Entry to normalize

        Returns:
            FlextResult containing normalized entry

        """
        try:
            # Access entry attributes
            attributes_dict = entry.attributes.attributes.copy()

            # Ensure objectClass compatibility for Oracle OID
            if "objectClass" in attributes_dict:
                object_class_attr = attributes_dict["objectClass"]
                # Handle both list and AttributeValues types
                if isinstance(object_class_attr, list):
                    object_classes = object_class_attr
                elif hasattr(object_class_attr, "values"):
                    object_classes = object_class_attr.values
                else:
                    object_classes = [str(object_class_attr)]

                # Map standard objectClasses to Oracle equivalents
                mapped_classes = []
                has_person = False
                has_org_person = False

                for oc in object_classes:
                    mapped_classes.append(oc)

                    # Track person-related classes
                    if oc == "person":
                        has_person = True
                    elif oc in ("organizationalPerson", "inetOrgPerson"):
                        has_org_person = True

                # For user entries, consider adding orclUserV2 for extended features
                # (Only if not already present and is a person-like entry)
                if (
                    has_person or has_org_person
                ) and "orclUserV2" not in mapped_classes:
                    # Note: orclUserV2 should only be added if Oracle schema supports it
                    # and entry will have required Oracle attributes
                    pass  # Conservative approach - don't auto-add

                # Update objectClass if changed
                if mapped_classes != object_classes:
                    attributes_dict["objectClass"] = mapped_classes

            # Handle Oracle-specific attribute mappings
            # Map userPassword to orclPassword if Oracle extensions are used
            # (Conservative: keep both for compatibility)

            # Create normalized entry
            normalized_attributes = FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            )
            normalized_entry = FlextLdifModels.Entry(
                dn=entry.dn, attributes=normalized_attributes
            )

            return FlextResult[FlextLdifModels.Entry].ok(normalized_entry)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Oracle OID entry normalization failed: {e}"
            )

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @override
    def get_max_page_size(self) -> int:
        """Oracle OID max page size."""
        return 1000

    @override
    def supports_paged_results(self) -> bool:
        """Oracle OID supports paged results."""
        return True

    @override
    def supports_vlv(self) -> bool:
        """Oracle OID supports VLV."""
        return True

    @override
    def search_with_paging(
        self,
        connection: Connection,
        base_dn: str,
        search_filter: str,
        attributes: FlextTypes.StringList | None = None,
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute paged search on Oracle OID."""
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

            from flext_ldap.entry_adapter import FlextLDAPEntryAdapter

            adapter = FlextLDAPEntryAdapter()
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
    # ORACLE OID-SPECIFIC OPERATIONS
    # =========================================================================

    def get_oracle_version(self) -> str:
        """Get Oracle OID version identifier.

        Returns:
            Oracle OID version (e.g., "11g", "12c")

        """
        return "12c"  # Default to latest

    def supports_oracle_extensions(self) -> bool:
        """Check if Oracle-specific extensions are supported.

        Returns:
            True - Oracle OID supports proprietary extensions

        """
        return True

    def get_oracle_object_classes(self) -> FlextTypes.StringList:
        """Get Oracle-specific object classes.

        Returns:
            List of Oracle object classes

        """
        return [
            "orclUserV2",
            "orclContainer",
            "orclApplicationEntity",
            "orclService",
            "orclSubscriber",
        ]

    def get_oracle_attributes(self) -> FlextTypes.StringList:
        """Get Oracle-specific attributes.

        Returns:
            List of Oracle attributes

        """
        return [
            "orclPassword",
            "orclCommonAttribute",
            "orclGUID",
            "orclIsEnabled",
            "orclPasswordPolicyDN",
            "orclaci",  # ACL attribute
        ]

    def is_oracle_user(self, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is Oracle user (has orclUserV2).

        Args:
            entry: Entry to check

        Returns:
            True if entry has Oracle user object class

        """
        if "objectClass" in entry.attributes.attributes:
            object_class_attr = entry.attributes.attributes["objectClass"]
            # Handle both list and AttributeValues types
            if isinstance(object_class_attr, list):
                object_classes = object_class_attr
            elif hasattr(object_class_attr, "values"):
                object_classes = object_class_attr.values
            else:
                object_classes = [str(object_class_attr)]
            return "orclUserV2" in object_classes
        return False
