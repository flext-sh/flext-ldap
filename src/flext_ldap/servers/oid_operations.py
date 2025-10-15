"""Oracle Internet Directory (OID) server operations implementation.

Complete implementation for Oracle OID with orclaci ACLs.

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


class FlextLdapServersOIDOperations(FlextLdapServersBaseOperations):
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
    def get_default_port(self, *, use_ssl: bool = False) -> int:
        """Get default port for Oracle OID."""
        return 636 if use_ssl else 389

    @override
    def supports_start_tls(self) -> bool:
        """Oracle OID supports START_TLS."""
        return True

    @override
    def get_bind_mechanisms(self) -> FlextCore.Types.StringList:
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
    def discover_schema(
        self, connection: Connection
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Discover schema from Oracle OID.

        Args:
            connection: Active ldap3 connection

        Returns:
            FlextCore.Result containing schema information

        """
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Connection not bound"
                )

            success: bool = connection.search(
                search_base=self.get_schema_dn(),
                search_filter="(objectClass=*)",
                attributes=["objectClasses", "attributeTypes"],
            )

            if not success or not connection.entries:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Schema discovery failed"
                )

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
                "server_type": "oid",
            }

            return FlextCore.Result[FlextCore.Types.Dict].ok(schema_data)

        except Exception as e:
            self.logger.exception("Schema discovery error", extra={"error": str(e)})
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Schema discovery failed: {e}"
            )

    @override
    def parse_object_class(
        self, object_class_def: str
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Parse Oracle OID objectClass definition."""
        try:
            return FlextCore.Result[FlextCore.Types.Dict].ok({
                "definition": object_class_def,
                "server_type": "oid",
            })
        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(f"Parse failed: {e}")

    @override
    def parse_attribute_type(
        self, attribute_def: str
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Parse Oracle OID attributeType definition."""
        try:
            return FlextCore.Result[FlextCore.Types.Dict].ok({
                "definition": attribute_def,
                "server_type": "oid",
            })
        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(f"Parse failed: {e}")

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
        self,
        connection: Connection,
        dn: str,
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Get orclaci ACLs from Oracle OID."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                    "Connection not bound"
                )

            success: bool = connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["orclaci"],
            )

            if not success or not connection.entries:
                return FlextCore.Result[list[FlextCore.Types.Dict]].ok([])

            entry = connection.entries[0]
            acl_values = entry.orclaci.values if hasattr(entry, "orclaci") else []

            acls: list[FlextCore.Types.Dict] = []
            for acl_str in acl_values:
                parse_result = self.parse_acl(str(acl_str))
                if parse_result.is_success:
                    acls.append(parse_result.unwrap())

            return FlextCore.Result[list[FlextCore.Types.Dict]].ok(acls)

        except Exception as e:
            self.logger.exception("Get ACLs error", extra={"error": str(e)})
            return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                f"Get ACLs failed: {e}"
            )

    @override
    def set_acls(
        self,
        connection: Connection,
        dn: str,
        acls: list[FlextCore.Types.Dict],
    ) -> FlextCore.Result[bool]:
        """Set orclaci ACLs on Oracle OID."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[bool].fail("Connection not bound")

            formatted_acls: FlextCore.Types.StringList = []
            for acl in acls:
                format_result = self.format_acl(acl)
                if format_result.is_failure:
                    return FlextCore.Result[bool].fail(
                        format_result.error or "ACL format failed",
                    )
                formatted_acls.append(format_result.unwrap())

            success = connection.modify(
                dn,
                {"orclaci": [(MODIFY_REPLACE, formatted_acls)]},
            )

            if not success:
                error_msg = connection.result.get(
                    FlextLdapConstants.DictKeys.DESCRIPTION,
                    "Unknown error",
                )
                return FlextCore.Result[bool].fail(f"Set ACLs failed: {error_msg}")

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            self.logger.exception("Set ACLs error", extra={"error": str(e)})
            return FlextCore.Result[bool].fail(f"Set ACLs failed: {e}")

    @override
    def parse_acl(self, acl_string: str) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Parse orclaci ACL string for Oracle OID.

        Oracle OID ACL format (orclaci):
        access to entry|attr:<target> by <subject>:<permissions>

        Examples:
        - access to entry by * : browse
        - access to attr:userPassword by self : write
        - access to entry by group="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups" : add, delete, write

        Args:
            acl_string: orclaci ACL string

        Returns:
            FlextCore.Result containing parsed ACL with structure:
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
            acl_dict: FlextCore.Types.Dict = {
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

            return FlextCore.Result[FlextCore.Types.Dict].ok(acl_dict)

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Oracle OID ACL parse failed: {e}",
            )

    @override
    def format_acl(self, acl_dict: FlextCore.Types.Dict) -> FlextCore.Result[str]:
        """Format ACL dict[str, object] to orclaci string for Oracle OID.

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
            FlextCore.Result containing formatted ACL string

        Examples:
            - access to entry by * : browse
            - access to attr:userPassword by self : write

        """
        try:
            # Use raw if available
            if "raw" in acl_dict:
                return FlextCore.Result[str].ok(str(acl_dict["raw"]))

            # Build structured ACL
            parts = ["access to"]

            # Add target
            target_type = acl_dict.get(FlextLdapConstants.DictKeys.TARGET_TYPE, "entry")
            target = str(acl_dict.get(FlextLdapConstants.DictKeys.TARGET, "*"))

            if target_type == "attr":
                parts.append(f"attr:{target}")
            elif target == "*":
                parts.append("entry")
            else:
                parts.append(target)

            # Add "by" clause
            parts.append("by")

            subject = str(acl_dict.get(FlextLdapConstants.DictKeys.SUBJECT, "*"))
            parts.append(subject)

            # Add permissions
            permissions = acl_dict.get(
                FlextLdapConstants.DictKeys.PERMISSIONS,
                ["read"],
            )
            if permissions and isinstance(permissions, list):
                perms_str = ", ".join(str(p) for p in permissions)
                parts.append(f": {perms_str}")

            return FlextCore.Result[str].ok(" ".join(parts))

        except Exception as e:
            return FlextCore.Result[str].fail(f"Oracle OID ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @override
    def add_entry(
        self,
        connection: Connection,
        entry: FlextLdifModels.Entry,
    ) -> FlextCore.Result[bool]:
        """Add entry to Oracle OID."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[bool].fail("Connection not bound")

            norm_result = self.normalize_entry(entry)
            if norm_result.is_failure:
                return FlextCore.Result[bool].fail(
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

            success: bool = connection.add(
                str(normalized_entry.dn),
                object_class,
                attributes=ldap3_attrs or None,
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
        """Modify entry in Oracle OID."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[bool].fail("Connection not bound")

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

            success: bool = connection.modify(
                dn, cast("dict[str, list[tuple[int, list[str] | str]]]", ldap3_mods)
            )

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
    def delete_entry(self, connection: Connection, dn: str) -> FlextCore.Result[bool]:
        """Delete entry from Oracle OID."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[bool].fail("Connection not bound")

            success: bool = connection.delete(dn)

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
        """Normalize entry for Oracle OID.

        Oracle OID Considerations:
        - May need Oracle-specific object classes (orclUserV2, orclContainer)
        - Handles orclaci ACL attributes
        - Supports Oracle-specific attributes (orclPassword, orclCommonAttribute)

        Args:
            entry: FlextLdif Entry to normalize

        Returns:
            FlextCore.Result containing normalized entry

        """
        try:
            # Access entry attributes
            attributes_dict = entry.attributes.attributes.copy()

            # Ensure objectClass compatibility for Oracle OID
            if "objectClass" in attributes_dict:
                object_class_attr = attributes_dict["objectClass"]
                # Handle both list and AttributeValues types
                if isinstance(object_class_attr, list):
                    object_classes: FlextCore.Types.StringList = object_class_attr
                elif hasattr(object_class_attr, "values"):
                    object_classes = object_class_attr.values
                else:
                    object_classes = [str(object_class_attr)]

                # Map standard objectClasses to Oracle equivalents
                mapped_classes: FlextCore.Types.StringList = []
                has_person = False
                has_org_person = False

                for oc in object_classes:
                    mapped_classes.append(str(oc))

                    # Track person-related classes
                    oc_str = str(oc)
                    if oc_str == "person":
                        has_person = True
                    elif oc_str in {"organizationalPerson", "inetOrgPerson"}:
                        has_org_person = True

                # For user entries, consider adding orclUserV2 for extended features
                # (Only if not already present and is a person-like entry)
                if (has_person or has_org_person) and "orclUserV2" not in [
                    str(oc) for oc in object_classes
                ]:
                    # Note: orclUserV2 should only be added if Oracle schema supports it
                    # and entry will have required Oracle attributes
                    pass  # Conservative approach - don't auto-add

                # Update objectClass if changed
                if mapped_classes != object_classes:
                    attributes_dict["objectClass"] = FlextLdifModels.AttributeValues(
                        values=mapped_classes,
                    )

            # Handle Oracle-specific attribute mappings
            # Map userPassword to orclPassword if Oracle extensions are used
            # (Conservative: keep both for compatibility)

            # Create normalized entry
            normalized_attributes = FlextLdifModels.LdifAttributes(
                attributes=attributes_dict,
            )
            normalized_entry = FlextLdifModels.Entry(
                dn=entry.dn,
                attributes=normalized_attributes,
            )

            return FlextCore.Result[FlextLdifModels.Entry].ok(normalized_entry)

        except Exception as e:
            return FlextCore.Result[FlextLdifModels.Entry].fail(
                f"Oracle OID entry normalization failed: {e}",
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
        attributes: FlextCore.Types.StringList | None = None,
        scope: str = "subtree",
        page_size: int = 100,
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Execute paged search on Oracle OID.

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
            entries: list[FlextLdapModels.Entry] = []

            for ldap3_entry in entry_generator:
                if "dn" in ldap3_entry and "attributes" in ldap3_entry:
                    entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                    if entry_result.is_success:
                        ldif_entry = entry_result.unwrap()
                        ldap_entry = FlextLdapModels.Entry.from_ldif(ldif_entry)
                        entries.append(ldap_entry)

            return FlextCore.Result[list[FlextLdapModels.Entry]].ok(entries)

        except Exception as e:
            self.logger.exception("Paged search error", extra={"error": str(e)})
            return FlextCore.Result[list[FlextLdapModels.Entry]].fail(
                f"Paged search failed: {e}",
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

    def get_oracle_object_classes(self) -> FlextCore.Types.StringList:
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

    def get_oracle_attributes(self) -> FlextCore.Types.StringList:
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

    @override
    def detect_server_type_from_root_dse(self, root_dse: FlextCore.Types.Dict) -> str:
        """Detect server type from Root DSE for Oracle OID."""
        # Oracle OID specific detection logic
        if "vendorname" in root_dse:
            vendor = str(root_dse["vendorname"]).lower()
            if "oracle" in vendor or "oid" in vendor:
                return "oid"
        return "generic"

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Get Root DSE attributes for Oracle OID."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Connection not established"
                )

            root_dse = connection.server.info
            if not root_dse:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Root DSE not available"
                )

            return FlextCore.Result[FlextCore.Types.Dict].ok(dict(root_dse))
        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to get Root DSE: {e}"
            )

    @override
    def get_supported_controls(
        self, connection: Connection
    ) -> FlextCore.Result[FlextCore.Types.StringList]:
        """Get supported LDAP controls for Oracle OID."""
        try:
            if not connection or not connection.bound:
                return FlextCore.Result[FlextCore.Types.StringList].fail(
                    "Connection not established"
                )

            controls = connection.server.info.supported_controls
            if controls is None:
                return FlextCore.Result[FlextCore.Types.StringList].ok([])

            return FlextCore.Result[FlextCore.Types.StringList].ok(list(controls))
        except Exception as e:
            return FlextCore.Result[FlextCore.Types.StringList].fail(
                f"Failed to get supported controls: {e}"
            )

    @override
    def normalize_entry_for_server(
        self,
        entry: FlextLdapModels.Entry | FlextLdifModels.Entry,
        target_server_type: str | None = None,
    ) -> FlextCore.Result[FlextLdapModels.Entry]:
        """Normalize entry for Oracle OID server.

        Args:
            entry: Entry to normalize (accepts both LDAP and LDIF entry types)
            target_server_type: Ignored for OID (uses self._server_type)

        Returns:
            FlextCore.Result containing normalized entry

        """
        try:
            # Convert FlextLdapModels.Entry to FlextLdifModels.Entry if needed
            if isinstance(entry, FlextLdapModels.Entry):
                ldif_entry = cast("FlextLdifModels.Entry", entry)
            else:
                ldif_entry = entry

            # Oracle OID specific normalization
            normalized_entry = ldif_entry.model_copy()

            # Ensure Oracle-specific object classes are present
            if "objectClass" not in normalized_entry.attributes.attributes:
                normalized_entry.attributes.attributes["objectClass"] = (
                    FlextLdifModels.AttributeValues(values=["top", "person"])
                )

            # Cast back to FlextLdapModels.Entry for return type
            return FlextCore.Result[FlextLdapModels.Entry].ok(
                cast("FlextLdapModels.Entry", normalized_entry),
            )
        except Exception as e:
            return FlextCore.Result[FlextLdapModels.Entry].fail(
                f"Failed to normalize entry: {e}",
            )

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str | None = None,
    ) -> FlextCore.Result[bool]:
        """Validate entry compatibility with Oracle OID."""
        try:
            # Oracle OID specific validation
            # Convert DistinguishedName to string if needed before strip()
            dn_str = str(entry.dn) if entry.dn else ""
            if not dn_str or not dn_str.strip():
                return FlextCore.Result[bool].fail("Entry DN cannot be empty")

            if not entry.attributes:
                return FlextCore.Result[bool].fail("Entry must have attributes")

            # Check for required object classes
            object_classes = entry.attributes.get("objectClass")
            if not object_classes:
                return FlextCore.Result[bool].fail(
                    "Entry must have objectClass attribute"
                )

            return FlextCore.Result[bool].ok(True)
        except Exception as e:
            return FlextCore.Result[bool].fail(f"Entry validation failed: {e}")
