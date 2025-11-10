"""Oracle Internet Directory (OID) server operations implementation.

Complete implementation for Oracle OID with orclaci ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import MODIFY_REPLACE, Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.typings import FlextLdapTypes


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
        super().__init__(server_type=FlextLdapConstants.ServerTypes.OID)

    # --------------------------------------------------------------------- #
    # INHERITED METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods are used directly from the base class without override:
    # - get_default_port(): Returns 389 (standard LDAP port)
    # - supports_start_tls(): Returns True (standard LDAP feature)
    # - get_schema_dn(): Returns "cn=subschemasubentry" (OID-specific)
    # - discover_schema(): Generic schema discovery implementation
    # - get_acls(): OID-specific ACL retrieval with orclaci
    # - set_acls(): OID-specific ACL setting with orclaci
    # - add_entry(): Generic entry addition
    # - modify_entry(): Generic entry modification
    # - delete_entry(): Generic entry deletion
    # - get_max_page_size(): Returns 1000 (standard page size)
    # - supports_paged_results(): Returns True (standard LDAP feature)
    # - search_with_paging(): Generic paged search implementation
    # - normalize_entry_for_server(): Generic entry normalization
    #
    # --------------------------------------------------------------------- #
    # OVERRIDDEN METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods override the base class with Oracle OID-specific logic:
    # - get_bind_mechanisms(): Returns OID-specific bind mechanisms
    # - parse_object_class(): OID-specific objectClass parsing
    # - parse_attribute_type(): OID-specific attributeType parsing
    # - get_acl_attribute_name(): Returns "orclaci" (OID ACL attribute)
    # - get_acl_format(): Returns "oracle" (Oracle ACI format)
    # - parse(): OID-specific ACL parsing with Oracle ACI
    # - format_acl(): OID-specific ACL formatting to Oracle ACI
    # - normalize_entry(): OID-specific entry normalization
    # - supports_vlv(): Returns True (OID supports VLV)
    # - get_root_dse_attributes(): OID-specific Root DSE retrieval
    # - detect_server_type_from_root_dse(): OID server detection logic
    # - get_supported_controls(): OID-specific supported controls
    # - validate_entry_for_server(): OID-specific entry validation

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    @override
    def get_bind_mechanisms(self) -> list[str]:
        """Get supported BIND mechanisms."""
        return [
            FlextLdapConstants.SaslMechanisms.SIMPLE,
            FlextLdapConstants.SaslMechanisms.SASL_EXTERNAL,
            FlextLdapConstants.SaslMechanisms.SASL_DIGEST_MD5,
        ]

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """Oracle OID uses cn=subschemasubentry."""
        return "cn=subschemasubentry"

    # discover_schema() - Use base implementation

    @override
    def parse_object_class(
        self,
        object_class_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse Oracle OID objectClass definition - enhanced with OID note."""
        result = super().parse_object_class(object_class_def)
        if not result.is_failure:
            entry = result.unwrap()
            # Add OID-specific note
            entry.attributes.attributes["note"] = ["Oracle OID schema parsing"]
        return result

    @override
    def parse_attribute_type(
        self,
        attribute_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse Oracle OID attributeType definition - enhanced with OID note."""
        result = super().parse_attribute_type(attribute_def)
        if not result.is_failure:
            entry = result.unwrap()
            # Add OID-specific note
            entry.attributes.attributes["note"] = ["Oracle OID schema parsing"]
        return result

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @override
    def get_acl_attribute_name(self) -> str:
        """Oracle OID uses orclaci attribute."""
        return FlextLdapConstants.AclAttributes.ORCLACI

    @override
    def get_acl_format(self) -> str:
        """Oracle OID ACL format identifier."""
        return FlextLdapConstants.AclFormat.ORACLE

    # get_acls() inherited from base class - uses get_acl_attribute_name()

    @override
    def set_acls(
        self,
        _connection: Connection,
        _dn: str,
        _acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set orclaci ACLs on Oracle OID."""
        try:
            if not _connection or not _connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            formatted_acls: list[str] = []
            for acl in _acls:
                # Convert dict to Entry for format_acl
                # LdifAttributes.create returns FlextResult, need to unwrap
                attrs_result = FlextLdifModels.LdifAttributes.create(acl)
                if attrs_result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to create LdifAttributes: {attrs_result.error}",
                    )
                attrs = attrs_result.unwrap()

                acl_entry = FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value=FlextLdapConstants.SyntheticDns.ACL_RULE,
                    ),
                    attributes=attrs,
                )
                format_result = self.format_acl(acl_entry)
                if format_result.is_failure:
                    return FlextResult[bool].fail(
                        format_result.error or "ACL format failed",
                    )
                formatted_acls.append(format_result.unwrap())

            # Cast to Protocol type for proper type checking with ldap3
            typed_conn = cast("FlextLdapTypes.Ldap3Protocols.Connection", _connection)
            mods = cast(
                "dict[str, list[tuple[int, list[str]]]]",
                {
                    FlextLdapConstants.AclAttributes.ORCLACI: [
                        (MODIFY_REPLACE, formatted_acls),
                    ],
                },
            )
            success = typed_conn.modify(_dn, mods)

            if not success:
                error_msg = (
                    _connection.result.get(
                        FlextLdapConstants.LdapDictKeys.DESCRIPTION,
                        FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR,
                    )
                    if _connection.result
                    else FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR
                )
                return FlextResult[bool].fail(f"Set ACLs failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Set ACLs error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Set ACLs failed: {e}")

    # OID ACL Parse Helper Methods

    def _parse_oid_target_clause(
        self,
        target_clause: str,
    ) -> dict[str, list[str]]:
        """Parse OID target clause (entry or attr:name)."""
        attributes: dict[str, list[str]] = {}

        if target_clause.startswith(FlextLdapConstants.AclSyntaxKeywords.ATTR_PREFIX):
            attributes[FlextLdapConstants.AclAttributes.TARGET_TYPE] = [
                FlextLdapConstants.AclSyntaxKeywords.TARGET_TYPE_ATTR,
            ]
            attributes[FlextLdapConstants.AclAttributes.TARGET] = [
                target_clause[len(FlextLdapConstants.AclSyntaxKeywords.ATTR_PREFIX) :],
            ]
        elif target_clause == FlextLdapConstants.AclSyntaxKeywords.ENTRY:
            attributes[FlextLdapConstants.AclAttributes.TARGET_TYPE] = [
                FlextLdapConstants.AclSyntaxKeywords.TARGET_TYPE_ENTRY,
            ]
            attributes[FlextLdapConstants.AclAttributes.TARGET] = ["*"]
        else:
            attributes[FlextLdapConstants.AclAttributes.TARGET_TYPE] = [
                FlextLdapConstants.AclSyntaxKeywords.TARGET_TYPE_ENTRY,
            ]
            attributes[FlextLdapConstants.AclAttributes.TARGET] = [target_clause]

        return attributes

    def _parse_oid_by_clause(
        self,
        by_clause: str,
    ) -> dict[str, list[str]]:
        """Parse OID by clause (<subject>:<permissions>)."""
        attributes: dict[str, list[str]] = {}

        if ":" not in by_clause:
            return attributes

        parts = by_clause.rsplit(":", 1)
        attributes[FlextLdapConstants.AclAttributes.SUBJECT] = [parts[0].strip()]

        # Parse permissions (comma-separated)
        permissions_str = parts[1].strip()
        permissions = [p.strip() for p in permissions_str.split(",")]
        attributes[FlextLdapConstants.AclAttributes.PERMISSIONS] = permissions

        return attributes

    @override
    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
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
            FlextResult containing parsed ACL with structure:
            {
                "raw": original string,
                "format": FlextLdapConstants.AclFormat.ORACLE,
                "server_type": FlextLdapConstants.ServerTypes.OID,
                "target_type": "entry" or "attr",
                "target": target specification,
                "subject": access subject,
                "permissions": list of permissions
            }

        """
        try:
            # Initialize base attributes
            acl_attributes: dict[str, list[str]] = {
                FlextLdapConstants.AclAttributes.RAW: [acl_string],
                FlextLdapConstants.AclAttributes.FORMAT: [
                    FlextLdapConstants.AclFormat.ORACLE,
                ],
                FlextLdapConstants.AclAttributes.SERVER_TYPE_ALT: [
                    FlextLdapConstants.ServerTypes.OID,
                ],
            }

            # Parse Oracle OID syntax using helper methods
            if acl_string.startswith(
                FlextLdapConstants.AclSyntaxKeywords.ACCESS_TO + " "
            ):
                remainder = acl_string[
                    len(FlextLdapConstants.AclSyntaxKeywords.ACCESS_TO) + 1 :
                ]

                # Split into target and "by" clause
                by_split = remainder.split(
                    f" {FlextLdapConstants.AclSyntaxKeywords.BY} ",
                    1,
                )
                target_clause = by_split[0].strip()

                # Parse target using helper
                acl_attributes.update(self._parse_oid_target_clause(target_clause))

                # Parse "by" clause using helper
                if len(by_split) > 1:
                    by_clause = by_split[1].strip()
                    acl_attributes.update(self._parse_oid_by_clause(by_clause))

            # Convert to Entry format
            acl_attrs_for_create: dict[str, str | list[str]] = {}
            for key, values in acl_attributes.items():
                if isinstance(values, list) and len(values) == 1:
                    acl_attrs_for_create[key] = values[0]
                else:
                    acl_attrs_for_create[key] = values

            entry_result = FlextLdifModels.Entry.create(
                dn=FlextLdapConstants.SyntheticDns.ACL_RULE,
                attributes=acl_attrs_for_create,
            )
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create ACL entry: {entry_result.error}",
                )
            return entry_result

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to parse OID ACL: {e}",
            )

    @override
    def format_acl(self, acl_entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Format ACL Entry to orclaci string for Oracle OID.

        Args:
            acl_entry: ACL Entry with attributes containing structure:
                {
                    "targetType": "entry" or "attr",
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
            # Extract attributes from entry
            raw_attr = acl_entry.attributes.get(FlextLdapConstants.AclAttributes.RAW)
            if raw_attr and len(raw_attr) > 0:
                return FlextResult[str].ok(raw_attr[0])

            # Build structured ACL
            parts = [FlextLdapConstants.AclSyntaxKeywords.ACCESS_TO]

            # Add target
            target_type_attr = acl_entry.attributes.get(
                FlextLdapConstants.AclAttributes.TARGET_TYPE,
                [FlextLdapConstants.AclSyntaxKeywords.TARGET_TYPE_ENTRY],
            )
            target_type = (
                target_type_attr[0]
                if target_type_attr
                else FlextLdapConstants.AclSyntaxKeywords.TARGET_TYPE_ENTRY
            )

            target_attr = acl_entry.attributes.get(
                FlextLdapConstants.AclAttributes.TARGET,
                ["*"],
            )
            target = target_attr[0] if target_attr else "*"

            if target_type == FlextLdapConstants.AclSyntaxKeywords.TARGET_TYPE_ATTR:
                parts.append(
                    f"{FlextLdapConstants.AclSyntaxKeywords.ATTR_PREFIX}{target}",
                )
            elif target == "*":
                parts.append(FlextLdapConstants.AclSyntaxKeywords.ENTRY)
            else:
                parts.append(target)

            # Add "by" clause
            parts.append(FlextLdapConstants.AclSyntaxKeywords.BY)

            subject_attr = acl_entry.attributes.get(
                FlextLdapConstants.AclAttributes.SUBJECT,
                ["*"],
            )
            subject = subject_attr[0] if subject_attr else "*"
            parts.append(subject)

            # Add permissions
            permissions = acl_entry.attributes.get(
                FlextLdapConstants.AclAttributes.PERMISSIONS,
                [FlextLdapConstants.AclPermissions.READ],
            )
            if permissions:
                perms_str = ", ".join(str(p) for p in permissions)
                parts.append(f": {perms_str}")

            return FlextResult[str].ok(" ".join(parts))

        except Exception as e:
            return FlextResult[str].fail(f"Oracle OID ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    # add_entry(), modify_entry(), delete_entry() - Use base implementations

    @override
    def normalize_entry(
        self,
        entry: FlextLdifModels.Entry,
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

            # Map objectClasses for Oracle OID
            if FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS in attributes_dict:
                object_class_attr = attributes_dict[
                    FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
                ]
                # Handle both list and AttributeValues types
                if isinstance(object_class_attr, list):
                    object_classes: list[str] = object_class_attr
                elif hasattr(object_class_attr, "values"):
                    object_classes = object_class_attr.values
                else:
                    object_classes = [str(object_class_attr)]

                # Map standard objectClasses to Oracle equivalents
                mapped_classes: list[str] = []
                has_person = False
                has_org_person = False

                for oc in object_classes:
                    mapped_classes.append(str(oc))

                    # Track person-related classes
                    oc_str = str(oc)
                    if oc_str == FlextLdapConstants.ObjectClasses.PERSON:
                        has_person = True
                    elif oc_str in {
                        FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_PERSON,
                        FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
                    }:
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
                    # Use list directly instead of AttributeValues
                    attributes_dict[
                        FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
                    ] = mapped_classes

            # Handle Oracle-specific attribute mappings
            # Map userPassword to orclPassword if Oracle extensions are used
            # (Keep both for Oracle OID attribute support)

            # Create normalized entry
            normalized_attributes = FlextLdifModels.LdifAttributes(
                attributes=attributes_dict,
            )
            normalized_entry = FlextLdifModels.Entry(
                dn=entry.dn,
                attributes=normalized_attributes,
            )

            return FlextResult[FlextLdifModels.Entry].ok(normalized_entry)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Oracle OID entry normalization failed: {e}",
            )

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @override
    def supports_vlv(self) -> bool:
        """Oracle OID supports VLV."""
        return True

    # search_with_paging() - Use base implementation

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

    def get_oracle_object_classes(self) -> list[str]:
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

    def get_oracle_attributes(self) -> list[str]:
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
            FlextLdapConstants.AclAttributes.ORCLACI,  # ACL attribute
        ]

    def is_oracle_user(self, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is Oracle user (has orclUserV2).

        Args:
        entry: Entry to check

        Returns:
        True if entry has Oracle user object class

        """
        if (
            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
            in entry.attributes.attributes
        ):
            object_class_attr = entry.attributes.attributes[
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
            ]
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
    def detect_server_type_from_root_dse(self, _root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE for Oracle OID."""
        # Oracle OID specific detection logic
        if FlextLdapConstants.RootDseAttributes.VENDOR_NAME_LOWER in _root_dse:
            vendor = str(
                _root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_NAME_LOWER],
            ).lower()
            if (
                FlextLdapConstants.VendorNames.ORACLE in vendor
                or FlextLdapConstants.ServerTypes.OID in vendor
            ):
                return FlextLdapConstants.ServerTypes.OID
        return FlextLdapConstants.Defaults.SERVER_TYPE

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes for Oracle OID."""
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
        """Get supported LDAP controls for Oracle OID."""
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
        entry: FlextLdifModels.Entry,
        _target_server_type: str | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for Oracle OID server.

        Args:
        entry: Entry to normalize (accepts both LDAP and LDIF entry types)
        _target_server_type: Ignored for OID (uses self._server_type)

        Returns:
        FlextResult containing normalized entry

        """
        try:
            # Entry is already FlextLdifModels.Entry
            ldif_entry = entry

            # Oracle OID specific normalization
            normalized_entry = ldif_entry.model_copy()

            # Ensure Oracle-specific object classes are present
            if "objectClass" not in normalized_entry.attributes.attributes:
                # Use list directly instead of AttributeValues
                normalized_entry.attributes.attributes["objectClass"] = [
                    FlextLdapConstants.ObjectClasses.TOP,
                    FlextLdapConstants.ObjectClasses.PERSON,
                ]

            # Return normalized entry (no cast needed)
            return FlextResult[FlextLdifModels.Entry].ok(normalized_entry)
        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to normalize entry: {e}",
            )

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for Oracle OID."""
        try:
            # Oracle OID specific validation
            # Convert DistinguishedName to string if needed before strip()
            dn_str = str(entry.dn) if entry.dn else ""
            if not dn_str or not dn_str.strip():
                return FlextResult[bool].fail("Entry DN cannot be empty")

            if not entry.attributes:
                return FlextResult[bool].fail("Entry must have attributes")

            # Check for required object classes
            object_classes = entry.attributes.get(
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
            )
            if not object_classes:
                return FlextResult[bool].fail("Entry must have objectClass attribute")

            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")
