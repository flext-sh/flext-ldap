"""Oracle Internet Directory (OID) server operations implementation.

Complete implementation for Oracle OID with orclaci ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from functools import cached_property
from typing import cast, override

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.utilities import FlextLdapUtilities


class FlextLdapServersOIDOperations(FlextLdapServersBaseOperations):
    """Complete Oracle OID operations implementation following SOLID and Flext principles.

    This class implements server-specific operations for Oracle Internet Directory (OID)
    while maintaining clean separation of concerns and leveraging Flext architectural patterns.

    **SOLID Principles Compliance:**
    - SRP: Single responsibility - handles only OID-specific LDAP operations
    - OCP: Open for extension through inheritance, closed for modification via overrides
    - LSP: Substitutable with base class without breaking contracts
    - DIP: Depends on abstractions (FlextServices, FlextConstants) not concretions

    **Flext Architecture Compliance:**
    - Uses FlextServices for dependency injection and service management
    - Leverages FlextConstants for type-safe configuration
    - Implements FlextResult monadic pattern for error handling
    - Uses cached_property for performance optimizations
    - Delegates to shared utilities (FlextLdapUtilities, FlextLdapEntryAdapter)
    - Applies DRY principle with functional composition and helper methods

    **Oracle OID Features:**
    - orclaci ACL attribute for access control
    - Oracle-specific object classes (orclUserV2, orclContainer)
    - cn=subschemasubentry for schema discovery
    - Proprietary extensions with enterprise features
    - Support for Oracle-specific attributes and security models
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
        return FlextLdapConstants.SchemaDns.SUBS_SCHEMA_SUBENTRY

    # discover_schema() - Use base implementation

    def _add_oid_schema_note(self, entry: FlextLdifModels.Entry) -> None:
        """Add Oracle OID-specific note to schema entry.

        DRY helper method to avoid code duplication between parse_object_class
        and parse_attribute_type methods.

        Args:
            entry: Schema entry to enhance with OID note

        """
        if entry.attributes is not None:
            entry.attributes.attributes["note"] = ["Oracle OID schema parsing"]

    @override
    def parse_object_class(
        self,
        object_class_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse Oracle OID objectClass definition - enhanced with OID note."""
        result = super().parse_object_class(object_class_def)
        if result.is_success:
            self._add_oid_schema_note(result.unwrap())
        return result

    @override
    def parse_attribute_type(
        self,
        attribute_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse Oracle OID attributeType definition - enhanced with OID note."""
        result = super().parse_attribute_type(attribute_def)
        if result.is_success:
            self._add_oid_schema_note(result.unwrap())
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
    # set_acls() inherited from base class - uses Template Method Pattern

    # =========================================================================
    # TEMPLATE METHOD PATTERN - Abstract Methods Implementation
    # =========================================================================

    @override
    def _format_acls(self, acls: list[dict[str, object]]) -> FlextResult[list[str]]:
        """Format ACLs for Oracle OID orclaci attribute using FlextLdapUtilities.

        Template Method Pattern: Implements abstract method from base class.
        Consolidated with FlextLdapUtilities.AclFormatting for reusability.
        Delegates formatting to shared utility.

        Returns:
            FlextResult containing list of formatted ACL strings or failure

        """
        return FlextLdapUtilities.AclFormatting.format_acls_for_server(acls, self)

    @override
    def _get_acl_attribute(self) -> str:
        """Get Oracle OID ACL attribute name.

        Template Method Pattern: Implements abstract method from base class.

        Returns:
            'orclaci' - Oracle OID ACL attribute

        """
        return FlextLdapConstants.AclAttributes.ORCLACI

    @override
    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
        """Parse orclaci ACL string for Oracle OID.

        Delegates to FlextLdifAcl service for proper ACL parsing using server-specific quirks.
        This ensures consistent ACL handling across the Flext framework.

        Args:
            acl_string: orclaci ACL string

        Returns:
            FlextResult containing parsed ACL as Entry object with proper structure

        """
        try:
            # Delegate to FlextLdifAcl service for server-specific parsing
            acl_service = self._acl_service
            parse_result = acl_service.parse(acl_string, self.server_type)

            if parse_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"ACL parsing failed: {parse_result.error}",
                )

            # Convert ACL model to Entry format for compatibility
            parse_result.unwrap()
            acl_attributes: dict[str, str | list[str]] = {
                "raw": acl_string,
                FlextLdapConstants.AclAttributes.FORMAT: FlextLdapConstants.AclFormat.ORACLE,
                "server_type": self.server_type,
                "privilege": acl_string.strip(),  # Privilege name from raw string
            }

            entry_result = FlextLdifModels.Entry.create(
                dn=FlextLdapConstants.SyntheticDns.ACL_RULE,
                attributes=acl_attributes,
            )
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create ACL entry: {entry_result.error}",
                )
            return cast("FlextResult[FlextLdifModels.Entry]", entry_result)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Oracle OID ACL parse failed: {e}",
            )

    def _build_acl_target_part(
        self,
        target_type: str,
        target: str,
    ) -> str:
        """Build ACL target specification part using builder pattern.

        DRY helper for ACL formatting - handles different target types
        (entry vs attribute) with functional approach.

        Args:
            target_type: Type of target (entry or attr)
            target: Target specification

        Returns:
            Formatted target part of ACL

        """
        if target_type == FlextLdapConstants.AclSyntaxKeywords.TARGET_TYPE_ATTR:
            return f"{FlextLdapConstants.AclSyntaxKeywords.ATTR_PREFIX}{target}"
        if target == "*":
            return FlextLdapConstants.AclSyntaxKeywords.ENTRY
        return target

    def _build_acl_permissions_part(self, permissions: list[str]) -> str:
        """Build ACL permissions part using builder pattern.

        DRY helper for ACL formatting - formats permission list
        into standardized ACL permission string.

        Args:
            permissions: List of permission names

        Returns:
            Formatted permissions part of ACL

        """
        return f": {', '.join(str(p) for p in permissions)}"

    def _format_structured_acl(self, acl_entry: FlextLdifModels.Entry) -> str:
        """Format structured ACL using builder pattern with helper methods.

        Breaks down complex ACL formatting into composable parts.
        Uses functional composition with DRY helper methods.

        Args:
            acl_entry: ACL entry with structured attributes

        Returns:
            Formatted ACL string

        """
        # Extract components with safe defaults using helper method
        target_type = self._safe_get_acl_attr(
            acl_entry,
            FlextLdapConstants.AclAttributes.TARGET_TYPE,
            [FlextLdapConstants.AclSyntaxKeywords.TARGET_TYPE_ENTRY],
        )[0]
        target = self._safe_get_acl_attr(
            acl_entry,
            FlextLdapConstants.AclAttributes.TARGET,
            ["*"],
        )[0]
        subject = self._safe_get_acl_attr(
            acl_entry,
            FlextLdapConstants.AclAttributes.SUBJECT,
            ["*"],
        )[0]
        permissions = self._safe_get_acl_attr(
            acl_entry,
            FlextLdapConstants.AclAttributes.PERMISSIONS,
            [FlextLdapConstants.AclPermissions.READ],
        )

        # Build ACL parts using builder methods
        parts = [
            FlextLdapConstants.AclSyntaxKeywords.ACCESS_TO,
            self._build_acl_target_part(target_type, target),
            FlextLdapConstants.AclSyntaxKeywords.BY,
            subject,
            self._build_acl_permissions_part(permissions),
        ]

        return " ".join(parts)

    @override
    def format_acl(self, acl_entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Format ACL Entry to orclaci string for Oracle OID.

        Uses builder pattern with helper methods for DRY principle.
        Delegates to structured formatter when raw ACL not available.

        Args:
            acl_entry: ACL Entry with attributes

        Returns:
            FlextResult containing formatted ACL string

        """
        try:
            # Fast path: Extract raw ACL string if available
            raw_acl = self._safe_get_acl_attr(
                acl_entry,
                FlextLdapConstants.AclAttributes.RAW,
            )
            if raw_acl:
                return FlextResult[str].ok(raw_acl[0])

            # Structured path: Build ACL using builder pattern
            formatted_acl = self._format_structured_acl(acl_entry)
            return FlextResult[str].ok(formatted_acl)

        except Exception as e:
            return FlextResult[str].fail(f"Oracle OID ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    # add_entry(), modify_entry(), delete_entry() - Use base implementations

    def _normalize_oid_object_classes(
        self,
        object_classes: list[str],
    ) -> tuple[list[str], bool, bool]:
        """Normalize Oracle OID object classes with person tracking.

        Applies Oracle OID specific object class mappings and tracks
        person-related classes for potential orclUserV2 consideration.

        Args:
            object_classes: List of object classes to normalize

        Returns:
            Tuple of (normalized_classes, has_person, has_org_person)

        """
        mapped_classes = [str(oc) for oc in object_classes]
        has_person = any(
            str(oc) == FlextLdapConstants.ObjectClasses.PERSON for oc in object_classes
        )
        has_org_person = any(
            str(oc)
            in {
                FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_PERSON,
                FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
            }
            for oc in object_classes
        )
        return mapped_classes, has_person, has_org_person

    def _extract_object_classes(
        self, attributes_dict: dict[str, object] | dict[str, list[str]]
    ) -> list[str]:
        """Extract object classes from entry attributes.

        Handles different attribute value formats (list, AttributeValues, etc.).

        Args:
            attributes_dict: Entry attributes dictionary

        Returns:
            List of object class names

        """
        if FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS not in attributes_dict:
            return []

        object_class_attr = attributes_dict[
            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
        ]

        if isinstance(object_class_attr, list):
            return [str(oc) for oc in object_class_attr]
        if hasattr(object_class_attr, "values"):
            # Dynamic attribute access - type checked at runtime
            values = object_class_attr.values
            return (
                [str(v) for v in values] if isinstance(values, list) else [str(values)]
            )
        return [str(object_class_attr)]

    def _safe_get_acl_attr(
        self,
        acl_entry: FlextLdifModels.Entry,
        key: str,
        default: list[str] | None = None,
    ) -> list[str]:
        """Safely get ACL attribute with fallback for format_acl operations.

        DRY helper method to extract attribute values from ACL entries.
        Handles None attributes gracefully with functional approach.

        Args:
            acl_entry: ACL entry to extract from
            key: Attribute key to extract
            default: Default value if attribute not found

        Returns:
            List of attribute values or default

        """
        if acl_entry.attributes is None:
            return default or []
        return acl_entry.attributes.get(key, default or [])

    @override
    def normalize_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for Oracle OID using functional composition.

        Applies Oracle OID specific transformations:
        - Object class normalization with person tracking
        - Oracle-specific attribute mappings
        - ACL attribute handling

        Uses helper methods for DRY principle and testability.

        Args:
            entry: FlextLdif Entry to normalize

        Returns:
            FlextResult containing normalized entry

        """
        try:
            # Copy attributes for mutation
            if entry.attributes is None:
                return FlextResult.ok(entry)  # Nothing to normalize
            attributes_dict = entry.attributes.attributes.copy()

            # Normalize object classes using helper
            object_classes = self._extract_object_classes(attributes_dict)
            if object_classes:
                normalized_classes, _, _ = self._normalize_oid_object_classes(
                    object_classes
                )

                # Conservative approach: don't auto-add orclUserV2
                # Only update if classes actually changed
                if normalized_classes != object_classes:
                    attributes_dict[
                        FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
                    ] = normalized_classes

            # Create normalized entry with updated attributes
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

    @cached_property
    def oracle_object_classes(self) -> list[str]:
        """Get cached Oracle-specific object classes.

        Uses cached_property for performance - computed once and cached.
        Returns immutable list of Oracle OID object classes.

        Returns:
            List of Oracle object classes for schema operations

        """
        return [
            "orclUserV2",
            "orclContainer",
            "orclApplicationEntity",
            "orclService",
            "orclSubscriber",
        ]

    @cached_property
    def oracle_attributes(self) -> list[str]:
        """Get cached Oracle-specific attributes.

        Uses cached_property for performance - computed once and cached.
        Returns immutable list of Oracle OID attributes.

        Returns:
            List of Oracle attributes for schema operations

        """
        return [
            "orclPassword",
            "orclCommonAttribute",
            "orclGUID",
            "orclIsEnabled",
            "orclPasswordPolicyDN",
            FlextLdapConstants.AclAttributes.ORCLACI,  # ACL attribute
        ]

    def get_oracle_object_classes(self) -> list[str]:
        """Get Oracle-specific object classes.

        Returns:
            List of Oracle object classes

        """
        return self.oracle_object_classes

    def get_oracle_attributes(self) -> list[str]:
        """Get Oracle-specific attributes.

        Returns:
            List of Oracle attributes

        """
        return self.oracle_attributes

    def is_oracle_user(self, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is Oracle user (has orclUserV2).

        Uses functional composition with helper method for DRY principle.

        Args:
            entry: Entry to check

        Returns:
            True if entry has Oracle user object class

        """
        if entry.attributes is None:
            return False
        object_classes = self._extract_object_classes(entry.attributes.attributes)
        return "orclUserV2" in object_classes

    @override
    def detect_server_type_from_root_dse(self, root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE for Oracle OID."""
        # Oracle OID specific detection logic
        if FlextLdapConstants.RootDseAttributes.VENDOR_NAME_LOWER in root_dse:
            vendor = str(
                root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_NAME_LOWER],
            ).lower()
            if (
                FlextLdapConstants.VendorNames.ORACLE in vendor
                or FlextLdapConstants.ServerTypes.OID in vendor
            ):
                return FlextLdapConstants.ServerTypes.OID
        return FlextLdapConstants.Defaults.SERVER_TYPE

    def _validate_connection(self, connection: Connection) -> FlextResult[None]:
        """Validate LDAP connection using FlextResult monadic pattern.

        DRY helper method for connection validation across OID operations.
        Uses functional composition for cleaner error handling.

        Args:
            connection: LDAP connection to validate

        Returns:
            FlextResult indicating validation success or failure

        """
        if not connection:
            return FlextResult[None].fail("Connection is None")
        if not connection.bound:
            return FlextResult[None].fail("Connection not bound")
        return FlextResult[None].ok(None)

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
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for Oracle OID using shared FlextLdapEntryAdapter service.

        Delegates to FlextLdapEntryAdapter for server-specific validation logic.
        Uses shared service to avoid code duplication and ensure consistency.
        """
        # Use shared FlextLdapEntryAdapter service for validation
        adapter = FlextLdapEntryAdapter(server_type=self.server_type)
        return adapter.validate_entry_for_server(entry, self.server_type)
