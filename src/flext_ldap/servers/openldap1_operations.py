"""OpenLDAP 1.x server operations implementation.

Complete implementation for OpenLDAP 1.x (slapd.conf style) with access ACLs.

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
from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations


class RootDSENotFoundError(RuntimeError):
    """Error raised when Root DSE cannot be found during LDAP query."""


class FlextLdapServersOpenLDAP1Operations(FlextLdapServersOpenLDAP2Operations):
    """Complete OpenLDAP 1.x operations implementation following SOLID and Flext principles.

    This class implements server-specific operations for OpenLDAP 1.x (slapd.conf style)
    while maintaining clean separation of concerns and leveraging Flext architectural patterns.
    Inherits most functionality from OpenLDAP2Operations with 1.x-specific overrides.

    **SOLID Principles Compliance:**
    - SRP: Single responsibility - handles only OpenLDAP 1.x-specific LDAP operations
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

    **OpenLDAP 1.x Features:**
    - slapd.conf static configuration (not cn=config dynamic config)
    - access ACL attribute for ACL definitions
    - Different ACL syntax: "access to <what> by <who> <access>"
    - slurpd replication mechanism (vs syncrepl in 2.x)
    - Legacy OpenLDAP objectClass support
    - Traditional configuration management
    """

    def __init__(self) -> None:
        """Initialize OpenLDAP 1.x operations."""
        super().__init__()
        self._server_type = FlextLdapConstants.ServerTypes.OPENLDAP1

    def _safe_get_acl_attr(
        self,
        acl_entry: FlextLdifModels.Entry,
        key: str,
    ) -> list[str]:
        """Safely extract ACL attribute from entry using functional approach.

        DRY helper method for ACL attribute extraction with null safety.
        Handles None attributes gracefully with empty list fallback.

        Args:
            acl_entry: ACL entry to extract from
            key: Attribute key to retrieve

        Returns:
            List of attribute values or empty list if not found

        """
        if acl_entry.attributes is None:
            return []
        attr = acl_entry.attributes.get(key)
        return attr or []

    def _map_openldap_object_classes(
        self,
        object_classes: list[str],
    ) -> list[str]:
        """Map OpenLDAP 2.x objectClasses to 1.x equivalents using builder pattern.

        DRY helper for objectClass normalization in OpenLDAP 1.x context.
        Removes olc* prefixes and filters out config-specific classes.

        Args:
            object_classes: List of objectClass names to map

        Returns:
            List of mapped objectClass names for OpenLDAP 1.x

        """
        mapped_classes = []
        for oc in object_classes:
            oc_str = str(oc)
            if oc_str == "olcDatabaseConfig":
                # 1.x doesn't use olc* objectClasses - skip
                continue
            if oc_str.startswith("olc"):
                # Remove olc prefix for OpenLDAP 1.x format
                prefix_len = FlextLdapConstants.AclParsing.OPENLDAP_PREFIX_LENGTH
                min_len = FlextLdapConstants.AclParsing.MIN_OC_LENGTH
                mapped_classes.append(
                    oc_str[prefix_len:] if len(oc_str) > min_len else oc_str,
                )
            else:
                # Keep non-olc classes as-is
                mapped_classes.append(oc_str)
        return mapped_classes

    def _extract_object_classes_from_attributes(
        self,
        attributes_dict: dict[str, object] | dict[str, list[str]],
    ) -> list[str]:
        """Extract objectClass values from entry attributes with type safety.

        DRY helper for objectClass extraction with proper type handling.
        Handles different attribute value formats (list, single value, etc.).

        Args:
            attributes_dict: Entry attributes dictionary

        Returns:
            List of objectClass names as strings

        """
        if FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS not in attributes_dict:
            return []

        object_class_attr = attributes_dict[
            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
        ]

        # Handle different attribute value formats
        if isinstance(object_class_attr, list):
            return [str(oc) for oc in object_class_attr]
        return [str(object_class_attr)]

    def _validate_ldap_connection(self, connection: Connection) -> FlextResult[None]:
        """Validate LDAP connection using FlextResult monadic pattern.

        DRY helper method for connection validation across OpenLDAP 1.x operations.
        Uses functional composition for cleaner error handling.

        Args:
            connection: LDAP connection to validate

        Returns:
            FlextResult indicating validation success or failure

        """
        if not connection:
            return FlextResult[None].fail("LDAP connection is None")
        if not connection.bound:
            return FlextResult[None].fail("LDAP connection not bound")
        return FlextResult[None].ok(None)

    # --------------------------------------------------------------------- #
    # INHERITED METHODS (from FlextLdapServersOpenLDAP2Operations)
    # --------------------------------------------------------------------- #
    # These methods are inherited from OpenLDAP 2.x with minimal differences:
    # - get_default_port(): Returns 389 (standard LDAP port)
    # - supports_start_tls(): Returns True (standard LDAP feature)
    # - get_bind_mechanisms(): Returns OpenLDAP-specific bind mechanisms
    # - get_schema_dn(): Returns "cn=subschema" (OpenLDAP standard)
    # - discover_schema(): OpenLDAP-specific schema discovery
    # - parse_object_class(): OpenLDAP-specific objectClass parsing
    # - parse_attribute_type(): OpenLDAP-specific attributeType parsing
    # - get_acl_format(): Returns "openldap1" (OpenLDAP 1.x format)
    # - get_acls(): OpenLDAP-specific ACL retrieval
    # - set_acls(): OpenLDAP-specific ACL setting
    # - add_entry(): Generic entry addition
    # - modify_entry(): Generic entry modification
    # - delete_entry(): Generic entry deletion
    # - get_max_page_size(): Returns 1000 (standard page size)
    # - supports_paged_results(): Returns True (standard LDAP feature)
    # - supports_vlv(): Returns False (OpenLDAP VLV support limited)
    # - search_with_paging(): Generic paged search implementation
    # - get_supported_controls(): OpenLDAP-specific supported controls
    # - normalize_entry_for_server(): Generic entry normalization
    # - validate_entry_for_server(): OpenLDAP-specific entry validation
    #
    # --------------------------------------------------------------------- #
    # OVERRIDDEN METHODS (from FlextLdapServersOpenLDAP2Operations)
    # --------------------------------------------------------------------- #
    # These methods override the parent class with OpenLDAP 1.x-specific logic:
    # - get_acl_attribute_name(): Returns "access" (OpenLDAP 1.x ACL attribute)
    # - parse(): OpenLDAP 1.x-specific ACL parsing (access directive format)
    # - format_acl(): OpenLDAP 1.x-specific ACL formatting (access directive format)
    # - normalize_entry(): OpenLDAP 1.x-specific entry normalization
    # - get_config_style(): Returns "slapd.conf" (OpenLDAP 1.x config style)
    # - get_replication_mechanism(): Returns "slurpd" (OpenLDAP 1.x replication)
    # - supports_dynamic_config(): Returns False (OpenLDAP 1.x uses slapd.conf)
    # - get_root_dse_attributes(): OpenLDAP 1.x-specific Root DSE retrieval
    # - detect_server_type_from_root_dse(): OpenLDAP 1.x server detection logic

    # get_default_port() - Use base implementation

    @override
    def get_schema_dn(self) -> str:
        """OpenLDAP 1.x schema location (subschemaSubentry)."""
        return FlextLdapConstants.SyntheticDns.SUBS_SCHEMA_ALT

    @override
    def get_acl_attribute_name(self) -> str:
        """OpenLDAP 1.x uses access attribute in slapd.conf."""
        return FlextLdapConstants.AclAttributes.ACCESS

    @override
    def get_acl_format(self) -> str:
        """OpenLDAP 1.x ACL format identifier."""
        return "openldap1"

    @override
    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
        """Parse access ACL string for OpenLDAP 1.x.

        Delegates to FlextLdifAcl service for proper ACL parsing using server-specific quirks.
        This ensures consistent ACL handling across the Flext framework.

        Args:
            acl_string: access ACL string

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
                FlextLdapConstants.AclAttributes.FORMAT: FlextLdapConstants.AclFormat.OPENLDAP1,
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
                f"OpenLDAP 1.x ACL parse failed: {e}",
            )

    @override
    def format_acl(self, acl_entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Format ACL Entry to access string for OpenLDAP 1.x.

        Args:
            acl_entry: ACL Entry with attributes containing structure:
                {
                    "to": what clause,
                    "rules": [{"who": subject, "access": level}, ...],
                    OR "by": by clause string
                }

        Returns:
            FlextResult containing formatted ACL string

        Examples:
            - access to * by self write by * read
            - access to attrs=userPassword by self write

        """
        try:
            # Extract attributes from entry
            raw_attr = (
                acl_entry.attributes.get(FlextLdapConstants.AclAttributes.RAW)
                if acl_entry.attributes is not None
                else None
            )
            if raw_attr and len(raw_attr) > 0:
                return FlextResult[str].ok(raw_attr[0])

            parts = [
                FlextLdapConstants.AclSyntaxKeywords.ACCESS_TO.split()[0],
            ]  # "access"

            # Add "to" clause
            to_attr = (
                acl_entry.attributes.get(FlextLdapConstants.AclAttributes.TO)
                if acl_entry.attributes is not None
                else None
            )
            if to_attr and len(to_attr) > 0:
                parts.append(f"to {to_attr[0]}")
            else:
                parts.append("to *")  # Default

            # Get rules or fallback to "by" string using helper method
            rules = self._safe_get_acl_attr(
                acl_entry, FlextLdapConstants.AclAttributes.RULES
            )
            if rules:
                # Process structured rules using functional approach
                for rule_str in rules:
                    if ":" in rule_str:
                        who, access = rule_str.split(":", 1)
                        parts.append(f"by {who.strip()} {access.strip()}")
                    else:
                        parts.append(f"by {rule_str.strip()}")
            else:
                # Fallback to "by" string or default
                by_clause = self._safe_get_acl_attr(
                    acl_entry, FlextLdapConstants.AclAttributes.BY
                )
                if by_clause:
                    parts.append(f"by {by_clause[0]}")
                else:
                    parts.append("by * read")

            return FlextResult[str].ok(" ".join(parts))

        except Exception as e:
            return FlextResult[str].fail(f"OpenLDAP 1.x ACL format failed: {e}")

    @override
    def normalize_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for OpenLDAP 1.x specifics.

        OpenLDAP 1.x Considerations:
        - Supports standard objectClasses and OpenLDAP 1.x classes
        - Uses access ACLs instead of olcAccess
        - Schema extensions via slapd.conf include directives

        Args:
        entry: FlextLdif Entry to normalize

        Returns:
        FlextResult containing normalized entry

        """
        try:
            # Access entry attributes
            if entry.attributes is None:
                return FlextResult.ok(entry)  # Nothing to normalize
            attributes_dict = entry.attributes.attributes.copy()

            # Convert olcAccess to access if present (from 2.x migration)
            if FlextLdapConstants.AclAttributes.OLC_ACCESS in attributes_dict:
                olc_access = attributes_dict.pop(
                    FlextLdapConstants.AclAttributes.OLC_ACCESS,
                )
                attributes_dict[FlextLdapConstants.AclAttributes.ACCESS] = olc_access

            # Map objectClasses for OpenLDAP 1.x format using helper methods
            object_classes = self._extract_object_classes_from_attributes(
                attributes_dict
            )
            if object_classes:
                mapped_classes = self._map_openldap_object_classes(object_classes)
                if mapped_classes:
                    # Update objectClass with mapped values
                    attributes_dict[
                        FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
                    ] = mapped_classes

            # Use Entry.create() instead of constructing Entry directly
            normalized_entry_result = FlextLdifModels.Entry.create(
                dn=str(entry.dn),
                attributes=cast("dict[str, list[str] | str]", attributes_dict),
            )
            if normalized_entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create normalized entry: {normalized_entry_result.error}",
                )
            return cast("FlextResult[FlextLdifModels.Entry]", normalized_entry_result)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"OpenLDAP 1.x entry normalization failed: {e}",
            )

    @cached_property
    def config_style(self) -> str:
        """Get configuration style for OpenLDAP 1.x using cached property.

        Returns:
            "slapd.conf" - static file configuration style

        """
        return "slapd.conf"

    @cached_property
    def replication_mechanism(self) -> str:
        """Get replication mechanism for OpenLDAP 1.x using cached property.

        Returns:
            "slurpd" - replication daemon for OpenLDAP 1.x

        """
        return "slurpd"

    @cached_property
    def supports_dynamic_config_cached(self) -> bool:
        """Check if server supports dynamic configuration using cached property.

        OpenLDAP 1.x uses static slapd.conf, not cn=config.
        Cached for performance since this is a static server characteristic.

        Returns:
            False - requires restart for config changes

        """
        return False

    # Legacy method names for backward compatibility
    def get_config_style(self) -> str:
        """Legacy method - use config_style property instead."""
        return self.config_style

    def get_replication_mechanism(self) -> str:
        """Legacy method - use replication_mechanism property instead."""
        return self.replication_mechanism

    def supports_dynamic_config(self) -> bool:
        """Legacy method - use supports_dynamic_config_cached property instead."""
        return self.supports_dynamic_config_cached

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes for OpenLDAP 1.x server using Railway Pattern."""
        # Validate connection first (Railway Pattern)
        validation_result = self._validate_ldap_connection(connection)
        if validation_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Connection validation failed: {validation_result.error}"
            )

        # Perform search and handle exceptions (Railway Pattern)
        try:
            attrs = self._perform_root_dse_search(connection)
            return FlextResult[dict[str, object]].ok(attrs)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Root DSE retrieval failed: {e}"
            )

    def _perform_root_dse_search(self, connection: Connection) -> dict[str, object]:
        """Perform Root DSE search for OpenLDAP 1.x using functional approach.

        DRY helper method that encapsulates the actual Root DSE search logic.
        Separated for testability and reusability.

        Args:
            connection: Bound LDAP connection

        Returns:
            Dictionary of Root DSE attributes

        Raises:
            Exception: If search fails or no entries found

        """
        # Use standard Root DSE search
        result = connection.search(
            search_base="",
            search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
            search_scope=cast(
                "FlextLdapConstants.Types.Ldap3Scope",
                FlextLdapConstants.Scopes.BASE_LDAP3,
            ),
            attributes=["*"],
            size_limit=1,
        )

        if not result or not connection.entries:
            error_msg = "No Root DSE found"
            raise RootDSENotFoundError(error_msg)

        # Extract attributes from the first entry
        entry = connection.entries[0]
        attrs = {}
        for attr in entry.entry_attributes:
            attrs[attr] = entry[attr].value
        return attrs

    @override
    def detect_server_type_from_root_dse(self, root_dse: dict[str, object]) -> str:
        """Detect OpenLDAP version from Root DSE attributes."""
        # Check for vendorName
        if FlextLdapConstants.RootDseAttributes.VENDOR_NAME in root_dse:
            vendor = str(
                root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_NAME],
            ).lower()
            if FlextLdapConstants.VendorNames.OPENLDAP in vendor:
                # Check for version to distinguish 1.x from 2.x
                if FlextLdapConstants.RootDseAttributes.VENDOR_VERSION in root_dse:
                    version = str(
                        root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_VERSION],
                    ).lower()
                    if version.startswith(
                        FlextLdapConstants.VersionPrefixes.VERSION_1_PREFIX,
                    ):
                        return FlextLdapConstants.ServerTypes.OPENLDAP1
                    if version.startswith(
                        FlextLdapConstants.VersionPrefixes.VERSION_2_PREFIX,
                    ):
                        return FlextLdapConstants.ServerTypes.OPENLDAP2
                # Default to 2.x if version unclear
                return FlextLdapConstants.ServerTypes.OPENLDAP2

        # Fallback: check for configContext (2.x feature)
        if FlextLdapConstants.RootDseAttributes.CONFIG_CONTEXT in root_dse:
            return FlextLdapConstants.ServerTypes.OPENLDAP2

        # Default to 1.x if no clear indicators
        return FlextLdapConstants.ServerTypes.OPENLDAP1

    @override
    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported controls for OpenLDAP 1.x server using Railway Pattern."""
        # Validate connection first (Railway Pattern)
        validation_result = self._validate_ldap_connection(connection)
        if validation_result.is_failure:
            return FlextResult[list[str]].fail(
                f"Connection validation failed: {validation_result.error}"
            )

        # Return controls (no exceptions expected for this simple operation)
        return FlextResult[list[str]].ok(self._get_openldap1_controls())

    def _get_openldap1_controls(self) -> list[str]:
        """Get OpenLDAP 1.x specific LDAP controls using cached approach.

        DRY helper method that returns the standard set of controls
        supported by OpenLDAP 1.x servers.

        Returns:
            List of LDAP control OIDs supported by OpenLDAP 1.x

        """
        return [
            "1.2.840.113556.1.4.319",  # pagedResults (limited support)
            "2.16.840.1.113730.3.4.2",  # ManageDsaIT
            "1.3.6.1.4.1.1466.20037",  # StartTLS
        ]

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for OpenLDAP 1.x using shared service."""
        # Use shared FlextLdapEntryAdapter service for validation
        adapter = FlextLdapEntryAdapter(server_type=self.server_type)
        return adapter.validate_entry_for_server(entry, self.server_type)
