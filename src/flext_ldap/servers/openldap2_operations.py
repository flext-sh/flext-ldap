"""OpenLDAP 2.x server operations implementation.

Complete implementation for OpenLDAP 2.x (cn=config style) with olcAccess ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from functools import cached_property
from typing import cast, override

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import MODIFY_REPLACE, Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.utilities import FlextLdapUtilities


class FlextLdapServersOpenLDAP2Operations(FlextLdapServersBaseOperations):
    """Complete OpenLDAP 2.x operations implementation following SOLID and Flext principles.

    This class implements server-specific operations for OpenLDAP 2.x (cn=config style)
    while maintaining clean separation of concerns and leveraging Flext architectural patterns.

    **SOLID Principles Compliance:**
    - SRP: Single responsibility - handles only OpenLDAP 2.x-specific LDAP operations
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

    **OpenLDAP 2.x Features:**
    - cn=config dynamic configuration with olcDatabase entries
    - olcAccess ACL attribute for access control
    - Enterprise features with paged results and advanced controls
    - START_TLS and SASL authentication support
    - Server-side sorting and content synchronization
    """

    def __init__(self) -> None:
        """Initialize OpenLDAP 2.x operations."""
        super().__init__(server_type=FlextLdapConstants.ServerTypes.OPENLDAP2)

    @cached_property
    def openldap2_default_controls(self) -> list[str]:
        """Get cached default supported controls for OpenLDAP 2.x.

        Uses cached_property for performance - computed once and cached.
        Returns immutable list of default control OIDs for OpenLDAP 2.x.

        Returns:
            List of default control OIDs for fallback scenarios

        """
        return [
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

    # --------------------------------------------------------------------- #
    # INHERITED METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods are used directly from the base class without override:
    # - get_default_port(): Returns 389 (standard LDAP port)
    # - supports_start_tls(): Returns True (standard LDAP feature)
    # - get_schema_dn(): Returns "cn=subschema" (OpenLDAP standard)
    # - get_max_page_size(): Returns 1000 (standard page size)
    # - supports_paged_results(): Returns True (standard LDAP feature)
    # - supports_vlv(): Returns False (OpenLDAP VLV support limited)
    # - search_with_paging(): Generic paged search implementation
    # - get_supported_controls(): OpenLDAP-specific supported controls
    # - normalize_entry_for_server(): Generic entry normalization
    #
    # --------------------------------------------------------------------- #
    # OVERRIDDEN METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods override the base class with OpenLDAP 2.x-specific logic:
    # - get_bind_mechanisms(): Returns OpenLDAP-specific bind mechanisms
    # - discover_schema(): OpenLDAP-specific schema discovery
    # - parse_object_class(): OpenLDAP-specific objectClass parsing
    # - parse_attribute_type(): OpenLDAP-specific attributeType parsing
    # - get_acl_attribute_name(): Returns "olcAccess" (OpenLDAP 2.x ACL attribute)
    # - get_acl_format(): Returns "openldap2" (OpenLDAP 2.x format)
    # - get_acls(): OpenLDAP-specific ACL retrieval with olcAccess
    # - set_acls(): OpenLDAP-specific ACL setting with olcAccess
    # - parse(): OpenLDAP 2.x-specific ACL parsing (olcAccess format)
    # - format_acl(): OpenLDAP 2.x-specific ACL formatting (olcAccess format)
    # - get_root_dse_attributes(): OpenLDAP 2.x-specific Root DSE retrieval
    # - detect_server_type_from_root_dse(): OpenLDAP 2.x server detection logic
    # - validate_entry_for_server(): OpenLDAP 2.x-specific entry validation

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
            FlextLdapConstants.SaslMechanisms.SASL_GSSAPI,
        ]

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """OpenLDAP 2.x uses cn=subschema."""
        return FlextLdapConstants.Defaults.SCHEMA_SUBENTRY

    @override
    def discover_schema(
        self,
        connection: Connection,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Discover schema from OpenLDAP 2.x - enhanced with matchingRules."""
        try:
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                    conn_check.error,
                )

            # OpenLDAP 2.x needs more schema attributes
            search_result = connection.search(
                search_base=self.get_schema_dn(),
                search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                attributes=[
                    FlextLdapConstants.SchemaAttributes.OBJECT_CLASSES,
                    FlextLdapConstants.SchemaAttributes.ATTRIBUTE_TYPES,
                    FlextLdapConstants.SchemaAttributes.LDAP_SYNTAXES,
                    FlextLdapConstants.SchemaAttributes.MATCHING_RULES,
                ],
            )

            if not search_result or not connection.entries:
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                    "Schema discovery failed",
                )

            schema_result = FlextLdifModels.SchemaDiscoveryResult(
                server_type=FlextLdapConstants.ServerTypes.OPENLDAP2,
            )

            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(schema_result)

        except Exception as e:
            self.logger.exception("Schema discovery error", extra={"error": str(e)})
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                f"Schema discovery failed: {e}",
            )

    @override
    def parse_object_class(
        self,
        object_class_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse OpenLDAP 2.x objectClass definition - enhanced with OpenLDAP 2.x note."""
        result = super().parse_object_class(object_class_def)
        if not result.is_failure:
            entry = result.unwrap()
            # Add OpenLDAP 2.x-specific note
            if entry.attributes is not None:
                entry.attributes.attributes["note"] = ["OpenLDAP 2.x schema parsing"]
        return result

    @override
    def parse_attribute_type(
        self,
        attribute_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse OpenLDAP 2.x attributeType definition - enhanced with OpenLDAP 2.x note."""
        result = super().parse_attribute_type(attribute_def)
        if not result.is_failure:
            entry = result.unwrap()
            # Add OpenLDAP 2.x-specific note
            if entry.attributes is not None:
                entry.attributes.attributes["note"] = ["OpenLDAP 2.x schema parsing"]
        return result

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @override
    def get_acl_attribute_name(self) -> str:
        """OpenLDAP 2.x uses olcAccess attribute."""
        return FlextLdapConstants.AclAttributes.OLC_ACCESS

    @override
    def get_acl_format(self) -> str:
        """OpenLDAP 2.x ACL format identifier."""
        return "openldap2"

    # get_acls() inherited from base class - uses get_acl_attribute_name()

    @override
    def _format_acls(self, acls: list[dict[str, object]]) -> FlextResult[list[str]]:
        """Format ACL dictionaries to olcAccess strings using FlextLdapUtilities.

        Template Method Pattern: Implements abstract method from base class.
        Consolidated with FlextLdapUtilities.AclFormatting for reusability.
        Delegates formatting to shared utility.

        Args:
            acls: List of ACL dictionaries

        Returns:
            FlextResult containing formatted olcAccess strings or error

        """
        return FlextLdapUtilities.AclFormatting.format_acls_for_server(acls, self)

    @override
    def _get_acl_attribute(self) -> str:
        """Get OpenLDAP 2.x ACL attribute name.

        Template Method Pattern: Implements abstract method from base class.

        Returns:
            'olcAccess' - OpenLDAP 2.x ACL attribute

        """
        return FlextLdapConstants.AclAttributes.OLC_ACCESS

    def set_acls(
        self,
        _connection: Connection,
        _dn: str,
        _acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set olcAccess ACLs on OpenLDAP 2.x.

        Refactored with Railway Pattern: 6→4 returns (SOLID/DRY compliance).

        Args:
            _connection: Active ldap3 connection
            _dn: DN of config entry
            _acls: List of ACL dictionaries

        Returns:
            FlextResult indicating success

        """
        try:
            # Railway Pattern: Early validation
            if not _connection or not _connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # Railway Pattern: Delegate formatting to helper
            format_result = self._format_acls(_acls)
            if format_result.is_failure:
                return FlextResult[bool].fail(str(format_result.error))

            formatted_acls = format_result.unwrap()

            # Railway Pattern: Execute modify operation
            mods = {
                FlextLdapConstants.AclAttributes.OLC_ACCESS: [
                    (MODIFY_REPLACE, formatted_acls),
                ],
            }
            success: bool = _connection.modify(_dn, mods)

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
            self.logger.exception("Set ACLs error", extra={"dn": _dn, "error": str(e)})
            return FlextResult[bool].fail(f"Set ACLs failed: {e}")

    @override
    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
        """Parse olcAccess ACL string for OpenLDAP 2.x.

        Delegates to FlextLdifAcl service for proper ACL parsing using server-specific quirks.
        This ensures consistent ACL handling across the Flext framework.

        Args:
            acl_string: olcAccess ACL string

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
                FlextLdapConstants.AclAttributes.FORMAT: FlextLdapConstants.AclFormat.OPENLDAP2,
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
            # Cast to ensure correct Entry type from FlextLdifModels
            return cast(
                "FlextResult[FlextLdifModels.Entry]",
                entry_result,
            )

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"OpenLDAP 2.x ACL parse failed: {e}",
            )

    @override
    def format_acl(self, acl_entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Format ACL Entry to olcAccess string.

        Args:
        acl_entry: ACL Entry object

        Returns:
        FlextResult containing formatted ACL string

        """
        try:
            # Extract attributes from entry
            raw_attr = None
            if acl_entry.attributes is not None:
                raw_attr = acl_entry.attributes.get(
                    FlextLdapConstants.AclAttributes.RAW
                )
            if raw_attr and len(raw_attr) > 0:
                return FlextResult[str].ok(raw_attr[0])

            # Otherwise construct from parts
            parts: list[str] = []

            index_attr = None
            if acl_entry.attributes is not None:
                index_attr = acl_entry.attributes.get(
                    FlextLdapConstants.AclAttributes.INDEX,
                )
            if index_attr and len(index_attr) > 0:
                parts.append(f"{{{index_attr[0]}}}")

            to_attr = None
            if acl_entry.attributes is not None:
                to_attr = acl_entry.attributes.get(FlextLdapConstants.AclAttributes.TO)
            if to_attr and len(to_attr) > 0:
                parts.append(f"to {to_attr[0]}")

            by_attr = None
            if acl_entry.attributes is not None:
                by_attr = acl_entry.attributes.get(
                    FlextLdapConstants.AclSyntaxKeywords.BY
                )
            if by_attr and len(by_attr) > 0:
                parts.append(f"by {by_attr[0]}")

            return FlextResult[str].ok(" ".join(parts))

        except Exception as e:
            return FlextResult[str].fail(f"ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    # add_entry(), modify_entry(), delete_entry() - Use base implementations

    # normalize_entry() - Use base implementation (returns entry as-is)

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    # get_max_page_size(), supports_paged_results() - Use base defaults
    # supports_vlv() - Use base default (False)

    # search_with_paging() - Use base implementation

    # =========================================================================
    # Root DSE OPERATIONS
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
            search_result = connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                search_scope=cast(
                    "FlextLdapConstants.Types.Ldap3Scope",
                    FlextLdapConstants.Scopes.BASE_LDAP3,
                ),
                attributes=["*", "+"],
            )

            if not search_result or not connection.entries:
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

        # Check for configContext (2.x feature - cn=config)
        if FlextLdapConstants.RootDseAttributes.CONFIG_CONTEXT in root_dse:
            return FlextLdapConstants.ServerTypes.OPENLDAP2

        # Fallback to generic openldap
        return FlextLdapConstants.ServerTypes.OPENLDAP

    def _extract_supported_controls_from_root_dse(
        self, root_dse: dict[str, object]
    ) -> list[str]:
        """Extract supportedControl OIDs from Root DSE attributes.

        Extracted helper for Railway Pattern (SOLID compliance).

        Args:
            root_dse: Root DSE attributes dictionary

        Returns:
            List of control OIDs (empty list if not found)

        """
        if "supportedControl" not in root_dse:
            return []

        controls = root_dse["supportedControl"]
        if isinstance(controls, list):
            return [str(c) for c in controls]
        return [str(controls)]

    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported controls for OpenLDAP 2.x server.

        Refactored with Railway Pattern: 6→4 returns (SOLID/DRY compliance).

        Args:
            connection: Active ldap3 connection

        Returns:
            FlextResult containing list of supported control OIDs

        """
        try:
            # Railway Pattern: Early validation
            if not connection or not connection.bound:
                return FlextResult[list[str]].fail("Connection not bound")

            # Railway Pattern: Get Root DSE which contains supportedControl attribute
            root_dse_result = self.get_root_dse_attributes(connection)
            if root_dse_result.is_failure:
                # Fallback to cached default OpenLDAP 2.x controls
                return FlextResult[list[str]].ok(self.openldap2_default_controls)

            # Railway Pattern: Delegate extraction to helper
            root_dse = root_dse_result.unwrap()
            controls = self._extract_supported_controls_from_root_dse(root_dse)
            return FlextResult[list[str]].ok(controls)

        except Exception as e:
            self.logger.exception("Control retrieval error", extra={"error": str(e)})
            return FlextResult[list[str]].fail(f"Control retrieval failed: {e}")

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for OpenLDAP 2.x using shared service."""
        # Use shared FlextLdapEntryAdapter service for validation
        adapter = FlextLdapEntryAdapter(server_type=self.server_type)
        return adapter.validate_entry_for_server(entry, self.server_type)
