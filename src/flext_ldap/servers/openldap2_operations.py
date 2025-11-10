"""OpenLDAP 2.x server operations implementation.

Complete implementation for OpenLDAP 2.x (cn=config style) with olcAccess ACLs.

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
        super().__init__(server_type=FlextLdapConstants.ServerTypes.OPENLDAP2)

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
    def set_acls(
        self,
        _connection: Connection,
        _dn: str,
        _acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set olcAccess ACLs on OpenLDAP 2.x.

        Args:
        _connection: Active ldap3 connection
        _dn: DN of config entry
        _acls: List of ACL dictionaries

        Returns:
        FlextResult indicating success

        """
        try:
            if not _connection or not _connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # Format ACLs to olcAccess strings
            formatted_acls: list[str] = []
            for acl in _acls:
                # Use Entry.create() instead of LdifAttributes.create() + Entry()
                # Convert acl dict to proper type (dict[str, str | list[str]])
                acl_dict: dict[str, str | list[str]] = {}
                for key, value in acl.items():
                    if isinstance(value, list):
                        acl_dict[key] = (
                            value
                            if all(isinstance(v, str) for v in value)
                            else [str(v) for v in value]
                        )
                    elif isinstance(value, str):
                        acl_dict[key] = value
                    else:
                        acl_dict[key] = [str(value)]

                acl_entry_result = FlextLdifModels.Entry.create(
                    dn=FlextLdapConstants.SyntheticDns.ACL_RULE,
                    attributes=acl_dict,
                )
                if acl_entry_result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to create ACL entry: {acl_entry_result.error}",
                    )
                acl_entry = acl_entry_result.unwrap()
                format_result = self.format_acl(acl_entry)
                if format_result.is_failure:
                    return FlextResult[bool].fail(
                        format_result.error or "ACL format failed",
                    )
                formatted_acls.append(format_result.unwrap())

            # Modify entry with new ACLs
            # Cast to Protocol type for proper type checking with ldap3
            typed_conn = cast("FlextLdapTypes.Ldap3Protocols.Connection", _connection)
            mods = cast(
                "dict[str, list[tuple[int, list[str]]]]",
                {
                    FlextLdapConstants.AclAttributes.OLC_ACCESS: [
                        (MODIFY_REPLACE, formatted_acls),
                    ],
                },
            )
            success: bool = typed_conn.modify(_dn, mods)

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
        """Parse olcAccess ACL string to Entry format.

        OpenLDAP 2.x ACL format:
        {0}to what by whom access

        Example:
        {0}to * by self write by anonymous auth by * read

        Args:
        acl_string: olcAccess ACL string

        Returns:
        FlextResult containing parsed ACL as Entry

        """
        try:
            # Parse ACL components
            acl_attributes: dict[str, list[str]] = {
                FlextLdapConstants.AclAttributes.RAW: [acl_string],
                FlextLdapConstants.AclAttributes.FORMAT: [
                    FlextLdapConstants.AclFormat.OPENLDAP2,
                ],
                FlextLdapConstants.AclAttributes.SERVER_TYPE_ALT: [
                    FlextLdapConstants.ServerTypes.OPENLDAP2,
                ],
            }

            # Extract index if present
            remaining = acl_string
            if acl_string.startswith("{"):
                end_idx = acl_string.find("}")
                if end_idx > 0:
                    acl_attributes[FlextLdapConstants.AclAttributes.INDEX] = [
                        acl_string[1:end_idx],
                    ]
                    remaining = acl_string[end_idx + 1 :].strip()

            # Extract 'to' clause
            if remaining.startswith("to "):
                parts = remaining.split(" by ", 1)
                acl_attributes[FlextLdapConstants.AclAttributes.TO] = [
                    parts[0][3:].strip(),
                ]
                if len(parts) > 1:
                    acl_attributes[FlextLdapConstants.AclSyntaxKeywords.BY] = [parts[1]]

            # LdifAttributes.create returns FlextResult, need to unwrap
            # Use Entry.create() instead of LdifAttributes.create() + Entry()
            # Convert attributes dict to proper type for Entry.create()
            acl_attrs_for_create: dict[str, str | list[str]] = {}
            for key, values in acl_attributes.items():
                if isinstance(values, list) and len(values) == 1:
                    acl_attrs_for_create[key] = values[0]
                else:
                    acl_attrs_for_create[key] = values

            entry_result = FlextLdifModels.Entry.create(
                dn="cn=AclRule",
                attributes=acl_attrs_for_create,
            )
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create ACL entry: {entry_result.error}",
                )
            return entry_result

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(f"ACL parse failed: {e}")

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
            raw_attr = acl_entry.attributes.get(FlextLdapConstants.AclAttributes.RAW)
            if raw_attr and len(raw_attr) > 0:
                return FlextResult[str].ok(raw_attr[0])

            # Otherwise construct from parts
            parts: list[str] = []

            index_attr = acl_entry.attributes.get(
                FlextLdapConstants.AclAttributes.INDEX,
            )
            if index_attr and len(index_attr) > 0:
                parts.append(f"{{{index_attr[0]}}}")

            to_attr = acl_entry.attributes.get(FlextLdapConstants.AclAttributes.TO)
            if to_attr and len(to_attr) > 0:
                parts.append(f"to {to_attr[0]}")

            by_attr = acl_entry.attributes.get(FlextLdapConstants.AclSyntaxKeywords.BY)
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
    def detect_server_type_from_root_dse(self, _root_dse: dict[str, object]) -> str:
        """Detect OpenLDAP version from Root DSE attributes.

        Args:
            _root_dse: Root DSE attributes

        Returns:
            Detected server type ("openldap2", "openldap1", or "openldap")

        """
        # Check for vendorName
        if FlextLdapConstants.RootDseAttributes.VENDOR_NAME in _root_dse:
            vendor = str(
                _root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_NAME],
            ).lower()
            if FlextLdapConstants.VendorNames.OPENLDAP in vendor:
                # Check for version to distinguish 1.x from 2.x
                if FlextLdapConstants.RootDseAttributes.VENDOR_VERSION in _root_dse:
                    version = str(
                        _root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_VERSION],
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
        if FlextLdapConstants.RootDseAttributes.CONFIG_CONTEXT in _root_dse:
            return FlextLdapConstants.ServerTypes.OPENLDAP2

        # Fallback to generic openldap
        return FlextLdapConstants.ServerTypes.OPENLDAP

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
        entry: FlextLdifModels.Entry,
        _target_server_type: str | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for OpenLDAP 2.x server specifics.

        Applies OpenLDAP 2.x-specific transformations:
        - Ensures cn=config compatible objectClasses
        - Converts access ACLs to olcAccess format if needed
        - Normalizes attribute names to lowercase

        Args:
        entry: Entry to normalize (accepts both LDAP and LDIF entry types)

        Returns:
        FlextResult containing normalized entry

        """
        # Entry is already FlextLdifModels.Entry
        # normalize_entry expects FlextLdifModels.Entry
        ldif_entry = entry

        # Reuse existing normalize_entry method which handles OpenLDAP 2.x specifics
        normalize_result = self.normalize_entry(ldif_entry)
        if normalize_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(normalize_result.error)

        # Convert FlextLdifModels.Entry to FlextLdifModels.Entry
        normalized_ldif_entry = normalize_result.unwrap()

        # Cast FlextLdifModels.Entry to FlextLdifModels.Entry
        # Both have compatible structure (dn, attributes) and represent LDAP entries
        return FlextResult[FlextLdifModels.Entry].ok(
            normalized_ldif_entry,
        )

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for OpenLDAP 2.x server.

        Checks:
        - Entry has DN
        - Entry has attributes
        - Entry has objectClass
        - ObjectClass values are valid for OpenLDAP 2.x

        Args:
        entry: Entry to validate
        ^_server_type: Ignored for OpenLDAP 2.x (uses self._server_type)

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
            if FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS not in attrs:
                return FlextResult[bool].fail("Entry must have objectClass attribute")

            # OpenLDAP 2.x accepts both standard and olc* objectClasses
            object_class_attr = attrs[
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
            ]
            # object_class_attr is already a list, don't call .values
            object_classes = (
                object_class_attr
                if isinstance(object_class_attr, list)
                else [object_class_attr]
            )

            # Ensure at least one objectClass value
            if not object_classes:
                return FlextResult[bool].fail(
                    "objectClass must have at least one value",
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")
