"""Base server operations abstract class for LDAP servers.

Abstract base class defining interface for all server-specific LDAP
operations implementations with ACL, schema, and entry management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import cast

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdifModels
from flext_ldif.services import (
    FlextLdifAcl,
    FlextLdifDn,
)
from ldap3 import BASE, LEVEL, MODIFY_REPLACE, SUBTREE, Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.services.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.typings import FlextLdapTypes


class FlextLdapServersBaseOperations(FlextService[None], ABC):
    """Abstract base class for server-specific LDAP operations.

    All server implementations (OpenLDAP, OID, OUD, AD, etc.) must extend
    this class and implement the required methods for:
    - Connection handling
    - Schema operations
    - ACL operations
    - Entry operations
    - Search operations
    """

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize base server operations.

        Args:
        server_type: LDAP server type identifier (optional)

        """
        super().__init__()
        # logger inherited from FlextService
        self._server_type = server_type or FlextLdapConstants.Defaults.SERVER_TYPE
        # Use flext-ldif services for DN and ACL operations
        self._dn_service = FlextLdifDn()
        self._acl_service = FlextLdifAcl()

    def execute(self) -> FlextResult[None]:
        """Execute method required by FlextService."""
        return FlextResult[None].ok(None)

    @property
    def server_type(self) -> str:
        """Get server type identifier."""
        return self._server_type

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    def get_default_port(self, *, use_ssl: bool = False) -> int:
        """Get default port for this server type.

        Args:
        use_ssl: Whether SSL is used

        Returns:
        Default port number (636 for SSL, 389 otherwise)

        """
        return 636 if use_ssl else 389

    def supports_start_tls(self) -> bool:
        """Check if server supports START_TLS.

        Default: True (most modern LDAP servers support START_TLS)
        """
        return True

    def get_bind_mechanisms(self) -> list[str]:
        """Get supported BIND mechanisms (SIMPLE, SASL, etc.).

        Default: ["SIMPLE"] - Override for SASL-specific support
        """
        return [FlextLdapConstants.SaslMechanisms.SIMPLE]

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_schema_dn(self) -> str:
        """Get schema subentry DN for this server type.

        Returns:
        Schema DN (e.g., 'cn=subschema', 'cn=schema')

        """

    def discover_schema(
        self,
        connection: Connection,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Discover schema from server - default implementation.

        Default implementation searches schema DN for objectClasses and attributeTypes.
        Override for server-specific schema discovery.

        Args:
        connection: Active LDAP connection

        Returns:
        FlextResult containing schema information

        """
        try:
            # Check connection
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                    conn_check.error,
                )

            # Search schema subentry for standard schema attributes
            search_result = connection.search(
                search_base=self.get_schema_dn(),
                search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                attributes=["objectClasses", "attributeTypes"],
            )

            if not search_result or not connection.entries:
                schema_result = FlextLdifModels.SchemaDiscoveryResult(
                    server_type=self.server_type,
                )
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(
                    schema_result,
                )

            # Success - return schema result
            schema_result = FlextLdifModels.SchemaDiscoveryResult(
                server_type=self.server_type,
            )
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(schema_result)

        except Exception as e:
            self.logger.exception("Schema discovery error", extra={"error": str(e)})
            schema_result = FlextLdifModels.SchemaDiscoveryResult(
                server_type=self.server_type,
            )
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(schema_result)

    def parse_object_class(
        self,
        object_class_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse objectClass definition from schema - default implementation.

        Args:
        object_class_def: ObjectClass definition string

        Returns:
        FlextResult containing parsed objectClass as Entry

        """
        # Default implementation: return definition with server_type info as Entry

        # Create LdifAttributes with proper initialization
        attrs_data = {
            "definition": [object_class_def],
            "serverType": [self.server_type],
        }

        # Use the proper constructor signature: attributes=dict, metadata=None
        attributes = FlextLdifModels.LdifAttributes(attributes=attrs_data)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=ObjectClassDefinition"),
            attributes=attributes,
        )
        return FlextResult.ok(entry)

    def parse_attribute_type(
        self,
        attribute_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse attributeType definition from schema - default implementation.

        Args:
        attribute_def: AttributeType definition string

        Returns:
        FlextResult containing parsed attribute as Entry

        """
        # Default implementation: return definition with server_type info as Entry

        # Create LdifAttributes with proper initialization
        attrs_data = {
            "definition": [attribute_def],
            "serverType": [self.server_type],
        }

        # Use the proper constructor signature: attributes=dict, metadata=None
        attributes = FlextLdifModels.LdifAttributes(attributes=attrs_data)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=AttributeTypeDefinition"),
            attributes=attributes,
        )
        return FlextResult.ok(entry)

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_acl_attribute_name(self) -> str:
        """Get ACL attribute name for this server type.

        Returns:
        ACL attribute name (e.g., 'olcAccess', 'aci', 'orclaci')

        """

    @abstractmethod
    def get_acl_format(self) -> str:
        """Get ACL format identifier.

        Returns:
        ACL format (e.g., 'openldap2', 'oracle', '389ds')

        """

    def get_acls(
        self,
        _connection: Connection,
        _dn: str,
    ) -> FlextResult[list[FlextLdifModels.Acl]]:
        """Get ACLs for a given DN - default implementation.

        Default implementation: returns empty list.
        Override for server-specific ACL retrieval.

        Returns:
        FlextResult containing list of ACL entries

        """
        # Default implementation returns empty list
        return FlextResult[list[FlextLdifModels.Acl]].ok([])

    def set_acls(
        self,
        _connection: Connection,
        _dn: str,
        _acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set ACLs for a given DN - default implementation.

        Default implementation: not supported.
        Override for server-specific ACL setting.

        Returns:
        FlextResult indicating success

        """
        return FlextResult[bool].fail(
            f"ACL setting not supported for server type: {self.server_type}",
        )

    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
        """Parse ACL string using FlextLdifAcl.

        Delegates to FlextLdifAcl.parse() to eliminate duplication
        and ensure RFC-compliant ACL parsing with server-specific quirks support.

        Args:
        acl_string: ACL string in server-specific format

        Returns:
        FlextResult containing parsed ACL as Entry object

        """
        # Use FlextLdifAcl for ACL parsing
        try:
            # Parse ACL using FlextLdifAcl
            acl_result = self._acl_service.parse(acl_string, self.server_type)
            if acl_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"ACL parsing failed: {acl_result.error}",
                )

            # Convert FlextLdifModels.Acl to Entry format
            acl = acl_result.unwrap()

            # Extract ACL data to entry attributes
            acl_attributes: dict[str, list[str]] = {
                FlextLdapConstants.AclAttributes.RAW: [acl_string],
                "format": [self.get_acl_format()],
                "serverType": [self.server_type],
            }

            # Add ACL-specific attributes from Acl model
            if acl.target:
                # AclTarget has target_dn attribute (not value)
                target_dn = (
                    acl.target.target_dn
                    if hasattr(acl.target, "target_dn")
                    else str(acl.target)
                )
                acl_attributes[FlextLdapConstants.AclAttributes.TARGET] = [target_dn]
                if hasattr(acl.target, "attributes") and acl.target.attributes:
                    attr_list = (
                        acl.target.attributes
                        if isinstance(acl.target.attributes, list)
                        else [acl.target.attributes]
                    )
                    acl_attributes[
                        FlextLdapConstants.AclAttributes.TARGET_ATTRIBUTES
                    ] = [str(a) for a in attr_list]
            if acl.subject:
                # AclSubject has subject_type and subject_value
                if hasattr(acl.subject, "subject_value") and acl.subject.subject_value:
                    acl_attributes[FlextLdapConstants.AclAttributes.SUBJECT] = [
                        str(acl.subject.subject_value),
                    ]
                elif hasattr(acl.subject, "subject_type"):
                    acl_attributes[FlextLdapConstants.AclAttributes.SUBJECT] = [
                        f"{acl.subject.subject_type}:{str(acl.subject.subject_value) if hasattr(acl.subject, 'subject_value') else ''}",
                    ]
                else:
                    acl_attributes[FlextLdapConstants.AclAttributes.SUBJECT] = [
                        str(acl.subject),
                    ]
            if acl.permissions:
                perms = acl.permissions
                # AclPermissions has individual permission flags (read, write, etc.)
                perm_list: list[str] = [
                    perm_name
                    for perm_name in FlextLdapConstants.AclPermissions.ALL_PERMISSIONS
                    if hasattr(perms, perm_name) and getattr(perms, perm_name)
                ]
                if perm_list:
                    acl_attributes[FlextLdapConstants.AclAttributes.PERMISSIONS] = (
                        perm_list
                    )
                else:
                    acl_attributes[FlextLdapConstants.AclAttributes.PERMISSIONS] = [
                        str(perms),
                    ]

            # Use Entry.create() instead of constructing Entry directly
            # Convert attributes dict to proper type for Entry.create()
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
            return FlextResult[FlextLdifModels.Entry].fail(f"ACL parse failed: {e}")

    def format_acl(self, acl_entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Format ACL Entry using FlextLdifAcl.

        Delegates to FlextLdifAcl when possible, falls back to raw attribute extraction.

        Args:
        acl_entry: ACL Entry object

        Returns:
        FlextResult containing formatted ACL string

        """
        # Extract raw ACL string if available
        raw_attr = acl_entry.attributes.get(FlextLdapConstants.AclAttributes.RAW)
        if raw_attr and len(raw_attr) > 0:
            return FlextResult[str].ok(raw_attr[0])

        # Server-specific implementations should override this to use FlextLdifAcl
        # format capabilities when available
        return FlextResult[str].fail(
            f"ACL formatting requires raw ACL string (format: {self.get_acl_format()})",
        )

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    def add_entry(
        self,
        connection: Connection,
        entry: FlextLdifModels.Entry,
        *,
        should_normalize: bool = True,
    ) -> FlextResult[bool]:
        """Add entry to LDAP server - default implementation.

        Args:
        connection: Active LDAP connection
        entry: FlextLdif Entry to add
        should_normalize: Whether to normalize entry first (default: True)

        Returns:
        FlextResult indicating success

        """
        try:
            # Check connection
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[bool].fail(conn_check.error)

            # Prepare entry (extract DN, objectClass, convert attributes)
            prep_result = self._prepare_entry_for_add(
                entry,
                should_normalize=should_normalize,
            )
            if prep_result.is_failure:
                return FlextResult[bool].fail(prep_result.error)

            dn, object_class, ldap3_attrs = prep_result.unwrap()

            # Cast to Protocol type for proper type checking with ldap3
            typed_conn = cast("FlextLdapTypes.Ldap3Protocols.Connection", connection)
            attrs_casted = cast(
                "dict[str, str | list[str]] | None",
                ldap3_attrs or None,
            )
            success = typed_conn.add(dn, object_class, attributes=attrs_casted)

            if not success:
                error_msg = self._get_connection_error_message(connection)
                return FlextResult[bool].fail(f"Add entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Add entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    def modify_entry(
        self,
        connection: Connection,
        dn: str,
        modifications: dict[str, object],
    ) -> FlextResult[bool]:
        """Modify existing entry - default implementation.

        Args:
        connection: Active LDAP connection
        dn: Distinguished Name of entry to modify
        modifications: Modifications to apply

        Returns:
        FlextResult indicating success

        """
        try:
            # Check connection
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[bool].fail(conn_check.error)

            # Convert modifications to ldap3 format
            ldap3_mods = self._convert_modifications_to_ldap3(modifications)

            # Cast to Protocol type for proper type checking with ldap3
            typed_conn = cast("FlextLdapTypes.Ldap3Protocols.Connection", connection)
            mods = cast("dict[str, list[tuple[int, list[str]]]]", ldap3_mods)
            success = typed_conn.modify(dn, mods)

            if not success:
                error_msg = self._get_connection_error_message(connection)
                return FlextResult[bool].fail(f"Modify entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Modify entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    def delete_entry(self, connection: Connection, dn: str) -> FlextResult[bool]:
        """Delete entry from LDAP server - default implementation.

        Args:
        connection: Active LDAP connection
        dn: Distinguished Name of entry to delete

        Returns:
        FlextResult indicating success

        """
        try:
            # Check connection
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[bool].fail(conn_check.error)

            # Cast to Protocol type for proper type checking with ldap3
            typed_conn = cast("FlextLdapTypes.Ldap3Protocols.Connection", connection)
            success = typed_conn.delete(dn)

            if not success:
                error_msg = self._get_connection_error_message(connection)
                return FlextResult[bool].fail(f"Delete entry failed: {error_msg}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Delete entry error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    def normalize_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for this server type.

        Default implementation: returns entry as-is for validation.
        Override for server-specific transformations.

        Args:
        entry: FlextLdif Entry to normalize

        Returns:
        FlextResult containing normalized entry

        """
        self.logger.debug(
            "Entry normalized for server type",
            extra={"server_type": self._server_type},
        )
        return FlextResult[FlextLdifModels.Entry].ok(entry)

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    def get_max_page_size(self) -> int:
        """Get maximum page size for paged searches.

        Default: 1000 entries per page
        """
        return 1000

    def supports_paged_results(self) -> bool:
        """Check if server supports paged result control.

        Default: True (RFC 2696 is widely supported)
        """
        return True

    def supports_vlv(self) -> bool:
        """Check if server supports Virtual List View control.

        Default: False (VLV is less common than paged results)
        Override in implementations that support it (OID, OUD, AD)
        """
        return False

    def search_with_paging(
        self,
        connection: Connection,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "subtree",
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute paged search - default implementation using ldap3.

        Args:
            connection: Active LDAP connection
            base_dn: Search base DN
            search_filter: LDAP search filter
            attributes: Attributes to retrieve
            scope: Search scope ("base", "level", or "subtree")
            page_size: Page size for results

        Returns:
            FlextResult containing list of entries

        """
        try:
            # Check connection
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(conn_check.error)

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

            # Convert results to FlextLdif entries
            adapter = FlextLdapEntryAdapter()
            entries: list[FlextLdifModels.Entry] = []

            for ldap3_entry in entry_generator:
                if "dn" in ldap3_entry and "attributes" in ldap3_entry:
                    entry_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                    if entry_result.is_success:
                        entries.append(entry_result.unwrap())

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except Exception as e:
            self.logger.exception("Paged search error", extra={"error": str(e)})
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Paged search failed: {e}",
            )

    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes - default implementation.

        Default implementation using standard LDAP Root DSE search.

        Args:
            connection: Active LDAP connection

        Returns:
            FlextResult containing Root DSE attributes

        """
        try:
            # Check connection
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[dict[str, object]].fail(conn_check.error)

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

            if result and connection.entries:
                # Extract attributes from the single entry
                entry = connection.entries[0]
                attrs: dict[str, object] = {}
                for attr in entry.entry_attributes:
                    attrs[attr] = entry[attr].value

                return FlextResult[dict[str, object]].ok(attrs)

            return FlextResult[dict[str, object]].fail("No Root DSE found")

        except Exception as e:
            self.logger.exception("Root DSE retrieval error", extra={"error": str(e)})
            return FlextResult[dict[str, object]].fail(
                f"Root DSE retrieval failed: {e}",
            )

    def detect_server_type_from_root_dse(self, _root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE - default implementation.

        Default implementation returns "generic".
        Override for server-specific detection logic.

        Returns:
            Detected server type ("generic" by default)

        """
        # Default implementation returns generic
        return FlextLdapConstants.Defaults.SERVER_TYPE

    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported LDAP controls - default implementation.

        Default implementation returns standard LDAP controls.
        Override for server-specific control support.

        Args:
            connection: Active LDAP connection

        Returns:
            FlextResult containing list of supported control OIDs

        """
        try:
            # Check connection
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[list[str]].fail(conn_check.error)

            # Return standard LDAP controls
            standard_controls = [
                "1.2.840.113556.1.4.319",  # pagedResults
                "1.2.840.113556.1.4.473",  # sortRequest/sortResponse
                "1.3.6.1.4.1.1466.20037",  # StartTLS
            ]

            return FlextResult[list[str]].ok(standard_controls)

        except Exception as e:
            self.logger.exception("Control retrieval error", extra={"error": str(e)})
            return FlextResult[list[str]].fail(f"Control retrieval failed: {e}")

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _target_server_type: str | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for this server type.

        Default implementation: delegates to normalize_entry().
        Override for server-specific cross-server normalization.

        Returns:
            FlextResult containing normalized entry

        """
        return self.normalize_entry(entry)

    def normalize_attribute_name(self, attribute_name: str) -> str:
        """Normalize LDAP attribute name per server conventions.

        Args:
            attribute_name: Attribute name to normalize

        Returns:
            Normalized attribute name (default: lowercase)

        """
        return attribute_name.lower()

    def normalize_object_class(self, object_class: str) -> str:
        """Normalize LDAP object class name per server conventions.

        Args:
            object_class: Object class name to normalize

        Returns:
            Normalized object class name (default: lowercase)

        """
        return object_class.lower()

    def normalize_dn(self, dn: str) -> str:
        """Normalize distinguished name using FlextLdifDn (RFC 4514).

        Delegates to FlextLdifDn for RFC 4514 compliant normalization.

        Args:
            dn: DN to normalize

        Returns:
            Normalized DN string

        """
        normalize_result = self._dn_service.normalize(dn)
        if normalize_result.is_failure:
            # Fallback to cleaned DN if normalization fails
            return self._dn_service.clean_dn(dn)
        return normalize_result.unwrap()

    # =========================================================================
    # HELPER METHODS - Common LDAP operations used by all servers
    # =========================================================================

    def _check_connection(self, connection: Connection | None) -> FlextResult[None]:
        """Check if connection is valid and bound.

        Args:
            connection: LDAP connection to check

        Returns:
            FlextResult[None] indicating if connection is valid

        """
        if not connection:
            return FlextResult[None].fail("Connection is None")
        if not connection.bound:
            return FlextResult[None].fail("Connection not bound")
        return FlextResult[None].ok(None)

    def _prepare_entry_for_add(
        self,
        entry: FlextLdifModels.Entry,
        *,
        should_normalize: bool = True,
    ) -> FlextResult[tuple[str, list[str], dict[str, list[str]]]]:
        """Prepare entry for add operation.

        Extracts DN, objectClass, and converts attributes to ldap3 format.

        Args:
            entry: Entry to prepare
            should_normalize: Whether to normalize entry first

        Returns:
            FlextResult with tuple of (dn, object_class, ldap3_attrs)

        """
        # Optionally normalize entry
        if should_normalize:
            norm_result = self.normalize_entry(entry)
            if norm_result.is_failure:
                return FlextResult.fail(norm_result.error or "Normalization failed")
            entry = norm_result.unwrap()

        # Extract DN, objectClass, and attributes
        dn = str(entry.dn)
        attrs = entry.attributes.attributes

        # Extract objectClass
        oc_attr = attrs.get(
            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
            [FlextLdapConstants.Defaults.OBJECT_CLASS_TOP],
        )
        object_class: list[str] = oc_attr if isinstance(oc_attr, list) else [oc_attr]

        # Convert attributes to ldap3 format
        ldap3_attrs: dict[str, list[str]] = {}
        for attr_name, attr_value in attrs.items():
            if (
                attr_name != FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
            ):  # Skip objectClass (passed separately)
                value_list = (
                    attr_value if isinstance(attr_value, list) else [attr_value]
                )
                ldap3_attrs[attr_name] = [str(v) for v in value_list]

        return FlextResult.ok((dn, object_class, ldap3_attrs))

    def _convert_modifications_to_ldap3(
        self,
        modifications: dict[str, object],
    ) -> dict[str, list[tuple[object, list[str]]]]:
        """Convert modifications dict to ldap3 format.

        Args:
            modifications: Dict of attribute name to values

        Returns:
            Dict in ldap3 format: {attr: [(MODIFY_REPLACE, [values])]}

        """
        ldap3_mods: dict[str, list[tuple[object, list[str]]]] = {}
        for attr, value in modifications.items():
            values = value if isinstance(value, list) else [value]
            str_values = [str(v) for v in values]
            ldap3_mods[attr] = cast(
                "list[tuple[object, list[str]]]",
                [(MODIFY_REPLACE, str_values)],
            )
        return ldap3_mods

    def _get_connection_error_message(
        self,
        connection: Connection,
        default_msg: str = FlextLdapConstants.ErrorStrings.UNKNOWN_ERROR,
    ) -> str:
        """Get error message from connection result.

        Args:
            connection: LDAP connection
            default_msg: Default message if no error found

        Returns:
            Error message string

        """
        if hasattr(connection, "result") and isinstance(connection.result, dict):
            return str(
                connection.result.get(
                    FlextLdapConstants.LdapDictKeys.DESCRIPTION,
                    default_msg,
                ),
            )
        return default_msg

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for this server type - default implementation.

        Performs basic validation: checks DN and attributes exist.
        Override for server-specific validation logic.

        Returns:
            FlextResult indicating validation success or failure

        """
        try:
            # Basic validation: check DN exists
            dn_str = str(entry.dn) if entry.dn else ""
            if not dn_str or not dn_str.strip():
                return FlextResult[bool].fail("Entry DN cannot be empty")

            # Basic validation: check attributes exist
            if not entry.attributes or not entry.attributes.attributes:
                return FlextResult[bool].fail("Entry must have attributes")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self.logger.exception("Entry validation error", extra={"error": str(e)})
            return FlextResult[bool].fail(f"Entry validation failed: {e}")
