"""Oracle Unified Directory (OUD) server operations implementation.

Complete implementation for Oracle OUD with ds-privilege-name ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast, override

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import MODIFY_REPLACE, Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.services.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities


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
        super().__init__(server_type=FlextLdapConstants.ServerTypes.OUD)

    # --------------------------------------------------------------------- #
    # INHERITED METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods are used directly from the base class without override:
    # - get_default_port(): Returns 389 (standard LDAP port)
    # - supports_start_tls(): Returns True (standard LDAP feature)
    # - get_schema_dn(): Returns "cn=schema" (OUD-specific)
    # - get_max_page_size(): Returns 1000 (standard page size)
    # - supports_paged_results(): Returns True (standard LDAP feature)
    # - search_with_paging(): Generic paged search implementation
    # - normalize_entry_for_server(): Generic entry normalization
    #
    # --------------------------------------------------------------------- #
    # OVERRIDDEN METHODS (from FlextLdapServersBaseOperations)
    # --------------------------------------------------------------------- #
    # These methods override the base class with Oracle OUD-specific logic:
    # - get_bind_mechanisms(): Returns OUD-specific bind mechanisms
    # - discover_schema(): OUD-specific schema discovery with ldapSyntaxes
    # - parse_object_class(): OUD-specific objectClass parsing
    # - parse_attribute_type(): OUD-specific attributeType parsing
    # - get_acl_attribute_name(): Returns "ds-privilege-name" (OUD ACL attribute)
    # - get_acl_format(): Returns "oracle" (Oracle ACI format)
    # - get_acls(): OUD-specific ACL retrieval with ds-privilege-name
    # - set_acls(): OUD-specific ACL setting with ds-privilege-name
    # - parse(): OUD-specific ACL parsing with Oracle ACI
    # - format_acl(): OUD-specific ACL formatting to Oracle ACI
    # - modify_entry(): OUD-specific entry modification (schema quirks)
    # - supports_vlv(): Returns True (OUD supports VLV)
    # - get_root_dse_attributes(): OUD-specific Root DSE retrieval
    # - detect_server_type_from_root_dse(): OUD server detection logic
    # - get_supported_controls(): OUD-specific supported controls
    # - validate_entry_for_server(): OUD-specific entry validation

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
            FlextLdapConstants.SaslMechanisms.SASL_PLAIN,
        ]

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @override
    def get_schema_dn(self) -> str:
        """Oracle OUD uses cn=schema."""
        return FlextLdapConstants.SchemaDns.SCHEMA

    @override
    def discover_schema(
        self,
        connection: Connection,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Discover schema from Oracle OUD - enhanced with ldapSyntaxes."""
        # OUD needs ldapSyntaxes in addition to standard schema
        try:
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                    conn_check.error,
                )

            search_result = connection.search(
                search_base=self.get_schema_dn(),
                search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                attributes=[
                    FlextLdapConstants.SchemaAttributes.OBJECT_CLASSES,
                    FlextLdapConstants.SchemaAttributes.ATTRIBUTE_TYPES,
                    FlextLdapConstants.SchemaAttributes.LDAP_SYNTAXES,
                ],
            )

            if not search_result or not connection.entries:
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                    "Schema discovery failed",
                )

            schema_result = FlextLdifModels.SchemaDiscoveryResult(server_type="oud")
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
        """Parse Oracle OUD objectClass definition - enhanced with OUD note."""
        result = super().parse_object_class(object_class_def)
        if not result.is_failure:
            entry = result.unwrap()
            # Add OUD-specific note
            entry.attributes.attributes["note"] = ["Oracle OUD schema parsing"]
        return result

    @override
    def parse_attribute_type(
        self,
        attribute_def: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Parse Oracle OUD attributeType definition - enhanced with OUD note."""
        result = super().parse_attribute_type(attribute_def)
        if not result.is_failure:
            entry = result.unwrap()
            # Add OUD-specific note
            entry.attributes.attributes["note"] = ["Oracle OUD schema parsing"]
        return result

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @override
    def get_acl_attribute_name(self) -> str:
        """Oracle OUD uses ds-privilege-name attribute."""
        return FlextLdapConstants.AclAttributes.DS_PRIVILEGE_NAME

    @override
    def get_acl_format(self) -> str:
        """Oracle OUD ACL format identifier."""
        return FlextLdapConstants.AclFormat.ORACLE

    # get_acls() inherited from base class - uses get_acl_attribute_name()

    def _format_acls_for_oud(
        self, acls: list[dict[str, object]]
    ) -> FlextResult[list[str]]:
        """Format ACL dictionaries to ds-privilege-name strings using FlextLdapUtilities.

        Consolidated with FlextLdapUtilities.AclFormatting for reusability.
        Delegates formatting to shared utility.

        Args:
            acls: List of ACL dictionaries

        Returns:
            FlextResult containing formatted ds-privilege-name strings or error

        """
        return FlextLdapUtilities.AclFormatting.format_acls_for_server(acls, self)

    def set_acls(
        self,
        _connection: Connection,
        _dn: str,
        _acls: list[dict[str, object]],
    ) -> FlextResult[bool]:
        """Set ds-privilege-name ACLs on Oracle OUD.

        Refactored with Railway Pattern: 6→4 returns (SOLID/DRY compliance).

        Args:
            _connection: Active ldap3 connection
            _dn: DN of entry to set ACLs on
            _acls: List of ACL dictionaries

        Returns:
            FlextResult[bool] indicating success or failure

        """
        try:
            # Railway Pattern: Early validation
            if not _connection or not _connection.bound:
                return FlextResult[bool].fail("Connection not bound")

            # Railway Pattern: Delegate formatting to helper
            format_result = self._format_acls_for_oud(_acls)
            if format_result.is_failure:
                return FlextResult[bool].fail(str(format_result.error))

            formatted_acls = format_result.unwrap()

            # Railway Pattern: Execute modify operation
            typed_conn = cast("FlextLdapTypes.Ldap3Protocols.Connection", _connection)
            mods = cast(
                "dict[str, list[tuple[int, list[str]]]]",
                {
                    FlextLdapConstants.AclAttributes.DS_PRIVILEGE_NAME: [
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

    @override
    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
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
                FlextLdapConstants.AclAttributes.FORMAT: FlextLdapConstants.AclFormat.ORACLE,
                "server_type": "oud",
                "privilege": privilege name
            }

        """
        try:
            # ds-privilege-name contains privilege identifiers
            privilege_name = acl_string.strip()

            # Map common privileges to categories
            if privilege_name in FlextLdapConstants.OudPrivileges.CONFIG_PRIVILEGES:
                category = FlextLdapConstants.OudPrivilegeCategories.CONFIGURATION
            elif privilege_name in FlextLdapConstants.OudPrivileges.PASSWORD_PRIVILEGES:
                category = FlextLdapConstants.OudPrivilegeCategories.PASSWORD
            elif (
                privilege_name
                in FlextLdapConstants.OudPrivileges.ADMINISTRATIVE_PRIVILEGES
            ):
                category = FlextLdapConstants.OudPrivilegeCategories.ADMINISTRATIVE
            elif (
                privilege_name in FlextLdapConstants.OudPrivileges.MANAGEMENT_PRIVILEGES
            ):
                category = FlextLdapConstants.OudPrivilegeCategories.MANAGEMENT
            else:
                category = FlextLdapConstants.OudPrivilegeCategories.CUSTOM

            acl_attributes: dict[str, list[str]] = {
                FlextLdapConstants.AclAttributes.RAW: [acl_string],
                FlextLdapConstants.AclAttributes.FORMAT: [
                    FlextLdapConstants.AclFormat.ORACLE,
                ],
                FlextLdapConstants.AclAttributes.SERVER_TYPE_ALT: [
                    FlextLdapConstants.ServerTypes.OUD,
                ],
                FlextLdapConstants.LdapDictKeys.PRIVILEGE: [privilege_name],
                FlextLdapConstants.LdapDictKeys.CATEGORY: [category],
            }

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
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Oracle OUD ACL parse failed: {e}",
            )

    @override
    def format_acl(self, acl_entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Format ACL Entry to ds-privilege-name string for Oracle OUD.

        Args:
            acl_entry: ACL Entry with attributes containing structure:
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
            # Extract attributes from entry
            raw_attr = acl_entry.attributes.get("raw")
            if raw_attr and len(raw_attr) > 0:
                return FlextResult[str].ok(raw_attr[0])

            # Use privilege name if available
            privilege_attr = acl_entry.attributes.get(
                FlextLdapConstants.LdapDictKeys.PRIVILEGE,
            )
            if privilege_attr and len(privilege_attr) > 0:
                return FlextResult[str].ok(privilege_attr[0])

            # Default fallback
            return FlextResult[str].fail(
                "Oracle OUD ACL formatting requires 'privilege' or 'raw' field",
            )

        except Exception as e:
            return FlextResult[str].fail(f"Oracle OUD ACL format failed: {e}")

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    # add_entry(), delete_entry() - Use base implementations

    @override
    def modify_entry(
        self,
        connection: Connection,
        dn: str,
        modifications: dict[str, object],
    ) -> FlextResult[bool]:
        """Modify entry in Oracle OUD with OUD-specific quirks.

        Applies OUD schema quirk: lowercase attribute names for cn=schema
        """
        try:
            conn_check = self._check_connection(connection)
            if conn_check.is_failure:
                return FlextResult[bool].fail(conn_check.error)

            # Apply OUD schema quirk: lowercase attribute names for cn=schema
            is_schema_mod = dn.lower() == FlextLdapConstants.SchemaDns.SCHEMA.lower()

            # Convert modifications to ldap3 format
            ldap3_mods: dict[str, list[tuple[object, list[str]]]] = {}
            for attr, value in modifications.items():
                # Apply schema quirk
                attr_name = attr
                if is_schema_mod:
                    if attr.lower() == "attributetypes":
                        attr_name = "attributetypes"
                    elif attr.lower() == "objectclasses":
                        attr_name = "objectclasses"

                # Handle tuple format (operation, values)
                if isinstance(value, list) and value and isinstance(value[0], tuple):
                    operation, val_list = value[0]
                    values = val_list if isinstance(val_list, list) else [val_list]
                else:
                    operation = MODIFY_REPLACE
                    values = value if isinstance(value, list) else [value]

                str_values = [str(v) for v in values]
                ldap3_mods[attr_name] = cast(
                    "list[tuple[object, list[str]]]",
                    [(operation, str_values)],
                )

            # Use base class helper for the rest
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

    # normalize_entry() - Use base implementation (returns entry as-is)

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @override
    def supports_vlv(self) -> bool:
        """Oracle OUD supports VLV."""
        return True

    # search_with_paging() - Use base implementation

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
            FlextLdapConstants.OudPrivileges.CONFIG_READ,
            FlextLdapConstants.OudPrivileges.CONFIG_WRITE,
            FlextLdapConstants.OudPrivileges.PASSWORD_RESET,
            FlextLdapConstants.OudPrivileges.PASSWORD_MODIFY,
            FlextLdapConstants.OudPrivileges.PRIVILEGE_CHANGE,
            FlextLdapConstants.OudPrivileges.PROXIED_AUTH,
            FlextLdapConstants.OudPrivileges.BYPASS_ACL,
            FlextLdapConstants.OudPrivileges.UPDATE_SCHEMA,
            FlextLdapConstants.OudPrivileges.LDIF_IMPORT,
            FlextLdapConstants.OudPrivileges.LDIF_EXPORT,
            FlextLdapConstants.OudPrivileges.BACKEND_BACKUP,
            FlextLdapConstants.OudPrivileges.BACKEND_RESTORE,
        ]

    def get_privilege_category(self, privilege: str) -> str:
        """Get category for a privilege.

        Refactored: 7→1 returns using category mapping (SOLID/DRY compliance).

        Args:
        privilege: Privilege name

        Returns:
        Category name

        """
        # Mapping: (privilege_set, category) tuples for O(n) worst-case lookup
        # where n is number of categories (6), which is constant and small
        category_mappings = [
            (FlextLdapConstants.OudPrivileges.CONFIG_PRIVILEGES, FlextLdapConstants.OudPrivilegeCategories.CONFIGURATION),
            (FlextLdapConstants.OudPrivileges.PASSWORD_PRIVILEGES, FlextLdapConstants.OudPrivilegeCategories.PASSWORD),
            (FlextLdapConstants.OudPrivileges.ADMINISTRATIVE_PRIVILEGES, FlextLdapConstants.OudPrivilegeCategories.ADMINISTRATIVE),
            (FlextLdapConstants.OudPrivileges.MANAGEMENT_PRIVILEGES, FlextLdapConstants.OudPrivilegeCategories.MANAGEMENT),
            (FlextLdapConstants.OudPrivileges.DATA_MANAGEMENT_PRIVILEGES, FlextLdapConstants.OudPrivilegeCategories.DATA_MANAGEMENT),
            (FlextLdapConstants.OudPrivileges.MAINTENANCE_PRIVILEGES, FlextLdapConstants.OudPrivilegeCategories.MAINTENANCE),
        ]

        # Single return: find matching category or default to CUSTOM
        result_category = FlextLdapConstants.OudPrivilegeCategories.CUSTOM
        for privilege_set, category in category_mappings:
            if privilege in privilege_set:
                result_category = category
                break

        return result_category

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
        return "multi-master"  # OUD-specific replication mode

    @override
    def detect_server_type_from_root_dse(self, _root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE for Oracle OUD."""
        # Oracle OUD specific detection logic
        if FlextLdapConstants.RootDseAttributes.VENDOR_NAME_LOWER in _root_dse:
            vendor = str(
                _root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_NAME_LOWER],
            ).lower()
            if (
                FlextLdapConstants.VendorNames.ORACLE in vendor
                or FlextLdapConstants.ServerTypes.OUD in vendor
            ):
                return FlextLdapConstants.ServerTypes.OUD
        return FlextLdapConstants.Defaults.SERVER_TYPE

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
        entry: FlextLdifModels.Entry | Mapping[str, object],
        _target_server_type: str | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for Oracle OUD server using shared service."""
        # Ensure entry is FlextLdifModels.Entry first
        ensure_result = self._ensure_ldif_entry(
            entry, context="normalize_entry_for_server"
        )
        if ensure_result.is_failure:
            return ensure_result

        ldif_entry = ensure_result.unwrap()

        # Use shared FlextLdapEntryAdapter service for normalization
        adapter = FlextLdapEntryAdapter(server_type=self.server_type)
        return adapter.normalize_entry_for_server(ldif_entry, self.server_type)

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for Oracle OUD using shared service."""
        # Use shared FlextLdapEntryAdapter service for validation
        adapter = FlextLdapEntryAdapter(server_type=self.server_type)
        return adapter.validate_entry_for_server(entry, self.server_type)
