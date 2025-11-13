"""Oracle Unified Directory (OUD) server operations implementation.

Complete implementation for Oracle OUD with ds-privilege-name ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextDecorators, FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import MODIFY_REPLACE, Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.services.entry_adapter import FlextLdapEntryAdapter
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
    # set_acls() inherited from base class - uses Template Method Pattern

    # =========================================================================
    # TEMPLATE METHOD PATTERN - Abstract Methods Implementation
    # =========================================================================

    @override
    def _format_acls(self, acls: list[dict[str, object]]) -> FlextResult[list[str]]:
        """Format ACL dictionaries to ds-privilege-name strings using FlextLdapUtilities.

        Template Method Pattern: Implements abstract method from base class.
        Consolidated with FlextLdapUtilities.AclFormatting for reusability.
        Delegates formatting to shared utility.

        Args:
            acls: List of ACL dictionaries

        Returns:
            FlextResult containing formatted ds-privilege-name strings or error

        """
        return FlextLdapUtilities.AclFormatting.format_acls_for_server(acls, self)

    @override
    def _get_acl_attribute(self) -> str:
        """Get Oracle OUD ACL attribute name.

        Template Method Pattern: Implements abstract method from base class.

        Returns:
            'ds-privilege-name' - Oracle OUD ACL attribute

        """
        return FlextLdapConstants.AclAttributes.DS_PRIVILEGE_NAME

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
                ldap3_mods[attr_name] = [(operation, str_values)]

            # Execute modification using ldap3 Connection interface
            success = connection.modify(dn, ldap3_mods)

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
        """Get category for a privilege using efficient lookup.

        Uses O(1) dict lookup instead of O(n) loop for better performance.
        Leverages FlextConstants for type-safe category mappings.

        Args:
            privilege: Privilege name

        Returns:
            Category name from FlextLdapConstants.OudPrivilegeCategories

        """
        # Build reverse mapping: privilege → category for O(1) lookup
        privilege_to_category = {
            priv: FlextLdapConstants.OudPrivilegeCategories.CONFIGURATION
            for priv in FlextLdapConstants.OudPrivileges.CONFIG_PRIVILEGES
        }
        privilege_to_category.update({
            priv: FlextLdapConstants.OudPrivilegeCategories.PASSWORD
            for priv in FlextLdapConstants.OudPrivileges.PASSWORD_PRIVILEGES
        })
        privilege_to_category.update({
            priv: FlextLdapConstants.OudPrivilegeCategories.ADMINISTRATIVE
            for priv in FlextLdapConstants.OudPrivileges.ADMINISTRATIVE_PRIVILEGES
        })
        privilege_to_category.update({
            priv: FlextLdapConstants.OudPrivilegeCategories.MANAGEMENT
            for priv in FlextLdapConstants.OudPrivileges.MANAGEMENT_PRIVILEGES
        })
        privilege_to_category.update({
            priv: FlextLdapConstants.OudPrivilegeCategories.DATA_MANAGEMENT
            for priv in FlextLdapConstants.OudPrivileges.DATA_MANAGEMENT_PRIVILEGES
        })
        privilege_to_category.update({
            priv: FlextLdapConstants.OudPrivilegeCategories.MAINTENANCE
            for priv in FlextLdapConstants.OudPrivileges.MAINTENANCE_PRIVILEGES
        })

        return privilege_to_category.get(
            privilege,
            FlextLdapConstants.OudPrivilegeCategories.CUSTOM,
        )

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
    @FlextDecorators.log_method_call(level="DEBUG")
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for Oracle OUD using shared FlextLdapEntryAdapter service.

        Uses FlextDecorators for automatic logging and FlextLdapEntryAdapter
        for server-specific validation logic. Delegates to shared service
        to avoid code duplication and ensure consistency.
        """
        # Use shared FlextLdapEntryAdapter service for validation
        adapter = FlextLdapEntryAdapter(server_type=self.server_type)
        return adapter.validate_entry_for_server(entry, self.server_type)
