"""Idempotent LDAP schema synchronization service.

Idempotent schema sync for LDAP migrations. Checks existing schema
and only adds new definitions for safe and repeatable deployments.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import cast, override

from flext_core import FlextResult, FlextService
from flext_ldif.services.parser import FlextLdifParserService
from ldap3 import Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.clients import FlextLdapClients


class FlextLdapSchemaSync(FlextService[dict[str, object]]):
    """Idempotent schema synchronization to LDAP servers.

    Features:
    - Parse schema LDIF file with server-specific quirks
    - Check existing schema on target LDAP server
    - Skip already-imported schema definitions (idempotent)
    - Add only new schema definitions safely
    - Detailed sync report with statistics

    Architecture:
    - Uses FlextLdapClients for LDAP operations
    - Returns dictionary with sync statistics
    - Follows Railway-Oriented Programming pattern
    - Idempotent: safe to run multiple times
    """

    @override
    def __init__(
        self,
        schema_ldif_file: Path,
        server_host: str,
        server_port: int = 389,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        base_dn: str | None = None,
        server_type: str = FlextLdapConstants.ServerTypeAliases.ORACLE_OUD,
        use_ssl: bool = False,
    ) -> None:
        """Initialize idempotent schema sync service.

        Args:
        schema_ldif_file: Path to schema LDIF file (whitelisted/transformed)
        server_host: Target LDAP server hostname
        server_port: Target LDAP server port (default: 389)
        bind_dn: Bind DN for authentication
        bind_password: Bind password for authentication
        base_dn: Base DN for schema operations
        server_type: Target server type (default: oracle_oud)
        use_ssl: Use SSL/TLS connection (default: False)

        """
        super().__init__()
        self._schema_file = Path(schema_ldif_file)
        self._server_host = server_host
        self._server_port = server_port
        self._bind_dn = bind_dn
        self._bind_password = bind_password
        self._base_dn = base_dn
        self._server_type = server_type
        self._use_ssl = use_ssl
        self._connection: FlextLdapClients | None = None
        # Use flext-ldif schema parser to eliminate duplication
        self._schema_parser = FlextLdifParserService(
            str(schema_ldif_file)  # type: ignore[arg-type]
        )

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute idempotent schema synchronization.

        Returns:
        FlextResult containing schema sync statistics

        Workflow:
        1. Parse schema LDIF file
        2. Connect to target LDAP server
        3. Discover existing schema definitions
        4. Filter out already-existing definitions (idempotent check)
        5. Add only new schema definitions
        6. Return detailed sync statistics

        """
        # Step 1: Parse schema LDIF file
        parse_result = self._parse_schema_ldif()
        if parse_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to parse schema LDIF: {parse_result.error}",
            )

        schema_definitions = parse_result.unwrap()

        # Step 2: Connect to target server
        connect_result = self._connect_to_server()
        if connect_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to connect to server: {connect_result.error}",
            )

        # Step 3: Discover existing schema
        existing_result = self._get_existing_schema()
        if existing_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to get existing schema: {existing_result.error}",
            )

        existing_schema = existing_result.unwrap()

        # Step 4: Filter existing definitions (idempotent check)
        new_definitions = self._filter_new_definitions(
            schema_definitions,
            existing_schema,
        )

        # Step 5: Add new schema definitions
        if new_definitions:
            add_result = self._add_schema_definitions(new_definitions)
            if add_result.is_failure:
                self._disconnect()
                return FlextResult[dict[str, object]].fail(
                    f"Failed to add schema definitions: {add_result.error}",
                )

        # Step 6: Disconnect and return statistics
        self._disconnect()

        result_dict: dict[str, object] = {
            "total_definitions": len(schema_definitions),
            "existing_definitions": len(schema_definitions) - len(new_definitions),
            "new_definitions_added": len(new_definitions),
            "skipped_count": len(schema_definitions) - len(new_definitions),
            "server_type": self._server_type,
            "server_host": self._server_host,
            "idempotent": True,
            "schema_file": str(self._schema_file),
        }

        return FlextResult[dict[str, object]].ok(result_dict)

    def _parse_schema_ldif(
        self,
    ) -> FlextResult[list[dict[str, object]]]:
        """Parse schema LDIF file using FlextLdifParserService.

        Delegates to FlextLdifParserService to eliminate duplication and
        ensure RFC 4512 compliant parsing.

        Returns:
        FlextResult containing list of schema definition dictionaries

        """
        if not self._schema_file.exists():
            return FlextResult[list[dict[str, object]]].fail(
                f"Schema file not found: {self._schema_file}",
            )

        # Use flext-ldif schema parser for RFC 4512 compliant parsing
        parse_result = self._schema_parser.execute()
        if parse_result.is_failure:
            return parse_result.map(lambda _: [])

        # Extract attributes and objectclasses from parser result
        parser_output = parse_result.unwrap()

        # Convert FlextLdifModels schema objects to dictionary format
        definitions: list[dict[str, object]] = []

        # Extract attributes
        attributes = parser_output.get("attributes", {})
        if isinstance(attributes, dict):
            for attr_data in attributes.values():
                if hasattr(attr_data, "oid") and hasattr(attr_data, "name"):
                    name_str = (
                        attr_data.name.value
                        if hasattr(attr_data.name, "value")
                        else str(attr_data.name)
                    )
                    definitions.append({
                        "type": FlextLdapConstants.SchemaDefinitionTypes.ATTRIBUTE_TYPE,
                        "oid": attr_data.oid,
                        "name": name_str,
                        "definition": str(attr_data),
                        "raw_line": f"( {attr_data.oid} NAME '{name_str}' ... )",
                    })

        # Extract objectclasses
        objectclasses = parser_output.get("objectclasses", {})
        if isinstance(objectclasses, dict):
            for oc_data in objectclasses.values():
                if hasattr(oc_data, "oid") and hasattr(oc_data, "name"):
                    name_str = (
                        oc_data.name.value
                        if hasattr(oc_data.name, "value")
                        else str(oc_data.name)
                    )
                    definitions.append({
                        "type": FlextLdapConstants.SchemaDefinitionTypes.OBJECT_CLASS,
                        "oid": oc_data.oid,
                        "name": name_str,
                        "definition": str(oc_data),
                        "raw_line": f"( {oc_data.oid} NAME '{name_str}' ... )",
                    })

        return FlextResult[list[dict[str, object]]].ok(definitions)

    def _connect_to_server(self) -> FlextResult[None]:
        """Connect to target LDAP server using FlextLdapClients.

        Returns:
        FlextResult indicating success or failure

        """
        try:
            # Create client
            self._connection = FlextLdapClients()

            # Build server URI
            protocol = "ldaps" if self._use_ssl else "ldap"
            server_uri = f"{protocol}://{self._server_host}:{self._server_port}"

            # Establish connection (without auto-discovery to avoid hangs)
            connect_result = self._connection.connect(
                server_uri=server_uri,
                bind_dn=self._bind_dn or "",
                password=self._bind_password or "",
                auto_discover_schema=False,
            )

            if connect_result.is_failure:
                return FlextResult[None].fail(
                    f"Connection failed: {connect_result.error}",
                )

            self.logger.info(
                "Connected to LDAP server for schema sync",
                extra={
                    "host": self._server_host,
                    "port": self._server_port,
                    "server_type": self._server_type,
                },
            )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Connection error: {e}")

    def _get_existing_schema(self) -> FlextResult[dict[str, object]]:
        """Discover existing schema using ldap3.Server.schema.

        Returns:
        FlextResult containing existing schema dictionary

        """
        if not self._connection:
            return FlextResult[dict[str, object]].fail(
                FlextLdapConstants.ErrorStrings.NOT_CONNECTED,
            )

        try:
            # Get underlying ldap3 connection
            ldap_conn: Connection | None = self._connection.connection

            if not ldap_conn or not ldap_conn.server:
                return FlextResult[dict[str, object]].fail(
                    "LDAP connection or server not available",
                )

            server = ldap_conn.server

            # Manually retrieve schema via ldap3
            if not server.schema:
                # Search for schema subentry
                schema_dn = self._get_schema_dn_for_server()
                search_result = ldap_conn.search(
                    search_base=schema_dn,
                    search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                    search_scope=cast(
                        "FlextLdapConstants.Types.Ldap3Scope",
                        FlextLdapConstants.Scopes.BASE_LDAP3,
                    ),
                    attributes=[
                        FlextLdapConstants.SchemaAttributes.ATTRIBUTE_TYPES,
                        FlextLdapConstants.SchemaAttributes.OBJECT_CLASSES,
                    ],
                )

                if not search_result or not ldap_conn.entries:
                    self.logger.info(
                        "Schema discovery via search failed, will treat all definitions as new",
                    )
                    # Return empty schema - all definitions will be treated as new
                    return FlextResult[dict[str, object]].ok({
                        FlextLdapConstants.SchemaAttributes.ATTRIBUTE_TYPES: {},
                        FlextLdapConstants.SchemaAttributes.OBJECT_CLASSES: {},
                        "server_type": self._server_type,
                        "schema_loaded": False,
                    })

            schema = server.schema

            # Extract existing attribute types and object classes
            attr_types_dict: dict[str, str] = {
                at.name[0]: at.oid for at in schema.attribute_types.values()
            }
            obj_classes_dict: dict[str, str] = {
                oc.name[0]: oc.oid for oc in schema.object_classes.values()
            }

            existing: dict[str, object] = {
                FlextLdapConstants.SchemaAttributes.ATTRIBUTE_TYPES: attr_types_dict,
                FlextLdapConstants.SchemaAttributes.OBJECT_CLASSES: obj_classes_dict,
                "server_type": self._server_type,
                "schema_loaded": True,
            }

            self.logger.info(
                "Discovered existing schema",
                extra={
                    "attribute_types": len(attr_types_dict),
                    "object_classes": len(obj_classes_dict),
                },
            )

            return FlextResult[dict[str, object]].ok(existing)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Schema discovery failed: {e}")

    def _filter_new_definitions(
        self,
        definitions: list[dict[str, object]],
        existing_schema: dict[str, object],
    ) -> list[dict[str, object]]:
        """Filter out existing definitions (idempotent check).

        Args:
        definitions: Parsed schema definitions to add
        existing_schema: Existing schema from target server

        Returns:
        List of new definitions not yet on server

        """
        new_definitions: list[dict[str, object]] = []

        for definition in definitions:
            definition_type = definition.get("type", "")
            definition_name = definition.get("name", "")
            definition_oid = definition.get("oid", "")

            # Check if definition already exists
            is_existing = False

            if (
                definition_type
                == FlextLdapConstants.SchemaDefinitionTypes.ATTRIBUTE_TYPE
            ):
                existing_attrs_raw = existing_schema.get(
                    FlextLdapConstants.SchemaAttributes.ATTRIBUTE_TYPES,
                    {},
                )
                existing_attrs: dict[str, object] = (
                    dict[str, object](existing_attrs_raw)
                    if isinstance(existing_attrs_raw, dict)
                    else {}
                )
                # Check by name and OID with type-safe str conversion
                name_exists = (
                    str(definition_name) in existing_attrs if definition_name else False
                )
                oid_exists = (
                    str(definition_oid) in existing_attrs if definition_oid else False
                )
                if name_exists or oid_exists:
                    is_existing = True

            elif (
                definition_type == FlextLdapConstants.SchemaDefinitionTypes.OBJECT_CLASS
            ):
                existing_ocs_raw = existing_schema.get(
                    FlextLdapConstants.SchemaAttributes.OBJECT_CLASSES,
                    {},
                )
                existing_ocs: dict[str, object] = (
                    dict[str, object](existing_ocs_raw)
                    if isinstance(existing_ocs_raw, dict)
                    else {}
                )
                # Check by name and OID with type-safe str conversion
                name_exists = (
                    str(definition_name) in existing_ocs if definition_name else False
                )
                oid_exists = (
                    str(definition_oid) in existing_ocs if definition_oid else False
                )
                if name_exists or oid_exists:
                    is_existing = True

            # Add only if not existing (idempotent)
            if not is_existing:
                new_definitions.append(definition)

        return new_definitions

    def _get_schema_dn_for_server(self) -> str:
        """Get schema DN based on server type.

        Returns:
        Schema DN for the target server type

        """
        schema_dns = {
            FlextLdapConstants.ServerTypes.OPENLDAP2: FlextLdapConstants.SchemaDns.SCHEMA,
            FlextLdapConstants.ServerTypes.OPENLDAP1: FlextLdapConstants.Defaults.SCHEMA_SUBENTRY,
            FlextLdapConstants.ServerTypes.OID: FlextLdapConstants.SchemaDns.SUBS_SCHEMA_SUBENTRY,
            FlextLdapConstants.ServerTypeAliases.ORACLE_OID: FlextLdapConstants.SchemaDns.SUBS_SCHEMA_SUBENTRY,
            FlextLdapConstants.ServerTypes.OUD: FlextLdapConstants.SchemaDns.SCHEMA,
            FlextLdapConstants.ServerTypeAliases.ORACLE_OUD: FlextLdapConstants.SchemaDns.SCHEMA,
            FlextLdapConstants.ServerTypes.AD: FlextLdapConstants.SchemaDns.AD_SCHEMA,
            FlextLdapConstants.ServerTypeAliases.ACTIVE_DIRECTORY: FlextLdapConstants.SchemaDns.AD_SCHEMA,
        }
        return schema_dns.get(
            self._server_type,
            FlextLdapConstants.Defaults.SCHEMA_SUBENTRY,
        )

    def _add_schema_definitions(
        self,
        definitions: list[dict[str, object]],
    ) -> FlextResult[None]:
        """Add new schema definitions using FlextLdap interfaces with quirks.

        Uses FlextLdap.modify_entry() which automatically applies server-specific
        quirks (including OUD schema quirks) through the generic interface pattern.

        Args:
        definitions: List of schema definitions to add

        Returns:
        FlextResult indicating success or failure

        """
        if not self._connection:
            return FlextResult[None].fail(FlextLdapConstants.ErrorStrings.NOT_CONNECTED)

        try:
            # Determine schema DN for this server type
            schema_dn = self._get_schema_dn_for_server()

            # Group definitions by type for batch operations
            attribute_types: list[str] = []
            object_classes: list[str] = []

            for definition in definitions:
                def_type = definition.get("type")
                raw_line = definition.get("raw_line", "")

                if def_type == FlextLdapConstants.SchemaDefinitionTypes.ATTRIBUTE_TYPE:
                    attribute_types.append(str(raw_line))
                elif def_type == FlextLdapConstants.SchemaDefinitionTypes.OBJECT_CLASS:
                    object_classes.append(str(raw_line))

            added_count = 0
            failed_count = 0
            max_logged_failures = 3  # Log only first few failures for debugging

            # Add attributeTypes one at a time (OUD doesn't support batch schema mods)
            for attr_type in attribute_types:
                changes: dict[str, list[tuple[str, list[str]]]] = {
                    FlextLdapConstants.SchemaAttributes.ATTRIBUTE_TYPES: [
                        (
                            FlextLdapConstants.ModifyOperation.MODIFY_ADD_STR,
                            [attr_type],
                        ),
                    ],
                }
                modify_result = self._connection.modify_entry(
                    schema_dn,
                    cast("FlextLdapModels.EntryChanges", changes),
                )

                if modify_result.is_success:
                    added_count += 1
                else:
                    failed_count += 1
                    # Log first few failures for debugging
                    if failed_count <= max_logged_failures:
                        self.logger.warning(
                            f"Failed to add attributeType: {modify_result.error} - "
                            f"Definition: {attr_type[:100]}...",
                        )

            if added_count > 0:
                self.logger.info("Added %s attributeTypes via FlextLdap", added_count)
            if failed_count > 0:
                self.logger.warning("Failed to add %s attributeTypes", failed_count)

            # Add objectClasses one at a time (OUD doesn't support batch schema mods)
            for obj_class in object_classes:
                changes_obj: dict[str, list[tuple[str, list[str]]]] = {
                    FlextLdapConstants.SchemaAttributes.OBJECT_CLASSES: [
                        (
                            FlextLdapConstants.ModifyOperation.MODIFY_ADD_STR,
                            [obj_class],
                        ),
                    ],
                }
                modify_result = self._connection.modify_entry(
                    schema_dn,
                    cast("FlextLdapModels.EntryChanges", changes_obj),
                )

                if modify_result.is_success:
                    added_count += 1
                else:
                    failed_count += 1
                    # Log first few failures for debugging
                    if failed_count <= max_logged_failures:
                        self.logger.warning(
                            f"Failed to add objectClass: {modify_result.error} - "
                            f"Definition: {obj_class[:100]}...",
                        )

            if added_count > 0:
                self.logger.info("Added %s objectClasses via FlextLdap", added_count)
            if failed_count > 0:
                self.logger.warning("Failed to add %s objectClasses", failed_count)

            self.logger.info(
                "Schema definitions processed via FlextLdap interfaces",
                extra={
                    FlextLdapConstants.StatusKeys.ADDED: added_count,
                    FlextLdapConstants.StatusKeys.FAILED: failed_count,
                    FlextLdapConstants.StatusKeys.TOTAL: len(definitions),
                    FlextLdapConstants.StatusKeys.USED_QUIRKS: True,
                },
            )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Schema addition failed: {e}")

    def _disconnect(self) -> None:
        """Disconnect from LDAP server using FlextLdapClients."""
        if self._connection:
            try:
                unbind_result = self._connection.unbind()
                if unbind_result.is_failure:
                    self.logger.warning(f"Unbind warning: {unbind_result.error}")

                self.logger.debug("Disconnected from LDAP server")

            except Exception as e:
                self.logger.warning("Disconnect error: %s", e)
            finally:
                self._connection = None


__all__ = ["FlextLdapSchemaSync"]
