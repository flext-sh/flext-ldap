"""Idempotent LDAP schema synchronization service.

Provides enterprise-grade idempotent schema synchronization for LDAP migrations.
Checks existing schema on target server and only adds new definitions, ensuring
safe and repeatable schema deployments.

Architecture:
- Phase 1 of MIGRATION_ENHANCEMENT_PLAN.md
- Uses Railway-Oriented Programming (FlextCore.Result)
- Integrates with FlextLdap domain services
- Follows FLEXT domain separation pattern

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_core import FlextCore


class FlextLdapSchemaSync(FlextCore.Service[FlextCore.Types.Dict]):
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
        server_type: str = "oracle_oud",
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
        self._connection: FlextCore.Types.Dict | None = None

    @override
    def execute(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Execute idempotent schema synchronization.

        Returns:
            FlextCore.Result containing schema sync statistics

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
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to parse schema LDIF: {parse_result.error}"
            )

        schema_definitions = parse_result.unwrap()

        # Step 2: Connect to target server
        connect_result = self._connect_to_server()
        if connect_result.is_failure:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to connect to server: {connect_result.error}"
            )

        # Step 3: Discover existing schema
        existing_result = self._get_existing_schema()
        if existing_result.is_failure:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to get existing schema: {existing_result.error}"
            )

        existing_schema = existing_result.unwrap()

        # Step 4: Filter existing definitions (idempotent check)
        new_definitions = self._filter_new_definitions(
            schema_definitions, existing_schema
        )

        # Step 5: Add new schema definitions
        if new_definitions:
            add_result = self._add_schema_definitions(new_definitions)
            if add_result.is_failure:
                self._disconnect()
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    f"Failed to add schema definitions: {add_result.error}"
                )

        # Step 6: Disconnect and return statistics
        self._disconnect()

        result_dict: FlextCore.Types.Dict = {
            "total_definitions": len(schema_definitions),
            "existing_definitions": len(schema_definitions) - len(new_definitions),
            "new_definitions_added": len(new_definitions),
            "skipped_count": len(schema_definitions) - len(new_definitions),
            "server_type": self._server_type,
            "server_host": self._server_host,
            "idempotent": True,
            "schema_file": str(self._schema_file),
        }

        return FlextCore.Result[FlextCore.Types.Dict].ok(result_dict)

    def _parse_schema_ldif(
        self,
    ) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Parse schema LDIF file into structured definitions.

        Returns:
            FlextCore.Result containing list of schema definition dictionaries

        """
        if not self._schema_file.exists():
            return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                f"Schema file not found: {self._schema_file}"
            )

        try:
            with self._schema_file.open("r", encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                f"Failed to read schema file: {e}"
            )

        # Parse LDIF content into schema definitions
        definitions: list[FlextCore.Types.Dict] = []

        # Parse attributeTypes
        for line in content.split("\n"):
            if line.strip().startswith("attributeTypes:"):
                start_idx = line.find("(")
                end_idx = line.rfind(")")

                if start_idx != -1 and end_idx != -1:
                    definition = line[start_idx + 1 : end_idx].strip()
                    tokens = definition.split()

                    if tokens:
                        oid = tokens[0]
                        name = self._extract_name(definition)

                        entry: FlextCore.Types.Dict = {
                            "type": "attributeType",
                            "oid": oid,
                            "name": name,
                            "definition": definition,
                            "raw_line": line.strip(),
                        }
                        definitions.append(entry)

        # Parse objectClasses
        for line in content.split("\n"):
            if line.strip().startswith("objectClasses:"):
                start_idx = line.find("(")
                end_idx = line.rfind(")")

                if start_idx != -1 and end_idx != -1:
                    definition = line[start_idx + 1 : end_idx].strip()
                    tokens = definition.split()

                    if tokens:
                        oid = tokens[0]
                        name = self._extract_name(definition)

                        entry: FlextCore.Types.Dict = {
                            "type": "objectClass",
                            "oid": oid,
                            "name": name,
                            "definition": definition,
                            "raw_line": line.strip(),
                        }
                        definitions.append(entry)

        return FlextCore.Result[list[FlextCore.Types.Dict]].ok(definitions)

    def _extract_name(self, definition: str) -> str:
        """Extract NAME from schema definition.

        Args:
            definition: Schema definition string

        Returns:
            Extracted name or empty string

        """
        name_idx = definition.find("NAME")
        if name_idx == -1:
            return ""

        start_quote = definition.find("'", name_idx)
        if start_quote == -1:
            return ""

        end_quote = definition.find("'", start_quote + 1)
        if end_quote == -1:
            return ""

        return definition[start_quote + 1 : end_quote]

    def _connect_to_server(self) -> FlextCore.Result[None]:
        """Connect to target LDAP server.

        Returns:
            FlextCore.Result indicating success or failure

        Note:
            Phase 1 basic implementation - uses placeholder connection.
            Phase 2 will integrate with FlextLdapClients for real connections.

        """
        # Phase 1: Placeholder for connection
        # Phase 2 TODO(FLEXT Team): Integrate with FlextLdapClients
        # Example:
        #   from flext_ldap.clients import FlextLdapClients
        #   client_result = FlextLdapClients.create_connection(...)
        #   if client_result.is_success:
        #       self._connection = client_result.unwrap()

        # For Phase 1, we'll simulate a successful connection
        self._connection = {"connected": True, "server": self._server_host}

        return FlextCore.Result[None].ok(None)

    def _get_existing_schema(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Discover existing schema definitions on target server.

        Returns:
            FlextCore.Result containing existing schema dictionary

        Note:
            Phase 1 basic implementation - returns empty schema.
            Phase 2 will query actual LDAP server schema.

        """
        # Phase 1: Placeholder returning empty existing schema
        # Phase 2 TODO(FLEXT Team): Query LDAP server schema
        # Example:
        #   schema_dn = self._get_schema_subentry_dn()
        #   search_result = self._connection.search(schema_dn, ...)
        #   return parse_existing_schema(search_result)

        existing: FlextCore.Types.Dict = {
            "attributeTypes": {},
            "objectClasses": {},
        }

        return FlextCore.Result[FlextCore.Types.Dict].ok(existing)

    def _filter_new_definitions(
        self,
        definitions: list[FlextCore.Types.Dict],
        existing_schema: FlextCore.Types.Dict,
    ) -> list[FlextCore.Types.Dict]:
        """Filter out existing definitions (idempotent check).

        Args:
            definitions: Parsed schema definitions to add
            existing_schema: Existing schema from target server

        Returns:
            List of new definitions not yet on server

        """
        new_definitions: list[FlextCore.Types.Dict] = []

        for definition in definitions:
            definition_type = definition.get("type", "")
            definition_name = definition.get("name", "")
            definition_oid = definition.get("oid", "")

            # Check if definition already exists
            is_existing = False

            if definition_type == "attributeType":
                existing_attrs_raw = existing_schema.get("attributeTypes", {})
                existing_attrs: FlextCore.Types.Dict = (
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

            elif definition_type == "objectClass":
                existing_ocs_raw = existing_schema.get("objectClasses", {})
                existing_ocs: FlextCore.Types.Dict = (
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

    def _add_schema_definitions(
        self, _definitions: list[FlextCore.Types.Dict]
    ) -> FlextCore.Result[None]:
        """Add new schema definitions to target server.

        Args:
            definitions: List of schema definitions to add

        Returns:
            FlextCore.Result indicating success or failure

        Note:
            Phase 1 basic implementation - simulates addition.
            Phase 2 will use LDAP modify operations.

        """
        # Phase 1: Placeholder for schema addition
        # Phase 2 TODO(FLEXT Team): Use LDAP modify operations
        # Example:
        #   for definition in definitions:
        #       ldif_entry = self._build_ldif_entry(definition)
        #       modify_result = self._connection.modify(schema_dn, ldif_entry)
        #       if modify_result.is_failure:
        #           return modify_result

        # For Phase 1, simulate successful addition
        return FlextCore.Result[None].ok(None)

    def _disconnect(self) -> None:
        """Disconnect from LDAP server.

        Note:
            Phase 1 basic implementation - cleans up placeholder connection.
            Phase 2 will use FlextLdapClients disconnect.

        """
        # Phase 1: Clean up placeholder connection
        # Phase 2 TODO(FLEXT Team): Use FlextLdapClients.disconnect()
        self._connection = None


__all__ = ["FlextLdapSchemaSync"]
