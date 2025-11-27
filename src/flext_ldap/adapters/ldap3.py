"""LDAP3 adapter service - Service wrapper for ldap3 library.

This module provides a service adapter around ldap3 following flext-ldif patterns.
Reuses FlextLdifParser for parsing LDAP results to Entry models. Handles connection
management, search operations, and CRUD operations (add, modify, delete) with proper
error handling and type safety.

Modules: Ldap3Adapter
Scope: LDAP3 library integration, connection management, CRUD operations,
    entry conversion
Pattern: Service adapter extending FlextService, delegates to
    FlextLdifParser for parsing

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable

from flext_core import FlextResult, FlextRuntime, FlextService
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser
from ldap3 import Connection, Server

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes

Ldap3Scope = FlextLdapConstants.LiteralTypes.Ldap3Scope


class Ldap3Adapter(FlextService[bool]):
    """Service adapter for ldap3 library following flext-ldif patterns.

    Wraps ldap3 Connection and Server objects to provide a simplified
    interface for LDAP operations. Reuses FlextLdifParser for automatic
    conversion of LDAP results to Entry models.
    """

    class ConnectionManager:
        """Connection management logic (SRP)."""

        @staticmethod
        def create_server(config: FlextLdapModels.ConnectionConfig) -> Server:
            """Create ldap3 Server object."""
            if config.use_ssl:
                return Server(
                    host=config.host,
                    port=config.port,
                    use_ssl=True,
                    connect_timeout=config.timeout,
                )
            return Server(
                host=config.host,
                port=config.port,
                connect_timeout=config.timeout,
            )

        @staticmethod
        def create_connection(
            server: Server, config: FlextLdapModels.ConnectionConfig
        ) -> Connection:
            """Create ldap3 Connection object."""
            return Connection(
                server=server,
                user=config.bind_dn,
                password=config.bind_password,
                auto_bind=config.auto_bind,
                auto_range=config.auto_range,
                receive_timeout=config.timeout,
            )

        @staticmethod
        def handle_tls(
            connection: Connection, config: FlextLdapModels.ConnectionConfig
        ) -> FlextResult[bool]:
            """Handle STARTTLS if requested."""
            if not config.use_tls or config.use_ssl:
                return FlextResult[bool].ok(True)

            try:
                if not connection.start_tls():
                    return FlextResult[bool].fail("Failed to start TLS")
                return FlextResult[bool].ok(True)
            except Exception as tls_error:
                error_msg = f"Failed to start TLS: {tls_error}"
                return FlextResult[bool].fail(error_msg)

    class ResultConverter:
        """Result conversion logic (SRP)."""

        @staticmethod
        def convert_ldap3_results(
            connection: Connection,
        ) -> list[tuple[str, dict[str, list[str]]]]:
            """Convert ldap3 connection entries to parser format."""
            results: list[tuple[str, dict[str, list[str]]]] = []

            for entry in connection.entries:
                attrs: dict[str, list[str]] = {}
                dn = str(entry.entry_dn)

                for attr in entry.entry_attributes:
                    values = entry[attr].values
                    if FlextRuntime.is_list_like(values) or isinstance(values, tuple):
                        attrs[attr] = [str(v) for v in values]
                    elif values is None:
                        attrs[attr] = []
                    else:
                        attrs[attr] = [str(values)]

                results.append((dn, attrs))

            return results

        @staticmethod
        def normalize_metadata(
            metadata: object,
        ) -> FlextLdifModels.QuirkMetadata | None:
            """Normalize metadata to public QuirkMetadata type.

            Handles both public and internal QuirkMetadata types from parser.
            """
            if not metadata:
                return None

            metadata_type_name = type(metadata).__name__
            if metadata_type_name == "QuirkMetadata":
                if isinstance(metadata, FlextLdifModels.QuirkMetadata):
                    return metadata
                if hasattr(metadata, "model_dump"):
                    # Type narrowing: metadata has model_dump method
                    model_dump_method = getattr(metadata, "model_dump", None)
                    if model_dump_method is not None and callable(model_dump_method):
                        dumped = model_dump_method()
                        return FlextLdifModels.QuirkMetadata.model_validate(dumped)
                return FlextLdifModels.QuirkMetadata.model_validate(metadata)

            if isinstance(metadata, dict):
                return FlextLdifModels.QuirkMetadata.model_validate(metadata)

            return None

        @staticmethod
        def convert_parsed_entries(
            parse_response: FlextLdifModels.ParseResponse,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Convert parsed entries to properly typed Entry list."""
            entries: list[FlextLdifModels.Entry] = []

            for idx, parsed in enumerate(parse_response.entries):
                if not hasattr(parsed, "dn") or not hasattr(parsed, "attributes"):
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Invalid entry structure from parser at index {idx}"
                    )

                dn_obj = (
                    parsed.dn
                    if isinstance(parsed.dn, FlextLdifModels.DistinguishedName)
                    else FlextLdifModels.DistinguishedName(value=str(parsed.dn))
                )

                attrs_raw = parsed.attributes
                if isinstance(attrs_raw, FlextLdifModels.LdifAttributes):
                    entry_attrs = attrs_raw
                elif FlextRuntime.is_dict_like(attrs_raw):
                    attrs_dict: dict[str, list[str]] = {}
                    for key, value in attrs_raw.items():
                        if FlextRuntime.is_list_like(value):
                            attrs_dict[key] = [str(v) for v in value]
                        else:
                            attrs_dict[key] = [str(value)] if value is not None else []

                    entry_attrs = FlextLdifModels.LdifAttributes.model_validate(
                        {"attributes": attrs_dict}
                    )
                else:
                    attr_type = type(attrs_raw).__name__
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Invalid attributes type at index {idx}: {attr_type}"
                    )

                # Normalize metadata to handle both public and internal
                # QuirkMetadata types
                parsed_metadata = getattr(parsed, "metadata", None)
                metadata_obj = Ldap3Adapter.ResultConverter.normalize_metadata(
                    parsed_metadata
                )

                if metadata_obj:
                    entry = FlextLdifModels.Entry(
                        dn=dn_obj,
                        attributes=entry_attrs,
                        metadata=metadata_obj,
                    )
                else:
                    entry = FlextLdifModels.Entry(dn=dn_obj, attributes=entry_attrs)
                entries.append(entry)

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    class OperationExecutor:
        """LDAP operation execution logic (SRP)."""

        def __init__(self, adapter: Ldap3Adapter) -> None:
            """Initialize with adapter instance."""
            self._adapter = adapter

        def execute_add(
            self,
            connection: Connection,
            dn_str: str,
            ldap_attrs: dict[str, list[str]],
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Execute LDAP add operation."""
            try:
                add_func: FlextLdapTypes.LdapAddCallable = connection.add
                success = add_func(dn_str, None, ldap_attrs)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type="add",
                            message="Entry added successfully",
                            entries_affected=1,
                        )
                    )

                return self._extract_error_result(connection, "Add failed")
            except Exception as e:
                error_msg = f"Add failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        def execute_modify(
            self,
            connection: Connection,
            dn: str | FlextLdifModels.DistinguishedName,
            changes: FlextLdapTypes.LdapModifyChanges,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Execute LDAP modify operation."""
            try:
                dn_str = FlextLdif.utilities.DN.get_dn_value(dn)
                modify_func: FlextLdapTypes.LdapModifyCallable = connection.modify
                success = modify_func(dn_str, changes)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type="modify",
                            message="Entry modified successfully",
                            entries_affected=1,
                        )
                    )

                return self._extract_error_result(connection, "Modify failed")
            except Exception as e:
                error_msg = f"Modify failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        def execute_delete(
            self,
            connection: Connection,
            dn: str | FlextLdifModels.DistinguishedName,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Execute LDAP delete operation."""
            try:
                dn_str = FlextLdif.utilities.DN.get_dn_value(dn)
                delete_func: FlextLdapTypes.LdapDeleteCallable = connection.delete
                success = delete_func(dn_str)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type="delete",
                            message="Entry deleted successfully",
                            entries_affected=1,
                        )
                    )

                return self._extract_error_result(connection, "Delete failed")
            except Exception as e:
                error_msg = f"Delete failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        @staticmethod
        def _extract_error_result(
            connection: Connection, prefix: str
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Extract error message from connection result."""
            error_msg = f"{prefix}: LDAP operation returned failure status"
            result_dict = connection.result
            if FlextRuntime.is_dict_like(result_dict) and "description" in result_dict:
                error_msg = f"{prefix}: {result_dict['description']}"
            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    class SearchExecutor:
        """Search operation execution logic (SRP)."""

        def __init__(self, adapter: Ldap3Adapter) -> None:
            """Initialize with adapter instance."""
            self._adapter = adapter

        def execute(
            self,
            connection: Connection,
            base_dn: str,
            filter_str: str,
            ldap_scope: Ldap3Scope,
            search_attributes: list[str],
            size_limit: int,
            time_limit: int,
            server_type: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Execute LDAP search and convert results."""
            try:
                connection.search(
                    search_base=base_dn,
                    search_filter=filter_str,
                    search_scope=ldap_scope,
                    attributes=search_attributes,
                    size_limit=size_limit,
                    time_limit=time_limit,
                )

                result_code = connection.result.get("result", -1)
                if (
                    result_code
                    not in FlextLdapConstants.LdapResultCodes.PARTIAL_SUCCESS_CODES
                ):
                    error_msg = connection.result.get("message", "LDAP search failed")
                    error_desc = connection.result.get("description", "unknown")
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"LDAP search failed: {error_desc} - {error_msg}"
                    )

                ldap3_results = self._adapter.ResultConverter.convert_ldap3_results(
                    connection
                )
                parse_result = self._adapter.parser.parse_ldap3_results(
                    ldap3_results, server_type
                )

                if parse_result.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        str(parse_result.error) if parse_result.error else ""
                    )

                return self._adapter.ResultConverter.convert_parsed_entries(
                    parse_result.unwrap()
                )
            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Search failed: {e!s}"
                )

    _connection: Connection | None
    _server: Server | None
    _parser: FlextLdifParser
    _entry_adapter: FlextLdapEntryAdapter

    @property
    def parser(self) -> FlextLdifParser:
        """Get parser instance."""
        return self._parser

    def __init__(
        self,
        parser: FlextLdifParser | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize adapter service with parser."""
        super().__init__(**kwargs)
        if parser is None:
            parser_kwarg = kwargs.pop("parser", None)
            if parser_kwarg is not None:
                if not isinstance(parser_kwarg, FlextLdifParser):
                    parser_type = type(parser_kwarg).__name__
                    error_msg = f"parser must be FlextLdifParser, got {parser_type}"
                    raise TypeError(error_msg)
                parser = parser_kwarg
        if parser is None:
            parser = FlextLdif.get_instance().parser
        self._connection = None
        self._server = None
        self._parser = parser
        self._entry_adapter = FlextLdapEntryAdapter()

    def connect(
        self,
        config: FlextLdapModels.ConnectionConfig,
        **_kwargs: object,
    ) -> FlextResult[bool]:
        """Establish LDAP connection using ldap3."""
        try:
            self._server = self.ConnectionManager.create_server(config)
            self._connection = self.ConnectionManager.create_connection(
                self._server, config
            )

            tls_result = self.ConnectionManager.handle_tls(self._connection, config)
            if tls_result.is_failure:
                return tls_result

            if not self._connection.bound:
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Connection failed: {e!s}")

    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self._connection:
            try:
                unbind_func: Callable[[], None] = self._connection.unbind
                unbind_func()
            except Exception as e:
                self.logger.debug("Error during disconnect", error=str(e))
            finally:
                self._connection = None
                self._server = None

    @property
    def connection(self) -> Connection | None:
        """Get underlying ldap3 Connection object."""
        return self._connection

    @property
    def is_connected(self) -> bool:
        """Check if adapter has an active connection."""
        return self._connection is not None and self._connection.bound

    def _get_connection(self) -> FlextResult[Connection]:
        """Get connection with fast fail if not available."""
        if not self.is_connected or self._connection is None:
            return FlextResult[Connection].fail(
                FlextLdapConstants.ErrorStrings.NOT_CONNECTED
            )
        return FlextResult[Connection].ok(self._connection)

    def _map_scope(self, scope: str) -> FlextResult[Ldap3Scope]:
        """Map scope string to ldap3 scope constant."""
        scope_map: dict[str, Ldap3Scope] = {
            FlextLdapConstants.SearchScope.BASE: "BASE",
            FlextLdapConstants.SearchScope.ONELEVEL: "LEVEL",
            FlextLdapConstants.SearchScope.SUBTREE: "SUBTREE",
        }
        mapped = scope_map.get(scope.upper())
        return (
            FlextResult[Ldap3Scope].ok(mapped)
            if mapped
            else FlextResult[Ldap3Scope].fail(f"Invalid LDAP scope: {scope}")
        )

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation and convert to Entry models."""
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(connection_result.error) if connection_result.error else ""
            )

        scope_result = self._map_scope(search_options.scope)
        if scope_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(scope_result.error) if scope_result.error else ""
            )

        entries_result = self.SearchExecutor(self).execute(
            connection_result.unwrap(),
            search_options.base_dn,
            search_options.filter_str,
            scope_result.unwrap(),
            search_options.attributes or [],
            search_options.size_limit,
            search_options.time_limit,
            server_type,
        )

        if entries_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(entries_result.error) if entries_result.error else ""
            )

        return FlextResult[FlextLdapModels.SearchResult].ok(
            FlextLdapModels.SearchResult(
                entries=entries_result.unwrap(), search_options=search_options
            )
        )

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry using Entry model."""
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else ""
            )

        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Failed to convert entry attributes: {attrs_result.error}"
            )

        return self.OperationExecutor(self).execute_add(
            connection_result.unwrap(),
            str(entry.dn) if entry.dn else "unknown",
            attrs_result.unwrap(),
        )

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: FlextLdapTypes.LdapModifyChanges,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry."""
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else ""
            )
        return self.OperationExecutor(self).execute_modify(
            connection_result.unwrap(), dn, changes
        )

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry."""
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else ""
            )
        return self.OperationExecutor(self).execute_delete(
            connection_result.unwrap(), dn
        )

    def execute(self, **_kwargs: object) -> FlextResult[bool]:
        """Execute service health check."""
        if not self.is_connected:
            return FlextResult[bool].fail(FlextLdapConstants.ErrorStrings.NOT_CONNECTED)
        return FlextResult[bool].ok(True)
