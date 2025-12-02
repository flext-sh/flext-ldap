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

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import cast

from flext_core import FlextResult, FlextRuntime, FlextService
from flext_core.typings import FlextTypes
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif._models.results import (
    FlextLdifModelsResults,  # Private import required for ParseResponse type
)
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.utilities import FlextLdifUtilities
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPException
from pydantic import ConfigDict

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.typings import FlextLdapTypes

# ldap3 expects Literal["BASE", "LEVEL", "SUBTREE"]
# We use StrEnum internally and pass validated string values to ldap3


class Ldap3Adapter(FlextService[bool]):
    """Service adapter for ldap3 library following flext-ldif patterns.

    Wraps ldap3 Connection and Server objects to provide a simplified
    interface for LDAP operations. Reuses FlextLdifParser for automatic
    conversion of LDAP results to Entry models.
    """

    # Service requires mutable state for connection management
    model_config = ConfigDict(frozen=False)

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
            server: Server,
            config: FlextLdapModels.ConnectionConfig,
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
            connection: Connection,
            config: FlextLdapModels.ConnectionConfig,
        ) -> FlextResult[bool]:
            """Handle STARTTLS if requested."""
            if not config.use_tls or config.use_ssl:
                return FlextResult[bool].ok(True)

            try:
                if not connection.start_tls():
                    return FlextResult[bool].fail("Failed to start TLS")
                return FlextResult[bool].ok(True)
            except LDAPException as tls_error:
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
        def extract_dn(parsed: object) -> object:
            """Extract DN from parsed entry.

            Returns:
                FlextLdifModels.DistinguishedName instance (typed as object for mypy compatibility with aliases).

            """
            if not hasattr(parsed, "dn"):
                return FlextLdifModels.DistinguishedName.model_validate({"value": ""})

            # Type narrowing: parsed has dn attribute
            # Use getattr to satisfy pyright type checking for object type
            dn_raw: object = getattr(parsed, "dn", None)
            if dn_raw is None:
                return FlextLdifModels.DistinguishedName.model_validate({"value": ""})
            # Check if already DistinguishedName instance
            # DistinguishedName is an alias, so we use runtime check
            dn_type = type(
                FlextLdifModels.DistinguishedName.model_validate({"value": ""}),
            )
            if isinstance(dn_raw, dn_type):
                return dn_raw
            # Create new DistinguishedName from string
            return FlextLdifModels.DistinguishedName.model_validate({
                "value": str(dn_raw),
            })

        @staticmethod
        def extract_attributes(parsed: object) -> FlextLdifModels.LdifAttributes:
            """Extract attributes from parsed entry."""
            if not hasattr(parsed, "attributes"):
                return FlextLdifModels.LdifAttributes.model_validate({"attributes": {}})

            # Type narrowing: parsed has attributes attribute
            # Use getattr to satisfy pyright type checking for object type
            attrs_raw: object = getattr(parsed, "attributes", None)
            if attrs_raw is None:
                return FlextLdifModels.LdifAttributes.model_validate({"attributes": {}})
            if isinstance(attrs_raw, FlextLdifModels.LdifAttributes):
                return attrs_raw

            # Extract attributes dict from various formats
            attrs_dict: dict[str, list[str]] = {}
            # Type narrowing: check if attrs_raw has attributes attribute
            if hasattr(attrs_raw, "attributes"):
                # Use getattr to satisfy pyright type checking for object type
                attrs_attr: object = getattr(attrs_raw, "attributes", None)
                if attrs_attr is None:
                    attrs_attr = {}
                if isinstance(attrs_attr, dict):
                    attrs_dict = attrs_attr
            elif FlextRuntime.is_dict_like(attrs_raw):
                attrs_dict = {
                    k: [str(item) for item in v]
                    if FlextRuntime.is_list_like(v)
                    else [str(v)]
                    for k, v in attrs_raw.items()
                }

            return FlextLdifModels.LdifAttributes.model_validate({
                "attributes": attrs_dict,
            })

        @staticmethod
        def extract_metadata(parsed: object) -> object | None:
            """Extract metadata from parsed entry.

            Returns:
                FlextLdifModels.QuirkMetadata instance or None (typed as object for mypy compatibility with aliases).

            """
            if not hasattr(parsed, "metadata"):
                return None

            # Type narrowing: parsed has metadata attribute
            # Use getattr to satisfy pyright type checking for object type
            metadata_raw: object = getattr(parsed, "metadata", None)
            if not metadata_raw:
                return None

            # Check if already QuirkMetadata instance
            # QuirkMetadata is an alias, so we use runtime check
            metadata_type = type(
                FlextLdifModels.QuirkMetadata.model_validate({"quirk_type": "rfc"}),
            )
            if isinstance(metadata_raw, metadata_type):
                return metadata_raw

            # Type narrowing: normalize_metadata accepts dict, Mapping, or None
            # metadata_raw is object, need to check type before passing
            metadata_for_normalize: (
                dict[str, str | int | float | bool | None]
                | Mapping[str, str | int | float | bool | None]
                | None
            )
            if isinstance(metadata_raw, (dict, Mapping)):
                metadata_for_normalize = cast(
                    "dict[str, str | int | float | bool | None] | Mapping[str, str | int | float | bool | None]",
                    metadata_raw,
                )
            else:
                metadata_for_normalize = None
            normalized = Ldap3Adapter.ResultConverter.normalize_metadata(
                metadata_for_normalize,
            )
            if normalized:
                return FlextLdifModels.QuirkMetadata.model_validate(normalized)
            return None

        @staticmethod
        def normalize_metadata(
            metadata: (
                dict[str, str | int | float | bool | None]
                | Mapping[str, str | int | float | bool | None]
                | None
            ),
        ) -> dict[str, str | int | float | bool | None] | None:
            """Normalize metadata for Entry model validation.

            Returns dict suitable for QuirkMetadata.model_validate().
            Uses runtime validation since QuirkMetadata is an alias.
            """
            if not metadata:
                return None

            # Type narrowing: check if dict (can be validated directly)
            if isinstance(metadata, dict):
                return metadata

            # Handle Mapping types
            if FlextRuntime.is_dict_like(metadata):
                # Use dict comprehension for better performance (PERF403)
                result: dict[str, str | int | float | bool | None] = {
                    key: value
                    for key, value in metadata.items()
                    if isinstance(key, str)
                    and (isinstance(value, (str, int, float, bool)) or value is None)
                }
                return result

            # Handle objects with model_dump method (Pydantic models)
            # Type narrowing: check if metadata has model_dump method
            model_dump_method = getattr(metadata, "model_dump", None)
            if model_dump_method is not None and callable(model_dump_method):
                # Type narrowing: metadata has model_dump callable
                dumped: object = model_dump_method()
                if isinstance(dumped, dict):
                    return dumped

            return None

        @staticmethod
        def convert_parsed_entries(
            parse_response: FlextLdifModelsResults.ParseResponse,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Convert parsed entries to properly typed Entry list."""
            entries: list[FlextLdifModels.Entry] = []

            # ParseResponse.entries is Sequence[Entry] - direct access
            entries_raw = parse_response.entries
            if not entries_raw:
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            for parsed in entries_raw:
                # ParseResponse.entries contains Entry models - direct use
                # Entry already has proper DN and attributes types
                if isinstance(parsed, FlextLdifModels.Entry):
                    entries.append(parsed)
                    continue

                # Convert domain Entry to public Entry if needed
                # Extract DN - use direct conversion helper
                dn_obj = Ldap3Adapter.ResultConverter.extract_dn(parsed)
                # Extract attributes - use direct conversion helper
                attrs_obj = Ldap3Adapter.ResultConverter.extract_attributes(parsed)
                # Extract metadata - use direct conversion helper
                metadata_obj = Ldap3Adapter.ResultConverter.extract_metadata(parsed)

                # Create Entry with extracted objects
                # DistinguishedName and QuirkMetadata are type aliases, runtime validation ensures correctness
                # Type narrowing via cast for pyright compatibility
                # mypy doesn't support type aliases in cast, so we use type: ignore[valid-type]
                dn_typed = cast("FlextLdifModels.DistinguishedName | None", dn_obj)  # type: ignore[valid-type]  # DistinguishedName alias
                metadata_typed = cast(
                    "FlextLdifModels.QuirkMetadata | None", metadata_obj
                )  # type: ignore[valid-type]  # QuirkMetadata alias
                entry = FlextLdifModels.Entry(
                    dn=dn_typed,
                    attributes=attrs_obj,
                    metadata=metadata_typed,
                )
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
                add_func: FlextLdapTypes.Ldap.AddCallable = connection.add
                success = add_func(dn_str, None, ldap_attrs)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type=FlextLdapConstants.OperationType.ADD,
                            message="Entry added successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Add failed")
            except LDAPException as e:
                error_msg = f"Add failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        def execute_modify(
            self,
            connection: Connection,
            dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
            changes: FlextLdapTypes.Ldap.ModifyChanges,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Execute LDAP modify operation."""
            try:
                dn_str = FlextLdifUtilities.DN.get_dn_value(dn)
                modify_func: FlextLdapTypes.Ldap.ModifyCallable = connection.modify
                success = modify_func(dn_str, changes)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type=FlextLdapConstants.OperationType.MODIFY,
                            message="Entry modified successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Modify failed")
            except LDAPException as e:
                error_msg = f"Modify failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        def execute_delete(
            self,
            connection: Connection,
            dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Execute LDAP delete operation."""
            try:
                dn_str = FlextLdifUtilities.DN.get_dn_value(dn)
                delete_func: FlextLdapTypes.Ldap.DeleteCallable = connection.delete
                success = delete_func(dn_str)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type=FlextLdapConstants.OperationType.DELETE,
                            message="Entry deleted successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Delete failed")
            except LDAPException as e:
                error_msg = f"Delete failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        @staticmethod
        def _extract_error_result(
            connection: Connection,
            prefix: str,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Extract error message from connection result."""
            error_msg = f"{prefix}: LDAP operation returned failure status"
            result_dict = connection.result
            if FlextRuntime.is_dict_like(result_dict) and "description" in result_dict:
                error_msg = f"{prefix}: {result_dict['description']}"
            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    class SearchExecutor:
        """Search operation execution logic (SRP)."""

        @dataclass(frozen=True)
        class SearchParams:
            """Search parameters grouped together to reduce method arguments."""

            base_dn: str
            filter_str: str
            ldap_scope: FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral
            search_attributes: list[str]
            size_limit: int
            time_limit: int

        def __init__(self, adapter: Ldap3Adapter) -> None:
            """Initialize with adapter instance."""
            self._adapter = adapter

        @staticmethod
        def _normalize_to_ldif_server_type(
            server_type: str,
        ) -> FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None:
            """Normalize server type string to parser-compatible ServerTypeLiteral.

            Returns only parser-compatible server types (excludes oracle_oid/oracle_oud).
            This matches the exact type expected by FlextLdifParser.parse_ldap3_results.
            """
            # Use Constants.ServerTypeMappings for flext-ldif compatibility
            result_raw = FlextLdapConstants.ServerTypeMappings.LDIF_COMPATIBLE.get(
                server_type,
            )
            # Type narrowing: result_raw is str | None, but we need ServerTypeLiteral | None
            # ServerTypeLiteral is a Literal type, so we cast the result
            result: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None = cast(
                "FlextLdifConstants.LiteralTypes.ServerTypeLiteral | None",
                result_raw,
            )
            return result

        def execute(
            self,
            connection: Connection,
            params: SearchParams,
            server_type: FlextLdifConstants.ServerTypes | str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Execute LDAP search and convert results."""
            try:
                connection.search(
                    search_base=params.base_dn,
                    search_filter=params.filter_str,
                    search_scope=params.ldap_scope,
                    attributes=params.search_attributes,
                    size_limit=params.size_limit,
                    time_limit=params.time_limit,
                )

                result_code = connection.result.get("result", -1)
                if (
                    result_code
                    not in FlextLdapConstants.LdapResultCodes.PARTIAL_SUCCESS_CODES
                ):
                    error_msg = connection.result.get("message", "LDAP search failed")
                    error_desc = connection.result.get("description", "unknown")
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"LDAP search failed: {error_desc} - {error_msg}",
                    )

                ldap3_results = self._adapter.ResultConverter.convert_ldap3_results(
                    connection,
                )
                # Convert server_type to ServerTypeLiteral for parser
                # Map flext-ldap ServerTypes to flext-ldif ServerTypeLiteral
                server_type_str = (
                    server_type.value
                    if isinstance(server_type, FlextLdifConstants.ServerTypes)
                    else str(server_type)
                )
                # Normalize server type (map oracle_oid/oracle_oud to oid/oud)
                # Use ServerTypes StrEnum values for type safety
                normalized_server_type = (
                    FlextLdifConstants.ServerTypes.OID.value
                    if server_type_str
                    in {FlextLdifConstants.ServerTypes.OID.value, "oracle_oid"}
                    else FlextLdifConstants.ServerTypes.OUD.value
                    if server_type_str
                    in {FlextLdifConstants.ServerTypes.OUD.value, "oracle_oud"}
                    else server_type_str
                )
                # Convert to flext-ldif ServerTypeLiteral using helper function
                # Helper returns only parser-compatible types (excludes oracle_* variants)
                server_type_literal = self._normalize_to_ldif_server_type(
                    normalized_server_type,
                )
                parse_result = self._adapter.parser.parse_ldap3_results(
                    ldap3_results,
                    server_type_literal,
                )

                if parse_result.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        str(parse_result.error) if parse_result.error else "",
                    )

                return self._adapter.ResultConverter.convert_parsed_entries(
                    parse_result.unwrap(),
                )
            except LDAPException as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Search failed: {e!s}",
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
        **kwargs: FlextTypes.GeneralValueType,
    ) -> None:
        """Initialize adapter service with parser.

        Args:
            **kwargs: Keyword arguments including:
                - parser: Optional FlextLdifParser instance. If None, uses default from FlextLdif.
                - Additional service configuration parameters (delegated to FlextService).

        """
        # Extract parser from kwargs if provided
        parser_raw = kwargs.pop("parser", None)
        parser: FlextLdifParser | None = (
            parser_raw if isinstance(parser_raw, FlextLdifParser) else None
        )
        # Initialize parent with remaining kwargs
        super().__init__(**kwargs)
        # Set parser - use default if not provided
        if parser is None:
            parser = FlextLdif.get_instance().parser
        self._connection = None
        self._server = None
        self._parser = parser
        # Create adapter instance directly
        self._entry_adapter = FlextLdapEntryAdapter()

    def connect(
        self,
        config: FlextLdapModels.ConnectionConfig,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[bool]:
        """Establish LDAP connection using ldap3."""
        try:
            self._server = self.ConnectionManager.create_server(config)
            self._connection = self.ConnectionManager.create_connection(
                self._server,
                config,
            )

            tls_result = self.ConnectionManager.handle_tls(self._connection, config)
            if tls_result.is_failure:
                return tls_result

            if not self._connection.bound:
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            return FlextResult[bool].ok(True)
        except LDAPException as e:
            return FlextResult[bool].fail(f"Connection failed: {e!s}")

    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self._connection:
            try:
                unbind_func: Callable[[], None] = self._connection.unbind
                unbind_func()
            except (LDAPException, OSError) as e:
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
                FlextLdapConstants.ErrorStrings.NOT_CONNECTED,
            )
        return FlextResult[Connection].ok(self._connection)

    @staticmethod
    def _map_scope(
        scope: FlextLdapConstants.SearchScope | str,
    ) -> FlextResult[FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral]:
        """Map scope string to ldap3 scope constant.

        Uses direct StrEnum value mapping for type-safe conversion.
        """
        # Normalize to StrEnum if string provided
        # Type narrowing: scope is str | SearchScope
        # SearchScope is a StrEnum (subclass of str), so check for SearchScope first
        if isinstance(scope, FlextLdapConstants.SearchScope):
            # Type narrowing: scope is SearchScope
            scope_enum = scope
        else:
            # Type narrowing: scope is str (SearchScope is also str, but already handled above)
            # Convert string to SearchScope enum
            try:
                scope_enum = FlextLdapConstants.SearchScope(scope.upper())
            except ValueError:
                return FlextResult[
                    FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral
                ].fail(f"Invalid LDAP scope: {scope}")

        # Direct mapping using StrEnum values with proper type narrowing
        ldap3_scope_mapping: dict[
            FlextLdapConstants.SearchScope,
            FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral,
        ] = {
            FlextLdapConstants.SearchScope.BASE: "BASE",
            FlextLdapConstants.SearchScope.ONELEVEL: "LEVEL",
            FlextLdapConstants.SearchScope.SUBTREE: "SUBTREE",
        }

        if scope_enum in ldap3_scope_mapping:
            ldap3_value = ldap3_scope_mapping[scope_enum]
            return FlextResult[FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral].ok(
                ldap3_value,
            )

        return FlextResult[FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral].fail(
            f"Invalid LDAP scope: {scope}",
        )

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: FlextLdifConstants.ServerTypes
        | str = FlextLdifConstants.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation and convert to Entry models."""
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )

        # Convert scope to str or SearchScope for _map_scope
        # SearchOptions.scope is str, but may need conversion to SearchScope enum
        # Type narrowing: scope is str from SearchOptions model
        scope_for_mapping: str | FlextLdapConstants.SearchScope = search_options.scope
        scope_result = Ldap3Adapter._map_scope(scope_for_mapping)
        if scope_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(scope_result.error) if scope_result.error else "",
            )

        search_params = self.SearchExecutor.SearchParams(
            base_dn=search_options.base_dn,
            filter_str=search_options.filter_str,
            ldap_scope=scope_result.unwrap(),
            search_attributes=search_options.attributes or [],
            size_limit=search_options.size_limit,
            time_limit=search_options.time_limit,
        )
        entries_result = self.SearchExecutor(self).execute(
            connection_result.unwrap(),
            search_params,
            server_type,
        )

        if entries_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(entries_result.error) if entries_result.error else "",
            )

        return FlextResult[FlextLdapModels.SearchResult].ok(
            FlextLdapModels.SearchResult(
                entries=entries_result.unwrap(),
                search_options=search_options,
            ),
        )

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry using Entry model."""
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )

        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Failed to convert entry attributes: {attrs_result.error}",
            )

        return self.OperationExecutor(self).execute_add(
            connection_result.unwrap(),
            str(entry.dn) if entry.dn else "unknown",
            attrs_result.unwrap(),
        )

    def modify(
        self,
        dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
        changes: FlextLdapTypes.Ldap.ModifyChanges,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry."""
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )
        return self.OperationExecutor(self).execute_modify(
            connection_result.unwrap(),
            dn,  # Type: str | DistinguishedNameProtocol (runtime validated)
            changes,
        )

    def delete(
        self,
        dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry."""
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )
        return self.OperationExecutor(self).execute_delete(
            connection_result.unwrap(),
            dn,
        )

    def execute(self, **_kwargs: str | float | bool | None) -> FlextResult[bool]:
        """Execute service health check."""
        if not self.is_connected:
            return FlextResult[bool].fail(FlextLdapConstants.ErrorStrings.NOT_CONNECTED)
        return FlextResult[bool].ok(True)
