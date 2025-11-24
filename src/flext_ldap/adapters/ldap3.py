"""LDAP3 adapter service - Service wrapper for ldap3 library.

This module provides a service adapter around ldap3 following flext-ldif patterns.
Reuses FlextLdifParser for parsing LDAP results to Entry models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

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

    This is a SERVICE adapter, not just a wrapper, following the same
    patterns as flext-ldif services.
    """

    _connection: Connection | None
    _server: Server | None
    _parser: FlextLdifParser
    _entry_adapter: FlextLdapEntryAdapter

    def __init__(
        self,
        parser: FlextLdifParser | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize adapter service with parser.

        Args:
            parser: Parser instance (optional, uses FlextLdif API if not provided)
            **kwargs: Additional keyword arguments passed to parent class

        """
        super().__init__(**kwargs)
        # Extract parser from kwargs if not provided directly
        if parser is None:
            parser_from_kwargs = kwargs.pop("parser", None)
            if parser_from_kwargs is not None:
                parser = cast("FlextLdifParser", parser_from_kwargs)
        if parser is None:
            ldif = FlextLdif.get_instance()
            parser = ldif.parser
        self._connection = None
        self._server = None
        self._parser = parser
        self._entry_adapter = FlextLdapEntryAdapter()

    def connect(
        self,
        config: FlextLdapModels.ConnectionConfig,
        **_kwargs: object,
    ) -> FlextResult[bool]:
        """Establish LDAP connection using ldap3.

        Args:
            config: Connection configuration

        Returns:
            FlextResult[bool] - ok(True) on success, fail(error) on failure

        """
        self.logger.debug(
            "Connecting to LDAP server",
            operation="connect",
            host=config.host,
            port=config.port,
            use_ssl=config.use_ssl,
            use_tls=config.use_tls,
            bind_dn=config.bind_dn[:50] if config.bind_dn else None,
        )

        try:
            # Create server object
            if config.use_ssl:
                self._server = Server(
                    host=config.host,
                    port=config.port,
                    use_ssl=True,
                    connect_timeout=config.timeout,
                )
            else:
                self._server = Server(
                    host=config.host,
                    port=config.port,
                    connect_timeout=config.timeout,
                )

            # Create connection
            self._connection = Connection(
                server=self._server,
                user=config.bind_dn,
                password=config.bind_password,
                auto_bind=config.auto_bind,
                auto_range=config.auto_range,
                receive_timeout=config.timeout,
            )

            # Handle STARTTLS if requested
            if config.use_tls and not config.use_ssl:
                try:
                    tls_result = self._connection.start_tls()
                    if not tls_result:  # pragma: no cover
                        self.logger.error(
                            "TLS negotiation failed",
                            operation="connect",
                            host=config.host,
                            port=config.port,
                        )
                        return FlextResult[bool].fail("Failed to start TLS")
                except Exception as tls_error:
                    self.logger.exception(
                        "TLS negotiation exception",
                        operation="connect",
                        host=config.host,
                        port=config.port,
                        error=str(tls_error),
                    )
                    return FlextResult[bool].fail(f"Failed to start TLS: {tls_error}")

            if not self._connection.bound:
                self.logger.error(
                    "LDAP bind failed",
                    operation="connect",
                    host=config.host,
                    port=config.port,
                )
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            self.logger.info(
                "LDAP connection established",
                operation="connect",
                host=config.host,
                port=config.port,
            )
            return FlextResult[bool].ok(data=True)

        except Exception as e:
            _ = self.logger.exception(
                "Failed to connect to LDAP server",
                host=config.host,
                port=config.port,
                use_ssl=config.use_ssl,
                use_tls=config.use_tls,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[bool].fail(f"Connection failed: {e!s}")

    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self._connection:
            try:
                # Connection.unbind()
                # Use cast to inform type checker while maintaining runtime safety
                unbind_func = cast("Callable[[], None]", self._connection.unbind)
                unbind_func()
            except Exception as e:
                _ = self.logger.debug(
                    "Error during disconnect",
                    error=str(e),
                    error_type=type(e).__name__,
                )
            finally:
                self._connection = None
                self._server = None

    @property
    def connection(self) -> Connection | None:
        """Get underlying ldap3 Connection object.

        Returns:
            Connection object if connected, None otherwise

        """
        return self._connection

    @property
    def is_connected(self) -> bool:
        """Check if adapter has an active connection.

        Returns:
            True if connected and bound, False otherwise

        """
        return self._connection is not None and self._connection.bound

    def _get_connection(self) -> FlextResult[Connection]:
        """Get connection with fast fail if not available.

        Returns:
            FlextResult containing Connection or error

        Notes:
            - is_connected property guarantees: self._connection is not None and self._connection.bound
            - Therefore, if is_connected is True, _connection is definitely not None
            - Type narrowing via assert for type checker (runtime unreachable if is_connected=True)

        """
        if not self.is_connected or self._connection is None:
            return FlextResult[Connection].fail("Not connected to LDAP server")

        return FlextResult[Connection].ok(self._connection)

    def _map_scope(self, scope: str) -> FlextResult[Ldap3Scope]:
        """Map scope string to ldap3 scope constant.

        Args:
            scope: Scope string (BASE, ONELEVEL, SUBTREE)

        Returns:
            FlextResult containing ldap3 scope constant or error

        """
        scope_upper = scope.upper()
        if scope_upper == FlextLdapConstants.SearchScope.BASE:
            return FlextResult[Ldap3Scope].ok("BASE")
        if scope_upper == FlextLdapConstants.SearchScope.ONELEVEL:
            return FlextResult[Ldap3Scope].ok("LEVEL")
        if scope_upper == FlextLdapConstants.SearchScope.SUBTREE:
            return FlextResult[Ldap3Scope].ok("SUBTREE")

        error_msg = (
            f"Invalid LDAP scope: {scope}. Must be "
            f"{FlextLdapConstants.SearchScope.BASE}, "
            f"{FlextLdapConstants.SearchScope.ONELEVEL}, or "
            f"{FlextLdapConstants.SearchScope.SUBTREE}"
        )
        self.logger.error(
            "Invalid LDAP scope",
            operation="_map_scope",
            scope=scope,
        )
        return FlextResult[Ldap3Scope].fail(error_msg)

    def _convert_ldap3_results(
        self,
        connection: Connection,
    ) -> list[tuple[str, dict[str, list[str]]]]:
        """Convert ldap3 connection entries to parser format.

        Preserves all original data including None values, empty lists, and special characters.
        Tracks conversions for metadata.

        Args:
            connection: ldap3 Connection with search results

        Returns:
            List of tuples (dn, attributes_dict)

        """
        ldap3_results: list[tuple[str, dict[str, list[str]]]] = []

        for entry in connection.entries:
            entry_attrs: dict[str, list[str]] = {}
            original_dn = str(entry.entry_dn)

            for attr in entry.entry_attributes:
                attr_values = entry[attr].values

                # Preserve all data - convert to list format but keep original structure
                if FlextRuntime.is_list_like(attr_values) or isinstance(
                    attr_values,
                    tuple,
                ):
                    # Type narrowing: is_list_like ensures list[object], convert to list[str]
                    entry_attrs[attr] = [str(v) for v in attr_values]
                elif attr_values is None:
                    # Preserve None as empty list (LDAP format requirement)
                    entry_attrs[attr] = []
                else:
                    # Single value - convert to list
                    entry_attrs[attr] = [str(attr_values)]

            ldap3_results.append((original_dn, entry_attrs))

        return ldap3_results

    def _convert_parsed_entries(
        self,
        parse_response: FlextLdifModels.ParseResponse,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Convert parsed entries to properly typed Entry list.

        Preserves all metadata from parsing phase. Never loses data.

        Args:
            parse_response: ParseResponse from FlextLdifParser

        Returns:
            FlextResult containing list of Entry models or error

        """
        entries_list: list[FlextLdifModels.Entry] = []

        for idx, parsed_entry in enumerate(parse_response.entries):
            # Fast fail - validate entry structure (separate checks, no or)
            if not hasattr(parsed_entry, "dn"):
                self.logger.error(
                    "Invalid entry: missing dn",
                    entry_index=idx,
                    total_entries=len(parse_response.entries),
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Invalid entry structure from parser: missing dn at index {idx}",
                )
            if not hasattr(parsed_entry, "attributes"):
                self.logger.error(
                    "Invalid entry: missing attributes",
                    entry_index=idx,
                    entry_dn=str(parsed_entry.dn)
                    if hasattr(parsed_entry, "dn")
                    else "unknown",
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Invalid entry structure from parser: missing attributes at index {idx}",
                )

            # Use proper type conversion
            dn_obj = (
                parsed_entry.dn
                if isinstance(parsed_entry.dn, FlextLdifModels.DistinguishedName)
                else FlextLdifModels.DistinguishedName(value=str(parsed_entry.dn))
            )

            # Type narrowing: after hasattr check, we know attributes exists
            # Use getattr for type safety (mypy doesn't understand hasattr narrowing)
            entry_attributes_raw = parsed_entry.attributes
            entry_attributes: FlextLdifModels.LdifAttributes
            if isinstance(entry_attributes_raw, FlextLdifModels.LdifAttributes):
                entry_attributes = entry_attributes_raw
            elif FlextRuntime.is_dict_like(entry_attributes_raw):
                # Type narrowing: is_dict_like ensures dict[str, object]
                # Convert to dict[str, list[str]] format expected by LdifAttributes
                attrs_dict: dict[str, list[str]] = {}
                for key, value in entry_attributes_raw.items():
                    if FlextRuntime.is_list_like(value):
                        attrs_dict[key] = [str(v) for v in value]
                    else:
                        attrs_dict[key] = [str(value)] if value is not None else []
                entry_attributes = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
            else:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Invalid attributes type at index {idx}: {type(entry_attributes_raw).__name__}",
                )

            # Preserve metadata if present (NEVER lose metadata)
            if hasattr(parsed_entry, "metadata") and parsed_entry.metadata:
                entry_metadata = cast(
                    "FlextLdifModels.QuirkMetadata",
                    parsed_entry.metadata,
                )
                entry_obj = FlextLdifModels.Entry(
                    dn=dn_obj,
                    attributes=entry_attributes,
                    metadata=entry_metadata,
                )
            else:
                entry_obj = FlextLdifModels.Entry(
                    dn=dn_obj,
                    attributes=entry_attributes,
                )

            entries_list.append(entry_obj)

        return FlextResult[list[FlextLdifModels.Entry]].ok(entries_list)

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation and convert to Entry models.

        Uses FlextLdifParser.parse_ldap3_results() to automatically convert
        LDAP results to Entry models, reusing flext-ldif parsing logic.

        Args:
            search_options: Search configuration (required)
            server_type: LDAP server type for parsing (default: RFC constant)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        self.logger.debug(
            "Executing LDAP search",
            operation="search",
            base_dn=search_options.base_dn[:100] if search_options.base_dn else None,
            filter_str=search_options.filter_str[:100]
            if search_options.filter_str
            else None,
            scope=search_options.scope,
        )

        connection_result = self._get_connection()
        if connection_result.is_failure:
            self.logger.error(
                "Search failed: not connected",
                operation="search",
                base_dn=search_options.base_dn[:100]
                if search_options.base_dn
                else None,
                error=str(connection_result.error)
                if connection_result.error
                else "Unknown error",
            )
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(connection_result.error)
                if connection_result.error
                else "Unknown error",
            )
        connection = connection_result.unwrap()

        # Map scope next
        scope_result = self._map_scope(search_options.scope)
        if scope_result.is_failure:
            # FlextResult contract: error is guaranteed non-None when is_failure is True
            error_msg = str(scope_result.error)
            self.logger.error(
                "Search failed: scope mapping failed",
                operation="search",
                base_dn=search_options.base_dn[:100]
                if search_options.base_dn
                else None,
                scope=search_options.scope,
                error=error_msg,
            )
            return FlextResult[FlextLdapModels.SearchResult].fail(error_msg)
        ldap_scope = scope_result.unwrap()

        # Use provided attributes (None means all attributes)
        # When None, pass empty list to ldap3 which means "all attributes"
        search_attributes: list[str] = (
            search_options.attributes if search_options.attributes is not None else []
        )

        entries_result = self._execute_search(
            connection,
            search_options.base_dn,
            search_options.filter_str,
            ldap_scope,
            search_attributes,
            search_options.size_limit,
            search_options.time_limit,
            server_type,
        )

        # Convert list result to SearchResult
        if entries_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(entries_result.error) if entries_result.error else "Unknown error",
            )

        entries = entries_result.unwrap()

        search_result = FlextLdapModels.SearchResult(
            entries=entries,
            search_options=search_options,
        )

        self.logger.debug(
            "Search completed",
            operation="search",
            base_dn=search_options.base_dn[:100] if search_options.base_dn else None,
            entries_found=len(entries),
            scope=search_options.scope,
        )

        return FlextResult[FlextLdapModels.SearchResult].ok(search_result)

    def _execute_search(
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
        """Execute LDAP search and convert results.

        Args:
            connection: LDAP connection
            base_dn: Base DN for search
            filter_str: LDAP filter string
            ldap_scope: LDAP scope constant
            search_attributes: Attributes to retrieve
            size_limit: Maximum number of entries
            time_limit: Maximum time in seconds
            server_type: LDAP server type for parsing

        Returns:
            FlextResult containing list of Entry models

        """
        try:
            connection.search(
                search_base=base_dn,
                search_filter=filter_str,
                search_scope=ldap_scope,
                attributes=search_attributes,
                size_limit=size_limit,
                time_limit=time_limit,
            )

            # Check result code (not search return which is False for empty results)
            # Success codes per RFC 4511: 0=success, 3/4/11=partial success
            result_code = connection.result.get("result", -1)
            partial_success_codes = {0, 3, 4, 11}
            is_success = result_code in partial_success_codes

            if not is_success:
                error_msg = connection.result.get("message", "LDAP search failed")
                error_desc = connection.result.get("description", "unknown")
                self.logger.error(
                    "LDAP search failed",
                    operation="search",
                    base_dn=base_dn[:100] if base_dn else None,
                    filter_str=filter_str[:100] if filter_str else None,
                    result_code=result_code,
                    error=f"{error_desc} - {error_msg}",
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"LDAP search failed: {error_desc} - {error_msg}",
                )

            # Convert ldap3 results to parser format
            ldap3_results = self._convert_ldap3_results(connection)

            # Parse results using FlextLdif
            parse_result = self._parser.parse_ldap3_results(ldap3_results, server_type)
            if parse_result.is_failure:
                self.logger.error(
                    "Failed to parse LDAP results",
                    operation="search",
                    base_dn=base_dn[:100] if base_dn else None,
                    server_type=server_type,
                    error=str(parse_result.error),
                    error_type=type(parse_result.error).__name__
                    if parse_result.error
                    else "Unknown",
                    entries_count=len(ldap3_results),
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    str(parse_result.error) if parse_result.error else "Unknown error",
                )

            parse_response = parse_result.unwrap()

            # Convert parsed entries to Entry models
            entries_result = self._convert_parsed_entries(parse_response)

            if entries_result.is_failure:
                self.logger.error(
                    "Failed to convert parsed entries",
                    operation="search",
                    base_dn=base_dn[:100] if base_dn else None,
                    error=str(entries_result.error),
                    error_type=type(entries_result.error).__name__
                    if entries_result.error
                    else "Unknown",
                    parsed_count=len(parse_response.entries),
                )

            return entries_result

        except Exception as e:
            _ = self.logger.exception(
                "LDAP search failed",
                operation="search",
                base_dn=base_dn,
                filter_str=filter_str[:100] if filter_str else None,
                server_type=server_type,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Search failed: {e!s}",
            )

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry using Entry model.

        Reuses FlextLdifModels.Entry for type safety and consistency.

        Args:
            entry: Entry model to add (reusing FlextLdifModels.Entry)

        Returns:
            FlextResult[OperationResult] - ok(result) on success, fail(error) on failure

        """
        entry_dn_str = str(entry.dn) if entry.dn else "unknown"
        self.logger.debug(
            "Adding LDAP entry",
            operation="add",
            entry_dn=entry_dn_str[:100] if entry_dn_str else None,
        )

        connection_result = self._get_connection()
        if connection_result.is_failure:
            self.logger.error(
                "Add failed: not connected",
                operation="add",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                error=str(connection_result.error)
                if connection_result.error
                else "Unknown error",
            )
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error)
                if connection_result.error
                else "Unknown error",
            )

        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.is_failure:
            self.logger.error(
                "Add failed: attribute conversion failed",
                operation="add",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                error=str(attrs_result.error),
            )
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Failed to convert entry attributes: {attrs_result.error}",
            )

        ldap_attrs = attrs_result.unwrap()
        result = self._execute_add(
            connection_result.unwrap(),
            entry_dn_str,
            ldap_attrs,
        )

        if result.is_success:
            self.logger.info(
                "LDAP entry added",
                operation="add",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
            )
        else:
            self.logger.error(
                "LDAP add failed",
                operation="add",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                error=str(result.error),
            )

        return result

    def _execute_add(
        self,
        connection: Connection,
        dn_str: str,
        ldap_attrs: dict[str, list[str]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Execute LDAP add operation.

        Args:
            connection: LDAP connection
            dn_str: Distinguished name
            ldap_attrs: Attributes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        try:
            # Connection.add(dn, object_class=None, attributes=None, controls=None)
            # Use cast to inform type checker while maintaining runtime safety
            add_func = cast(
                "FlextLdapTypes.LdapAddCallable",
                connection.add,
            )
            success = add_func(dn_str, None, ldap_attrs)

            if success:
                return FlextResult[FlextLdapModels.OperationResult].ok(
                    FlextLdapModels.OperationResult(
                        success=True,
                        operation_type="add",
                        message="Entry added successfully",
                        entries_affected=1,
                    ),
                )

            result_dict = connection.result
            error_msg = "Add failed: LDAP operation returned failure status"
            if FlextRuntime.is_dict_like(result_dict) and "description" in result_dict:
                # Type narrowing: is_dict_like ensures dict[str, object]
                error_msg = f"Add failed: {result_dict['description']}"

            self.logger.error(
                "LDAP add operation failed",
                operation="add",
                entry_dn=dn_str[:100] if dn_str else None,
                error=error_msg[:200],
            )

            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        except Exception as e:
            self.logger.exception(
                "LDAP add exception",
                operation="add",
                entry_dn=dn_str[:100] if dn_str else None,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Add failed: {e!s}",
            )

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
                (string or DistinguishedName model)
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult[OperationResult] - ok(result) on success, fail(error) on failure

        """
        dn_str = FlextLdif.utilities.DN.get_dn_value(dn) if dn else "unknown"
        self.logger.debug(
            "Modifying LDAP entry",
            operation="modify",
            entry_dn=dn_str[:100] if dn_str else None,
            changes_count=len(changes),
        )

        connection_result = self._get_connection()
        if connection_result.is_failure:
            self.logger.error(
                "Modify failed: not connected",
                operation="modify",
                entry_dn=dn_str[:100] if dn_str else None,
                error=str(connection_result.error)
                if connection_result.error
                else "Unknown error",
            )
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error)
                if connection_result.error
                else "Unknown error",
            )

        result = self._execute_modify(connection_result.unwrap(), dn, changes)

        if result.is_success:
            self.logger.info(
                "LDAP entry modified",
                operation="modify",
                entry_dn=dn_str[:100] if dn_str else None,
            )
        else:
            self.logger.error(
                "LDAP modify failed",
                operation="modify",
                entry_dn=dn_str[:100] if dn_str else None,
                error=str(result.error),
            )

        return result

    def _execute_modify(
        self,
        connection: Connection,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Execute modify operation.

        Args:
            connection: Active LDAP connection
            dn: Distinguished name (string or DistinguishedName model)
            changes: Modification changes

        Returns:
            FlextResult containing OperationResult

        """
        try:
            dn_str = FlextLdif.utilities.DN.get_dn_value(dn)

            # Connection.modify(dn, changes, controls=None)
            # Use cast to inform type checker while maintaining runtime safety
            modify_func = cast(
                "FlextLdapTypes.LdapModifyCallable",
                connection.modify,
            )
            success = modify_func(dn_str, changes)

            if success:
                result = FlextLdapModels.OperationResult(
                    success=True,
                    operation_type="modify",
                    message="Entry modified successfully",
                    entries_affected=1,
                )
                return FlextResult[FlextLdapModels.OperationResult].ok(result)

            result_dict = connection.result
            error_msg = "Modify failed: LDAP operation returned failure status"
            if FlextRuntime.is_dict_like(result_dict) and "description" in result_dict:
                # Type narrowing: is_dict_like ensures dict[str, object]
                error_msg = f"Modify failed: {result_dict['description']}"

            self.logger.error(
                "LDAP modify operation failed",
                operation="modify",
                entry_dn=dn_str[:100] if dn_str else None,
                error=error_msg[:200],
            )

            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        except Exception as e:
            entry_dn_val = FlextLdif.utilities.DN.get_dn_value(dn) if dn else "unknown"
            self.logger.exception(
                "LDAP modify exception",
                entry_dn=entry_dn_val[:100],
                error=str(e),
            )
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Modify failed: {e!s}",
            )

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        **_kwargs: object,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete
                (string or DistinguishedName model)

        Returns:
            FlextResult[OperationResult] - ok(result) on success, fail(error) on failure

        """
        dn_str = FlextLdif.utilities.DN.get_dn_value(dn) if dn else "unknown"
        self.logger.debug(
            "Deleting LDAP entry",
            operation="delete",
            entry_dn=dn_str[:100] if dn_str else None,
        )

        connection_result = self._get_connection()
        if connection_result.is_failure:
            self.logger.error(
                "Delete failed: not connected",
                operation="delete",
                entry_dn=dn_str[:100] if dn_str else None,
                error=str(connection_result.error)
                if connection_result.error
                else "Unknown error",
            )
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error)
                if connection_result.error
                else "Unknown error",
            )

        result = self._execute_delete(connection_result.unwrap(), dn)

        if result.is_success:
            self.logger.info(
                "LDAP entry deleted",
                operation="delete",
                entry_dn=dn_str[:100] if dn_str else None,
            )
        else:
            self.logger.error(
                "LDAP delete failed",
                operation="delete",
                entry_dn=dn_str[:100] if dn_str else None,
                error=str(result.error),
            )

        return result

    def _execute_delete(
        self,
        connection: Connection,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Execute delete operation.

        Args:
            connection: Active LDAP connection
            dn: Distinguished name (string or DistinguishedName model)

        Returns:
            FlextResult containing OperationResult

        """
        try:
            dn_str = FlextLdif.utilities.DN.get_dn_value(dn)

            # Connection.delete(dn, controls=None)
            # Use cast to inform type checker while maintaining runtime safety
            delete_func = cast("FlextLdapTypes.LdapDeleteCallable", connection.delete)
            success = delete_func(dn_str)

            if success:
                result = FlextLdapModels.OperationResult(
                    success=True,
                    operation_type="delete",
                    message="Entry deleted successfully",
                    entries_affected=1,
                )
                return FlextResult[FlextLdapModels.OperationResult].ok(result)

            result_dict = connection.result
            error_msg = "Delete failed: LDAP operation returned failure status"
            if FlextRuntime.is_dict_like(result_dict) and "description" in result_dict:
                # Type narrowing: is_dict_like ensures dict[str, object]
                error_msg = f"Delete failed: {result_dict['description']}"

            self.logger.error(
                "LDAP delete operation failed",
                operation="delete",
                entry_dn=dn_str[:100] if dn_str else None,
                error=error_msg[:200],
            )

            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        except Exception as e:
            entry_dn_val = FlextLdif.utilities.DN.get_dn_value(dn) if dn else "unknown"
            self.logger.exception(
                "LDAP delete exception",
                entry_dn=entry_dn_val[:100],
                error=str(e),
            )
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Delete failed: {e!s}",
            )

    def execute(self, **_kwargs: object) -> FlextResult[bool]:
        """Execute service health check.

        Args:
            **_kwargs: Unused - health check requires no configuration

        Returns:
            FlextResult[bool] - ok(True) if connected, fail(error) otherwise

        """
        if not self.is_connected:
            return FlextResult[bool].fail("Not connected to LDAP server")
        return FlextResult[bool].ok(data=True)
