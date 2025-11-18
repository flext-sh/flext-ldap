"""LDAP3 adapter service - Service wrapper for ldap3 library.

This module provides a service adapter around ldap3 following flext-ldif patterns.
Reuses FlextLdifParser for parsing LDAP results to Entry models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif import FlextLdifModels, FlextLdifParser
from ldap3 import Connection, Server

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

Ldap3Scope = FlextLdapConstants.LiteralTypes.Ldap3Scope

logger = FlextLogger(__name__)


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
    ) -> None:
        """Initialize adapter service with parser.

        Args:
            parser: FlextLdifParser instance (optional, creates default if not provided)

        """
        super().__init__()
        self._connection = None
        self._server = None
        self._parser = parser or FlextLdifParser()
        self._entry_adapter = FlextLdapEntryAdapter()

    def connect(
        self,
        config: FlextLdapModels.ConnectionConfig,
    ) -> FlextResult[bool]:
        """Establish LDAP connection using ldap3.

        Args:
            config: Connection configuration

        Returns:
            FlextResult[bool] - ok(True) on success, fail(error) on failure

        """
        try:
            # Create server object with explicit parameters
            # STARTTLS is handled by Connection.start_tls(), not Server
            if config.use_ssl:
                self._server = Server(
                    host=config.host,
                    port=config.port,
                    use_ssl=True,
                    connect_timeout=config.timeout,  # Timeout for TCP connection
                )
            else:
                self._server = Server(
                    host=config.host,
                    port=config.port,
                    connect_timeout=config.timeout,  # Timeout for TCP connection
                )

            # Create connection with explicit parameters
            # ldap3 Connection accepts None for user/password (anonymous bind)
            self._connection = Connection(
                server=self._server,
                user=config.bind_dn,
                password=config.bind_password,
                auto_bind=config.auto_bind,
                auto_range=config.auto_range,
                receive_timeout=config.timeout,
            )

            # Handle STARTTLS if requested (after connection creation)
            if (
                config.use_tls
                and not config.use_ssl
                and not self._connection.start_tls()
            ):
                return FlextResult[bool].fail("Failed to start TLS")

            if not self._connection.bound:
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            _ = logger.info(
                "Connected to LDAP server",
                host=config.host,
                port=config.port,
                use_ssl=config.use_ssl,
            )
            return FlextResult[bool].ok(True)

        except Exception as e:
            _ = logger.exception(
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
                self._connection.unbind()
            except Exception as e:
                _ = logger.debug(
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

        """
        # Fast fail if not connected
        if not self.is_connected:
            return FlextResult[Connection].fail("Not connected to LDAP server")

        # Type narrowing: connection is guaranteed non-None after is_connected check
        # is_connected property returns: self._connection is not None and self._connection.bound
        # Therefore, if is_connected is True, _connection is definitely not None
        # However, type checker cannot infer this, so we need to assert it
        if self._connection is None:
            # Defensive check for race conditions (theoretically unreachable but defensive)
            return FlextResult[Connection].fail(
                "Connection is None despite is_connected=True",
            )
        connection: Connection = self._connection
        return FlextResult[Connection].ok(connection)

    def _map_scope(self, scope: str) -> FlextResult[Ldap3Scope]:
        """Map scope string to ldap3 scope constant.

        Args:
            scope: Scope string (BASE, ONELEVEL, SUBTREE)

        Returns:
            FlextResult containing ldap3 scope constant or error

        """
        scope_upper = scope.upper()
        # Map FlextLdap scopes to ldap3 scopes using Constants
        # Use literal string values for type compatibility
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
        return FlextResult[Ldap3Scope].fail(error_msg)

    def _convert_ldap3_results(
        self,
        connection: Connection,
    ) -> list[tuple[str, dict[str, list[str]]]]:
        """Convert ldap3 connection entries to parser format.

        Args:
            connection: ldap3 Connection with search results

        Returns:
            List of tuples (dn, attributes_dict)

        """
        ldap3_results: list[tuple[str, dict[str, list[str]]]] = []
        for entry in connection.entries:
            entry_attrs: dict[str, list[str]] = {}
            for attr in entry.entry_attributes:
                attr_values = entry[attr].values
                entry_attrs[attr] = (
                    list(attr_values)
                    if isinstance(attr_values, (list, tuple))
                    else [str(attr_values)]
                )
            ldap3_results.append((str(entry.entry_dn), entry_attrs))
        return ldap3_results

    def _convert_parsed_entries(
        self,
        parse_response: FlextLdifModels.ParseResponse,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Convert parsed entries to properly typed Entry list.

        Args:
            parse_response: ParseResponse from FlextLdifParser

        Returns:
            FlextResult containing list of Entry models or error

        """
        # Monadic pattern - validate and convert entries
        entries_list: list[FlextLdifModels.Entry] = []
        for parsed_entry in parse_response.entries:
            # Fast fail - validate entry structure (separate checks, no or)
            if not hasattr(parsed_entry, "dn"):
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "Invalid entry structure from parser: missing dn",
                )
            if not hasattr(parsed_entry, "attributes"):
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "Invalid entry structure from parser: missing attributes",
                )
            # Use proper type conversion
            dn_obj = (
                parsed_entry.dn
                if isinstance(parsed_entry.dn, FlextLdifModels.DistinguishedName)
                else FlextLdifModels.DistinguishedName(value=str(parsed_entry.dn))
            )
            entry_obj = FlextLdifModels.Entry(
                dn=dn_obj,
                attributes=parsed_entry.attributes,
            )
            entries_list.append(entry_obj)
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries_list)

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Perform LDAP search operation and convert to Entry models.

        Uses FlextLdifParser.parse_ldap3_results() to automatically convert
        LDAP results to Entry models, reusing flext-ldif parsing logic.

        Args:
            search_options: Search configuration (required)
            server_type: LDAP server type for parsing (default: RFC constant)

        Returns:
            FlextResult containing list of Entry models (reusing FlextLdifModels.Entry)

        """
        # Validate connection first
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                connection_result.error,
            )
        connection = connection_result.unwrap()

        # Map scope next
        scope_result = self._map_scope(search_options.scope)
        if scope_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(scope_result.error)
        ldap_scope = scope_result.unwrap()

        # Use provided attributes (None means all attributes)
        # When None, pass empty list to ldap3 which means "all attributes"
        search_attributes: list[str] = (
            search_options.attributes if search_options.attributes is not None else []
        )
        return self._execute_search(
            connection,
            search_options.base_dn,
            search_options.filter_str,
            ldap_scope,
            search_attributes,
            search_options.size_limit,
            search_options.time_limit,
            server_type,
        )

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
            _ = connection.search(
                search_base=base_dn,
                search_filter=filter_str,
                search_scope=ldap_scope,
                attributes=search_attributes,
                size_limit=size_limit,
                time_limit=time_limit,
            )

            # Check if search operation failed
            # result_code == 0 means success, even if no entries found
            # Empty results are valid (no entries match filter)
            # CORRECT: Check result code, not search_success (which is False for empty results)
            # Partial success codes (3, 4, 11) return partial results - NOT errors
            result_code = connection.result.get("result", -1)
            # Success codes per LDAP spec (RFC 4511):
            # 0 = success
            # 3 = timeLimitExceeded (partial success - returns partial results)
            # 4 = sizeLimitExceeded (partial success - returns partial results)
            # 11 = REDACTED_LDAP_BIND_PASSWORDLimitExceeded (partial success - returns partial results)
            partial_success_codes = {0, 3, 4, 11}
            if result_code not in partial_success_codes:
                error_msg = connection.result.get("message", "LDAP search failed")
                error_desc = connection.result.get("description", "unknown")
                _ = logger.warning(
                    "LDAP search failed",
                    base_dn=base_dn,
                    error_description=error_desc,
                    error_message=error_msg,
                    result_code=result_code,
                    server_type=server_type,
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"LDAP search failed: {error_desc} - {error_msg}",
                )

            ldap3_results = self._convert_ldap3_results(connection)
            # Parse results using FlextLdif
            parse_result = self._parser.parse_ldap3_results(ldap3_results, server_type)
            if parse_result.is_failure:
                _ = logger.warning(
                    "Failed to parse LDAP results",
                    error=str(parse_result.error),
                    error_type=type(parse_result.error).__name__,
                    results_count=len(ldap3_results)
                    if isinstance(ldap3_results, list)
                    else 0,
                    server_type=server_type,
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(parse_result.error)
            # Convert parsed entries to Entry models
            return self._convert_parsed_entries(parse_result.unwrap())

        except Exception as e:
            _ = logger.exception(
                "LDAP search failed",
                base_dn=base_dn,
                filter_str=filter_str,
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
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry using Entry model.

        Reuses FlextLdifModels.Entry for type safety and consistency.

        Args:
            entry: Entry model to add (reusing FlextLdifModels.Entry)

        Returns:
            FlextResult[OperationResult] - ok(result) on success, fail(error) on failure

        """
        # Monadic pattern - chain connection, attribute conversion, and add operation
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                connection_result.error,
            )

        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Failed to convert entry attributes: {attrs_result.error}",
            )

        return self._execute_add(
            connection_result.unwrap(),
            str(entry.dn),
            attrs_result.unwrap(),
        )

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
            success = connection.add(dn_str, attributes=ldap_attrs)
            if success:
                return FlextResult[FlextLdapModels.OperationResult].ok(
                    FlextLdapModels.OperationResult(
                        success=True,
                        operation_type="add",  # Use literal string value
                        message="Entry added successfully",
                        entries_affected=1,
                    ),
                )

            result_dict = connection.result
            error_msg = "Add failed: LDAP operation returned failure status"
            if isinstance(result_dict, dict) and "description" in result_dict:
                error_msg = f"Add failed: {result_dict['description']}"
            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        except Exception as e:
            _ = logger.exception(
                "LDAP add failed",
                entry_dn=dn_str,
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
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
                (string or DistinguishedName model)
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult[OperationResult] - ok(result) on success, fail(error) on failure

        """
        # Get connection and execute modify
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                connection_result.error,
            )
        return self._execute_modify(connection_result.unwrap(), dn, changes)

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
            # Extract DN string from DistinguishedName model or use string directly
            dn_str = (
                dn.value
                if isinstance(dn, FlextLdifModels.DistinguishedName)
                else str(dn)
            )

            success = connection.modify(dn_str, changes)
            if success:
                result = FlextLdapModels.OperationResult(
                    success=True,
                    operation_type="modify",  # Use literal string value
                    message="Entry modified successfully",
                    entries_affected=1,
                )
                return FlextResult[FlextLdapModels.OperationResult].ok(result)

            result_dict = connection.result
            error_msg = "Modify failed: LDAP operation returned failure status"
            if isinstance(result_dict, dict) and "description" in result_dict:
                error_msg = f"Modify failed: {result_dict['description']}"
            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        except Exception as e:
            _ = logger.exception(
                "LDAP modify failed",
                entry_dn=dn_str,
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Modify failed: {e!s}",
            )

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete
                (string or DistinguishedName model)

        Returns:
            FlextResult[OperationResult] - ok(result) on success, fail(error) on failure

        """
        # Get connection and execute delete
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                connection_result.error,
            )
        return self._execute_delete(connection_result.unwrap(), dn)

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
            # Extract DN string from DistinguishedName model or use string directly
            dn_str = (
                dn.value
                if isinstance(dn, FlextLdifModels.DistinguishedName)
                else str(dn)
            )

            success = connection.delete(dn_str)
            if success:
                result = FlextLdapModels.OperationResult(
                    success=True,
                    operation_type="delete",  # Use literal string value
                    message="Entry deleted successfully",
                    entries_affected=1,
                )
                return FlextResult[FlextLdapModels.OperationResult].ok(result)

            result_dict = connection.result
            error_msg = "Delete failed: LDAP operation returned failure status"
            if isinstance(result_dict, dict) and "description" in result_dict:
                error_msg = f"Delete failed: {result_dict['description']}"
            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        except Exception as e:
            _ = logger.exception(
                "LDAP delete failed",
                entry_dn=dn_str,
                error=str(e),
                error_type=type(e).__name__,
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
        return FlextResult[bool].ok(True)
