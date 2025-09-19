"""LDAP client implementation for flext-ldap.

This module provides the core LDAP client functionality using ldap3
with Clean Architecture patterns and flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import contextlib
import ssl
from collections.abc import Mapping
from typing import cast
from urllib.parse import urlparse

import ldap3
from ldap3 import ALL_ATTRIBUTES, SUBTREE
from ldap3.core.exceptions import LDAPException

from flext_core import FlextMixins, FlextProtocols, FlextResult, FlextTypes
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.typings import FlextLdapTypes

# LDAPSearchStrategies ELIMINATED - consolidated into FlextLdapClient nested classes
# Following flext-core consolidation pattern: ALL functionality within single class


class FlextLdapClient(
    FlextMixins.Service,
    FlextMixins.Loggable,
    FlextProtocols.Infrastructure.Connection,
):
    """Unified LDAP client consolidating all LDAP functionality in single class.

    This class follows SOLID principles and provides a unified interface for
    LDAP operations including connection management, search operations, and
    CRUD operations. It uses the ldap3 library directly without wrappers.

    Attributes:
        _connection: Active LDAP connection instance.
        _server: LDAP server configuration instance.

    """

    # =========================================================================
    # NESTED STRATEGY CLASSES - Following single class pattern with nesting
    # =========================================================================

    class SearchExecutionStrategy:
        """LDAP search execution strategy nested within unified client.

        This strategy handles the execution of LDAP search operations
        using the provided connection instance.

        Args:
            connection: LDAP connection instance for search operations.

        """

        def __init__(self, connection: FlextLdapProtocols.LdapProtocol | None) -> None:
            """Initialize search strategy with LDAP connection.

            Args:
                connection: LDAP connection instance for search operations.

            """
            self.connection = connection

        def execute_search(
            self,
            request: FlextLdapModels.SearchRequest,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Execute LDAP search using ldap3 connection.

            Args:
                request: Search request containing base DN, filter, and parameters.

            Returns:
                FlextResult containing search execution status and connection data.

            """
            if not self.connection or not getattr(self.connection, "bound", False):
                return FlextResult[FlextTypes.Core.Dict].fail(
                    "Not connected to LDAP server",
                )

            try:
                # Map scope to ldap3 constant
                scope = FlextLdapConstants.Scopes.SCOPE_MAP.get(
                    request.scope.lower(), SUBTREE
                )

                # Execute search using ldap3 directly
                connection_obj = self.connection
                # Ensure attributes is correct type for protocol
                search_attributes: list[str] | str | None
                if request.attributes is not None:
                    search_attributes = request.attributes
                else:
                    search_attributes = cast("str", ALL_ATTRIBUTES)
                success: bool = connection_obj.search(
                    search_base=request.base_dn,
                    search_filter=request.filter_str,
                    search_scope=scope,
                    attributes=search_attributes,
                    size_limit=request.size_limit,
                    time_limit=request.time_limit,
                )

                if not success:
                    error_message = str(
                        connection_obj.result.get("message", "Search failed"),
                    )
                    return FlextResult[FlextTypes.Core.Dict].fail(
                        f"Search failed: {error_message}",
                    )

                return FlextResult[FlextTypes.Core.Dict].ok(
                    {"success": True, "connection": connection_obj},
                )

            except LDAPException as e:
                return FlextResult[FlextTypes.Core.Dict].fail(
                    f"LDAP search failed: {e}",
                )
            except Exception as e:
                return FlextResult[FlextTypes.Core.Dict].fail(f"Search error: {e}")

    class EntryConversionStrategy:
        """LDAP entry conversion strategy nested within unified client.

        This strategy handles the conversion of ldap3 entries to structured
        format suitable for the application layer.
        """

        def convert_entries(
            self,
            connection: FlextLdapProtocols.LdapProtocol,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Convert ldap3 entries to structured format.

            Args:
                connection: LDAP connection with search results.

            Returns:
                FlextResult containing converted entries in structured format.

            """
            try:
                entries: list[FlextTypes.Core.Dict] = []
                connection_entries = connection.entries if connection else []

                for entry in connection_entries:
                    # Get DN directly from ldap3 entry
                    entry_dn = str(entry.entry_dn) if hasattr(entry, "entry_dn") else ""
                    entry_data: FlextTypes.Core.Dict = {"dn": entry_dn}

                    # Process attributes using strategy pattern
                    if hasattr(entry, "entry_attributes") and entry.entry_attributes:
                        if isinstance(entry.entry_attributes, dict):
                            # Handle dict format (attribute names as keys)
                            entry_attrs_dict = entry.entry_attributes
                            entry_attributes = list(entry_attrs_dict.keys())
                            for attr_name in entry_attributes:
                                attr_values = cast(
                                    "list[object]",
                                    entry_attrs_dict.get(attr_name, []),
                                )
                                if len(attr_values) == 1:
                                    entry_data[attr_name] = attr_values[0]
                                elif attr_values:  # Only add non-empty lists
                                    entry_data[attr_name] = attr_values
                        elif isinstance(entry.entry_attributes, list):
                            # Handle list format (attribute names as list items)
                            # Access attributes directly from entry object
                            for attr_name in entry.entry_attributes:
                                if hasattr(entry, attr_name):
                                    attr_value = getattr(entry, attr_name)
                                    if attr_value is not None:
                                        if (
                                            isinstance(attr_value, list)
                                            and len(attr_value) == 1
                                        ):
                                            entry_data[attr_name] = attr_value[0]
                                        elif (
                                            isinstance(attr_value, list) and attr_value
                                        ):
                                            entry_data[attr_name] = attr_value
                                        else:
                                            entry_data[attr_name] = attr_value
                    entries.append(entry_data)

                return FlextResult[FlextTypes.Core.Dict].ok({"entries": entries})

            except Exception as e:
                return FlextResult[FlextTypes.Core.Dict].fail(
                    f"Entry conversion error: {e}",
                )

    class ResponseBuilderStrategy:
        """Search response builder strategy nested within unified client.

        This strategy handles the construction of search responses from
        converted entries and request data.
        """

        def build_response(
            self,
            data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLdapModels.SearchResponse]:
            """Build search response from entries and request data.

            Args:
                data: Dictionary containing entries and request information.

            Returns:
                FlextResult containing structured search response.

            """
            try:
                entries = cast("list[dict[str, object]]", data.get("entries", []))
                request = cast("FlextLdapModels.SearchRequest", data.get("request"))

                response = FlextLdapModels.SearchResponse(
                    entries=entries,
                    total_count=len(entries),
                    has_more=len(entries) >= request.size_limit,
                )

                return FlextResult.ok(response)

            except Exception as e:
                return FlextResult.fail(
                    f"Response building error: {e}",
                )

    def __init__(self) -> None:
        """Initialize LDAP client with flext-core logging capabilities.

        Sets up the client with logging capabilities from FlextMixins.Service
        and initializes connection and server attributes to None.
        """
        # Initialize FlextMixins.Service for logging capabilities
        super().__init__()
        self._connection: FlextLdapProtocols.LdapProtocol | None = None
        self._server: ldap3.Server | None = None

    # =========================================================================
    # CONNECTION OPERATIONS - Consolidated connection management
    # =========================================================================

    async def connect(self, uri: str, bind_dn: str, password: str) -> FlextResult[None]:
        """Connect to LDAP server.

        Establishes connection to LDAP server using provided URI and credentials.
        Supports both LDAP and LDAPS protocols with SSL/TLS configuration.

        Args:
            uri: LDAP server URI (ldap:// or ldaps://).
            bind_dn: Distinguished name for authentication.
            password: Password for authentication.

        Returns:
            FlextResult[None]: Success or error result.

        """
        try:
            # Parse URI to get connection details
            parsed = urlparse(uri)
            use_ssl = parsed.scheme == "ldaps"
            host = (
                parsed.hostname
                or FlextLdapConstants.LDAP.DEFAULT_SERVER_URI.split("://")[1]
            )
            port = parsed.port or (
                FlextLdapConstants.LDAP.DEFAULT_SSL_PORT
                if use_ssl
                else FlextLdapConstants.LDAP.DEFAULT_PORT
            )

            # Create server
            self._server = ldap3.Server(
                host=host,
                port=port,
                use_ssl=use_ssl,
                get_info=ldap3.ALL,
                tls=ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None,
            )

            # Create connection and cast to Protocol for type safety
            connection = ldap3.Connection(
                self._server,
                user=bind_dn,
                password=password,
                auto_bind=True,
                raise_exceptions=True,
            )
            self._connection = cast("FlextLdapProtocols.LdapProtocol", connection)

            if not self._connection.bound:
                return FlextResult.fail("Failed to bind to LDAP server")

            self.log_info(
                "Connected to LDAP server",
                uri=uri,
                bind_dn=bind_dn,
            )
            return FlextResult.ok(None)

        except LDAPException as e:
            self.log_error(
                "LDAP connection failed",
                error=str(e),
                uri=uri,
            )
            return FlextResult.fail(f"LDAP connection failed: {e}")
        except Exception as e:
            self.log_error(
                "Unexpected connection error",
                error=str(e),
                uri=uri,
            )
            return FlextResult.fail(f"Connection error: {e}")

    async def bind(self, bind_dn: str, password: str) -> FlextResult[None]:
        """Bind with different credentials.

        Re-authenticates with the LDAP server using new credentials while
        maintaining the existing connection.

        Args:
            bind_dn: Distinguished name for authentication.
            password: Password for authentication.

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection:
            return FlextResult.fail("No connection established")

        try:
            # Use ldap3 directly - no wrapper needed
            self._connection.rebind(bind_dn, password)
            success = self._connection.result.get("description") == "success"
            if not success:
                error_message = str(
                    self._connection.result.get("message", "Authentication failed"),
                )
                return FlextResult.fail(f"Bind failed: {error_message}")

            self.log_info("Bind successful", dn=bind_dn)
            return FlextResult.ok(None)

        except LDAPException as e:
            self.log_error("LDAP bind failed", error=str(e), dn=bind_dn)
            return FlextResult.fail(f"Bind failed: {e}")
        except Exception as e:
            self.log_error("Unexpected bind error", error=str(e), dn=bind_dn)
            return FlextResult.fail(f"Bind error: {e}")

    async def unbind(self) -> FlextResult[None]:
        """Unbind from server and cleanup connections.

        Closes the LDAP connection and cleans up associated resources.
        Safe to call multiple times - returns success if already unbound.

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection:
            return FlextResult.ok(None)  # Already unbound

        try:
            # Direct method call - ldap3 Connection has unbind method (returns bool)
            self._connection.unbind()
            self._connection = None
            self._server = None

            self.log_info("Unbound from LDAP server")
            return FlextResult.ok(None)

        except LDAPException as e:
            self.log_error("LDAP unbind failed", error=str(e))
            return FlextResult.fail(f"Unbind failed: {e}")
        except Exception as e:
            self.log_error("Unexpected unbind error", error=str(e))
            return FlextResult.fail(f"Unbind error: {e}")

    def is_connected(self) -> bool:
        """Check if connected and bound to LDAP server.

        Implements the protocol method required by FlextProtocols.Infrastructure.Connection.
        Verifies both connection existence and binding status.

        Returns:
            bool: True when a bound connection exists, False otherwise.

        """
        return self._connection is not None and self._connection.bound

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self,
        base_dn: str,
        search_filter: str,
        scope: str = "subtree",
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Perform LDAP search following flext-core protocol signature.

        Executes a basic LDAP search operation with simplified parameters.
        This method follows the flext-core LdapConnection protocol interface.
        For advanced search operations with more control, use search_with_request().

        Args:
            base_dn: Base distinguished name for search.
            search_filter: LDAP search filter expression.
            scope: Search scope (base, one, subtree). Defaults to subtree.

        Returns:
            FlextResult containing search response with entries.

        """
        # Create SearchRequest from basic parameters
        request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            scope=scope,
            attributes=None,  # Default value
            size_limit=FlextLdapConstants.Connection.MAX_SIZE_LIMIT,  # Use constant
            time_limit=FlextLdapConstants.LDAP.DEFAULT_TIMEOUT,  # Use constant
        )
        # Delegate to the advanced method
        return await self.search_with_request(request)

    async def search_with_request(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Perform LDAP search with strategy pattern.

        Executes LDAP search using the strategy pattern with three phases:
        1. Search execution using ldap3 connection
        2. Entry conversion to structured format
        3. Response building with metadata

        Args:
            request: Complete search request with all parameters.

        Returns:
            FlextResult containing structured search response with entries.

        """
        try:
            # Strategy 1: Execute LDAP search
            search_strategy = self.SearchExecutionStrategy(
                self._connection,
            )
            execution_result = search_strategy.execute_search(request)

            if not execution_result.is_success:
                return FlextResult.fail(
                    execution_result.error or "Search execution failed",
                )

            # Strategy 2: Convert entries to structured format
            if self._connection is None:
                return FlextResult.fail(
                    "No active connection available",
                )

            conversion_strategy = self.EntryConversionStrategy()
            entries_result = conversion_strategy.convert_entries(self._connection)

            if not entries_result.is_success:
                return FlextResult.fail(
                    entries_result.error or "Entry conversion failed",
                )

            # Strategy 3: Build final response
            response_strategy = self.ResponseBuilderStrategy()
            response_data = {
                "entries": entries_result.value.get("entries", []),
                "request": request,
            }
            response_result = response_strategy.build_response(response_data)

            if not response_result.is_success:
                return FlextResult.fail(
                    response_result.error or "Response building failed",
                )

            # Log success with structured data
            self.log_info(
                "Search completed using Strategy Pattern",
                base_dn=request.base_dn,
                filter=request.filter_str,
                count=len(
                    cast("list[object]", entries_result.value.get("entries", [])),
                ),
            )

            return response_result

        except Exception as e:
            self.log_error(
                "Unexpected search strategy error",
                extra={"error": str(e)},
            )
            return FlextResult.fail(
                f"Search strategy error: {e}",
            )

    # =========================================================================
    # CRUD OPERATIONS - Consolidated Create, Update, Delete operations
    # =========================================================================

    async def add(self, dn: str, attributes: Mapping[str, object]) -> FlextResult[None]:
        """Add new entry to LDAP directory following flext-core protocol.

        Creates a new LDAP entry with the specified distinguished name and
        attributes. Follows the flext-core protocol interface for consistency.

        Args:
            dn: Distinguished name for the new entry.
            attributes: Dictionary of attributes to set on the entry.

        Returns:
            FlextResult[None]: Success or error result.

        """
        # Convert to FlextLdapTypes.Entry.AttributeDict and delegate to implementation
        ldap_attributes: FlextLdapTypes.Entry.AttributeDict = cast(
            "FlextLdapTypes.Entry.AttributeDict", dict(attributes)
        )
        return await self.add_entry(dn, ldap_attributes)

    async def add_entry(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Add new entry to LDAP directory.

        Internal implementation method that performs the actual LDAP add operation
        using the ldap3 library directly.

        Args:
            dn: Distinguished name for the new entry.
            attributes: Typed attribute dictionary for the entry.

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection or not self._connection.bound:
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Convert attributes to ldap3-compatible format
            ldap3_attributes: dict[str, object] = dict(attributes)
            # Direct method call - ldap3 Connection has add method (returns bool)
            success: bool = self._connection.add(dn, attributes=ldap3_attributes)
            if not success:
                return FlextResult.fail(f"Add failed: {self._connection.result}")

            self.log_info("Entry added", dn=dn)
            return FlextResult.ok(None)

        except LDAPException as e:
            self.log_error("LDAP add failed", error=str(e), dn=dn)
            return FlextResult.fail(f"Add failed: {e}")
        except Exception as e:
            self.log_error("Unexpected add error", error=str(e), dn=dn)
            return FlextResult.fail(f"Add error: {e}")

    async def modify(
        self,
        dn: str,
        modifications: FlextTypes.Core.Dict,
    ) -> FlextResult[None]:
        """Modify existing LDAP entry following flext-core protocol.

        Updates an existing LDAP entry with new attribute values.
        Follows the flext-core protocol interface for consistency.

        Args:
            dn: Distinguished name of the entry to modify.
            modifications: Dictionary of attribute modifications.

        Returns:
            FlextResult[None]: Success or error result.

        """
        # Convert to FlextLdapTypes.Entry.AttributeDict and delegate to implementation
        ldap_modifications: FlextLdapTypes.Entry.AttributeDict = cast(
            "FlextLdapTypes.Entry.AttributeDict",
            dict(modifications),
        )
        return await self.modify_entry(dn, ldap_modifications)

    async def modify_entry(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Modify existing LDAP entry.

        Internal implementation method that performs the actual LDAP modify operation
        using the ldap3 library directly with MODIFY_REPLACE operations.

        Args:
            dn: Distinguished name of the entry to modify.
            attributes: Typed attribute dictionary with new values.

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection or not self._connection.bound:
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Convert attributes to modification list
            changes: dict[str, list[tuple[object, object]]] = {}
            for attr_name, attr_value in attributes.items():
                changes[attr_name] = [(ldap3.MODIFY_REPLACE, attr_value)]

            # Convert changes to ldap3-compatible format
            ldap3_changes: dict[str, object] = dict(changes)
            # Direct method call - ldap3 Connection has modify method (returns bool)
            success: bool = self._connection.modify(dn, ldap3_changes)
            if not success:
                return FlextResult.fail(
                    f"Modify failed: {self._connection.result}",
                )

            self.log_info("Entry modified", dn=dn)
            return FlextResult.ok(None)

        except LDAPException as e:
            self.log_error("LDAP modify failed", error=str(e), dn=dn)
            return FlextResult.fail(f"Modify failed: {e}")
        except Exception as e:
            self.log_error(
                "Unexpected modify error",
                error=str(e),
                dn=dn,
            )
            return FlextResult.fail(f"Modify error: {e}")

    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry from LDAP directory.

        Removes an LDAP entry by its distinguished name.
        This operation is irreversible and should be used with caution.

        Args:
            dn: Distinguished name of the entry to delete.

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection or not self._connection.bound:
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Direct method call - ldap3 Connection has delete method (returns bool)
            success: bool = self._connection.delete(dn)
            if not success:
                return FlextResult.fail(
                    f"Delete failed: {self._connection.result}",
                )

            self.log_info("Entry deleted", dn=dn)
            return FlextResult.ok(None)

        except LDAPException as e:
            self.log_error("LDAP delete failed", error=str(e), dn=dn)
            return FlextResult.fail(f"Delete failed: {e}")
        except Exception as e:
            self.log_error(
                "Unexpected delete error",
                error=str(e),
                dn=dn,
            )
            return FlextResult.fail(f"Delete error: {e}")

    def __del__(self) -> None:
        """Cleanup on destruction.

        Ensures proper cleanup of LDAP connection when the client instance
        is garbage collected. Uses contextlib.suppress to handle any cleanup errors.
        """
        if self._connection and self._connection.bound:
            with contextlib.suppress(Exception):
                # Direct method call in cleanup context (returns bool)
                _: bool = self._connection.unbind()

    # =========================================================================
    # PROTOCOL METHODS - Required by FlextProtocols.Infrastructure.Connection
    # =========================================================================

    def __call__(self, *_args: object, **_kwargs: object) -> bool:
        """Callable interface for connection - protocol requirement.

        Implements the callable interface required by flext-core protocols.
        Returns the current connection status when the client is called.

        Returns:
            bool: True if connected and bound, False otherwise.

        """
        # Return connection status for callable interface
        return self.is_connected()

    def test_connection(self) -> FlextResult[str]:
        """Test connection to LDAP server - protocol requirement.

        Implements the protocol method required by flext-core connection protocols.
        Performs a basic connectivity test by checking the binding status.

        Returns:
            FlextResult[str]: Success message or error description.

        """
        if not self._connection:
            return FlextResult.fail("No connection established")

        try:
            # Test connection by performing a simple bind check
            if self._connection.bound:
                return FlextResult.ok("Connection test successful")
            return FlextResult.fail("Connection not bound")
        except Exception as e:
            return FlextResult.fail(f"Connection test failed: {e}")

    def get_connection_string(self) -> str:
        """Get connection string for LDAP server - protocol requirement.

        Implements the protocol method required by flext-core connection protocols.
        Returns a human-readable connection string for the current server configuration.

        Returns:
            str: Connection string in format scheme://host:port or error message.

        """
        if not self._server:
            return "No server configured"

        try:
            # Build connection string from server info using getattr for type safety
            scheme = "ldaps" if getattr(self._server, "use_ssl", False) else "ldap"
            host = getattr(
                self._server,
                "host",
                FlextLdapConstants.LDAP.DEFAULT_SERVER_URI.split("://")[1],
            )
            port = getattr(self._server, "port", FlextLdapConstants.LDAP.DEFAULT_PORT)
            return f"{scheme}://{host}:{port}"
        except Exception:
            return "Connection string unavailable"

    async def close_connection(self) -> FlextResult[None]:
        """Close connection to LDAP server - required by flext-core protocol.

        Implements the protocol method required by flext-core connection protocols.
        Delegates to the unbind method for actual connection cleanup.

        Returns:
            FlextResult[None]: Success or error result from unbind operation.

        """
        return await self.unbind()  # Protocol compliance - delegates to domain method


__all__ = [
    "FlextLdapClient",
]
