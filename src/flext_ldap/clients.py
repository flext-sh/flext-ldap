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
from typing import Literal, cast
from urllib.parse import urlparse

import ldap3
from flext_core import FlextMixins, FlextProtocols, FlextResult, FlextTypes
from ldap3 import ALL_ATTRIBUTES, BASE, LEVEL, SUBTREE, Connection
from ldap3.core.exceptions import LDAPException

from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.typings import LdapAttributeDict

# Python 3.13 type aliases
type LdapConnectionResult = FlextResult[Connection]
type SearchResultDict = FlextTypes.Core.Dict

# FlextLogger available via FlextMixins.Service inheritance

# Valid LDAP scope literals for ldap3
LdapScope = Literal["BASE", "LEVEL", "SUBTREE"]

# Scope mapping - ldap3 constants
SCOPE_MAP: dict[str, LdapScope] = {
    "base": cast("LdapScope", BASE),
    "ldap3.BASE": cast("LdapScope", BASE),
    "one": cast("LdapScope", LEVEL),
    "onelevel": cast("LdapScope", LEVEL),
    "sub": cast("LdapScope", SUBTREE),
    "subtree": cast("LdapScope", SUBTREE),
    "subordinates": cast("LdapScope", SUBTREE),
}


# LDAPSearchStrategies ELIMINATED - consolidated into FlextLDAPClient nested classes
# Following flext-core consolidation pattern: ALL functionality within single class


class FlextLDAPClient(
    FlextMixins.Service, FlextMixins.Loggable, FlextProtocols.Infrastructure.Connection
):
    """UNIFIED LDAP client - consolidates all LDAP functionality in single class following SOLID."""

    # =========================================================================
    # NESTED STRATEGY CLASSES - Following single class pattern with nesting
    # =========================================================================

    class SearchExecutionStrategy:
        """LDAP search execution strategy - nested within unified client."""

        def __init__(self, connection: Connection | None) -> None:
            """Initialize search strategy with LDAP connection."""
            self.connection = connection

        def execute_search(
            self,
            request: FlextLDAPEntities.SearchRequest,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Execute LDAP search using ldap3 connection."""
            if not self.connection or not getattr(self.connection, "bound", False):
                return FlextResult[FlextTypes.Core.Dict].fail(
                    "Not connected to LDAP server",
                )

            try:
                # Map scope to ldap3 constant
                scope = SCOPE_MAP.get(request.scope.lower(), SUBTREE)

                # Execute search using ldap3 directly
                connection_obj = self.connection
                success: bool = connection_obj.search(
                    search_base=request.base_dn,
                    search_filter=request.filter_str,
                    search_scope=scope,
                    attributes=request.attributes or ALL_ATTRIBUTES,
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
        """LDAP entry conversion strategy - nested within unified client."""

        def convert_entries(
            self,
            connection: Connection,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Convert ldap3 entries to structured format."""
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
                            entry_attributes = list(entry.entry_attributes.keys())
                            for attr_name in entry_attributes:
                                attr_values = entry.entry_attributes.get(attr_name, [])
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
        """Search response builder strategy - nested within unified client."""

        def build_response(
            self,
            data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
            """Build search response from entries and request data."""
            try:
                entries = cast("list[dict[str, object]]", data.get("entries", []))
                request = cast("FlextLDAPEntities.SearchRequest", data.get("request"))

                response = FlextLDAPEntities.SearchResponse(
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
        """Initialize LDAP client with flext-core logging capabilities."""
        # Initialize FlextMixins.Service for logging capabilities
        super().__init__()
        self._connection: Connection | None = None
        self._server: ldap3.Server | None = None

    # =========================================================================
    # CONNECTION OPERATIONS - Consolidated connection management
    # =========================================================================

    async def connect(self, uri: str, bind_dn: str, password: str) -> FlextResult[None]:
        """Connect to LDAP server.

        Returns:
            FlextResult[None]: Success or error result.

        """
        try:
            # Parse URI to get connection details
            parsed = urlparse(uri)
            use_ssl = parsed.scheme == "ldaps"
            host = parsed.hostname or "localhost"
            port = parsed.port or (636 if use_ssl else 389)

            # Create server
            self._server = ldap3.Server(
                host=host,
                port=port,
                use_ssl=use_ssl,
                get_info=ldap3.ALL,
                tls=ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None,
            )

            # Create connection
            self._connection = ldap3.Connection(
                self._server,
                user=bind_dn,
                password=password,
                auto_bind=True,
                raise_exceptions=True,
            )

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

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection:
            return FlextResult.ok(None)  # Already unbound

        try:
            # Safe method call using getattr for untyped ldap3
            unbind_method = getattr(self._connection, "unbind", lambda: None)
            unbind_method()
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
        """Check if connected and bound to LDAP server - protocol method.

        Returns:
            bool: True when a bound connection exists.

        """
        return self._connection is not None and getattr(
            self._connection, "bound", False
        )

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self,
        base_dn: str,
        search_filter: str,
        scope: str = "subtree",
    ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
        """LDAP search following flext-core protocol signature.

        This method follows the flext-core LdapConnection protocol.
        For advanced search operations, use search_with_request().
        """
        # Create SearchRequest from basic parameters
        request = FlextLDAPEntities.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            scope=scope,
            attributes=None,  # Default value
            size_limit=1000,  # Default value
            time_limit=30,  # Default value
        )
        # Delegate to the advanced method
        return await self.search_with_request(request)

    async def search_with_request(
        self,
        request: FlextLDAPEntities.SearchRequest,
    ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
        """Perform LDAP search with strategy pattern.

        Returns:
            FlextResult[FlextLDAPEntities.SearchResponse]: Structured response with entries.

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
                    cast("list[object]", entries_result.value.get("entries", []))
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

        Returns:
            FlextResult[None]: Success or error result.

        """
        # Convert to LdapAttributeDict and delegate to implementation
        ldap_attributes: LdapAttributeDict = cast("LdapAttributeDict", dict(attributes))
        return await self.add_entry(dn, ldap_attributes)

    async def add_entry(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Add new entry to LDAP directory.

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection or not self._connection.bound:
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Convert attributes to ldap3-compatible format
            ldap3_attributes = dict(attributes)
            # Safe method call using getattr for untyped ldap3
            add_method = getattr(self._connection, "add", lambda *_a, **_k: False)
            success = add_method(dn, attributes=ldap3_attributes)
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

    async def modify(self, dn: str, modifications: FlextTypes.Core.Dict) -> FlextResult[None]:
        """Modify existing LDAP entry following flext-core protocol.

        Returns:
            FlextResult[None]: Success or error result.

        """
        # Convert to LdapAttributeDict and delegate to implementation
        ldap_modifications: LdapAttributeDict = cast(
            "LdapAttributeDict", dict(modifications)
        )
        return await self.modify_entry(dn, ldap_modifications)

    async def modify_entry(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Modify existing LDAP entry.

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
            ldap3_changes = dict(changes)
            # Safe method call using getattr for untyped ldap3
            modify_method = getattr(self._connection, "modify", lambda *_a, **_k: False)
            success = modify_method(dn, ldap3_changes)
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

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection or not self._connection.bound:
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Safe method call using getattr for untyped ldap3
            delete_method = getattr(self._connection, "delete", lambda *_a, **_k: False)
            success = delete_method(dn)
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
        """Cleanup on destruction."""
        if self._connection and self._connection.bound:
            with contextlib.suppress(Exception):
                # Safe method call in cleanup context
                unbind_method = getattr(self._connection, "unbind", lambda: None)
                unbind_method()

    # =========================================================================
    # PROTOCOL METHODS - Required by FlextProtocols.Infrastructure.Connection
    # =========================================================================

    def __call__(self, *_args: object, **_kwargs: object) -> bool:
        """Callable interface for connection - protocol requirement."""
        # Return connection status for callable interface
        return self.is_connected()

    def test_connection(self) -> FlextResult[str]:
        """Test connection to LDAP server - protocol requirement."""
        if not self._connection:
            return FlextResult.fail("No connection established")

        try:
            # Test connection by performing a simple bind check
            is_bound = getattr(self._connection, "bound", False)
            if is_bound:
                return FlextResult.ok("Connection test successful")
            return FlextResult.fail("Connection not bound")
        except Exception as e:
            return FlextResult.fail(f"Connection test failed: {e}")

    def get_connection_string(self) -> str:
        """Get connection string for LDAP server - protocol requirement."""
        if not self._server:
            return "No server configured"

        try:
            # Build connection string from server info
            scheme = "ldaps" if getattr(self._server, "ssl", False) else "ldap"
            host = getattr(self._server, "host", "localhost")
            port = getattr(self._server, "port", 389)
            return f"{scheme}://{host}:{port}"
        except Exception:
            return "Connection string unavailable"

    async def close_connection(self) -> FlextResult[None]:
        """Close connection to LDAP server - required by flext-core protocol."""
        return await self.unbind()  # Protocol compliance - delegates to domain method


__all__ = [
    "SCOPE_MAP",
    "FlextLDAPClient",
    "LdapScope",
]
