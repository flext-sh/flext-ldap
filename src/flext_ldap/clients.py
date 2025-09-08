"""LDAP client module.

Implements connection management and basic LDAP operations using ldap3,
with strategy classes for search execution, entry conversion and response build.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import contextlib
import ssl
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urlparse

import ldap3
from flext_core import FlextLogger, FlextResult, FlextTypes
from ldap3 import ALL_ATTRIBUTES, BASE, LEVEL, SUBTREE, Connection
from ldap3.core.exceptions import LDAPException

from flext_ldap.entities import FlextLDAPEntities

if TYPE_CHECKING:
    from flext_ldap.typings import LdapAttributeDict, LdapSearchResult


logger = FlextLogger(__name__)

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


# =============================================================================
# LDAP SEARCH STRATEGIES - Strategy Pattern for Complex Operations
# =============================================================================


class LDAPSearchStrategies:
    """LDAP search strategies."""

    class SearchExecutionStrategy:
        """LDAP search execution strategy."""

        def __init__(self, connection: Connection | None) -> None:
            self.connection = connection

        def execute_search(
            self,
            request: FlextLDAPEntities.SearchRequest,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Execute LDAP search using ldap3 connection.

            Returns:
                FlextResult[FlextTypes.Core.Dict]: Result with connection context when successful.

            """
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
                    search_scope=cast("LdapScope", scope),
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
        """LDAP entry conversion strategy."""

        def convert_entries(
            self,
            connection: Connection,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Convert ldap3 entries to structured format.

            Returns:
                FlextResult[FlextTypes.Core.Dict]: Mapping with key "entries" as a list of results.

            """
            try:
                entries: list[LdapSearchResult] = []
                connection_entries = connection.entries if connection else []

                for entry in connection_entries:
                    # Get DN directly from ldap3 entry
                    entry_dn = str(entry.entry_dn) if hasattr(entry, "entry_dn") else ""
                    entry_data: LdapSearchResult = {"dn": entry_dn}

                    # Process attributes using strategy pattern
                    entry_attributes = (
                        list(entry.entry_attributes.keys())
                        if hasattr(entry, "entry_attributes")
                        else []
                    )
                    for attr_name in entry_attributes:
                        attr_values = (
                            entry.entry_attributes.get(attr_name, [])
                            if hasattr(entry, "entry_attributes")
                            else []
                        )
                        if len(attr_values) == 1:
                            entry_data[attr_name] = attr_values[0]
                        elif attr_values:  # Only add non-empty lists
                            entry_data[attr_name] = attr_values
                    entries.append(entry_data)

                return FlextResult[FlextTypes.Core.Dict].ok({"entries": entries})

            except Exception as e:
                return FlextResult[FlextTypes.Core.Dict].fail(
                    f"Entry conversion error: {e}",
                )

    class ResponseBuilderStrategy:
        """Search response builder strategy."""

        def build_response(
            self,
            data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
            """Build search response from entries and request data.

            Returns:
                FlextResult[FlextLDAPEntities.SearchResponse]: Typed search response.

            """
            try:
                entries = cast("list[LdapSearchResult]", data.get("entries", []))
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


# =============================================================================
# SINGLE FLEXT LDAP CLIENT CLASS - Consolidated client functionality
# =============================================================================


class FlextLDAPClient:
    """LDAP client with connection and operation methods."""

    def __init__(self) -> None:
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

            logger.info(
                "Connected to LDAP server",
                extra={"uri": uri, "bind_dn": bind_dn},
            )
            return FlextResult.ok(None)

        except LDAPException as e:
            logger.exception(
                "LDAP connection failed",
                extra={"error": str(e), "uri": uri},
            )
            return FlextResult.fail(f"LDAP connection failed: {e}")
        except Exception as e:
            logger.exception(
                "Unexpected connection error",
                extra={"error": str(e), "uri": uri},
            )
            return FlextResult.fail(f"Connection error: {e}")

    async def bind(self, dn: str, password: str) -> FlextResult[None]:
        """Bind with different credentials.

        Returns:
            FlextResult[None]: Success or error result.

        """
        if not self._connection:
            return FlextResult.fail("No connection established")

        try:
            # Use ldap3 directly - no wrapper needed
            self._connection.rebind(dn, password)
            success = self._connection.result.get("description") == "success"
            if not success:
                error_message = str(
                    self._connection.result.get("message", "Authentication failed"),
                )
                return FlextResult.fail(f"Bind failed: {error_message}")

            logger.debug("Bind successful", extra={"dn": dn})
            return FlextResult.ok(None)

        except LDAPException as e:
            logger.exception("LDAP bind failed", extra={"error": str(e), "dn": dn})
            return FlextResult.fail(f"Bind failed: {e}")
        except Exception as e:
            logger.exception("Unexpected bind error", extra={"error": str(e), "dn": dn})
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

            logger.debug("Unbound from LDAP server")
            return FlextResult.ok(None)

        except LDAPException as e:
            logger.exception("LDAP unbind failed", extra={"error": str(e)})
            return FlextResult.fail(f"Unbind failed: {e}")
        except Exception as e:
            logger.exception("Unexpected unbind error", extra={"error": str(e)})
            return FlextResult.fail(f"Unbind error: {e}")

    @property
    def is_connected(self) -> bool:
        """Check if connected and bound to LDAP server.

        Returns:
            bool: True when a bound connection exists.

        """
        return self._connection is not None and self._connection.bound

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self,
        request: FlextLDAPEntities.SearchRequest,
    ) -> FlextResult[FlextLDAPEntities.SearchResponse]:
        """Perform LDAP search with strategy pattern.

        Returns:
            FlextResult[FlextLDAPEntities.SearchResponse]: Structured response with entries.

        """
        try:
            # Strategy 1: Execute LDAP search
            search_strategy = LDAPSearchStrategies.SearchExecutionStrategy(
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

            conversion_strategy = LDAPSearchStrategies.EntryConversionStrategy()
            entries_result = conversion_strategy.convert_entries(self._connection)

            if not entries_result.is_success:
                return FlextResult.fail(
                    entries_result.error or "Entry conversion failed",
                )

            # Strategy 3: Build final response
            response_strategy = LDAPSearchStrategies.ResponseBuilderStrategy()
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
            logger.debug(
                "Search completed using Strategy Pattern",
                extra={
                    "base_dn": request.base_dn,
                    "filter": request.filter_str,
                    "count": len(cast("list", entries_result.value.get("entries", []))),
                },
            )

            return response_result

        except Exception as e:
            logger.exception(
                "Unexpected search strategy error",
                extra={"error": str(e)},
            )
            return FlextResult.fail(
                f"Search strategy error: {e}",
            )

    # =========================================================================
    # CRUD OPERATIONS - Consolidated Create, Update, Delete operations
    # =========================================================================

    async def add(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
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

            logger.info("Entry added", extra={"dn": dn})
            return FlextResult.ok(None)

        except LDAPException as e:
            logger.exception("LDAP add failed", extra={"error": str(e), "dn": dn})
            return FlextResult.fail(f"Add failed: {e}")
        except Exception as e:
            logger.exception("Unexpected add error", extra={"error": str(e), "dn": dn})
            return FlextResult.fail(f"Add error: {e}")

    async def modify(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
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

            logger.info("Entry modified", extra={"dn": dn})
            return FlextResult.ok(None)

        except LDAPException as e:
            logger.exception("LDAP modify failed", extra={"error": str(e), "dn": dn})
            return FlextResult.fail(f"Modify failed: {e}")
        except Exception as e:
            logger.exception(
                "Unexpected modify error",
                extra={"error": str(e), "dn": dn},
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

            logger.info("Entry deleted", extra={"dn": dn})
            return FlextResult.ok(None)

        except LDAPException as e:
            logger.exception("LDAP delete failed", extra={"error": str(e), "dn": dn})
            return FlextResult.fail(f"Delete failed: {e}")
        except Exception as e:
            logger.exception(
                "Unexpected delete error",
                extra={"error": str(e), "dn": dn},
            )
            return FlextResult.fail(f"Delete error: {e}")

    def __del__(self) -> None:
        """Cleanup on destruction."""
        if self._connection and self._connection.bound:
            with contextlib.suppress(Exception):
                # Safe method call in cleanup context
                unbind_method = getattr(self._connection, "unbind", lambda: None)
                unbind_method()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "SCOPE_MAP",
    "FlextLDAPClient",
    "LdapScope",
]
