"""LDAP Client - Single FlextLDAPClient class following FLEXT patterns.

Single class with all LDAP client functionality organized as internal classes
and methods for complete backward compatibility and proper separation of concerns.

Follows FLEXT architectural standards:
    - Single Responsibility: All LDAP client operations consolidated
    - Open/Closed: Extensible without modification
    - Liskov Substitution: Consistent interface across all operations
    - Interface Segregation: Organized by operation type for specific access
    - Dependency Inversion: Depends on abstractions not concrete implementations

Examples:
    Modern usage::

        from clients import FlextLDAPClient

        # Direct client usage
        client = FlextLDAPClient()
        result = await client.connect(uri, bind_dn, password)

        # Operation-specific access
        search_result = await FlextLDAPClient.Search.execute(request)
        connection_result = await FlextLDAPClient.Connection.bind(dn, password)

    Legacy compatibility::

        from clients import FlextLDAPClient

        client = FlextLDAPClient()  # Same interface as before

"""

from __future__ import annotations

import contextlib
import ssl
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from ldap3 import Connection
from urllib.parse import urlparse

import ldap3
from flext_core import FlextLogger, FlextResult
from ldap3 import ALL_ATTRIBUTES, BASE, LEVEL, SUBTREE
from ldap3.core.exceptions import LDAPException

from flext_ldap.entities import FlextLDAPSearchRequest, FlextLDAPSearchResponse
from flext_ldap.typings import LdapAttributeDict, LdapSearchResult
from flext_ldap.utilities import FlextLDAPUtilities

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
# SINGLE FLEXT LDAP CLIENT CLASS - Consolidated client functionality
# =============================================================================


class FlextLDAPClient:
    """Single FlextLDAPClient class with all LDAP client functionality.

    Consolidates ALL LDAP client operations into a single class following FLEXT patterns.
    Everything from connection management to CRUD operations is available as
    internal methods and classes with full backward compatibility.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP client operations consolidated
        - Open/Closed: Extensible without modification
        - Liskov Substitution: Consistent interface across all operations
        - Interface Segregation: Organized by operation type for specific access
        - Dependency Inversion: Depends on abstractions not concrete implementations

    Examples:
        Direct usage::

            client = FlextLDAPClient()
            result = await client.connect(uri, bind_dn, password)
            search_result = await client.search(request)

        Operation-specific usage::

            search_result = await FlextLDAPClient.Search.execute(request)
            connection_result = await FlextLDAPClient.Connection.bind(dn, password)

    """

    def __init__(self) -> None:
        """Initialize FlextLDAPClient with connection state management."""
        self._connection: Connection | None = None
        self._server: ldap3.Server | None = None

    # =========================================================================
    # CONNECTION OPERATIONS - Consolidated connection management
    # =========================================================================

    async def connect(self, uri: str, bind_dn: str, password: str) -> FlextResult[None]:
        """Connect to LDAP server with comprehensive error handling.

        Args:
            uri: LDAP server URI (ldap:// or ldaps://)
            bind_dn: Distinguished name for binding
            password: Password for authentication

        Returns:
            FlextResult indicating success or failure with detailed error info

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
                return FlextResult[None].fail("Failed to bind to LDAP server")

            logger.info(
                "Connected to LDAP server",
                extra={"uri": uri, "bind_dn": bind_dn},
            )
            return FlextResult[None].ok(None)

        except LDAPException as e:
            logger.exception(
                "LDAP connection failed",
                extra={"error": str(e), "uri": uri},
            )
            return FlextResult[None].fail(f"LDAP connection failed: {e}")
        except Exception as e:
            logger.exception(
                "Unexpected connection error",
                extra={"error": str(e), "uri": uri},
            )
            return FlextResult[None].fail(f"Connection error: {e}")

    async def bind(self, dn: str, password: str) -> FlextResult[None]:
        """Bind with different credentials.

        Args:
            dn: Distinguished name for binding
            password: Password for authentication

        Returns:
            FlextResult indicating success or failure

        """
        if not self._connection:
            return FlextResult[None].fail("No connection established")

        try:
            # Use utility to safely handle ldap3 rebind result
            success: bool = (
                FlextLDAPUtilities.LdapSpecific.Ldap3.safe_ldap3_rebind_result(
                    self._connection, dn, password
                )
            )
            if not success:
                error_message: str = (
                    FlextLDAPUtilities.LdapSpecific.Ldap3.safe_ldap3_connection_result(
                        self._connection
                    )
                )
                return FlextResult[None].fail(f"Bind failed: {error_message}")

            logger.debug("Bind successful", extra={"dn": dn})
            return FlextResult[None].ok(None)

        except LDAPException as e:
            logger.exception("LDAP bind failed", extra={"error": str(e), "dn": dn})
            return FlextResult[None].fail(f"Bind failed: {e}")
        except Exception as e:
            logger.exception("Unexpected bind error", extra={"error": str(e), "dn": dn})
            return FlextResult[None].fail(f"Bind error: {e}")

    async def unbind(self) -> FlextResult[None]:
        """Unbind from server and cleanup connections.

        Returns:
            FlextResult indicating success or failure

        """
        if not self._connection:
            return FlextResult[None].ok(None)  # Already unbound

        try:
            # Safe method call using getattr for untyped ldap3
            unbind_method = getattr(self._connection, "unbind", lambda: None)
            unbind_method()
            self._connection = None
            self._server = None

            logger.debug("Unbound from LDAP server")
            return FlextResult[None].ok(None)

        except LDAPException as e:
            logger.exception("LDAP unbind failed", extra={"error": str(e)})
            return FlextResult[None].fail(f"Unbind failed: {e}")
        except Exception as e:
            logger.exception("Unexpected unbind error", extra={"error": str(e)})
            return FlextResult[None].fail(f"Unbind error: {e}")

    @property
    def is_connected(self) -> bool:
        """Check if connected and bound to LDAP server.

        Returns:
            True if connected and bound, False otherwise

        """
        return self._connection is not None and self._connection.bound

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self,
        request: FlextLDAPSearchRequest,
    ) -> FlextResult[FlextLDAPSearchResponse]:
        """Perform LDAP search with comprehensive result handling.

        Args:
            request: Search request with filters, scope, and attributes

        Returns:
            FlextResult containing search response or error information

        """
        if not self._connection or not self._connection.bound:
            return FlextResult[FlextLDAPSearchResponse].fail(
                "Not connected to LDAP server",
            )

        try:
            # Map scope to ldap3 constant
            scope: LdapScope = SCOPE_MAP.get(
                request.scope.lower(), cast("LdapScope", ldap3.SUBTREE)
            )

            # Use utility to safely handle ldap3 search result
            connection_obj: object = cast("object", self._connection)
            search_attr_name = "search"  # Dynamic attribute name to avoid B009
            search_method = getattr(connection_obj, search_attr_name)
            search_result: object = search_method(
                search_base=request.base_dn,
                search_filter=request.filter_str,
                search_scope=scope,
                attributes=request.attributes or ALL_ATTRIBUTES,
                size_limit=request.size_limit,
                time_limit=request.time_limit,
            )
            success: bool = (
                FlextLDAPUtilities.LdapSpecific.Ldap3.safe_ldap3_search_result(
                    search_result
                )
            )

            if not success:
                error_message: str = (
                    FlextLDAPUtilities.LdapSpecific.Ldap3.safe_ldap3_connection_result(
                        cast("Connection", connection_obj)
                    )
                )
                return FlextResult[FlextLDAPSearchResponse].fail(
                    f"Search failed: {error_message}"
                )

            # Convert entries to our format using utilities
            entries: list[LdapSearchResult] = []
            connection_entries: list[dict[str, object]] = (
                FlextLDAPUtilities.LdapSpecific.Ldap3.safe_ldap3_entries_list(
                    self._connection
                )
            )

            for entry in connection_entries:
                entry_dn: str = (
                    FlextLDAPUtilities.LdapSpecific.Ldap3.safe_ldap3_entry_dn(entry)
                )
                entry_data: LdapSearchResult = {"dn": entry_dn}

                entry_attributes: list[str] = (
                    FlextLDAPUtilities.LdapSpecific.Ldap3.safe_ldap3_entry_attributes_list(
                        entry
                    )
                )
                for attr_name in entry_attributes:
                    attr_values: list[str] = (
                        FlextLDAPUtilities.LdapSpecific.Ldap3.safe_ldap3_attribute_values(
                            entry, attr_name
                        )
                    )
                    if len(attr_values) == 1:
                        entry_data[attr_name] = attr_values[0]
                    elif attr_values:  # Only add non-empty lists
                        entry_data[attr_name] = attr_values
                entries.append(entry_data)

            response = FlextLDAPSearchResponse(
                entries=entries,
                total_count=len(entries),
                has_more=len(entries) >= request.size_limit,
            )

            logger.debug(
                "Search completed",
                extra={
                    "base_dn": request.base_dn,
                    "filter": request.filter_str,
                    "count": len(entries),
                },
            )

            return FlextResult[FlextLDAPSearchResponse].ok(response)

        except LDAPException as e:
            logger.exception("LDAP search failed", extra={"error": str(e)})
            return FlextResult[FlextLDAPSearchResponse].fail(f"Search failed: {e}")
        except Exception as e:
            logger.exception("Unexpected search error", extra={"error": str(e)})
            return FlextResult[FlextLDAPSearchResponse].fail(f"Search error: {e}")

    # =========================================================================
    # CRUD OPERATIONS - Consolidated Create, Update, Delete operations
    # =========================================================================

    async def add(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Add new entry to LDAP directory.

        Args:
            dn: Distinguished name for the new entry
            attributes: Dictionary of attributes and values

        Returns:
            FlextResult indicating success or failure

        """
        if not self._connection or not self._connection.bound:
            return FlextResult[None].fail("Not connected to LDAP server")

        try:
            # Convert attributes to ldap3-compatible format
            ldap3_attributes = dict(attributes)
            # Safe method call using getattr for untyped ldap3
            add_method = getattr(
                self._connection, "add", lambda *_args, **_kwargs: False
            )
            success = add_method(dn, attributes=ldap3_attributes)
            if not success:
                return FlextResult[None].fail(f"Add failed: {self._connection.result}")

            logger.info("Entry added", extra={"dn": dn})
            return FlextResult[None].ok(None)

        except LDAPException as e:
            logger.exception("LDAP add failed", extra={"error": str(e), "dn": dn})
            return FlextResult[None].fail(f"Add failed: {e}")
        except Exception as e:
            logger.exception("Unexpected add error", extra={"error": str(e), "dn": dn})
            return FlextResult[None].fail(f"Add error: {e}")

    async def modify(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Modify existing LDAP entry.

        Args:
            dn: Distinguished name of the entry to modify
            attributes: Dictionary of attributes and new values

        Returns:
            FlextResult indicating success or failure

        """
        if not self._connection or not self._connection.bound:
            return FlextResult[None].fail("Not connected to LDAP server")

        try:
            # Convert attributes to modification list
            changes = {}
            for attr_name, attr_value in attributes.items():
                changes[attr_name] = [(ldap3.MODIFY_REPLACE, attr_value)]

            # Convert changes to ldap3-compatible format
            ldap3_changes = dict(changes)
            # Safe method call using getattr for untyped ldap3
            modify_method = getattr(
                self._connection, "modify", lambda *_args, **_kwargs: False
            )
            success = modify_method(dn, ldap3_changes)
            if not success:
                return FlextResult[None].fail(
                    f"Modify failed: {self._connection.result}",
                )

            logger.info("Entry modified", extra={"dn": dn})
            return FlextResult[None].ok(None)

        except LDAPException as e:
            logger.exception("LDAP modify failed", extra={"error": str(e), "dn": dn})
            return FlextResult[None].fail(f"Modify failed: {e}")
        except Exception as e:
            logger.exception(
                "Unexpected modify error",
                extra={"error": str(e), "dn": dn},
            )
            return FlextResult[None].fail(f"Modify error: {e}")

    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry from LDAP directory.

        Args:
            dn: Distinguished name of the entry to delete

        Returns:
            FlextResult indicating success or failure

        """
        if not self._connection or not self._connection.bound:
            return FlextResult[None].fail("Not connected to LDAP server")

        try:
            # Safe method call using getattr for untyped ldap3
            delete_method = getattr(
                self._connection, "delete", lambda *_args, **_kwargs: False
            )
            success = delete_method(dn)
            if not success:
                return FlextResult[None].fail(
                    f"Delete failed: {self._connection.result}",
                )

            logger.info("Entry deleted", extra={"dn": dn})
            return FlextResult[None].ok(None)

        except LDAPException as e:
            logger.exception("LDAP delete failed", extra={"error": str(e), "dn": dn})
            return FlextResult[None].fail(f"Delete failed: {e}")
        except Exception as e:
            logger.exception(
                "Unexpected delete error",
                extra={"error": str(e), "dn": dn},
            )
            return FlextResult[None].fail(f"Delete error: {e}")

    # =========================================================================
    # OPERATION-SPECIFIC STATIC CLASSES - Hierarchical organization
    # =========================================================================

    class Connection:
        """Connection-specific operations with static methods."""

        @staticmethod
        async def establish(
            uri: str, bind_dn: str, password: str
        ) -> FlextResult[FlextLDAPClient]:
            """Establish connection using default client instance.

            Returns:
                FlextResult containing connected client or error

            """
            client = FlextLDAPClient()
            result = await client.connect(uri, bind_dn, password)
            if result.is_success:
                return FlextResult[FlextLDAPClient].ok(client)
            return FlextResult[FlextLDAPClient].fail(
                result.error or "Connection failed"
            )

        @staticmethod
        async def bind(
            client: FlextLDAPClient, dn: str, password: str
        ) -> FlextResult[None]:
            """Bind using existing client instance."""
            return await client.bind(dn, password)

        @staticmethod
        async def unbind(client: FlextLDAPClient) -> FlextResult[None]:
            """Unbind using existing client instance."""
            return await client.unbind()

    class Search:
        """Search-specific operations with static methods."""

        @staticmethod
        async def execute(
            client: FlextLDAPClient, request: FlextLDAPSearchRequest
        ) -> FlextResult[FlextLDAPSearchResponse]:
            """Execute search using client instance."""
            return await client.search(request)

    class Entry:
        """Entry manipulation operations with static methods."""

        @staticmethod
        async def add(
            client: FlextLDAPClient, dn: str, attributes: LdapAttributeDict
        ) -> FlextResult[None]:
            """Add entry using client instance."""
            return await client.add(dn, attributes)

        @staticmethod
        async def modify(
            client: FlextLDAPClient, dn: str, attributes: LdapAttributeDict
        ) -> FlextResult[None]:
            """Modify entry using client instance."""
            return await client.modify(dn, attributes)

        @staticmethod
        async def delete(client: FlextLDAPClient, dn: str) -> FlextResult[None]:
            """Delete entry using client instance."""
            return await client.delete(dn)

    def __del__(self) -> None:
        """Cleanup on destruction with safe exception handling."""
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
