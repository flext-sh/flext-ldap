"""LDAP client implementations following SOLID principles."""

from __future__ import annotations

import contextlib
import ssl
from typing import Literal, cast, override
from urllib.parse import urlparse

import ldap3
from flext_core import FlextResult, get_logger
from ldap3 import BASE, LEVEL, SUBTREE
from ldap3.core.exceptions import LDAPException

from flext_ldap.entities import FlextLdapSearchRequest, FlextLdapSearchResponse
from flext_ldap.interfaces import IFlextLdapClient
from flext_ldap.typings import LdapAttributeDict, LdapSearchResult
from flext_ldap.utils import FlextLdapUtilities

logger = get_logger(__name__)

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


class FlextLdapClient(IFlextLdapClient):
    """LDAP client implementation using ldap3 library."""

    def __init__(self) -> None:
        """Initialize LDAP client."""
        self._connection: ldap3.Connection | None = None
        self._server: ldap3.Server | None = None

    @override
    async def connect(self, uri: str, bind_dn: str, password: str) -> FlextResult[None]:
        """Connect to LDAP server."""
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

    @override
    async def search(
        self,
        request: FlextLdapSearchRequest,
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Perform LDAP search."""
        if not self._connection or not self._connection.bound:
            return FlextResult[FlextLdapSearchResponse].fail(
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
                attributes=request.attributes or ldap3.ALL_ATTRIBUTES,
                size_limit=request.size_limit,
                time_limit=request.time_limit,
            )
            success: bool = FlextLdapUtilities.safe_ldap3_search_result(search_result)

            if not success:
                error_message: str = FlextLdapUtilities.safe_ldap3_connection_result(
                    connection_obj
                )
                return FlextResult[FlextLdapSearchResponse].fail(
                    f"Search failed: {error_message}"
                )

            # Convert entries to our format using utilities
            entries: list[LdapSearchResult] = []
            connection_entries: list[object] = (
                FlextLdapUtilities.safe_ldap3_entries_list(self._connection)
            )

            for entry in connection_entries:
                entry_dn: str = FlextLdapUtilities.safe_ldap3_entry_dn(entry)
                entry_data: LdapSearchResult = {"dn": entry_dn}

                entry_attributes: list[str] = (
                    FlextLdapUtilities.safe_ldap3_entry_attributes_list(entry)
                )
                for attr_name in entry_attributes:
                    attr_values: list[str] = (
                        FlextLdapUtilities.safe_ldap3_attribute_values(entry, attr_name)
                    )
                    if len(attr_values) == 1:
                        entry_data[attr_name] = attr_values[0]
                    elif attr_values:  # Only add non-empty lists
                        entry_data[attr_name] = attr_values
                entries.append(entry_data)

            response = FlextLdapSearchResponse(
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

            return FlextResult[FlextLdapSearchResponse].ok(response)

        except LDAPException as e:
            logger.exception("LDAP search failed", extra={"error": str(e)})
            return FlextResult[FlextLdapSearchResponse].fail(f"Search failed: {e}")
        except Exception as e:
            logger.exception("Unexpected search error", extra={"error": str(e)})
            return FlextResult[FlextLdapSearchResponse].fail(f"Search error: {e}")

    @override
    async def add(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Add entry to LDAP."""
        if not self._connection or not self._connection.bound:
            return FlextResult[None].fail("Not connected to LDAP server")

        try:
            success = self._connection.add(dn, attributes=attributes)  # type: ignore[no-untyped-call]
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

    @override
    async def modify(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Modify LDAP entry."""
        if not self._connection or not self._connection.bound:
            return FlextResult[None].fail("Not connected to LDAP server")

        try:
            # Convert attributes to modification list
            changes = {}
            for attr_name, attr_value in attributes.items():
                changes[attr_name] = [(ldap3.MODIFY_REPLACE, attr_value)]

            success = self._connection.modify(dn, changes)  # type: ignore[no-untyped-call]
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

    @override
    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete LDAP entry."""
        if not self._connection or not self._connection.bound:
            return FlextResult[None].fail("Not connected to LDAP server")

        try:
            success = self._connection.delete(dn)  # type: ignore[no-untyped-call]
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

    @override
    async def bind(self, dn: str, password: str) -> FlextResult[None]:
        """Bind with credentials."""
        if not self._connection:
            return FlextResult[None].fail("No connection established")

        try:
            # Use utility to safely handle ldap3 rebind result
            success: bool = FlextLdapUtilities.safe_ldap3_rebind_result(
                self._connection, dn, password
            )
            if not success:
                error_message: str = FlextLdapUtilities.safe_ldap3_connection_result(
                    self._connection
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

    @override
    async def unbind(self) -> FlextResult[None]:
        """Unbind from server."""
        if not self._connection:
            return FlextResult[None].ok(None)  # Already unbound

        try:
            self._connection.unbind()  # type: ignore[no-untyped-call]
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
        """Check if connected and bound."""
        return self._connection is not None and self._connection.bound

    def __del__(self) -> None:
        """Cleanup on destruction."""
        if self._connection and self._connection.bound:
            with contextlib.suppress(Exception):
                self._connection.unbind()  # type: ignore[no-untyped-call]
