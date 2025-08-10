"""LDAP Client - SOLID Infrastructure Implementation.

🏗️ CLEAN ARCHITECTURE: Infrastructure Layer (SOLID-compliant)
Implements SOLID principles while extending flext-core patterns.

Key SOLID Principles Applied:
    - Single Responsibility: Each class has one clear responsibility
    - Open/Closed: Extensible through composition and interfaces
    - Liskov Substitution: All implementations are perfectly substitutable
    - Interface Segregation: Implements focused protocols from protocols.py
    - Dependency Inversion: Depends on abstractions, not concretions

Architecture Benefits:
    - Extends flext-core FlextService and FlextRepository patterns
    - Implements protocols from protocols.py for maximum testability
    - Uses FlextResult[T] for railway-oriented programming
    - Integrates with FlextContainer for dependency injection

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import uuid
import warnings
from typing import Literal, Protocol, runtime_checkable

import ldap3
from flext_core import (
    FlextContainer,
    FlextResult,
    get_logger,
)
from ldap3 import ALL, Server
from ldap3.core.exceptions import LDAPException

from flext_ldap.constants import FlextLdapScope

# Import consolidated value objects
from flext_ldap.value_objects import (
    FlextLdapDistinguishedName,
    FlextLdapFilter,
)

logger = get_logger(__name__)


@runtime_checkable
class LDAP3ConnectionProtocol(Protocol):
    """Typed subset of ldap3.Connection used by this module."""

    def unbind(self) -> bool | None: ...
    def add(self, dn: str, attributes: dict[str, list[str]]) -> bool: ...
    def modify(self, dn: str, changes: dict[str, object]) -> bool: ...
    def delete(self, dn: str) -> bool: ...
    def search(
        self,
        *,
        search_base: str,
        search_filter: str,
        search_scope: Literal["BASE", "LEVEL", "SUBTREE"],
        attributes: object,
    ) -> bool: ...

    @property
    def entries(self) -> list[object]: ...

    @property
    def last_error(self) -> str | None: ...


# ===== CONNECTION MANAGEMENT SERVICE =====
# SRP: Handles only LDAP connection lifecycle


class LdapConnectionService:
    """LDAP connection management service.

    SRP: Responsible only for connection lifecycle management.
    Implements LdapConnectionProtocol from protocols.py.
    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize connection service with dependency injection."""
        self._container = container or FlextContainer()
        self._connections: dict[str, LDAP3ConnectionProtocol] = {}

        logger.info("LDAP connection service initialized")

    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[str]:
        """Establish LDAP connection and return connection ID.

        Implements LdapConnectionProtocol.connect()
        """
        try:
            # Generate unique connection ID
            connection_id = str(uuid.uuid4())

            # Create server object
            server = Server(server_url, get_info=ALL)

            # Create connection with auto-bind
            if bind_dn and password:
                connection = ldap3.Connection(
                    server,
                    user=bind_dn,
                    password=password,
                    auto_bind=True,
                )
            else:
                connection = ldap3.Connection(server, auto_bind=True)

            # Store connection
            self._connections[connection_id] = connection  # type: ignore[assignment]

            logger.info(
                "LDAP connection established",
                extra={"connection_id": connection_id, "server_url": server_url},
            )

            return FlextResult.ok(connection_id)

        except LDAPException as e:
            error_msg = f"Failed to connect to LDAP server {server_url}: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error connecting to LDAP: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def disconnect(self, connection_id: str) -> FlextResult[None]:
        """Close LDAP connection and cleanup resources.

        Implements LdapConnectionProtocol.disconnect()
        """
        try:
            if connection_id not in self._connections:
                return FlextResult.fail(f"Connection {connection_id} not found")

            connection = self._connections.pop(connection_id)
            if connection is not None:
                try:
                    connection.unbind()
                except Exception:
                    # Best-effort unbind; ignore typing of external lib
                    pass

            logger.info(
                "LDAP connection closed",
                extra={"connection_id": connection_id},
            )

            return FlextResult.ok(None)

        except Exception as e:
            error_msg = f"Error disconnecting from LDAP: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def is_connected(self, connection_id: str) -> FlextResult[bool]:
        """Check if connection is active and healthy.

        Implements LdapConnectionProtocol.is_connected()
        """
        try:
            if connection_id not in self._connections:
                return FlextResult.ok(False)

            connection = self._connections[connection_id]

            # Test connection with whoami operation
            try:
                connection.extend.standard.who_am_i()  # type: ignore[attr-defined]
                return FlextResult.ok(True)
            except LDAPException:
                # Connection is dead, remove it
                self._connections.pop(connection_id, None)
                return FlextResult.ok(False)

        except Exception as e:
            error_msg = f"Error checking connection status: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def _get_connection(
        self, connection_id: str
    ) -> FlextResult[LDAP3ConnectionProtocol]:
        """Internal method to get connection object."""
        if connection_id not in self._connections:
            return FlextResult.fail(f"Connection {connection_id} not found")

        return FlextResult.ok(self._connections[connection_id])


# ===== SEARCH SERVICE =====
# SRP: Handles only LDAP search/read operations


class LdapSearchService:
    """LDAP search operations service.

    SRP: Responsible only for LDAP search and read operations.
    Implements LdapSearchProtocol from protocols.py.
    """

    def __init__(self, connection_service: LdapConnectionService) -> None:
        """Initialize search service with connection dependency.

        DIP: Depends on connection service abstraction.
        """
        self._connection_service = connection_service

        logger.info("LDAP search service initialized")

    def _map_scope_to_ldap3(
        self, scope: FlextLdapScope
    ) -> Literal["BASE", "LEVEL", "SUBTREE"]:
        """Map FlextLdapScope to ldap3 constants."""
        scope_mapping: dict[str, Literal["BASE", "LEVEL", "SUBTREE"]] = {
            "base": "BASE",
            "one": "LEVEL",
            "sub": "SUBTREE",
            "children": "SUBTREE",  # ldap3 doesn't have children scope
        }
        return scope_mapping.get(scope.value, "SUBTREE")

    async def search(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        search_filter: FlextLdapFilter,
        scope: FlextLdapScope,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[dict[str, object]]]:
        """Search LDAP directory with filter.

        Implements LdapSearchProtocol.search()
        """
        try:
            # Get connection
            connection_result = self._connection_service._get_connection(connection_id)
            if not connection_result.is_success:
                return FlextResult.fail(connection_result.error or "Connection failed")
            connection: LDAP3ConnectionProtocol | None = (
                connection_result.data
            )  # narrow protocol

            # Map scope to ldap3 constants
            ldap_scope = self._map_scope_to_ldap3(scope)

            # Ensure connection is not None before use
            if connection is None:
                return FlextResult.fail("Connection is None")

            # Execute search
            success = connection.search(
                search_base=base_dn.dn,
                search_filter=search_filter.filter_str,
                search_scope=ldap_scope,
                attributes=attributes or ldap3.ALL_ATTRIBUTES,
            )

            if not success:
                error_msg = f"LDAP search failed: {connection.last_error}"
                return FlextResult.fail(error_msg)

            # Convert entries to dictionaries
            entries = []
            for entry in connection.entries:
                dn_value = getattr(entry, "entry_dn", "")
                entry_dict: dict[str, object] = {
                    "dn": str(dn_value),
                    "attributes": {},
                }

                # Type-safe attributes dict for indexed assignment
                attributes_dict = entry_dict["attributes"]
                if not isinstance(attributes_dict, dict):
                    attributes_dict = {}
                    entry_dict["attributes"] = attributes_dict

                # Convert attributes
                for attr_name in getattr(entry, "entry_attributes", []):
                    attr_values = getattr(entry, attr_name, None)
                    if attr_values:
                        if hasattr(attr_values, "values"):
                            attributes_dict[attr_name] = attr_values.values
                        else:
                            attributes_dict[attr_name] = [str(attr_values)]

                entries.append(entry_dict)

            logger.debug(
                "LDAP search completed",
                extra={
                    "connection_id": connection_id,
                    "base_dn": base_dn.dn,
                    "filter": search_filter.filter_str,
                    "results_count": len(entries),
                },
            )

            return FlextResult.ok(entries)

        except Exception as e:
            error_msg = f"Error performing LDAP search: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def search_one(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        attributes: list[str] | None = None,
    ) -> FlextResult[dict[str, object] | None]:
        """Find single entry by DN.

        Implements LdapSearchProtocol.search_one()
        """
        # Create base search with presence filter
        filter_obj = FlextLdapFilter.present("objectClass")

        scope_obj = FlextLdapScope.BASE

        search_result = await self.search(
            connection_id,
            dn,
            filter_obj,
            scope_obj,
            attributes,
        )

        if not search_result.is_success:
            return FlextResult.fail(search_result.error or "Search failed")

        entries = search_result.data
        return FlextResult.ok(entries[0] if entries else None)

    async def count_entries(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        search_filter: FlextLdapFilter,
        scope: FlextLdapScope,
    ) -> FlextResult[int]:
        """Count matching entries without retrieving data.

        Implements LdapSearchProtocol.count_entries()
        """
        # Search with no attributes to minimize data transfer
        search_result = await self.search(
            connection_id,
            base_dn,
            search_filter,
            scope,
            attributes=["1.1"],
        )

        if not search_result.is_success:
            return FlextResult.fail(search_result.error or "Search failed")

        return FlextResult.ok(len(search_result.data or []))


# ===== WRITE SERVICE =====
# SRP: Handles only LDAP write/modify operations


class LdapWriteService:
    """LDAP write operations service.

    SRP: Responsible only for LDAP write and modify operations.
    Implements LdapWriteProtocol from protocols.py.
    """

    def __init__(self, connection_service: LdapConnectionService) -> None:
        """Initialize write service with connection dependency.

        DIP: Depends on connection service abstraction.
        """
        self._connection_service = connection_service

        logger.info("LDAP write service initialized")

    async def create_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        attributes: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Create new LDAP entry.

        Implements LdapWriteProtocol.create_entry()
        """
        try:
            # Get connection
            connection_result = self._connection_service._get_connection(connection_id)
            if not connection_result.is_success:
                return FlextResult.fail(connection_result.error or "Connection failed")
            connection = connection_result.data

            # Ensure connection is not None before use
            if connection is None:
                return FlextResult.fail("Connection is None")

            # Execute add operation
            success = connection.add(dn.dn, attributes=attributes)

            if not success:
                error_msg = (
                    f"Failed to create LDAP entry {dn.dn}: {connection.last_error}"
                )
                return FlextResult.fail(error_msg)

            logger.info(
                "LDAP entry created successfully",
                extra={"connection_id": connection_id, "dn": dn.dn},
            )

            return FlextResult.ok(None)

        except Exception as e:
            error_msg = f"Error creating LDAP entry: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def modify_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        changes: dict[str, object],
    ) -> FlextResult[None]:
        """Modify existing LDAP entry.

        Implements LdapWriteProtocol.modify_entry()
        """
        try:
            # Get connection
            connection_result = self._connection_service._get_connection(connection_id)
            if not connection_result.is_success:
                return FlextResult.fail(connection_result.error or "Connection failed")
            connection = connection_result.data

            # Ensure connection is not None before use
            if connection is None:
                return FlextResult.fail("Connection is None")

            # Convert changes to ldap3 format
            modifications: dict[str, object] = {}
            for attr_name, attr_value in changes.items():
                if attr_value is None:
                    modifications[attr_name] = [(ldap3.MODIFY_DELETE, [])]
                else:
                    list_value = (
                        attr_value if isinstance(attr_value, list) else [attr_value]
                    )
                    modifications[attr_name] = [
                        (ldap3.MODIFY_REPLACE, [str(v) for v in list_value])
                    ]

            # Execute modify operation
            success = connection.modify(dn.dn, modifications)

            if not success:
                error_msg = (
                    f"Failed to modify LDAP entry {dn.dn}: {connection.last_error}"
                )
                return FlextResult.fail(error_msg)

            logger.info(
                "LDAP entry modified successfully",
                extra={"connection_id": connection_id, "dn": dn.dn},
            )

            return FlextResult.ok(None)

        except Exception as e:
            error_msg = f"Error modifying LDAP entry: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def delete_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Delete LDAP entry.

        Implements LdapWriteProtocol.delete_entry()
        """
        try:
            # Get connection
            connection_result = self._connection_service._get_connection(connection_id)
            if not connection_result.is_success:
                return FlextResult.fail(connection_result.error or "Connection failed")
            connection = connection_result.data

            # Ensure connection is not None before use
            if connection is None:
                return FlextResult.fail("Connection is None")

            # Execute delete operation
            success = connection.delete(dn.dn)

            if not success:
                error_msg = (
                    f"Failed to delete LDAP entry {dn.dn}: {connection.last_error}"
                )
                return FlextResult.fail(error_msg)

            logger.info(
                "LDAP entry deleted successfully",
                extra={"connection_id": connection_id, "dn": dn.dn},
            )

            return FlextResult.ok(None)

        except Exception as e:
            error_msg = f"Error deleting LDAP entry: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def move_entry(
        self,
        connection_id: str,
        old_dn: FlextLdapDistinguishedName,
        new_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Move/rename LDAP entry.

        Implements LdapWriteProtocol.move_entry()
        """
        try:
            # Get connection
            connection_result = self._connection_service._get_connection(connection_id)
            if not connection_result.is_success:
                return FlextResult.fail(connection_result.error or "Connection failed")
            connection = connection_result.data

            # Ensure connection is not None before use
            if connection is None:
                return FlextResult.fail("Connection is None")

            # Parse new DN to get RDN and new parent
            components = new_dn.get_components()
            if not components:
                return FlextResult.fail("Invalid DN format for move operation")

            new_rdn = f"{components[0][0]}={components[0][1]}"
            new_parent = new_dn.get_parent_dn()
            new_parent_dn = new_parent.dn if new_parent else None

            # Execute modify DN operation
            success = connection.modify(
                old_dn.dn,
                {
                    "distinguishedName": [
                        (
                            ldap3.MODIFY_REPLACE,
                            [new_dn.dn if new_parent_dn else new_rdn],
                        )
                    ]
                },
            )

            if not success:
                error_msg = f"Failed to move LDAP entry from {old_dn.dn} to {new_dn.dn}: {connection.last_error}"
                return FlextResult.fail(error_msg)

            logger.info(
                "LDAP entry moved successfully",
                extra={
                    "connection_id": connection_id,
                    "old_dn": old_dn.dn,
                    "new_dn": new_dn.dn,
                },
            )

            return FlextResult.ok(None)

        except Exception as e:
            error_msg = f"Error moving LDAP entry: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)


# ===== COMPOSITE CLIENT =====
# DIP: High-level client that composes services


class FlextLdapClient:
    """Composite LDAP client implementing all protocols.

    DIP: Composes lower-level services to provide complete LDAP functionality.
    Implements LdapClientProtocol from protocols.py.

    This is the main client that applications should use.
    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize composite client with dependency injection."""
        self._container = container or FlextContainer()

        # Compose services following DIP
        self._connection_service = LdapConnectionService(self._container)
        self._search_service = LdapSearchService(self._connection_service)
        self._write_service = LdapWriteService(self._connection_service)

        logger.info("SOLID LDAP client initialized with composed services")

    # Delegate to connection service (LdapConnectionProtocol)
    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[str]:
        """Establish LDAP connection and return connection ID."""
        return await self._connection_service.connect(server_url, bind_dn, password)

    async def disconnect(self, connection_id: str) -> FlextResult[None]:
        """Close LDAP connection and cleanup resources."""
        return await self._connection_service.disconnect(connection_id)

    async def is_connected(self, connection_id: str) -> FlextResult[bool]:
        """Check if connection is active and healthy."""
        return await self._connection_service.is_connected(connection_id)

    # Delegate to search service (LdapSearchProtocol)
    async def search(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        search_filter: FlextLdapFilter,
        scope: FlextLdapScope,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[dict[str, object]]]:
        """Search LDAP directory with filter."""
        return await self._search_service.search(
            connection_id,
            base_dn,
            search_filter,
            scope,
            attributes,
        )

    async def search_one(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        attributes: list[str] | None = None,
    ) -> FlextResult[dict[str, object] | None]:
        """Find single entry by DN."""
        return await self._search_service.search_one(connection_id, dn, attributes)

    async def count_entries(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        search_filter: FlextLdapFilter,
        scope: FlextLdapScope,
    ) -> FlextResult[int]:
        """Count matching entries without retrieving data."""
        return await self._search_service.count_entries(
            connection_id,
            base_dn,
            search_filter,
            scope,
        )

    # Delegate to write service (LdapWriteProtocol)
    async def create_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        attributes: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Create new LDAP entry."""
        return await self._write_service.create_entry(connection_id, dn, attributes)

    async def modify_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        changes: dict[str, object],
    ) -> FlextResult[None]:
        """Modify existing LDAP entry."""
        return await self._write_service.modify_entry(connection_id, dn, changes)

    async def delete_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Delete LDAP entry."""
        return await self._write_service.delete_entry(connection_id, dn)

    async def move_entry(
        self,
        connection_id: str,
        old_dn: FlextLdapDistinguishedName,
        new_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Move/rename LDAP entry."""
        return await self._write_service.move_entry(connection_id, old_dn, new_dn)


# ===== BACKWARD COMPATIBILITY ALIAS =====
# For gradual migration


class FlextLdapSimpleClient(FlextLdapClient):
    """Backward compatibility alias for FlextLdapClient.

    This maintains API compatibility during the SOLID refactoring.
    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize with backward compatibility."""
        warnings.warn(
            "FlextLdapSimpleClient is deprecated. Use FlextLdapClient instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(container)


# ===== FACTORY FUNCTION =====


def create_ldap_client(container: FlextContainer | None = None) -> FlextLdapClient:
    """Factory function to create SOLID LDAP client.

    Returns:
        FlextLdapClient: Fully configured SOLID LDAP client

    """
    return FlextLdapClient(container)
