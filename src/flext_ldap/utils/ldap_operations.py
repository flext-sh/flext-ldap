from __future__ import annotations

from flext_ldap.utils.constants import DEFAULT_LARGE_LIMIT

"""LDAP operation utilities for common operations across projects."""


import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import ldap3
from ldap3 import BASE, LEVEL, SUBTREE, Connection, Server

from flext_ldap.core.config import LDAPServerConfig
from flext_ldap.exceptions import OperationError
from flext_ldap.models import LDAPEntry

# Import unified Result for consistent return values
try:
    from flext_ldap.domain.results import Result
except ImportError:
    # Fallback for import order issues
    Result = None
from flext_ldap.domain_events import (
    LDAPConnectionEvent,
    LDAPOperationEvent,
)
from flext_ldap.event_handler import dispatch_event

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


class SearchScope(Enum):
    """LDAP search scope enumeration."""

    BASE = BASE
    LEVEL = LEVEL
    SUBTREE = SUBTREE


@dataclass
class ConnectionStats:
    """Connection statistics."""

    total_connections: int = 0
    active_connections: int = 0
    failed_connections: int = 0
    total_operations: int = 0
    failed_operations: int = 0


class LDAPConnectionPool:
    """LDAP connection pool for efficient connection management.

    Manages a pool of LDAP connections with automatic reconnection
    and load balancing.
    """

    def __init__(
        self,
        config: LDAPServerConfig,
        pool_size: int = 5,
        max_retries: int = 3,
    ) -> None:
        """Initialize connection pool."""
        self.config = config
        self.pool_size = pool_size
        self.max_retries = max_retries
        self.logger = logging.getLogger(__name__)

        self._pool: list[Connection] = []
        self._pool_lock = asyncio.Lock()
        self._stats = ConnectionStats()
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the connection pool."""
        if self._initialized:
            return

        async with self._pool_lock:
            for i in range(self.pool_size):
                try:
                    connection = await self._create_connection()
                    self._pool.append(connection)
                    self._stats.active_connections += 1
                    self.logger.debug("Created connection %s/%s", i + 1, self.pool_size)
                except Exception as e:
                    self.logger.exception(
                        "Failed to create connection %s: %s", i + 1, e
                    )
                    self._stats.failed_connections += 1

            self._stats.total_connections = len(self._pool)
            self._initialized = True

            self.logger.info(
                "Connection pool initialized: %s/%s connections",
                len(self._pool),
                self.pool_size,
            )

    async def _create_connection(self) -> Connection:
        """Create a new LDAP connection."""
        server = Server(
            host=self.config.host,
            port=self.config.port,
            use_ssl=self.config.use_ssl,
            get_info=ldap3.ALL,
        )

        connection = Connection(
            server,
            user=self.config.bind_dn,
            password=self.config.password,
            auto_bind=True,
            read_only=False,
        )

        # Dispatch connection event
        await dispatch_event(
            LDAPConnectionEvent(
                host=self.config.host,
                port=self.config.port,
                bind_dn=self.config.bind_dn,
                connected=True,
                connection_id=str(id(connection)),
            ),
        )

        return connection

    @asynccontextmanager
    async def get_connection(self) -> AsyncGenerator[Connection]:
        """Get a connection from the pool."""
        if not self._initialized:
            await self.initialize()

        connection = None
        try:
            async with self._pool_lock:
                if self._pool:
                    connection = self._pool.pop()

            if connection is None or not connection.bound:
                connection = await self._create_connection()

            yield connection

        except Exception as e:
            self.logger.exception("Connection error: %s", e)
            self._stats.failed_operations += 1
            raise
        finally:
            if connection and connection.bound:
                async with self._pool_lock:
                    if len(self._pool) < self.pool_size:
                        self._pool.append(connection)
                        connection.unbind()

    async def close_all(self) -> None:
        """Close all connections in the pool."""
        async with self._pool_lock:
            for connection in self._pool:
                try:
                    connection.unbind()
                except Exception as e:
                    self.logger.exception("Error closing connection: %s", e)

            self._pool.clear()
            self._stats.active_connections = 0
            self._initialized = False

            self.logger.info("All connections closed")

    def get_stats(self) -> ConnectionStats:
        """Get connection pool statistics."""
        return self._stats


class LDAPOperationHelper:
    """Helper class for common LDAP operations.

    Provides high-level methods for LDAP operations with consistent
    error handling and event dispatching.
    """

    def __init__(self, connection_pool: LDAPConnectionPool) -> None:
        """Initialize operation helper."""
        self.pool = connection_pool
        self.logger = logging.getLogger(__name__)

    async def search(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        scope: SearchScope = SearchScope.SUBTREE,
        attributes: list[str] | None = None,
        size_limit: int = 0,
    ) -> Result[list[LDAPEntry]] | list[LDAPEntry]:
        """Perform LDAP search operation."""
        start_time = asyncio.get_event_loop().time()

        try:
            async with self.pool.get_connection() as conn:
                success = conn.search(
                    search_base=base_dn,
                    search_filter=search_filter,
                    search_scope=scope.value,
                    attributes=attributes or ldap3.ALL_ATTRIBUTES,
                    size_limit=size_limit,
                )

                if not success:
                    msg = f"Search failed: {conn.result}"
                    raise OperationError(msg, operation_type="search")

                entries: list[Any] = []
                for entry in conn.entries:
                    # Convert ldap3 entry to our LDAPEntry model
                    attributes_dict: dict[str, Any] = {}
                    for attr_name in entry.entry_attributes:
                        attr_values = getattr(entry, attr_name)
                        if hasattr(attr_values, "values"):
                            attributes_dict[attr_name] = [
                                str(v) for v in attr_values.values
                            ]
                        else:
                            attributes_dict[attr_name] = [str(attr_values)]

                    entries.append(
                        LDAPEntry(dn=str(entry.entry_dn), attributes=attributes_dict)
                    )

                duration = asyncio.get_event_loop().time() - start_time
                execution_time_ms = duration * 1000

                # Dispatch operation event
                await dispatch_event(
                    LDAPOperationEvent(
                        operation="search",
                        dn=base_dn,
                        success=True,
                        duration_ms=duration * DEFAULT_LARGE_LIMIT,
                        entry_count=len(entries),
                    ),
                )

                # Return unified Result if available, otherwise legacy list
                if Result is not None:
                    return Result.ok(
                        entries,
                        execution_time_ms=execution_time_ms,
                        context={
                            "base_dn": base_dn,
                            "filter": search_filter,
                            "scope": scope.name,
                            "count": len(entries),
                        },
                    )
                return entries

        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            execution_time_ms = duration * 1000

            await dispatch_event(
                LDAPOperationEvent(
                    operation="search",
                    dn=base_dn,
                    success=False,
                    duration_ms=duration * DEFAULT_LARGE_LIMIT,
                    error_message=str(e),
                ),
            )

            self.logger.exception("Search operation failed: %s", e)

            # Return unified Result error if available, otherwise raise
            if Result is not None:
                return Result.from_exception(
                    e,
                    default_data=[],
                    execution_time_ms=execution_time_ms,
                )
            raise

    async def add_entry(self, entry: LDAPEntry) -> bool:
        """Add an LDAP entry."""
        start_time = asyncio.get_event_loop().time()

        try:
            async with self.pool.get_connection() as conn:
                success = conn.add(entry.dn, attributes=entry.attributes)

                duration = asyncio.get_event_loop().time() - start_time

                await dispatch_event(
                    LDAPOperationEvent(
                        operation="add",
                        dn=entry.dn,
                        success=success,
                        duration_ms=duration * DEFAULT_LARGE_LIMIT,
                        error_message=None if success else str(conn.result),
                    ),
                )

                if not success:
                    self.logger.error("Add operation failed: %s", conn.result)

                return success

        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time

            await dispatch_event(
                LDAPOperationEvent(
                    operation="add",
                    dn=entry.dn,
                    success=False,
                    duration_ms=duration * DEFAULT_LARGE_LIMIT,
                    error_message=str(e),
                ),
            )

            self.logger.exception("Add operation failed: %s", e)
            return False

    async def modify_entry(self, dn: str, changes: dict[str, Any]) -> bool:
        """Modify an LDAP entry."""
        start_time = asyncio.get_event_loop().time()

        try:
            async with self.pool.get_connection() as conn:
                success = conn.modify(dn, changes)

                duration = asyncio.get_event_loop().time() - start_time

                await dispatch_event(
                    LDAPOperationEvent(
                        operation="modify",
                        dn=dn,
                        success=success,
                        duration_ms=duration * DEFAULT_LARGE_LIMIT,
                        attributes_modified=list(changes.keys()),
                        error_message=None if success else str(conn.result),
                    ),
                )

                if not success:
                    self.logger.error("Modify operation failed: %s", conn.result)

                return success

        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time

            await dispatch_event(
                LDAPOperationEvent(
                    operation="modify",
                    dn=dn,
                    success=False,
                    duration_ms=duration * DEFAULT_LARGE_LIMIT,
                    error_message=str(e),
                ),
            )

            self.logger.exception("Modify operation failed: %s", e)
            return False

    async def delete_entry(self, dn: str) -> bool:
        """Delete an LDAP entry."""
        start_time = asyncio.get_event_loop().time()

        try:
            async with self.pool.get_connection() as conn:
                success = conn.delete(dn)

                duration = asyncio.get_event_loop().time() - start_time

                await dispatch_event(
                    LDAPOperationEvent(
                        operation="delete",
                        dn=dn,
                        success=success,
                        duration_ms=duration * DEFAULT_LARGE_LIMIT,
                        error_message=None if success else str(conn.result),
                    ),
                )

                if not success:
                    self.logger.error("Delete operation failed: %s", conn.result)

                return success

        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time

            await dispatch_event(
                LDAPOperationEvent(
                    operation="delete",
                    dn=dn,
                    success=False,
                    duration_ms=duration * DEFAULT_LARGE_LIMIT,
                    error_message=str(e),
                ),
            )

            self.logger.exception("Delete operation failed: %s", e)
            return False

    async def test_connection(self) -> bool:
        """Test LDAP connection."""
        try:
            async with self.pool.get_connection() as conn:
                return conn.bound
        except Exception as e:
            self.logger.exception("Connection test failed: %s", e)
            return False


async def connect_ldap(config: LDAPServerConfig) -> Connection:
    """Create a single LDAP connection."""
    server = Server(
        host=config.host,
        port=config.port,
        use_ssl=config.use_ssl,
        get_info=ldap3.ALL,
    )

    return Connection(
        server,
        user=config.bind_dn,
        password=config.password,
        auto_bind=True,
    )


async def validate_connection(config: LDAPServerConfig) -> dict[str, Any]:
    """Validate LDAP connection and return connection info."""
    try:
        connection = await connect_ldap(config)

        # Get server info
        server_info = {
            "connected": connection.bound,
            "server_host": config.host,
            "server_port": config.port,
            "bind_dn": config.bind_dn,
            "schema_info": None,
            "server_info": None,
        }

        if connection.bound:
            # Get basic server information
            if connection.server.info:
                server_info["server_info"] = {
                    "vendor": getattr(connection.server.info, "vendor_name", "Unknown"),
                    "version": getattr(
                        connection.server.info, "vendor_version", "Unknown"
                    ),
                    "naming_contexts": getattr(
                        connection.server.info, "naming_contexts", []
                    ),
                }

            # Get basic schema information
            if connection.server.schema:
                schema = connection.server.schema
                server_info["schema_info"] = {
                    "object_classes": (
                        len(schema.object_classes) if schema.object_classes else 0
                    ),
                    "attribute_types": (
                        len(schema.attribute_types) if schema.attribute_types else 0
                    ),
                }

        connection.unbind()
        return server_info

    except Exception as e:
        return {
            "connected": False,
            "error": str(e),
            "server_host": config.host,
            "server_port": config.port,
        }
