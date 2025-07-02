"""LDAP Connection Pool Implementations."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

from flext_ldap.connections.base import LDAPConnectionInfo
from flext_ldap.exceptions.connection import LDAPConnectionError
from flext_ldap.interfaces import (
    BaseConnectionComponent,
    IConnectionFactory,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    import ldap3


logger = logging.getLogger(__name__)


class AsyncConnectionPool(BaseConnectionComponent):
    """🔥 Single Responsibility: Manage connection pools only.

    SOLID Compliance:
    - S: Only manages connection pools
    - O: Extensible pool strategies
    - L: Interchangeable with other pools
    - I: Implements focused IConnectionPool
    - D: Depends on IConnectionFactory abstraction
    """

    def __init__(
        self,
        connection_info: LDAPConnectionInfo,
        factory: IConnectionFactory,
        pool_size: int = 10,
        max_pool_size: int = 20,
    ) -> None:
        """Initialize connection pool.

        Args:
            connection_info: Connection configuration
            factory: Connection factory for creating connections
            pool_size: Initial pool size
            max_pool_size: Maximum pool size
        """
        super().__init__(connection_info)
        self._factory = factory
        self._pool_size = pool_size
        self._max_pool_size = max_pool_size

        # Pool state
        self._pool: list[ldap3.Connection] = []
        self._active_connections: set[ldap3.Connection] = set()
        self._lock = asyncio.Lock()

        logger.info(
            "🔥 SOLID AsyncConnectionPool initialized (size: %s, max: %s)",
            pool_size,
            max_pool_size,
        )

    async def initialize(self) -> None:
        """Initialize connection pool."""
        await self.initialize_pool(self._pool_size)

    async def cleanup(self) -> None:
        """Cleanup all pool connections."""
        await self.cleanup_pool()

    async def initialize_pool(self, size: int) -> None:
        """🔥 Initialize connection pool with specified size.

        Args:
            size: Number of connections to create
        """
        async with self._lock:
            logger.info("Initializing connection pool with %s connections", size)

            for i in range(size):
                try:
                    connection = self._factory.create_connection(self.connection_info)
                    if connection.bind():
                        self._pool.append(connection)
                        logger.debug("Created pooled connection %s/%s", i + 1, size)
                    else:
                        logger.warning("Failed to bind pooled connection %s", i + 1)
                except Exception as e:
                    logger.exception(
                        "Failed to create pooled connection %s: %s",
                        i + 1,
                        e,
                    )

    async def cleanup_pool(self) -> None:
        """🔥 Cleanup all pooled connections."""
        async with self._lock:
            logger.info("Cleaning up connection pool")

            # Close active connections
            for connection in self._active_connections.copy():
                with contextlib.suppress(Exception):
                    connection.unbind()

            # Close pooled connections
            for connection in self._pool:
                with contextlib.suppress(Exception):
                    connection.unbind()

            self._active_connections.clear()
            self._pool.clear()

    @contextlib.asynccontextmanager
    async def acquire_connection(self) -> AsyncGenerator[ldap3.Connection, None]:
        """🔥 Acquire connection from pool.

        Yields:
            LDAP connection from pool
        """
        connection = None

        try:
            async with self._lock:
                # Try to get connection from pool
                if self._pool:
                    connection = self._pool.pop()
                # Create new connection if pool is empty and under limit
                elif len(self._active_connections) < self._max_pool_size:
                    connection = self._factory.create_connection(self.connection_info)
                    if not connection.bind():
                        msg = "Failed to bind new connection"
                        raise LDAPConnectionError(msg)
                else:
                    msg = "Pool exhausted and at maximum size"
                    raise LDAPConnectionError(msg)

                self._active_connections.add(connection)

            yield connection

        finally:
            if connection:
                async with self._lock:
                    self._active_connections.discard(connection)

                    # Return to pool if still healthy
                    if connection.bound and len(self._pool) < self._pool_size:
                        self._pool.append(connection)
                    else:
                        with contextlib.suppress(Exception):
                            connection.unbind()

    async def get_pool_stats(self) -> dict[str, int]:
        """Get connection pool statistics.

        Returns:
            Pool statistics dictionary
        """
        async with self._lock:
            return {
                "pool_size": len(self._pool),
                "active_connections": len(self._active_connections),
                "max_pool_size": self._max_pool_size,
                "total_capacity": self._max_pool_size,
            }
