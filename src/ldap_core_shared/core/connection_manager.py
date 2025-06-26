"""Enterprise LDAP Connection Manager with Advanced Pool Management."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import TYPE_CHECKING

import ldap3
from ldap3 import ALL, Connection, LDAPException, Server, Tls
from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPConnectionResult
from ldap_core_shared.utils.constants import (
    # Constants for magic values
    CONNECTION_MAX_AGE,
    CONNECTION_MAX_IDLE,
    DEFAULT_LARGE_LIMIT,
    DEFAULT_LDAP_PORT,
    DEFAULT_LDAP_TIMEOUT,
    DEFAULT_MAX_ITEMS,
    DEFAULT_MAX_POOL_SIZE,
    DEFAULT_POOL_SIZE,
)
from ldap_core_shared.utils.performance import (
    ConnectionPoolMetrics,
    LDAPMetrics,
    PerformanceMonitor,
)

# Vectorized connection pool import (lazy import to avoid circular dependency)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


class ConnectionInfo(BaseModel):
    """LDAP connection configuration."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    host: str
    port: int = Field(default=DEFAULT_LDAP_PORT, gt=0, lt=65536)
    base_dn: str
    bind_dn: str
    bind_password: str

    # Security settings
    use_ssl: bool = False
    use_tls: bool = False
    verify_cert: bool = True

    # Connection settings
    timeout: int = Field(default=DEFAULT_LDAP_TIMEOUT, gt=0)
    auto_bind: bool = True
    authentication: str = "SIMPLE"

    # SSH Tunnel settings (optional)
    ssh_host: str | None = None
    ssh_port: int = Field(default=22, gt=0, lt=65536)
    ssh_username: str | None = None
    ssh_password: str | None = None
    ssh_key_file: str | None = None


class PooledConnection:
    """Wrapper for pooled LDAP connections with metadata."""

    def __init__(self, connection: Connection, connection_info: ConnectionInfo) -> None:
        """Initialize pooled connection."""
        self.connection = connection
        self.connection_info = connection_info
        self.created_at = time.time()
        self.last_used = time.time()
        self.use_count = 0
        self.is_healthy = True
        self.is_in_use = False

    def mark_used(self) -> None:
        """Mark connection as recently used."""
        self.last_used = time.time()
        self.use_count += 1

    def is_stale(self, max_age_seconds: int = CONNECTION_MAX_AGE) -> bool:
        """Check if connection is stale and should be recreated."""
        return (time.time() - self.created_at) > max_age_seconds

    def is_idle(self, max_idle_seconds: int = CONNECTION_MAX_IDLE) -> bool:
        """Check if connection has been idle too long."""
        return (time.time() - self.last_used) > max_idle_seconds

    def validate_health(self) -> bool:
        """Perform health check on connection."""
        try:
            if not self.connection.bound:
                return False

            # Perform lightweight search to verify connection
            self.connection.search(
                search_base=self.connection_info.base_dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                size_limit=1,
            )
        except Exception:
            return False
        else:
            return True


class PerformanceHelper:
    """🔥 ZERO DUPLICATION - Centralized performance monitoring utilities."""

    @staticmethod
    def record_connection_operation(
        monitor: PerformanceMonitor,
        start_time: float,
        success: bool,
    ) -> None:
        """Record connection operation performance - NO DUPLICATION."""
        duration = time.time() - start_time
        monitor.record_operation(duration, success=success)


class ConnectionFactory:
    """🔥 ZERO DUPLICATION - Centralized connection creation factory."""

    @staticmethod
    def create_tls_config(connection_info: ConnectionInfo) -> Tls | None:
        """Create TLS configuration - NO DUPLICATION."""
        if connection_info.use_ssl or connection_info.use_tls:
            return Tls(validate=connection_info.verify_cert)
        return None

    @staticmethod
    def create_server(connection_info: ConnectionInfo) -> Server:
        """Create LDAP server configuration - NO DUPLICATION."""
        tls_config = ConnectionFactory.create_tls_config(connection_info)

        return Server(
            host=connection_info.host,
            port=connection_info.port,
            use_ssl=connection_info.use_ssl,
            tls=tls_config,
            get_info=ALL,
        )

    @staticmethod
    def create_connection(connection_info: ConnectionInfo) -> Connection:
        """Create LDAP connection - NO DUPLICATION."""
        server = ConnectionFactory.create_server(connection_info)

        return Connection(
            server=server,
            user=connection_info.bind_dn,
            password=connection_info.bind_password,
            auto_bind=connection_info.auto_bind,
            authentication=ldap3.SIMPLE,
            receive_timeout=connection_info.timeout,
        )


class ConnectionPool:
    """🔥🔥 Enterprise LDAP connection pool with ZERO DUPLICATION."""

    def __init__(
        self,
        connection_info: ConnectionInfo,
        pool_size: int = DEFAULT_POOL_SIZE,
        max_pool_size: int = DEFAULT_MAX_POOL_SIZE,
    ) -> None:
        """Initialize connection pool.

        Args:
            connection_info: LDAP connection configuration
            pool_size: Initial pool size
            max_pool_size: Maximum pool size
        """
        self.connection_info = connection_info
        self.pool_size = pool_size
        self.max_pool_size = max_pool_size

        # Pool state
        self._pool: list[PooledConnection] = []
        self._pool_lock = asyncio.Lock()
        self._total_connections_created = 0

        # Performance monitoring
        self._performance_monitor = PerformanceMonitor("connection_pool")
        self._metrics = {
            "connections_created": 0,
            "connections_reused": 0,
            "connections_closed": 0,
            "pool_hits": 0,
            "pool_misses": 0,
        }

    async def _create_connection(self) -> PooledConnection:
        """🔥 Create new LDAP connection using centralized factory - NO DUPLICATION."""
        connection = ConnectionFactory.create_connection(self.connection_info)

        pooled_conn = PooledConnection(connection, self.connection_info)
        self._total_connections_created += 1
        self._metrics["connections_created"] += 1

        return pooled_conn

    async def _cleanup_stale_connections(self) -> None:
        """Clean up stale and idle connections."""
        async with self._pool_lock:
            active_connections = []

            for pooled_conn in self._pool:
                if pooled_conn.is_in_use:
                    # Keep connections that are in use
                    active_connections.append(pooled_conn)
                elif (
                    pooled_conn.is_stale()
                    or pooled_conn.is_idle()
                    or not pooled_conn.validate_health()
                ):
                    # Close stale/unhealthy connections
                    with contextlib.suppress(Exception):
                        pooled_conn.connection.unbind()
                        self._metrics["connections_closed"] += 1
                else:
                    # Keep healthy connections
                    active_connections.append(pooled_conn)

            self._pool = active_connections

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[PooledConnection]:
        """Get connection from pool.

        Yields:
            PooledConnection: Connection from pool
        """
        start_time = time.time()
        available_connection = None

        try:
            # Clean up stale connections
            await self._cleanup_stale_connections()

            # Try to get connection from pool
            async with self._pool_lock:
                # Find available connection
                for pooled_conn in self._pool:
                    if not pooled_conn.is_in_use and pooled_conn.validate_health():
                        available_connection = pooled_conn
                        break

                if available_connection:
                    # Use existing connection
                    available_connection.is_in_use = True
                    available_connection.mark_used()
                    self._metrics["pool_hits"] += 1
                    self._metrics["connections_reused"] += 1
                # Create new connection if pool not at max capacity
                elif len(self._pool) < self.max_pool_size:
                    available_connection = await self._create_connection()
                    available_connection.is_in_use = True
                    self._pool.append(available_connection)
                    self._metrics["pool_misses"] += 1
                else:
                    connection_pool_exhausted_msg = "Connection pool exhausted"
                    raise RuntimeError(connection_pool_exhausted_msg)

            acquisition_time = time.time() - start_time
            self._performance_monitor.record_operation(acquisition_time, success=True)

            yield available_connection

        finally:
            # Return connection to pool
            if available_connection:
                available_connection.is_in_use = False

    async def close_pool(self) -> None:
        """Close all connections in pool."""
        async with self._pool_lock:
            for pooled_conn in self._pool:
                with contextlib.suppress(Exception):
                    pooled_conn.connection.unbind()

            self._pool.clear()

    def get_metrics(self) -> ConnectionPoolMetrics:
        """Get connection pool metrics."""
        active_count = sum(1 for conn in self._pool if conn.is_in_use)
        idle_count = len(self._pool) - active_count

        # Calculate utilization
        utilization = (
            (active_count / self.max_pool_size) * DEFAULT_MAX_ITEMS
            if self.max_pool_size > 0
            else 0.0
        )

        # Get performance metrics
        perf_metrics = self._performance_monitor.get_metrics()

        return ConnectionPoolMetrics(
            pool_size=len(self._pool),
            active_connections=active_count,
            idle_connections=idle_count,
            connections_created=self._metrics["connections_created"],
            connections_reused=self._metrics["connections_reused"],
            connections_closed=self._metrics["connections_closed"],
            average_acquisition_time=perf_metrics.average_duration
            * DEFAULT_LARGE_LIMIT,  # Convert to ms
            max_acquisition_time=perf_metrics.max_duration * DEFAULT_LARGE_LIMIT,  # Convert to ms
            pool_utilization=utilization,
        )


class LDAPConnectionManager:
    """Enterprise LDAP connection manager with advanced features."""

    def __init__(self, connection_info: ConnectionInfo) -> None:
        """Initialize connection manager.

        Args:
            connection_info: LDAP connection configuration
        """
        self.connection_info = connection_info
        self._pool: ConnectionPool | None = None
        self._performance_monitor = PerformanceMonitor("connection_manager")

    async def initialize_pool(
        self,
        pool_size: int = DEFAULT_POOL_SIZE,
        max_pool_size: int = DEFAULT_MAX_POOL_SIZE,
    ) -> None:
        """Initialize connection pool.

        Args:
            pool_size: Initial pool size
            max_pool_size: Maximum pool size
        """
        self._pool = ConnectionPool(
            connection_info=self.connection_info,
            pool_size=pool_size,
            max_pool_size=max_pool_size,
        )

    @contextmanager
    def get_connection(self) -> Iterator[ldap3.Connection]:
        """🔥🔥 Get LDAP connection using centralized factory - NO DUPLICATION.

        Yields:
            Connection: LDAP connection
        """
        start_time = time.time()
        connection = None

        try:
            connection = ConnectionFactory.create_connection(self.connection_info)
            yield connection

            # Record successful connection
            duration = time.time() - start_time
            self._performance_monitor.record_operation(duration, success=True)

        except Exception:
            # Record failed connection
            duration = time.time() - start_time
            self._performance_monitor.record_operation(duration, success=False)
            raise

        finally:
            if connection:
                try:
                    connection.unbind()
                except (LDAPException, OSError, AttributeError) as e:
                    # Log specific unbind errors but don't raise
                    self._logger.warning(f"Error during connection unbind: {e}")
                except Exception as e:
                    # Unexpected unbind error - log with more detail
                    self._logger.error(f"Unexpected error during connection unbind: {e}", exc_info=True)

    @asynccontextmanager
    async def get_pooled_connection(self) -> AsyncIterator[PooledConnection]:
        """Get connection from pool (async version).

        Yields:
            PooledConnection: Pooled LDAP connection
        """
        if not self._pool:
            await self.initialize_pool()

        if self._pool is None:
            msg = "Connection pool not initialized"
            raise RuntimeError(msg)

        async with self._pool.get_connection() as pooled_conn:
            yield pooled_conn

    def test_connection(self) -> LDAPConnectionResult:
        """Test LDAP connection.

        Returns:
            LDAPConnectionResult: Connection test result
        """
        start_time = time.time()

        try:
            with self.get_connection() as connection:
                connection_time = time.time() - start_time

                # Test basic search
                search_start = time.time()
                connection.search(
                    search_base=self.connection_info.base_dn,
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    size_limit=1,
                )
                response_time = time.time() - search_start

                return LDAPConnectionResult(
                    connected=True,
                    host=self.connection_info.host,
                    port=self.connection_info.port,
                    auth_method=self.connection_info.authentication,
                    encryption="ssl" if self.connection_info.use_ssl else "none",
                    connection_time=connection_time,
                    response_time=response_time,
                    ldap_info={
                        "server_info": (
                            str(connection.server.info)
                            if connection.server.info
                            else ""
                        ),
                        "schema_info": (
                            str(connection.server.schema)
                            if connection.server.schema
                            else ""
                        ),
                    },
                )

        except Exception as connection_error:
            connection_time = time.time() - start_time

            return LDAPConnectionResult(
                connected=False,
                host=self.connection_info.host,
                port=self.connection_info.port,
                connection_time=connection_time,
                response_time=0.0,
                connection_error=str(connection_error),
            )

    def get_performance_metrics(self) -> LDAPMetrics:
        """Get performance metrics."""
        return self._performance_monitor.get_metrics()

    async def close(self) -> None:
        """Close connection manager and cleanup resources."""
        if self._pool:
            await self._pool.close_pool()
