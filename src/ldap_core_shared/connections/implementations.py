"""🔥 SOLID Principle Implementations for LDAP Connection Management.

This module provides concrete implementations following SOLID principles:
- Single Responsibility: Each class has one clear purpose
- Open/Closed: Open for extension, closed for modification
- Liskov Substitution: All implementations are interchangeable
- Interface Segregation: Small, focused implementations
- Dependency Inversion: Depend on abstractions, not concretions

ZERO TOLERANCE SOLID implementation following enterprise patterns.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
from typing import TYPE_CHECKING, Any, Self

# Constants for magic values
MAX_RECENT_OPERATIONS = 100

import ldap3

from ldap_core_shared.connections.interfaces import (
    BaseConnectionComponent,
    IConnectionFactory,
    IConnectionPool,
    IHealthMonitor,
    IPerformanceTracker,
    ISecurityManager,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator

    from ldap_core_shared.connections.base import LDAPConnectionInfo

logger = logging.getLogger(__name__)


# ============================================================================
# 🔥 SINGLE RESPONSIBILITY IMPLEMENTATIONS
# ============================================================================


class StandardConnectionFactory(BaseConnectionComponent):
    """🎯 Single Responsibility: Create LDAP connections only.

    SOLID Compliance:
    - S: Only creates connections, nothing else
    - O: Extensible through inheritance
    - L: Interchangeable with other factories
    - I: Implements focused IConnectionFactory
    - D: Depends on LDAPConnectionInfo abstraction
    """

    def __init__(
        self,
        connection_info: LDAPConnectionInfo,
        security_manager: ISecurityManager | None = None,
    ) -> None:
        """Initialize factory with dependencies.

        Args:
            connection_info: Connection configuration
            security_manager: Optional security manager for TLS
        """
        super().__init__(connection_info)
        self._security_manager = security_manager or StandardSecurityManager(
            connection_info,
        )

    async def initialize(self) -> None:
        """Initialize factory component."""
        await self._security_manager.validate_credentials(self.connection_info)
        logger.info("🔥 SOLID StandardConnectionFactory initialized")

    async def cleanup(self) -> None:
        """Cleanup factory resources."""
        logger.debug("StandardConnectionFactory cleaned up")

    def create_connection(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> ldap3.Connection:
        """🔥 ZERO DUPLICATION: Create LDAP connection using factory pattern.

        Args:
            connection_info: Connection configuration

        Returns:
            Configured LDAP connection
        """
        # Create TLS configuration
        tls_config = None
        if connection_info.use_ssl:
            tls_config = ldap3.Tls(validate=ssl.CERT_REQUIRED)

        # Create server
        server = ldap3.Server(
            host=connection_info.host,
            port=connection_info.port,
            use_ssl=connection_info.use_ssl,
            tls=tls_config,
            get_info=ldap3.ALL,
        )

        # Create connection
        return ldap3.Connection(
            server=server,
            user=connection_info.bind_dn,
            password=connection_info.bind_password.get_secret_value(),
            authentication=connection_info.get_ldap3_authentication(),
            auto_bind=connection_info.auto_bind,
            lazy=False,
        )


class AsyncConnectionPool(BaseConnectionComponent):
    """🎯 Single Responsibility: Manage connection pooling only.

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
                        "Failed to create pooled connection %s: %s", i + 1, e
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
                    logger.debug("Retrieved connection from pool")
                elif len(self._active_connections) < self._max_pool_size:
                    # Create new connection if under limit
                    connection = self._factory.create_connection(self.connection_info)
                    if not connection.bind():
                        msg = "Failed to bind new connection"
                        raise ldap3.LDAPBindError(msg)
                    logger.debug("Created new connection")
                else:
                    msg = "Connection pool exhausted"
                    raise RuntimeError(msg)

                self._active_connections.add(connection)

            yield connection

        finally:
            await self.return_connection(connection)

    async def return_connection(self, connection: ldap3.Connection | None) -> None:
        """🔥 Return connection to pool.

        Args:
            connection: Connection to return
        """
        if not connection:
            return

        async with self._lock:
            self._active_connections.discard(connection)

            if len(self._pool) < self._pool_size and connection.bound:
                self._pool.append(connection)
                logger.debug("Returned connection to pool")
            else:
                with contextlib.suppress(Exception):
                    connection.unbind()
                    logger.debug("Closed excess connection")


class PerformanceTracker(BaseConnectionComponent):
    """🎯 Single Responsibility: Track performance metrics only.

    SOLID Compliance:
    - S: Only tracks performance metrics
    - O: Extensible metric types
    - L: Interchangeable with other trackers
    - I: Implements focused IPerformanceTracker
    - D: No dependencies on concretions
    """

    def __init__(self, connection_info: LDAPConnectionInfo) -> None:
        """Initialize performance tracker.

        Args:
            connection_info: Connection configuration
        """
        super().__init__(connection_info)
        self._metrics: dict[str, Any] = {
            "operations_count": 0,
            "total_duration": 0.0,
            "success_count": 0,
            "error_count": 0,
            "operations_by_type": {},
        }
        self._recent_operations: list[dict[str, Any]] = []

        logger.info("🔥 SOLID PerformanceTracker initialized")

    async def initialize(self) -> None:
        """Initialize performance tracker."""
        logger.debug("PerformanceTracker initialized")

    async def cleanup(self) -> None:
        """Cleanup performance tracker."""
        logger.debug("PerformanceTracker cleaned up")

    def record_operation(
        self,
        operation_type: str,
        duration: float,
        success: bool,
    ) -> None:
        """🔥 Record operation performance metrics.

        Args:
            operation_type: Type of operation (search, add, modify, delete)
            duration: Operation duration in seconds
            success: Whether operation succeeded
        """
        # Update general metrics
        self._metrics["operations_count"] += 1
        self._metrics["total_duration"] += duration

        if success:
            self._metrics["success_count"] += 1
        else:
            self._metrics["error_count"] += 1

        # Update operation type metrics
        if operation_type not in self._metrics["operations_by_type"]:
            self._metrics["operations_by_type"][operation_type] = {
                "count": 0,
                "total_duration": 0.0,
                "avg_duration": 0.0,
            }

        type_metrics = self._metrics["operations_by_type"][operation_type]
        type_metrics["count"] += 1
        type_metrics["total_duration"] += duration
        type_metrics["avg_duration"] = (
            type_metrics["total_duration"] / type_metrics["count"]
        )

        # Keep recent operations (last 100)
        self._recent_operations.append(
            {
                "type": operation_type,
                "duration": duration,
                "success": success,
                "timestamp": time.time(),
            },
        )

        if len(self._recent_operations) > MAX_RECENT_OPERATIONS:
            self._recent_operations = self._recent_operations[-MAX_RECENT_OPERATIONS:]

        logger.debug(
            f"Recorded {operation_type} operation: {duration:.3f}s ({'success' if success else 'error'})",
        )

    def get_metrics(self) -> dict[str, Any]:
        """🔥 Get comprehensive performance metrics.

        Returns:
            Performance metrics dictionary
        """
        # Calculate derived metrics
        total_ops = self._metrics["operations_count"]
        avg_duration = (
            self._metrics["total_duration"] / total_ops if total_ops > 0 else 0.0
        )
        success_rate = (
            self._metrics["success_count"] / total_ops if total_ops > 0 else 0.0
        )

        return {
            **self._metrics,
            "average_duration": avg_duration,
            "success_rate": success_rate,
            "error_rate": 1.0 - success_rate,
            "recent_operations": self._recent_operations[-10:],  # Last 10
        }


class StandardHealthMonitor(BaseConnectionComponent):
    """🎯 Single Responsibility: Monitor connection health only.

    SOLID Compliance:
    - S: Only monitors health
    - O: Extensible health checks
    - L: Interchangeable with other monitors
    - I: Implements focused IHealthMonitor
    - D: No dependencies on concretions
    """

    def __init__(
        self,
        connection_info: LDAPConnectionInfo,
        check_interval: float = 30.0,
    ) -> None:
        """Initialize health monitor.

        Args:
            connection_info: Connection configuration
            check_interval: Health check interval in seconds
        """
        super().__init__(connection_info)
        self._check_interval = check_interval
        self._monitoring_task: asyncio.Task[None] | None = None
        self._shutdown_event = asyncio.Event()

        logger.info(
            f"🔥 SOLID StandardHealthMonitor initialized (interval: {check_interval}s)",
        )

    async def initialize(self) -> None:
        """Initialize health monitor."""
        await self.start_monitoring()

    async def cleanup(self) -> None:
        """Cleanup health monitor."""
        await self.stop_monitoring()

    async def check_health(self, connection: ldap3.Connection) -> bool:
        """🔥 Check if connection is healthy.

        Args:
            connection: Connection to check

        Returns:
            True if healthy
        """
        try:
            if not connection.bound:
                return False

            # Perform lightweight search
            connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                size_limit=1,
            )

            logger.debug("Health check passed")
            return True

        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False

    async def start_monitoring(self) -> None:
        """🔥 Start health monitoring background task."""
        if self._monitoring_task:
            return

        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Health monitoring started")

    async def stop_monitoring(self) -> None:
        """🔥 Stop health monitoring."""
        if not self._monitoring_task:
            return

        self._shutdown_event.set()

        try:
            await asyncio.wait_for(self._monitoring_task, timeout=5.0)
        except TimeoutError:
            self._monitoring_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitoring_task

        self._monitoring_task = None
        logger.info("Health monitoring stopped")

    async def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(self._check_interval)
                # In real implementation, would check pool connections
                logger.debug("Health monitoring cycle completed")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Health monitoring error: {e}")


class StandardSecurityManager(BaseConnectionComponent):
    """🎯 Single Responsibility: Handle security concerns only.

    SOLID Compliance:
    - S: Only handles security
    - O: Extensible security policies
    - L: Interchangeable with other security managers
    - I: Implements focused ISecurityManager
    - D: No dependencies on concretions
    """

    def __init__(self, connection_info: LDAPConnectionInfo) -> None:
        """Initialize security manager.

        Args:
            connection_info: Connection configuration
        """
        super().__init__(connection_info)
        logger.info("🔥 SOLID StandardSecurityManager initialized")

    async def initialize(self) -> None:
        """Initialize security manager."""
        logger.debug("SecurityManager initialized")

    async def cleanup(self) -> None:
        """Cleanup security manager."""
        logger.debug("SecurityManager cleaned up")

    async def setup_tls(self, connection_info: LDAPConnectionInfo) -> ldap3.Tls | None:
        """🔥 Setup TLS configuration.

        Args:
            connection_info: Connection configuration

        Returns:
            TLS configuration object or None
        """
        if not connection_info.use_ssl:
            return None

        logger.info("Setting up TLS configuration")
        return ldap3.Tls(validate=ssl.CERT_REQUIRED)

    async def validate_credentials(self, connection_info: LDAPConnectionInfo) -> bool:
        """🔥 Validate connection credentials.

        Args:
            connection_info: Connection configuration

        Returns:
            True if credentials are valid
        """
        # Basic validation
        if not connection_info.bind_dn:
            logger.warning("Missing bind DN")
            return False

        if not connection_info.bind_password.get_secret_value():
            logger.warning("Missing bind password")
            return False

        logger.debug("Credentials validation passed")
        return True


# ============================================================================
# 🔥 SOLID COMPLIANT CONNECTION MANAGER IMPLEMENTATION
# ============================================================================


class SOLIDConnectionManager:
    """🔥 SOLID-Compliant LDAP Connection Manager.

    ZERO TOLERANCE SOLID implementation:
    - S: Single responsibility for connection orchestration
    - O: Open for extension through component injection
    - L: Implements ILDAPConnectionManager contract
    - I: Composed of segregated interfaces
    - D: Depends on abstractions, not concretions

    This is the main orchestrator that composes all SOLID components.
    """

    def __init__(
        self,
        connection_info: LDAPConnectionInfo,
        factory: IConnectionFactory | None = None,
        pool: IConnectionPool | None = None,
        health_monitor: IHealthMonitor | None = None,
        performance_tracker: IPerformanceTracker | None = None,
        security_manager: ISecurityManager | None = None,
    ) -> None:
        """Initialize SOLID connection manager with dependency injection.

        Args:
            connection_info: Connection configuration
            factory: Connection factory (injected dependency)
            pool: Connection pool (injected dependency)
            health_monitor: Health monitor (injected dependency)
            performance_tracker: Performance tracker (injected dependency)
            security_manager: Security manager (injected dependency)
        """
        self.connection_info = connection_info

        # 🔥 DEPENDENCY INVERSION: Inject dependencies
        self._factory = factory or StandardConnectionFactory(connection_info)
        self._security_manager = security_manager or StandardSecurityManager(
            connection_info,
        )
        self._performance_tracker = performance_tracker or PerformanceTracker(
            connection_info,
        )
        self._health_monitor = health_monitor or StandardHealthMonitor(connection_info)
        self._pool = pool or AsyncConnectionPool(
            connection_info,
            self._factory,
            pool_size=10,
            max_pool_size=20,
        )

        # Component lifecycle
        self._components = [
            self._factory,
            self._security_manager,
            self._performance_tracker,
            self._health_monitor,
            self._pool,
        ]

        logger.info(
            "🔥 SOLID-Compliant ConnectionManager initialized with zero duplication",
        )

    async def initialize(self) -> None:
        """🔥 Initialize all components following SOLID principles."""
        logger.info("Initializing SOLID connection manager components")

        for component in self._components:
            await component.initialize()

        logger.info("✅ All SOLID components initialized successfully")

    async def cleanup(self) -> None:
        """🔥 Cleanup all components following SOLID principles."""
        logger.info("Cleaning up SOLID connection manager components")

        # Cleanup in reverse order
        for component in reversed(self._components):
            await component.cleanup()

        logger.info("✅ All SOLID components cleaned up successfully")

    @contextlib.asynccontextmanager
    async def get_connection(self) -> AsyncGenerator[ldap3.Connection, None]:
        """🔥 Get managed connection using SOLID composition.

        Yields:
            LDAP connection
        """
        start_time = time.time()

        try:
            async with self._pool.acquire_connection() as connection:
                # Record successful acquisition
                duration = time.time() - start_time
                self._performance_tracker.record_operation(
                    "connection_acquire",
                    duration,
                    True,
                )

                yield connection

        except Exception as e:
            # Record failed acquisition
            duration = time.time() - start_time
            self._performance_tracker.record_operation(
                "connection_acquire",
                duration,
                False,
            )
            logger.exception(f"Connection acquisition failed: {e}")
            raise

    async def search(
        self,
        search_base: str,
        search_filter: str = "(objectClass=*)",
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        """🔥 Perform search using SOLID composition.

        Args:
            search_base: Base DN for search
            search_filter: LDAP search filter
            **kwargs: Additional search parameters

        Yields:
            Search results
        """
        start_time = time.time()

        try:
            async with self.get_connection() as connection:
                connection.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    **kwargs,
                )

                for entry in connection.entries:
                    yield {
                        "dn": entry.entry_dn,
                        "attributes": dict(entry.entry_attributes_as_dict),
                    }

                # Record successful search
                duration = time.time() - start_time
                self._performance_tracker.record_operation("search", duration, True)

        except Exception as e:
            # Record failed search
            duration = time.time() - start_time
            self._performance_tracker.record_operation("search", duration, False)
            logger.exception(f"Search operation failed: {e}")
            raise

    async def add_entry(self, dn: str, attributes: dict[str, Any]) -> bool:
        """🔥 Add entry using SOLID composition.

        Args:
            dn: Distinguished name
            attributes: Entry attributes

        Returns:
            True if successful
        """
        start_time = time.time()

        try:
            async with self.get_connection() as connection:
                result = connection.add(dn, attributes=attributes)

                # Record operation
                duration = time.time() - start_time
                self._performance_tracker.record_operation("add", duration, result)

                if result:
                    logger.info(f"Successfully added entry: {dn}")
                else:
                    logger.error(f"Failed to add entry {dn}: {connection.result}")

                return result

        except Exception as e:
            # Record failed add
            duration = time.time() - start_time
            self._performance_tracker.record_operation("add", duration, False)
            logger.exception(f"Add operation failed for {dn}: {e}")
            raise

    async def modify_entry(self, dn: str, changes: dict[str, Any]) -> bool:
        """🔥 Modify entry using SOLID composition.

        Args:
            dn: Distinguished name
            changes: Changes to apply

        Returns:
            True if successful
        """
        start_time = time.time()

        try:
            async with self.get_connection() as connection:
                # Convert changes to ldap3 format
                ldap3_changes = []
                for attr, value in changes.items():
                    if isinstance(value, list):
                        ldap3_changes.append((attr, ldap3.MODIFY_REPLACE, value))
                    else:
                        ldap3_changes.append((attr, ldap3.MODIFY_REPLACE, [value]))

                result = connection.modify(dn, ldap3_changes)

                # Record operation
                duration = time.time() - start_time
                self._performance_tracker.record_operation("modify", duration, result)

                if result:
                    logger.info(f"Successfully modified entry: {dn}")
                else:
                    logger.error(f"Failed to modify entry {dn}: {connection.result}")

                return result

        except Exception as e:
            # Record failed modify
            duration = time.time() - start_time
            self._performance_tracker.record_operation("modify", duration, False)
            logger.exception(f"Modify operation failed for {dn}: {e}")
            raise

    async def delete_entry(self, dn: str) -> bool:
        """🔥 Delete entry using SOLID composition.

        Args:
            dn: Distinguished name

        Returns:
            True if successful
        """
        start_time = time.time()

        try:
            async with self.get_connection() as connection:
                result = connection.delete(dn)

                # Record operation
                duration = time.time() - start_time
                self._performance_tracker.record_operation("delete", duration, result)

                if result:
                    logger.info(f"Successfully deleted entry: {dn}")
                else:
                    logger.error(f"Failed to delete entry {dn}: {connection.result}")

                return result

        except Exception as e:
            # Record failed delete
            duration = time.time() - start_time
            self._performance_tracker.record_operation("delete", duration, False)
            logger.exception(f"Delete operation failed for {dn}: {e}")
            raise

    def get_performance_metrics(self) -> dict[str, Any]:
        """🔥 Get performance metrics using SOLID composition.

        Returns:
            Performance metrics
        """
        return self._performance_tracker.get_metrics()

    async def health_check(self) -> bool:
        """🔥 Perform health check using SOLID composition.

        Returns:
            True if healthy
        """
        try:
            async with self.get_connection() as connection:
                return await self._health_monitor.check_health(connection)
        except Exception as e:
            logger.exception(f"Health check failed: {e}")
            return False

    # Context manager support
    async def __aenter__(self) -> Self:
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Async context manager exit."""
        await self.cleanup()


# ============================================================================
# 🔥 DEPENDENCY INJECTION FACTORY
# ============================================================================


class ConnectionManagerFactory:
    """🔥 Factory for creating SOLID connection managers.

    Enables different component configurations while maintaining SOLID compliance.
    """

    @staticmethod
    def create_standard_manager(
        connection_info: LDAPConnectionInfo,
    ) -> SOLIDConnectionManager:
        """Create standard SOLID connection manager.

        Args:
            connection_info: Connection configuration

        Returns:
            Configured connection manager
        """
        return SOLIDConnectionManager(connection_info)

    @staticmethod
    def create_high_performance_manager(
        connection_info: LDAPConnectionInfo,
    ) -> SOLIDConnectionManager:
        """Create high-performance SOLID connection manager.

        Args:
            connection_info: Connection configuration

        Returns:
            High-performance configured connection manager
        """
        # Custom components for high performance
        factory = StandardConnectionFactory(connection_info)
        pool = AsyncConnectionPool(
            connection_info,
            factory,
            pool_size=20,
            max_pool_size=50,
        )
        performance_tracker = PerformanceTracker(connection_info)
        health_monitor = StandardHealthMonitor(connection_info, check_interval=10.0)
        security_manager = StandardSecurityManager(connection_info)

        return SOLIDConnectionManager(
            connection_info,
            factory=factory,
            pool=pool,
            health_monitor=health_monitor,
            performance_tracker=performance_tracker,
            security_manager=security_manager,
        )
