"""🔥 SOLID Principle Implementations for LDAP Connection Management."""

from __future__ import annotations

import contextlib
import logging
import time
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator
    from types import TracebackType

import ldap3

from ldap_core_shared.connections.factories import StandardConnectionFactory
from ldap_core_shared.connections.monitoring import (
    PerformanceTracker,
    StandardHealthMonitor,
)
from ldap_core_shared.connections.pools import AsyncConnectionPool
from ldap_core_shared.connections.security import StandardSecurityManager

if TYPE_CHECKING:
    from ldap_core_shared.connections.base import LDAPConnectionInfo
    from ldap_core_shared.connections.interfaces import (
        IConnectionFactory,
        IConnectionPool,
        IHealthMonitor,
        IPerformanceTracker,
        ISecurityManager,
    )

logger = logging.getLogger(__name__)

# ============================================================================
# 🔥 SOLID COMPLIANT CONNECTION MANAGER IMPLEMENTATION
# ============================================================================


class ConnectionComponents:
    """Configuration container for SOLID connection components."""

    def __init__(
        self,
        factory: IConnectionFactory | None = None,
        pool: IConnectionPool | None = None,
        health_monitor: IHealthMonitor | None = None,
        performance_tracker: IPerformanceTracker | None = None,
        security_manager: ISecurityManager | None = None,
    ) -> None:
        self.factory = factory
        self.pool = pool
        self.health_monitor = health_monitor
        self.performance_tracker = performance_tracker
        self.security_manager = security_manager


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
        components: ConnectionComponents | None = None,
    ) -> None:
        """Initialize SOLID connection manager with dependency injection.

        Args:
            connection_info: Connection configuration
            components: Optional container for SOLID components
        """
        if components is None:
            components = ConnectionComponents()
        self.connection_info = connection_info

        # 🔥 DEPENDENCY INVERSION: Inject dependencies
        self._factory = components.factory or StandardConnectionFactory(connection_info)
        self._security_manager = components.security_manager or StandardSecurityManager(
            connection_info,
        )
        self._performance_tracker = (
            components.performance_tracker
            or PerformanceTracker(
                connection_info,
            )
        )
        self._health_monitor = components.health_monitor or StandardHealthMonitor(
            connection_info,
        )
        self._pool = components.pool or AsyncConnectionPool(
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
            logger.exception("Connection acquisition failed: %s", e)
            raise

    async def search(
        self,
        search_base: str,
        search_filter: str = "(objectClass=*)",
        **kwargs: str
        | list[str]
        | int
        | None,  # LDAP search parameters: attributes, scope, size_limit, time_limit
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
            logger.exception("Search operation failed: %s", e)
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
                    logger.info("Successfully added entry: %s", dn)
                else:
                    logger.error("Failed to add entry %s: %s", dn, connection.result)

                return result

        except Exception as e:
            # Record failed add
            duration = time.time() - start_time
            self._performance_tracker.record_operation("add", duration, False)
            logger.exception("Add operation failed for %s: %s", dn, e)
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
                    logger.info("Successfully modified entry: %s", dn)
                else:
                    logger.error("Failed to modify entry %s: %s", dn, connection.result)

                return result

        except Exception as e:
            # Record failed modify
            duration = time.time() - start_time
            self._performance_tracker.record_operation("modify", duration, False)
            logger.exception("Modify operation failed for %s: %s", dn, e)
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
                    logger.info("Successfully deleted entry: %s", dn)
                else:
                    logger.error("Failed to delete entry %s: %s", dn, connection.result)

                return result

        except Exception as e:
            # Record failed delete
            duration = time.time() - start_time
            self._performance_tracker.record_operation("delete", duration, False)
            logger.exception("Delete operation failed for %s: %s", dn, e)
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
            logger.exception("Health check failed: %s", e)
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
        exc_tb: TracebackType | None,
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
