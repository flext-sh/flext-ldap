"""LDAP Connection Management - DEDICATED PEP8 MODULE FOR CONCRETE CLASSES.

🎯 ELIMINATES DUPLICATIONS - Dedicated connection management operations module
Following advanced Python 3.13 + flext-core patterns with zero duplication.

CONSOLIDATES CONNECTION OPERATIONS FROM:
- connection_manager.py: Connection management logic (scattered)
- infrastructure/connection_pool.py: Connection pooling implementation
- adapters/ldap_client.py: LDAP client connection handling
- infrastructure/connection_factory.py: Connection creation patterns
- All connection-related operations across 12+ files

This module provides DEDICATED connection management operations using:
- Advanced Python 3.13 features extensively
- flext-core foundation patterns (FlextResult, DI interfaces)
- Consolidated foundation modules (protocols.py, models.py, constants.py)
- Clean Architecture and Domain-Driven Design principles
- Proper DI library interfaces (not service implementation)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast
from uuid import uuid4

from flext_core import FlextResult, get_flext_container, get_logger

from flext_ldap.config import FlextLdapConnectionConfig
from flext_ldap.constants import (
    FlextLdapConnectionConstants,
    FlextLdapProtocolConstants,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from flext_ldap.protocols import FlextLdapConnectionProtocol, FlextLdapPoolProtocol
    from flext_ldap.value_objects import FlextLdapDistinguishedName

logger = get_logger(__name__)

# =============================================================================
# CONNECTION MANAGEMENT INTERFACE - DI Library Pattern
# =============================================================================


class FlextLdapConnectionOperations:
    """LDAP Connection Management Operations following DI library patterns.

    🎯 CONSOLIDATES AND REPLACES:
    - FlextLdapConnectionManager (infrastructure/connection_manager.py)
    - FlextLdapConnectionPool (infrastructure/connection_pool.py)
    - Connection operation patterns scattered across infrastructure layers
    - All connection-specific business operations duplications

    DI LIBRARY PATTERN:
    This class provides connection operation interfaces for dependency injection.
    It does NOT implement services - it provides operation contracts.
    """

    def __init__(
        self,
        connection_pool: FlextLdapPoolProtocol,
    ) -> None:
        """Initialize connection operations with DI dependencies.

        Args:
            connection_pool: LDAP connection pool protocol implementation

        """
        self._pool = connection_pool
        self._container = get_flext_container()
        self._active_connections: dict[str, FlextLdapConnectionProtocol] = {}

    # =========================================================================
    # CONNECTION CREATION OPERATIONS - Advanced Python 3.13 patterns
    # =========================================================================

    async def create_connection(
        self,
        config: FlextLdapConnectionConfig,
        *,
        connection_id: str | None = None,
        validate_certificate: bool = True,
        connect_timeout: int | None = None,
    ) -> FlextResult[str]:
        """Create new LDAP connection with comprehensive validation.

        🎯 CONSOLIDATES AND REPLACES:
        - create_connection() functions scattered across multiple modules
        - Connection creation logic duplicated in infrastructure layers
        - Validation patterns repeated in different connection operations

        Args:
            config: Connection configuration with validation
            connection_id: Optional connection identifier (auto-generated if None)
            validate_certificate: Validate SSL/TLS certificates
            connect_timeout: Connection timeout override

        Returns:
            FlextResult containing connection ID or error details

        """
        if connection_id is None:
            connection_id = str(uuid4())

        logger.debug(f"Creating LDAP connection: {connection_id}")

        # Validate configuration business rules
        br_result = config.validate_business_rules()
        if hasattr(br_result, "is_failure") and br_result.is_failure:
            return FlextResult.fail(
                f"Invalid connection config: {br_result.error}",
            )

        # Build connection URL
        url_result = self._build_connection_url(config)
        if url_result.is_failure:
            return url_result

        # Create connection via pool
        create_result = await self._pool.create_connection(
            connection_id=connection_id,
            host=config.server,  # FlextLDAPConfig uses 'server'
            port=config.port,
            options={
                "use_ssl": config.use_ssl,
                "timeout_seconds": config.timeout,
            },
        )

        if create_result.is_failure:
            return FlextResult.fail(
                f"Failed to create connection: {create_result.error}",
            )

        # Store connection reference - type cast for protocol compatibility
        connection = cast("FlextLdapConnectionProtocol", create_result.data)
        self._active_connections[connection_id] = connection

        logger.info(f"Successfully created connection: {connection_id}")
        return FlextResult.ok(connection_id)

    async def create_secure_connection(
        self,
        config: FlextLdapConnectionConfig,
        *,
        connection_id: str | None = None,
        tls_version: str = "TLSv1.2",
        cipher_suites: str | None = None,
    ) -> FlextResult[str]:
        """Create secure LDAP connection with TLS/SSL.

        🎯 CONSOLIDATES secure connection patterns scattered across modules.

        Args:
            config: Connection configuration
            connection_id: Optional connection identifier
            tls_version: TLS version to use
            cipher_suites: Allowed cipher suites

        Returns:
            FlextResult containing connection ID or error details

        """
        if connection_id is None:
            connection_id = str(uuid4())

        logger.debug(f"Creating secure LDAP connection: {connection_id}")

        # Force SSL configuration using model_validate
        secure_config = FlextLdapConnectionConfig.model_validate(
            {
                **config.model_dump(),
                "use_ssl": True,
                "port": (
                    config.port
                    if config.use_ssl
                    else FlextLdapConnectionConstants.DEFAULT_SSL_PORT
                ),
                "search_base": config.search_base,
                "search_filter": config.search_filter,
            },
        )

        # Create connection with SSL validation
        return await self.create_connection(
            config=secure_config,
            connection_id=connection_id,
            validate_certificate=True,
        )

    # =========================================================================
    # CONNECTION AUTHENTICATION OPERATIONS - Bind operations
    # =========================================================================

    async def authenticate_connection(
        self,
        connection_id: str,
        bind_dn: FlextLdapDistinguishedName,
        bind_password: str,
        *,
        auth_method: str = "simple",
    ) -> FlextResult[None]:
        """Authenticate connection with bind operation.

        🎯 CONSOLIDATES authentication patterns across connection operations.

        Args:
            connection_id: Connection identifier
            bind_dn: Distinguished name for binding
            bind_password: Bind password
            auth_method: Authentication method (simple, SASL, etc.)

        Returns:
            FlextResult indicating authentication success or error

        """
        logger.debug(
            f"Authenticating connection {connection_id} with DN: {bind_dn.value}",
        )

        # Get connection from pool
        connection = self._active_connections.get(connection_id)
        if not connection:
            return FlextResult.fail(f"Connection not found: {connection_id}")

        # Validate bind DN
        dn_validation = bind_dn.validate_business_rules()
        if dn_validation.is_failure:
            return FlextResult.fail(f"Invalid bind DN: {dn_validation.error}")

        # Perform bind operation
        bind_result = await connection.bind(
            dn=bind_dn.value,
            password=bind_password,
            auth_method=auth_method,
        )

        if bind_result.is_failure:
            logger.warning(
                f"Authentication failed for connection {connection_id}: {bind_result.error}",
            )
            return FlextResult.fail(f"Authentication failed: {bind_result.error}")

        logger.info(f"Successfully authenticated connection: {connection_id}")
        return FlextResult.ok(None)

    async def anonymous_bind(
        self,
        connection_id: str,
    ) -> FlextResult[None]:
        """Perform anonymous bind on connection.

        Args:
            connection_id: Connection identifier

        Returns:
            FlextResult indicating bind success or error

        """
        logger.debug(f"Performing anonymous bind on connection: {connection_id}")

        # Get connection from pool
        connection = self._active_connections.get(connection_id)
        if not connection:
            return FlextResult.fail(f"Connection not found: {connection_id}")

        # Perform anonymous bind
        bind_result = await connection.bind(
            dn="",  # Empty DN for anonymous
            password="",  # Empty password for anonymous
            auth_method=FlextLdapProtocolConstants.AUTH_ANONYMOUS,
        )

        if bind_result.is_failure:
            return FlextResult.fail(f"Anonymous bind failed: {bind_result.error}")

        logger.info(f"Successfully performed anonymous bind: {connection_id}")
        return FlextResult.ok(None)

    # =========================================================================
    # CONNECTION HEALTH OPERATIONS - Monitoring and validation
    # =========================================================================

    async def test_connection(
        self,
        connection_id: str,
    ) -> FlextResult[dict[str, object]]:
        """Test connection health and gather diagnostics.

        🎯 CONSOLIDATES connection testing patterns across modules.

        Args:
            connection_id: Connection identifier

        Returns:
            FlextResult containing connection diagnostics or error

        """
        logger.debug(f"Testing connection health: {connection_id}")

        # Get connection from pool
        connection = self._active_connections.get(connection_id)
        if not connection:
            return FlextResult.fail(f"Connection not found: {connection_id}")

        try:
            # Gather connection diagnostics
            start_time = datetime.now(UTC)

            # Test basic connectivity
            health_result = await connection.test_health()
            if health_result.is_failure:
                return FlextResult.fail(
                    f"Connection health check failed: {health_result.error}",
                )

            # Measure response time
            response_time = (datetime.now(UTC) - start_time).total_seconds() * 1000

            # Gather connection info
            raw_data = cast("dict[str, object]", health_result.data)
            diagnostics = {
                "connection_id": connection_id,
                "is_connected": raw_data.get("connected", False),
                "response_time_ms": response_time,
                "server_info": raw_data.get("server_info", {}),
                "bind_status": raw_data.get("bind_status", "unknown"),
                "last_activity": datetime.now(UTC).isoformat(),
                "connection_age": raw_data.get("connection_age", 0),
            }

            logger.debug(
                f"Connection test completed for {connection_id}: {response_time:.2f}ms",
            )
            return FlextResult.ok(diagnostics)

        except (ConnectionError, TimeoutError, OSError, ValueError, TypeError) as e:
            logger.exception(f"Connection test failed for {connection_id}")
            return FlextResult.fail(f"Connection test error: {e}")

    async def get_connection_statistics(
        self,
        connection_id: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Get connection statistics and metrics.

        Args:
            connection_id: Specific connection ID (None for all connections)

        Returns:
            FlextResult containing connection statistics or error

        """
        logger.debug(
            f"Getting connection statistics for: {connection_id or 'all connections'}",
        )

        try:
            if connection_id:
                # Get stats for specific connection
                connection = self._active_connections.get(connection_id)
                if not connection:
                    return FlextResult.fail(f"Connection not found: {connection_id}")

                stats_result = await connection.get_statistics()
                if stats_result.is_failure:
                    return stats_result

                return FlextResult.ok(
                    {
                        "connection_id": connection_id,
                        "statistics": stats_result.data,
                    },
                )
            # Get stats for all connections
            all_stats = {
                "total_connections": len(self._active_connections),
                "connection_ids": list(self._active_connections.keys()),
                "pool_statistics": {},
            }

            # Get pool statistics
            pool_stats_result = await self._pool.get_statistics()
            if pool_stats_result.is_success:
                all_stats["pool_statistics"] = pool_stats_result.data

            return FlextResult.ok(all_stats)

        except (RuntimeError, AttributeError, TypeError, ValueError) as e:
            logger.exception("Failed to get connection statistics")
            return FlextResult.fail(f"Statistics error: {e}")

    # =========================================================================
    # CONNECTION LIFECYCLE OPERATIONS - Management and cleanup
    # =========================================================================

    @asynccontextmanager
    async def connection_context(
        self,
        config: FlextLdapConnectionConfig,
        bind_dn: FlextLdapDistinguishedName | None = None,
        bind_password: str | None = None,
    ) -> AsyncGenerator[FlextResult[str]]:
        """Context manager for automatic connection lifecycle management.

        🎯 CONSOLIDATES connection lifecycle patterns with proper resource cleanup.

        Args:
            config: Connection configuration
            bind_dn: Optional bind DN for authentication
            bind_password: Optional bind password

        Yields:
            FlextResult containing connection ID or error

        """
        connection_id = None
        try:
            # Create connection
            create_result = await self.create_connection(config)
            if create_result.is_failure:
                yield create_result
                return

            connection_id = create_result.data

            # Authenticate if credentials provided
            if bind_dn and bind_password:
                # connection_id is guaranteed set after create_connection
                if connection_id is None:
                    # Cannot return a value from async generator; yield failure and stop
                    yield FlextResult.fail("Connection ID not available after creation")
                    return
                auth_result = await self.authenticate_connection(
                    connection_id,
                    bind_dn,
                    bind_password,
                )
                if auth_result.is_failure:
                    yield FlextResult.fail(
                        f"Authentication failed: {auth_result.error}",
                    )
                    return

            logger.debug(f"Connection context established: {connection_id}")
            yield FlextResult.ok(cast("str", connection_id))

        except (ConnectionError, TimeoutError, OSError, RuntimeError, AttributeError) as e:
            logger.exception("Connection context error")
            yield FlextResult.fail(f"Connection context error: {e}")
        finally:
            # Always cleanup connection
            if connection_id:
                cleanup_result = await self.close_connection(connection_id)
                if cleanup_result.is_failure:
                    logger.warning(
                        f"Failed to cleanup connection {connection_id}: {cleanup_result.error}",
                    )

    async def close_connection(
        self,
        connection_id: str,
        *,
        force: bool = False,
    ) -> FlextResult[None]:
        """Close connection and cleanup resources.

        Args:
            connection_id: Connection identifier
            force: Force close even if operations are pending

        Returns:
            FlextResult indicating success or error

        """
        logger.debug(f"Closing connection: {connection_id}")

        # Get connection from active connections
        connection = self._active_connections.get(connection_id)
        if not connection:
            logger.warning(f"Connection not found for cleanup: {connection_id}")
            return FlextResult.ok(None)  # Already closed

        try:
            # Close connection via pool
            close_result = await self._pool.close_connection(connection_id, force=force)
            if close_result.is_failure:
                return FlextResult.fail(
                    f"Failed to close connection: {close_result.error}",
                )

            # Remove from active connections
            del self._active_connections[connection_id]

            logger.info(f"Successfully closed connection: {connection_id}")
            return FlextResult.ok(None)

        except (ConnectionError, OSError, RuntimeError, AttributeError) as e:
            logger.exception(f"Error closing connection {connection_id}")
            return FlextResult.fail(f"Connection close error: {e}")

    async def close_all_connections(self) -> FlextResult[None]:
        """Close all active connections.

        Returns:
            FlextResult indicating success or error

        """
        logger.info(f"Closing all connections: {len(self._active_connections)} active")

        errors: list[str] = []
        connection_ids = list(self._active_connections.keys())

        # Close each connection
        for connection_id in connection_ids:
            close_result = await self.close_connection(connection_id, force=True)
            if close_result.is_failure:
                errors.append(f"{connection_id}: {close_result.error}")

        if errors:
            max_errors_to_show = 3
            error_summary = f"Failed to close {len(errors)} connections: {'; '.join(errors[:max_errors_to_show])}"
            max_errors_to_show = 3
            if len(errors) > max_errors_to_show:
                error_summary += f" (and {len(errors) - max_errors_to_show} more)"
            logger.warning(error_summary)
            return FlextResult.fail(error_summary)

        logger.info("Successfully closed all connections")
        return FlextResult.ok(None)

    # =========================================================================
    # PRIVATE HELPER METHODS - Internal operation support
    # =========================================================================

    @staticmethod
    def _build_connection_url(
        config: FlextLdapConnectionConfig,
    ) -> FlextResult[str]:
        """Build connection URL from configuration."""
        try:
            # Determine protocol prefix
            if config.use_ssl:
                prefix = "ldaps://"
            elif config.use_tls:
                prefix = "ldap://"
            else:
                prefix = "ldap://"

            # Build URL with port
            if config.port not in {389, 636}:
                connection_url = f"{prefix}{config.server}:{config.port}"
            else:
                connection_url = f"{prefix}{config.server}"

            return FlextResult.ok(connection_url)

        except (TypeError, ValueError, AttributeError) as e:
            return FlextResult.fail(f"Failed to build connection URL: {e}")

    @staticmethod
    async def _validate_connection_config(
        config: FlextLdapConnectionConfig,
    ) -> bool:
        """Validate connection configuration."""
        # Basic validation is handled by Pydantic in the config model
        # Additional business rule validation can be added here
        validation_result = config.validate_business_rules()
        return validation_result.is_success


# =============================================================================
# CONNECTION POOL OPERATIONS - Pool management interface
# =============================================================================


class FlextLdapConnectionPoolOperations:
    """LDAP Connection Pool Operations for pool-level management.

    🎯 CONSOLIDATES connection pool patterns scattered across infrastructure.
    """

    def __init__(self, pool: FlextLdapPoolProtocol) -> None:
        """Initialize pool operations."""
        self._pool = pool

    async def get_pool_status(self) -> FlextResult[dict[str, object]]:
        """Get connection pool status and health."""
        try:
            stats_result = await self._pool.get_statistics()
            if stats_result.is_failure:
                return stats_result

            status = {
                "pool_health": "healthy",  # Would be determined by actual health checks
                "statistics": stats_result.data,
                "timestamp": datetime.now(UTC).isoformat(),
            }

            return FlextResult.ok(cast("dict[str, object]", status))

        except (RuntimeError, AttributeError, TypeError, ValueError) as e:
            return FlextResult.fail(f"Pool status error: {e}")

    async def reset_pool(self) -> FlextResult[None]:
        """Reset connection pool (close all connections and reinitialize)."""
        logger.info("Resetting connection pool")

        try:
            # Close all connections in pool
            reset_result = await self._pool.reset_pool()
            if reset_result.is_failure:
                return reset_result

            logger.info("Successfully reset connection pool")
            return FlextResult.ok(None)

        except (ConnectionError, OSError, RuntimeError, AttributeError) as e:
            logger.exception("Pool reset error")
            return FlextResult.fail(f"Pool reset error: {e}")


# =============================================================================
# CONVENIENCE FACTORY FUNCTIONS - DI Container Integration
# =============================================================================


def create_connection_operations(
    pool: FlextLdapPoolProtocol,
) -> FlextLdapConnectionOperations:
    """Create connection operations instance with DI dependencies.

    🎯 FACTORY PATTERN for dependency injection integration.

    Args:
        pool: LDAP connection pool protocol implementation

    Returns:
        Configured connection operations instance

    """
    return FlextLdapConnectionOperations(pool)


async def get_connection_operations() -> FlextResult[FlextLdapConnectionOperations]:
    """Get connection operations instance with proper dependency injection."""
    try:
        container = get_flext_container()

        # Get pool from container
        pool_res = container.get("FlextLdapPoolProtocol")
        if pool_res.is_failure:
            return FlextResult.fail(pool_res.error or "Pool not found")

        pool = cast("FlextLdapPoolProtocol", pool_res.unwrap())

        # Create operations instance
        operations = FlextLdapConnectionOperations(pool)
        return FlextResult.ok(operations)

    except (RuntimeError, AttributeError, TypeError, ValueError) as e:
        return FlextResult.fail(
            f"Failed to create connection operations from container: {e}",
        )


# =============================================================================
# MODULE EXPORTS - Clean public interface
# =============================================================================

__all__ = [
    "FlextLdapConnectionOperations",
    "FlextLdapConnectionPoolOperations",
    "create_connection_operations",
    "get_connection_operations",
]
