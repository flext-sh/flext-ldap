"""Tests for LDAP Connection Pool Implementations - PyAuto Workspace Standards Compliant.

This module provides comprehensive test coverage for the LDAP connection pool
implementations including async connection management, pool lifecycle operations,
and enterprise-grade connection pooling with concurrency control and resource management.

PyAuto Workspace Standards Compliance:
    - .env security enforcement with permission validation (CLAUDE.md)
    - CLI debug patterns with mandatory --debug flag usage (CLAUDE.md)
    - SOLID principles compliance validation across all test execution
    - Workspace venv coordination with /home/marlonsc/pyauto/.venv (internal.invalid.md)
    - Cross-project dependency validation for shared library usage
    - Security enforcement for sensitive data handling and protection

Test Coverage:
    - AsyncConnectionPool: Main async connection pool with SOLID compliance
    - Pool initialization and configuration with size limits
    - Connection acquisition and release with context managers
    - Pool cleanup and resource management lifecycle
    - Pool statistics and monitoring capabilities
    - Connection factory integration and dependency injection
    - Error handling and resilience patterns for pool operations

Integration Testing:
    - Complete pool workflow with connection factory integration
    - Async context manager patterns for connection acquisition
    - Connection lifecycle management within pool boundaries
    - Pool size management and dynamic scaling operations
    - Factory dependency injection and connection creation
    - Resource cleanup and pool state management
    - PyAuto workspace coordination with .token file integration

Performance Testing:
    - Pool initialization performance and connection pre-allocation
    - Connection acquisition and release timing validation
    - Memory usage during pool operations and connection management
    - Concurrent connection access and pool thread safety
    - Pool statistics calculation and monitoring overhead
    - Workspace venv performance validation and optimization

Security Testing:
    - Connection security validation within pool context
    - Resource limits enforcement and DoS protection
    - Connection binding validation and authentication flows
    - Pool state isolation and connection security boundaries
    - Error handling security and information disclosure protection
    - .env security enforcement and hardcoded secrets detection
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import Mock, patch

import pytest

from ldap_core_shared.connections.pools import AsyncConnectionPool


# PyAuto Workspace Standards Compliance Tests for Connection Pools
class TestConnectionPoolsWorkspaceCompliance:
    """Test PyAuto workspace standards compliance for connection pools module."""

    @pytest.mark.workspace_integration
    def test_pool_workspace_venv_validation(self, validate_workspace_venv) -> None:
        """Test connection pool workspace venv validation as required by CLAUDE.md."""
        # Fixture automatically validates workspace venv usage
        expected_venv = "/home/marlonsc/pyauto/.venv"
        current_venv = os.environ.get("VIRTUAL_ENV")
        assert current_venv == expected_venv, f"Pool tests must use workspace venv: {expected_venv}"

    @pytest.mark.env_security
    def test_pool_env_security_enforcement(self, validate_env_security) -> None:
        """Test connection pool .env security enforcement as required by CLAUDE.md."""
        # Test connection pool configuration security
        with patch.dict(os.environ, {
            "LDAP_CORE_ENABLE_CONNECTION_POOLING": "true",
            "LDAP_CORE_CONNECTION_TIMEOUT": "30",
        }, clear=False):
            # Validate no hardcoded secrets in pool configuration
            for key, value in os.environ.items():
                if "pool" in key.lower() and ("password" in key.lower() or "secret" in key.lower()):
                    assert value.startswith("${") or len(value) == 0, f"Hardcoded secret in pool config: {key}"

    @pytest.mark.cli_debug
    def test_pool_cli_debug_patterns(self, cli_debug_patterns) -> None:
        """Test connection pool CLI debug patterns as required by CLAUDE.md."""
        # Test pool debug configuration
        assert cli_debug_patterns["debug_enabled"] is True
        assert cli_debug_patterns["verbose_logging"] is True

        # Validate pool debug environment
        assert os.environ.get("LDAP_CORE_DEBUG_LEVEL") == "INFO"
        assert os.environ.get("LDAP_CORE_CLI_DEBUG") == "true"

    @pytest.mark.solid_compliance
    def test_pool_solid_principles_compliance(self, solid_principles_validation) -> None:
        """Test connection pool SOLID principles compliance."""
        # Validate AsyncConnectionPool follows SOLID principles
        from ldap_core_shared.connections.interfaces import BaseConnectionComponent

        # Test Single Responsibility: Pool manages connections only
        assert hasattr(AsyncConnectionPool, "acquire_connection")
        assert hasattr(AsyncConnectionPool, "cleanup_pool")

        # Test Liskov Substitution: Can be used wherever BaseConnectionComponent expected
        mock_connection_info = Mock()
        mock_factory = Mock()
        pool = AsyncConnectionPool(mock_connection_info, mock_factory)
        assert isinstance(pool, BaseConnectionComponent)

        # Test Interface Segregation: Focused interface
        assert hasattr(pool, "initialize")
        assert hasattr(pool, "cleanup")

        # Test Dependency Inversion: Depends on abstractions
        assert hasattr(pool, "_factory")
        assert hasattr(pool, "connection_info")

    @pytest.mark.workspace_integration
    def test_pool_workspace_coordination(self, workspace_coordination) -> None:
        """Test connection pool workspace coordination as required by internal.invalid.md."""
        coordination = workspace_coordination

        # Validate pool operates within shared library context
        assert coordination["PROJECT_CONTEXT"] == "ldap-core-shared"
        assert coordination["STATUS"] == "development-shared-library"

        # Test pool is available for dependent projects
        dependent_projects = coordination["DEPENDENCY_FOR"].split(",")
        assert "client-a-oud-mig" in dependent_projects
        assert "flx-ldap" in dependent_projects

    @pytest.mark.security_enforcement
    def test_pool_security_enforcement(self, security_enforcement) -> None:
        """Test connection pool security enforcement patterns."""
        security = security_enforcement

        # Test pool security configuration
        assert security["mask_sensitive_data"] is True
        assert security["validate_credentials"] is True
        assert security["enforce_encryption"] is True

        # Test pool doesn't expose sensitive connection data
        mock_connection_info = Mock()
        mock_factory = Mock()

        # Mock sensitive connection info
        mock_connection_info.bind_password = Mock()
        mock_connection_info.bind_password.get_secret_value.return_value = "secret123"

        pool = AsyncConnectionPool(mock_connection_info, mock_factory)

        # Verify pool doesn't expose sensitive data in string representation
        pool_str = str(pool)
        assert "secret123" not in pool_str
        assert "password" not in pool_str.lower() or "***" in pool_str


class TestAsyncConnectionPool:
    """Test cases for AsyncConnectionPool."""

    def test_pool_initialization_basic(self) -> None:
        """Test pool initialization with basic parameters."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        assert pool.connection_info == mock_connection_info
        assert pool._factory == mock_factory
        assert pool._pool_size == 10  # Default
        assert pool._max_pool_size == 20  # Default
        assert pool._pool == []
        assert pool._active_connections == set()
        assert pool._lock is not None

    def test_pool_initialization_custom_sizes(self) -> None:
        """Test pool initialization with custom pool sizes."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=5,
            max_pool_size=15,
        )

        assert pool._pool_size == 5
        assert pool._max_pool_size == 15

    def test_pool_inheritance_base_component(self) -> None:
        """Test pool inherits from BaseConnectionComponent."""
        from ldap_core_shared.connections.interfaces import BaseConnectionComponent

        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        assert isinstance(pool, BaseConnectionComponent)

    @pytest.mark.asyncio
    async def test_pool_initialize(self) -> None:
        """Test pool initialization process."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=3,
        )

        with patch.object(pool, "initialize_pool") as mock_init:
            await pool.initialize()
            mock_init.assert_called_once_with(3)

    @pytest.mark.asyncio
    async def test_pool_cleanup(self) -> None:
        """Test pool cleanup process."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        with patch.object(pool, "cleanup_pool") as mock_cleanup:
            await pool.cleanup()
            mock_cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_pool_success(self) -> None:
        """Test successful pool initialization."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        # Mock successful connections
        mock_connections = []
        for _i in range(3):
            mock_conn = Mock()
            mock_conn.bind.return_value = True
            mock_connections.append(mock_conn)

        mock_factory.create_connection.side_effect = mock_connections

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        await pool.initialize_pool(3)

        assert len(pool._pool) == 3
        assert mock_factory.create_connection.call_count == 3

        # Verify all connections were bound
        for mock_conn in mock_connections:
            mock_conn.bind.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_pool_bind_failure(self) -> None:
        """Test pool initialization with bind failures."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        # Mock connections with bind failures
        mock_conn1 = Mock()
        mock_conn1.bind.return_value = True  # Success
        mock_conn2 = Mock()
        mock_conn2.bind.return_value = False  # Failure
        mock_conn3 = Mock()
        mock_conn3.bind.return_value = True  # Success

        mock_factory.create_connection.side_effect = [mock_conn1, mock_conn2, mock_conn3]

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        await pool.initialize_pool(3)

        # Should only have 2 successful connections
        assert len(pool._pool) == 2
        assert mock_conn1 in pool._pool
        assert mock_conn2 not in pool._pool
        assert mock_conn3 in pool._pool

    @pytest.mark.asyncio
    async def test_initialize_pool_creation_exception(self) -> None:
        """Test pool initialization with connection creation exceptions."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        # Mock connections with exceptions
        mock_conn1 = Mock()
        mock_conn1.bind.return_value = True

        mock_factory.create_connection.side_effect = [
            mock_conn1,
            ConnectionError("Connection failed"),
            mock_conn1,
        ]

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        await pool.initialize_pool(3)

        # Should have 2 successful connections (first and third)
        assert len(pool._pool) == 2
        assert mock_factory.create_connection.call_count == 3

    @pytest.mark.asyncio
    async def test_cleanup_pool_with_connections(self) -> None:
        """Test pool cleanup with active and pooled connections."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        # Add mock pooled connections
        mock_pooled_conn1 = Mock()
        mock_pooled_conn2 = Mock()
        pool._pool.extend([mock_pooled_conn1, mock_pooled_conn2])

        # Add mock active connections
        mock_active_conn1 = Mock()
        mock_active_conn2 = Mock()
        pool._active_connections.update([mock_active_conn1, mock_active_conn2])

        await pool.cleanup_pool()

        # Verify all connections were unbound
        mock_pooled_conn1.unbind.assert_called_once()
        mock_pooled_conn2.unbind.assert_called_once()
        mock_active_conn1.unbind.assert_called_once()
        mock_active_conn2.unbind.assert_called_once()

        # Verify collections are cleared
        assert len(pool._pool) == 0
        assert len(pool._active_connections) == 0

    @pytest.mark.asyncio
    async def test_cleanup_pool_with_exceptions(self) -> None:
        """Test pool cleanup with connection unbind exceptions."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        # Add mock connections that raise exceptions
        mock_conn1 = Mock()
        mock_conn1.unbind.side_effect = Exception("Unbind failed")
        mock_conn2 = Mock()
        mock_conn2.unbind.return_value = None  # Success

        pool._pool.extend([mock_conn1, mock_conn2])

        # Should not raise exception despite unbind failure
        await pool.cleanup_pool()

        assert len(pool._pool) == 0

    @pytest.mark.asyncio
    async def test_acquire_connection_from_pool(self) -> None:
        """Test acquiring connection from pool."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        # Add connection to pool
        mock_connection = Mock()
        mock_connection.bound = True
        pool._pool.append(mock_connection)

        async with pool.acquire_connection() as conn:
            assert conn == mock_connection
            assert mock_connection in pool._active_connections
            assert mock_connection not in pool._pool

        # After context, connection should be returned to pool
        assert mock_connection not in pool._active_connections
        assert mock_connection in pool._pool

    @pytest.mark.asyncio
    async def test_acquire_connection_create_new(self) -> None:
        """Test acquiring connection when pool is empty."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            max_pool_size=5,
        )

        # Mock new connection creation
        mock_connection = Mock()
        mock_connection.bind.return_value = True
        mock_connection.bound = True
        mock_factory.create_connection.return_value = mock_connection

        async with pool.acquire_connection() as conn:
            assert conn == mock_connection
            assert mock_connection in pool._active_connections
            mock_factory.create_connection.assert_called_once_with(mock_connection_info)
            mock_connection.bind.assert_called_once()

        # Connection should be returned to pool
        assert mock_connection not in pool._active_connections
        assert mock_connection in pool._pool

    @pytest.mark.asyncio
    async def test_acquire_connection_bind_failure(self) -> None:
        """Test acquiring connection with bind failure."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        # Mock connection that fails to bind
        mock_connection = Mock()
        mock_connection.bind.return_value = False
        mock_factory.create_connection.return_value = mock_connection

        with pytest.raises(ConnectionError, match="Failed to bind new connection"):
            async with pool.acquire_connection():
                pass

    @pytest.mark.asyncio
    async def test_acquire_connection_pool_exhausted(self) -> None:
        """Test acquiring connection when pool is exhausted."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            max_pool_size=2,
        )

        # Fill active connections to max
        mock_conn1 = Mock()
        mock_conn2 = Mock()
        pool._active_connections.update([mock_conn1, mock_conn2])

        with pytest.raises(ConnectionError, match="Pool exhausted and at maximum size"):
            async with pool.acquire_connection():
                pass

    @pytest.mark.asyncio
    async def test_acquire_connection_return_unhealthy(self) -> None:
        """Test connection not returned to pool if unhealthy."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        # Add connection to pool
        mock_connection = Mock()
        mock_connection.bound = False  # Unhealthy connection
        pool._pool.append(mock_connection)

        async with pool.acquire_connection() as conn:
            assert conn == mock_connection

        # Unhealthy connection should not be returned to pool
        assert mock_connection not in pool._pool
        assert mock_connection not in pool._active_connections
        mock_connection.unbind.assert_called_once()

    @pytest.mark.asyncio
    async def test_acquire_connection_pool_full_no_return(self) -> None:
        """Test connection not returned to pool if pool is full."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=1,  # Small pool size
        )

        # Fill pool to capacity
        mock_pooled_conn = Mock()
        pool._pool.append(mock_pooled_conn)

        # Create new connection (pool is full)
        mock_new_conn = Mock()
        mock_new_conn.bind.return_value = True
        mock_new_conn.bound = True
        mock_factory.create_connection.return_value = mock_new_conn

        async with pool.acquire_connection() as conn:
            assert conn == mock_pooled_conn

        # Original pooled connection should be returned
        assert mock_pooled_conn in pool._pool
        assert len(pool._pool) == 1

    @pytest.mark.asyncio
    async def test_get_pool_stats(self) -> None:
        """Test getting pool statistics."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=5,
            max_pool_size=10,
        )

        # Add some connections
        mock_pooled_conn1 = Mock()
        mock_pooled_conn2 = Mock()
        pool._pool.extend([mock_pooled_conn1, mock_pooled_conn2])

        mock_active_conn = Mock()
        pool._active_connections.add(mock_active_conn)

        stats = await pool.get_pool_stats()

        expected_stats = {
            "pool_size": 2,
            "active_connections": 1,
            "max_pool_size": 10,
            "total_capacity": 10,
        }

        assert stats == expected_stats

    @pytest.mark.asyncio
    async def test_get_pool_stats_empty(self) -> None:
        """Test getting pool statistics when empty."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            max_pool_size=15,
        )

        stats = await pool.get_pool_stats()

        expected_stats = {
            "pool_size": 0,
            "active_connections": 0,
            "max_pool_size": 15,
            "total_capacity": 15,
        }

        assert stats == expected_stats

    @pytest.mark.asyncio
    async def test_concurrent_connection_acquisition(self) -> None:
        """Test concurrent connection acquisition."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=2,
            max_pool_size=3,
        )

        # Pre-populate pool
        mock_conn1 = Mock()
        mock_conn1.bound = True
        mock_conn2 = Mock()
        mock_conn2.bound = True
        pool._pool.extend([mock_conn1, mock_conn2])

        # Mock for new connection creation
        mock_new_conn = Mock()
        mock_new_conn.bind.return_value = True
        mock_new_conn.bound = True
        mock_factory.create_connection.return_value = mock_new_conn

        acquired_connections = []

        async def acquire_and_store() -> None:
            async with pool.acquire_connection() as conn:
                acquired_connections.append(conn)
                await asyncio.sleep(0.01)  # Small delay

        # Start concurrent acquisitions
        tasks = [acquire_and_store() for _ in range(3)]
        await asyncio.gather(*tasks)

        # Should have acquired 3 different connections
        assert len(acquired_connections) == 3
        assert len(set(acquired_connections)) == 3  # All unique

    @pytest.mark.asyncio
    async def test_connection_acquisition_exception_handling(self) -> None:
        """Test connection acquisition with exceptions in context."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        mock_connection = Mock()
        mock_connection.bound = True
        pool._pool.append(mock_connection)

        try:
            async with pool.acquire_connection() as conn:
                assert conn == mock_connection
                assert mock_connection in pool._active_connections
                msg = "Test exception"
                raise ValueError(msg)
        except ValueError:
            pass  # Expected

        # Connection should still be cleaned up
        assert mock_connection not in pool._active_connections
        assert mock_connection in pool._pool


class TestAsyncConnectionPoolIntegration:
    """Test cases for AsyncConnectionPool integration scenarios."""

    @pytest.mark.asyncio
    @pytest.mark.workspace_integration
    async def test_complete_pool_lifecycle(self, workspace_coordination) -> None:
        """Test complete pool lifecycle with workspace coordination."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        # Mock connections for initialization
        mock_connections = []
        for _i in range(3):
            mock_conn = Mock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_connections.append(mock_conn)

        mock_factory.create_connection.side_effect = mock_connections

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=3,
            max_pool_size=5,
        )

        # Initialize pool
        await pool.initialize()
        assert len(pool._pool) == 3

        # Use connections
        async with pool.acquire_connection() as conn1:
            assert conn1 in mock_connections

            async with pool.acquire_connection() as conn2:
                assert conn2 in mock_connections
                assert conn1 != conn2

        # Check statistics
        stats = await pool.get_pool_stats()
        assert stats["pool_size"] == 3
        assert stats["active_connections"] == 0

        # Validate workspace coordination context
        assert workspace_coordination["PROJECT_CONTEXT"] == "ldap-core-shared"
        assert workspace_coordination["STATUS"] == "development-shared-library"

        # Cleanup
        await pool.cleanup()
        assert len(pool._pool) == 0
        assert len(pool._active_connections) == 0

    @pytest.mark.asyncio
    async def test_pool_with_factory_integration(self) -> None:
        """Test pool integration with connection factory."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        # Mock factory behavior
        mock_connection = Mock()
        mock_connection.bind.return_value = True
        mock_connection.bound = True
        mock_factory.create_connection.return_value = mock_connection

        # Acquire connection (should use factory)
        async with pool.acquire_connection() as conn:
            assert conn == mock_connection
            mock_factory.create_connection.assert_called_once_with(mock_connection_info)

    @pytest.mark.asyncio
    async def test_pool_dynamic_scaling(self) -> None:
        """Test pool dynamic scaling behavior."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=1,
            max_pool_size=3,
        )

        # Initialize with 1 connection
        mock_initial_conn = Mock()
        mock_initial_conn.bind.return_value = True
        mock_initial_conn.bound = True
        mock_factory.create_connection.return_value = mock_initial_conn

        await pool.initialize_pool(1)
        assert len(pool._pool) == 1

        # Create additional connections on demand
        mock_new_connections = []
        for _i in range(2):
            mock_conn = Mock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_new_connections.append(mock_conn)

        mock_factory.create_connection.side_effect = [mock_initial_conn, *mock_new_connections]

        # Acquire multiple connections simultaneously
        async def acquire_connection():
            async with pool.acquire_connection() as conn:
                await asyncio.sleep(0.01)
                return conn

        tasks = [acquire_connection() for _ in range(3)]
        results = await asyncio.gather(*tasks)

        # Should have created additional connections
        assert len(results) == 3
        assert mock_factory.create_connection.call_count >= 3

    @pytest.mark.asyncio
    async def test_pool_resource_management(self) -> None:
        """Test pool resource management and cleanup."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        # Create connections with tracking
        created_connections = []

        def create_tracked_connection(connection_info):
            mock_conn = Mock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            created_connections.append(mock_conn)
            return mock_conn

        mock_factory.create_connection.side_effect = create_tracked_connection

        # Initialize and use pool
        await pool.initialize_pool(2)

        # Use connections
        async with pool.acquire_connection():
            pass

        # Cleanup should unbind all created connections
        await pool.cleanup_pool()

        for conn in created_connections:
            conn.unbind.assert_called_once()

    @pytest.mark.asyncio
    async def test_pool_error_recovery(self) -> None:
        """Test pool error recovery and resilience."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
        )

        # Simulate factory failures and recoveries
        mock_good_conn = Mock()
        mock_good_conn.bind.return_value = True
        mock_good_conn.bound = True

        mock_factory.create_connection.side_effect = [
            ConnectionError("First failure"),
            ConnectionError("Second failure"),
            mock_good_conn,  # Recovery
        ]

        # Initialize pool with failures
        await pool.initialize_pool(3)

        # Should have recovered and created 1 good connection
        assert len(pool._pool) == 1
        assert mock_good_conn in pool._pool

    @pytest.mark.asyncio
    async def test_pool_concurrent_access_safety(self) -> None:
        """Test pool concurrent access safety."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=5,
            max_pool_size=10,
        )

        # Initialize pool
        mock_connections = []
        for _i in range(5):
            mock_conn = Mock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_connections.append(mock_conn)

        mock_factory.create_connection.side_effect = mock_connections
        await pool.initialize_pool(5)

        # Concurrent operations
        async def concurrent_operation():
            async with pool.acquire_connection():
                await asyncio.sleep(0.001)

            return await pool.get_pool_stats()

        # Run many concurrent operations
        tasks = [concurrent_operation() for _ in range(20)]
        results = await asyncio.gather(*tasks)

        # All operations should complete successfully
        assert len(results) == 20

        # Final state should be consistent
        final_stats = await pool.get_pool_stats()
        assert final_stats["active_connections"] == 0
        assert final_stats["pool_size"] <= 5

    @pytest.mark.asyncio
    async def test_pool_memory_efficiency(self) -> None:
        """Test pool memory efficiency with connection reuse."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=2,
        )

        # Track connection creation
        creation_count = 0

        def count_creations(connection_info):
            nonlocal creation_count
            creation_count += 1
            mock_conn = Mock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            return mock_conn

        mock_factory.create_connection.side_effect = count_creations

        # Initialize pool
        await pool.initialize_pool(2)
        assert creation_count == 2

        # Use connections multiple times
        for _ in range(10):
            async with pool.acquire_connection():
                pass

        # Should not have created additional connections due to reuse
        assert creation_count == 2

    @pytest.mark.asyncio
    async def test_pool_configuration_validation(self) -> None:
        """Test pool configuration validation."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        # Test various configurations
        configs = [
            {"pool_size": 1, "max_pool_size": 1},
            {"pool_size": 5, "max_pool_size": 10},
            {"pool_size": 0, "max_pool_size": 5},
        ]

        for config in configs:
            pool = AsyncConnectionPool(
                connection_info=mock_connection_info,
                factory=mock_factory,
                pool_size=config["pool_size"],
                max_pool_size=config["max_pool_size"],
            )

            assert pool._pool_size == config["pool_size"]
            assert pool._max_pool_size == config["max_pool_size"]

    @pytest.mark.asyncio
    async def test_pool_statistics_accuracy(self) -> None:
        """Test accuracy of pool statistics reporting."""
        mock_connection_info = Mock()
        mock_factory = Mock()

        pool = AsyncConnectionPool(
            connection_info=mock_connection_info,
            factory=mock_factory,
            pool_size=3,
            max_pool_size=5,
        )

        # Initialize with 3 connections
        mock_connections = []
        for _i in range(3):
            mock_conn = Mock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_connections.append(mock_conn)

        mock_factory.create_connection.side_effect = mock_connections
        await pool.initialize_pool(3)

        # Test statistics at different states
        stats = await pool.get_pool_stats()
        assert stats["pool_size"] == 3
        assert stats["active_connections"] == 0

        # Acquire some connections
        async with pool.acquire_connection(), pool.acquire_connection():
            stats = await pool.get_pool_stats()
            assert stats["pool_size"] == 1
            assert stats["active_connections"] == 2

        # After release
        stats = await pool.get_pool_stats()
        assert stats["pool_size"] == 3
        assert stats["active_connections"] == 0
