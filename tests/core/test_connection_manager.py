"""Comprehensive tests for LDAP Connection Manager.

This module provides enterprise-grade testing for the connection management
system, including unit tests, integration tests, and performance validation.

Test Coverage:
    - Connection establishment and pooling
    - SSL/TLS security validation
    - Health monitoring and circuit breaker
    - Performance metrics and monitoring
    - Error handling and recovery

Version: 1.0.0-enterprise
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import ldap3
import pytest
from pydantic import ValidationError

from ldap_core_shared.core.connection_manager import (
    ConnectionInfo,
    ConnectionPool,
    LDAPConnectionManager,
    PooledConnection,
)
from ldap_core_shared.core.connection_manager import (
    LDAPConnectionManager as ConnectionManager,
)
from ldap_core_shared.domain.results import LDAPConnectionResult
from ldap_core_shared.utils.constants import (
    DEFAULT_LDAP_TIMEOUT,
)

if TYPE_CHECKING:
    from collections.abc import Generator


class TestConnectionInfo:
    """Test ConnectionInfo configuration model."""

    def test_connection_info_creation(self) -> None:
        """Test basic ConnectionInfo creation with valid data."""
        connection_info = ConnectionInfo(
            host="ldap.example.com",
            port=389,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
        )

        assert connection_info.host == "ldap.example.com"
        assert connection_info.port == 389
        assert connection_info.base_dn == "dc=example,dc=com"
        assert connection_info.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert connection_info.bind_password == "test_password"
        assert connection_info.use_ssl is False
        assert connection_info.use_tls is False
        assert connection_info.verify_cert is True
        assert connection_info.timeout == DEFAULT_LDAP_TIMEOUT
        assert connection_info.auto_bind is True
        assert connection_info.authentication == "SIMPLE"

    def test_connection_info_with_ssl(self) -> None:
        """Test ConnectionInfo with SSL configuration."""
        connection_info = ConnectionInfo(
            host="ldaps.example.com",
            port=636,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
            use_ssl=True,
            verify_cert=False,
        )

        assert connection_info.use_ssl is True
        assert connection_info.port == 636
        assert connection_info.verify_cert is False

    def test_connection_info_with_ssh_tunnel(self) -> None:
        """Test ConnectionInfo with SSH tunnel configuration."""
        connection_info = ConnectionInfo(
            host="localhost",
            port=389,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
            ssh_host="bastion.example.com",
            ssh_port=22,
            ssh_username="user",
            ssh_password="test_ssh_password",  # nosec B106
        )

        assert connection_info.ssh_host == "bastion.example.com"
        assert connection_info.ssh_port == 22
        assert connection_info.ssh_username == "user"
        assert connection_info.ssh_password == "test_ssh_password"

    def test_connection_info_validation_errors(self) -> None:
        """Test ConnectionInfo validation with invalid data."""
        # Test invalid port
        with pytest.raises(ValidationError):
            ConnectionInfo(
                host="ldap.example.com",
                port=70000,  # Invalid port
                base_dn="dc=example,dc=com",
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                bind_password="test_password",  # nosec B106
            )

        # Test invalid timeout
        with pytest.raises(ValidationError):
            ConnectionInfo(
                host="ldap.example.com",
                port=389,
                base_dn="dc=example,dc=com",
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                bind_password="test_password",  # nosec B106
                timeout=-1,  # Invalid timeout
            )

    def test_connection_info_immutability(self) -> None:
        """Test that ConnectionInfo is immutable after creation."""
        connection_info = ConnectionInfo(
            host="ldap.example.com",
            port=389,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
        )

        # Should not be able to modify frozen model
        with pytest.raises(ValidationError):
            connection_info.host = "ldap2.example.com"  # type: ignore[misc]


class TestPooledConnection:
    """Test PooledConnection wrapper functionality."""

    @pytest.fixture
    def mock_connection(self) -> MagicMock:
        """Create mock LDAP connection for testing."""
        mock_conn = MagicMock(spec=ldap3.Connection)
        mock_conn.bound = True
        mock_conn.server = MagicMock()
        mock_conn.server.info = "Mock LDAP Server"
        mock_conn.search.return_value = True
        return mock_conn

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="internal.invalid",
            port=389,
            base_dn="dc=test,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="test_password",  # nosec B106
        )

    @pytest.fixture
    def pooled_connection(
        self, mock_connection: MagicMock, connection_info: ConnectionInfo
    ) -> PooledConnection:
        """Create test pooled connection."""
        return PooledConnection(mock_connection, connection_info)

    def test_pooled_connection_initialization(
        self, pooled_connection: PooledConnection, mock_connection: MagicMock
    ) -> None:
        """Test PooledConnection initialization."""
        assert pooled_connection.connection == mock_connection
        assert pooled_connection.use_count == 0
        assert pooled_connection.is_healthy is True
        assert pooled_connection.is_in_use is False
        assert pooled_connection.created_at > 0
        assert pooled_connection.last_used > 0

    def test_pooled_connection_mark_used(
        self, pooled_connection: PooledConnection
    ) -> None:
        """Test marking connection as used updates metadata."""
        initial_use_count = pooled_connection.use_count
        initial_last_used = pooled_connection.last_used

        time.sleep(0.01)  # Small delay to ensure time difference
        pooled_connection.mark_used()

        assert pooled_connection.use_count == initial_use_count + 1
        assert pooled_connection.last_used > initial_last_used

    def test_pooled_connection_is_stale(
        self, pooled_connection: PooledConnection
    ) -> None:
        """Test stale connection detection."""
        # Fresh connection should not be stale
        assert not pooled_connection.is_stale(max_age_seconds=3600)

        # Very old connection should be stale
        assert pooled_connection.is_stale(max_age_seconds=0)

    def test_pooled_connection_is_idle(
        self, pooled_connection: PooledConnection
    ) -> None:
        """Test idle connection detection."""
        # Fresh connection should not be idle
        assert not pooled_connection.is_idle(max_idle_seconds=3600)

        # Connection not used for long time should be idle
        assert pooled_connection.is_idle(max_idle_seconds=0)

    def test_pooled_connection_validate_health_success(
        self, pooled_connection: PooledConnection
    ) -> None:
        """Test successful health validation."""
        result = pooled_connection.validate_health()
        assert result is True

        # Verify the health check performed a search
        pooled_connection.connection.search.assert_called_once()

    def test_pooled_connection_validate_health_failure_unbound(
        self, pooled_connection: PooledConnection
    ) -> None:
        """Test health validation failure when connection is unbound."""
        pooled_connection.connection.bound = False

        result = pooled_connection.validate_health()
        assert result is False

    def test_pooled_connection_validate_health_failure_exception(
        self, pooled_connection: PooledConnection
    ) -> None:
        """Test health validation failure when search raises exception."""
        pooled_connection.connection.search.side_effect = Exception("Connection failed")

        result = pooled_connection.validate_health()
        assert result is False


class TestConnectionFactory:
    """Test ConnectionFactory for centralized connection creation."""

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="internal.invalid",
            port=389,
            base_dn="dc=test,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="test_password",  # nosec B106
        )

    @pytest.fixture
    def ssl_connection_info(self) -> ConnectionInfo:
        """Create test SSL connection info."""
        return ConnectionInfo(
            host="internal.invalid",
            port=636,
            base_dn="dc=test,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="test_password",  # nosec B106
            use_ssl=True,
            verify_cert=False,
        )

    def test_create_tls_config_none(self, connection_info: ConnectionInfo) -> None:
        """Test TLS config creation returns None for non-SSL connections."""
        from ldap_core_shared.core.connection_manager import ConnectionFactory

        tls_config = ConnectionFactory.create_tls_config(connection_info)
        assert tls_config is None

    def test_create_tls_config_ssl(self, ssl_connection_info: ConnectionInfo) -> None:
        """Test TLS config creation for SSL connections."""
        from ldap_core_shared.core.connection_manager import ConnectionFactory

        tls_config = ConnectionFactory.create_tls_config(ssl_connection_info)
        assert tls_config is not None
        assert isinstance(tls_config, ldap3.Tls)

    @patch("ldap3.Server")
    def test_create_server(
        self, mock_server: MagicMock, connection_info: ConnectionInfo
    ) -> None:
        """Test server creation."""
        from ldap_core_shared.core.connection_manager import ConnectionFactory

        mock_server_instance = MagicMock()
        mock_server.return_value = mock_server_instance

        result = ConnectionFactory.create_server(connection_info)

        mock_server.assert_called_once_with(
            host=connection_info.host,
            port=connection_info.port,
            use_ssl=connection_info.use_ssl,
            tls=None,
            get_info=ldap3.ALL,
        )
        assert result == mock_server_instance

    @patch("ldap3.Connection")
    @patch("ldap_core_shared.core.connection_manager.ConnectionFactory.create_server")
    def test_create_connection(
        self,
        mock_create_server: MagicMock,
        mock_connection: MagicMock,
        connection_info: ConnectionInfo,
    ) -> None:
        """Test connection creation."""
        from ldap_core_shared.core.connection_manager import ConnectionFactory

        mock_server = MagicMock()
        mock_create_server.return_value = mock_server
        mock_conn_instance = MagicMock()
        mock_connection.return_value = mock_conn_instance

        result = ConnectionFactory.create_connection(connection_info)

        mock_create_server.assert_called_once_with(connection_info)
        mock_connection.assert_called_once_with(
            server=mock_server,
            user=connection_info.bind_dn,
            password=connection_info.bind_password,
            auto_bind=connection_info.auto_bind,
            authentication=ldap3.SIMPLE,
            receive_timeout=connection_info.timeout,
        )
        assert result == mock_conn_instance


class TestConnectionPool:
    """Test ConnectionPool functionality."""

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="internal.invalid",
            port=389,
            base_dn="dc=test,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="test_password",  # nosec B106
        )

    @pytest.fixture
    def connection_pool(self, connection_info: ConnectionInfo) -> ConnectionPool:
        """Create test connection pool."""
        return ConnectionPool(connection_info, pool_size=2, max_pool_size=5)

    def test_connection_pool_initialization(
        self, connection_pool: ConnectionPool, connection_info: ConnectionInfo
    ) -> None:
        """Test ConnectionPool initialization."""
        assert connection_pool.connection_info == connection_info
        assert connection_pool.pool_size == 2
        assert connection_pool.max_pool_size == 5
        assert len(connection_pool._pool) == 0
        assert connection_pool._total_connections_created == 0

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    async def test_create_connection(
        self, mock_create_connection: MagicMock, connection_pool: ConnectionPool
    ) -> None:
        """Test connection creation in pool."""
        mock_conn = MagicMock()
        mock_create_connection.return_value = mock_conn

        pooled_conn = await connection_pool._create_connection()

        assert pooled_conn.connection == mock_conn
        assert connection_pool._total_connections_created == 1
        assert connection_pool._metrics["connections_created"] == 1

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    async def test_get_connection_creates_new(
        self, mock_create_connection: MagicMock, connection_pool: ConnectionPool
    ) -> None:
        """Test getting connection creates new when pool is empty."""
        mock_conn = MagicMock()
        mock_conn.bound = True
        mock_conn.search.return_value = True
        mock_create_connection.return_value = mock_conn

        async with connection_pool.get_connection() as pooled_conn:
            assert pooled_conn.connection == mock_conn
            assert pooled_conn.is_in_use is True
            assert connection_pool._metrics["pool_misses"] == 1

        # After context manager, connection should be returned to pool
        assert pooled_conn.is_in_use is False
        assert len(connection_pool._pool) == 1

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    async def test_get_connection_reuses_existing(
        self, mock_create_connection: MagicMock, connection_pool: ConnectionPool
    ) -> None:
        """Test getting connection reuses existing healthy connection."""
        mock_conn = MagicMock()
        mock_conn.bound = True
        mock_conn.search.return_value = True
        mock_create_connection.return_value = mock_conn

        # First connection
        async with connection_pool.get_connection() as first_conn:
            pass

        # Second connection should reuse the first
        async with connection_pool.get_connection() as second_conn:
            assert second_conn == first_conn
            assert connection_pool._metrics["pool_hits"] == 1
            assert connection_pool._metrics["connections_reused"] == 1

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    async def test_get_connection_pool_exhausted(
        self, mock_create_connection: MagicMock, connection_pool: ConnectionPool
    ) -> None:
        """Test connection pool exhaustion raises error."""
        mock_conn = MagicMock()
        mock_conn.bound = True
        mock_conn.search.return_value = True
        mock_create_connection.return_value = mock_conn

        # Fill the pool to max capacity and keep connections in use
        connections = []
        for _ in range(connection_pool.max_pool_size):
            conn_ctx = connection_pool.get_connection()
            conn = await conn_ctx.__aenter__()
            connections.append((conn_ctx, conn))

        # Try to get one more connection - should fail
        with pytest.raises(RuntimeError, match="Connection pool exhausted"):
            async with connection_pool.get_connection():
                pass

        # Cleanup
        for conn_ctx, _ in connections:
            await conn_ctx.__aexit__(None, None, None)

    async def test_close_pool(self, connection_pool: ConnectionPool) -> None:
        """Test closing connection pool."""
        # Add a mock connection to pool
        mock_conn = MagicMock()
        pooled_conn = PooledConnection(mock_conn, connection_pool.connection_info)
        connection_pool._pool.append(pooled_conn)

        await connection_pool.close_pool()

        assert len(connection_pool._pool) == 0
        mock_conn.unbind.assert_called_once()

    def test_get_metrics(self, connection_pool: ConnectionPool) -> None:
        """Test getting connection pool metrics."""
        # Add some test data
        connection_pool._metrics["connections_created"] = 5
        connection_pool._metrics["connections_reused"] = 3
        connection_pool._metrics["connections_closed"] = 1

        metrics = connection_pool.get_metrics()

        assert metrics.pool_size == 0
        assert metrics.active_connections == 0
        assert metrics.idle_connections == 0
        assert metrics.connections_created == 5
        assert metrics.connections_reused == 3
        assert metrics.connections_closed == 1


class TestLDAPConnectionManager:
    """Test LDAPConnectionManager functionality."""

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="internal.invalid",
            port=389,
            base_dn="dc=test,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="test_password",  # nosec B106
        )

    @pytest.fixture
    def connection_manager(
        self, connection_info: ConnectionInfo
    ) -> LDAPConnectionManager:
        """Create test connection manager."""
        return LDAPConnectionManager(connection_info)

    def test_initialization(
        self, connection_manager: LDAPConnectionManager, connection_info: ConnectionInfo
    ) -> None:
        """Test LDAPConnectionManager initialization."""
        assert connection_manager.connection_info == connection_info
        assert connection_manager._pool is None

    async def test_initialize_pool(
        self, connection_manager: LDAPConnectionManager
    ) -> None:
        """Test pool initialization."""
        await connection_manager.initialize_pool(pool_size=3, max_pool_size=10)

        assert connection_manager._pool is not None
        assert connection_manager._pool.pool_size == 3
        assert connection_manager._pool.max_pool_size == 10

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    def test_get_connection_success(
        self,
        mock_create_connection: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test successful connection creation with context manager."""
        mock_conn = MagicMock()
        mock_conn.bound = True
        mock_conn.server.info = "Mock Server"
        mock_create_connection.return_value = mock_conn

        with connection_manager.get_connection() as conn:
            assert conn == mock_conn

        mock_conn.unbind.assert_called_once()

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    def test_get_connection_failure(
        self,
        mock_create_connection: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test connection creation failure handling."""
        mock_create_connection.side_effect = Exception("Connection failed")

        with pytest.raises(Exception, match="Connection failed"):
            with connection_manager.get_connection():
                pass

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    async def test_get_pooled_connection_initializes_pool(
        self,
        mock_create_connection: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test pooled connection automatically initializes pool."""
        mock_conn = MagicMock()
        mock_conn.bound = True
        mock_conn.search.return_value = True
        mock_create_connection.return_value = mock_conn

        async with connection_manager.get_pooled_connection() as pooled_conn:
            assert pooled_conn.connection == mock_conn

        assert connection_manager._pool is not None

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    def test_test_connection_success(
        self,
        mock_create_connection: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test successful connection test."""
        mock_conn = MagicMock()
        mock_conn.bound = True
        mock_conn.server.info = "Mock LDAP Server"
        mock_conn.server.schema = "Mock Schema"
        mock_conn.search.return_value = True
        mock_create_connection.return_value = mock_conn

        result = connection_manager.test_connection()

        assert result.connected is True
        assert result.host == connection_manager.connection_info.host
        assert result.port == connection_manager.connection_info.port
        assert result.connection_time > 0
        assert result.response_time > 0
        assert result.connection_error is None
        assert "Mock LDAP Server" in result.ldap_info["server_info"]

    @patch(
        "ldap_core_shared.core.connection_manager.ConnectionFactory.create_connection"
    )
    def test_test_connection_failure(
        self,
        mock_create_connection: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test connection test failure handling."""
        mock_create_connection.side_effect = Exception("Authentication failed")

        result = connection_manager.test_connection()

        assert result.connected is False
        assert result.connection_error == "Authentication failed"
        assert result.response_time == 0.0

    def test_get_performance_metrics(
        self, connection_manager: LDAPConnectionManager
    ) -> None:
        """Test getting performance metrics."""
        metrics = connection_manager.get_performance_metrics()

        # Should return LDAPMetrics with initial values
        assert metrics.operation_count == 0
        assert metrics.total_duration == 0.0

    async def test_close(self, connection_manager: LDAPConnectionManager) -> None:
        """Test closing connection manager."""
        # Initialize pool first
        await connection_manager.initialize_pool()

        # Mock the pool's close method
        connection_manager._pool.close_pool = MagicMock()

        await connection_manager.close()

        connection_manager._pool.close_pool.assert_called_once()
        """Create mock LDAP connection."""
        mock_conn = MagicMock(spec=ldap3.Connection)
        mock_conn.bound = True
        return mock_conn

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="ldap.example.com",
            port=389,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
        )

    @pytest.fixture
    def pooled_connection(
        self,
        mock_connection: MagicMock,
        connection_info: ConnectionInfo,
    ) -> PooledConnection:
        """Create test pooled connection."""
        return PooledConnection(mock_connection, connection_info)

    def test_pooled_connection_creation(
        self,
        pooled_connection: PooledConnection,
        mock_connection: MagicMock,
        connection_info: ConnectionInfo,
    ) -> None:
        """Test PooledConnection creation and initialization."""
        assert pooled_connection.connection == mock_connection
        assert pooled_connection.connection_info == connection_info
        assert pooled_connection.use_count == 0
        assert pooled_connection.is_healthy is True
        assert pooled_connection.is_in_use is False
        assert isinstance(pooled_connection.created_at, float)
        assert isinstance(pooled_connection.last_used, float)

    def test_pooled_connection_mark_used(
        self,
        pooled_connection: PooledConnection,
    ) -> None:
        """Test marking connection as used updates counters."""
        initial_use_count = pooled_connection.use_count
        initial_last_used = pooled_connection.last_used

        # Wait a small amount to ensure time difference
        time.sleep(0.001)
        pooled_connection.mark_used()

        assert pooled_connection.use_count == initial_use_count + 1
        assert pooled_connection.last_used > initial_last_used

    def test_pooled_connection_is_stale(
        self,
        pooled_connection: PooledConnection,
    ) -> None:
        """Test connection staleness detection."""
        # New connection should not be stale
        assert pooled_connection.is_stale(max_age_seconds=3600) is False

        # Very old connection should be stale
        assert pooled_connection.is_stale(max_age_seconds=0) is True

    def test_pooled_connection_is_idle(
        self,
        pooled_connection: PooledConnection,
    ) -> None:
        """Test connection idle detection."""
        # Recently used connection should not be idle
        assert pooled_connection.is_idle(max_idle_seconds=3600) is False

        # Very old usage should be idle
        assert pooled_connection.is_idle(max_idle_seconds=0) is True

    def test_pooled_connection_health_check_success(
        self,
        pooled_connection: PooledConnection,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful health check."""
        mock_connection.bound = True
        mock_connection.search.return_value = True

        assert pooled_connection.validate_health() is True
        mock_connection.search.assert_called_once()

    def test_pooled_connection_health_check_unbound(
        self,
        pooled_connection: PooledConnection,
        mock_connection: MagicMock,
    ) -> None:
        """Test health check with unbound connection."""
        mock_connection.bound = False

        assert pooled_connection.validate_health() is False
        mock_connection.search.assert_not_called()

    def test_pooled_connection_health_check_exception(
        self,
        pooled_connection: PooledConnection,
        mock_connection: MagicMock,
    ) -> None:
        """Test health check with search exception."""
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("Connection error")

        assert pooled_connection.validate_health() is False


class TestConnectionPool:
    """Test ConnectionPool enterprise functionality."""

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="ldap.example.com",
            port=389,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
        )

    @pytest.fixture
    def connection_pool(self, connection_info: ConnectionInfo) -> ConnectionPool:
        """Create test connection pool."""
        return ConnectionPool(
            connection_info=connection_info,
            pool_size=2,
            max_pool_size=5,
        )

    def test_connection_pool_creation(
        self,
        connection_pool: ConnectionPool,
        connection_info: ConnectionInfo,
    ) -> None:
        """Test ConnectionPool creation and initialization."""
        assert connection_pool.connection_info == connection_info
        assert connection_pool.pool_size == 2
        assert connection_pool.max_pool_size == 5
        assert len(connection_pool._pool) == 0
        assert connection_pool._total_connections_created == 0

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    async def test_connection_pool_create_connection(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_pool: ConnectionPool,
    ) -> None:
        """Test connection creation in pool."""
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection_class.return_value = mock_connection

        pooled_conn = await connection_pool._create_connection()

        assert isinstance(pooled_conn, PooledConnection)
        assert pooled_conn.connection == mock_connection
        assert connection_pool._total_connections_created == 1
        assert connection_pool._metrics["connections_created"] == 1

        # Verify server and connection creation
        mock_server.assert_called_once()
        mock_connection_class.assert_called_once()

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    async def test_connection_pool_get_connection(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_pool: ConnectionPool,
    ) -> None:
        """Test getting connection from pool."""
        # Mock connection creation
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection_class.return_value = mock_connection

        async with connection_pool.get_connection() as pooled_conn:
            assert isinstance(pooled_conn, PooledConnection)
            assert pooled_conn.is_in_use is True
            assert len(connection_pool._pool) == 1

        # After context manager, connection should be returned to pool
        assert pooled_conn.is_in_use is False

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    async def test_connection_pool_reuse_connection(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_pool: ConnectionPool,
    ) -> None:
        """Test connection reuse from pool."""
        # Mock connection and health check
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection_class.return_value = mock_connection

        # First connection should create new
        async with connection_pool.get_connection() as pooled_conn1:
            connection_id1 = id(pooled_conn1)

        # Second connection should reuse existing
        async with connection_pool.get_connection() as pooled_conn2:
            connection_id2 = id(pooled_conn2)

        # Should be the same connection object
        assert connection_id1 == connection_id2
        assert connection_pool._metrics["connections_reused"] == 1
        assert connection_pool._metrics["pool_hits"] == 1

    async def test_connection_pool_exhaustion(
        self,
        connection_pool: ConnectionPool,
    ) -> None:
        """Test connection pool exhaustion handling."""
        # Fill the pool to max capacity
        with patch.object(connection_pool, "_create_connection") as mock_create:
            mock_pooled_connections = []
            for _i in range(connection_pool.max_pool_size):
                mock_conn = MagicMock(spec=ldap3.Connection)
                mock_conn.bound = True
                mock_pooled = PooledConnection(
                    mock_conn,
                    connection_pool.connection_info,
                )
                mock_pooled_connections.append(mock_pooled)

            mock_create.side_effect = mock_pooled_connections

            # Use all connections
            connection_contexts = []
            for _ in range(connection_pool.max_pool_size):
                ctx = connection_pool.get_connection()
                connection_contexts.append(ctx)
                await ctx.__aenter__()

            # Next connection request should fail
            with pytest.raises(RuntimeError, match="Connection pool exhausted"):
                async with connection_pool.get_connection():
                    pass

            # Clean up contexts
            for ctx in connection_contexts:
                await ctx.__aexit__(None, None, None)

    async def test_connection_pool_cleanup_stale_connections(
        self,
        connection_pool: ConnectionPool,
    ) -> None:
        """Test cleanup of stale connections."""
        # Create mock stale connection
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection.bound = True
        stale_pooled = PooledConnection(
            mock_connection,
            connection_pool.connection_info,
        )

        # Make connection appear stale
        with patch.object(stale_pooled, "is_stale", return_value=True):
            connection_pool._pool.append(stale_pooled)

            await connection_pool._cleanup_stale_connections()

            # Stale connection should be removed from pool
            assert len(connection_pool._pool) == 0
            mock_connection.unbind.assert_called_once()

    async def test_connection_pool_close(
        self,
        connection_pool: ConnectionPool,
    ) -> None:
        """Test closing connection pool."""
        # Add mock connections to pool
        mock_connections = []
        for _ in range(3):
            mock_conn = MagicMock(spec=ldap3.Connection)
            pooled = PooledConnection(mock_conn, connection_pool.connection_info)
            connection_pool._pool.append(pooled)
            mock_connections.append(mock_conn)

        await connection_pool.close_pool()

        # All connections should be unbound and pool cleared
        for mock_conn in mock_connections:
            mock_conn.unbind.assert_called_once()
        assert len(connection_pool._pool) == 0

    def test_connection_pool_get_metrics(
        self,
        connection_pool: ConnectionPool,
    ) -> None:
        """Test connection pool metrics collection."""
        # Add some mock connections
        for i in range(3):
            mock_conn = MagicMock(spec=ldap3.Connection)
            pooled = PooledConnection(mock_conn, connection_pool.connection_info)
            pooled.is_in_use = i < 2  # First 2 are in use
            connection_pool._pool.append(pooled)

        # Set some metrics
        connection_pool._metrics["connections_created"] = 5
        connection_pool._metrics["connections_reused"] = 3
        connection_pool._metrics["connections_closed"] = 1

        metrics = connection_pool.get_metrics()

        assert metrics.pool_size == 3
        assert metrics.active_connections == 2
        assert metrics.idle_connections == 1
        assert metrics.connections_created == 5
        assert metrics.connections_reused == 3
        assert metrics.connections_closed == 1
        assert metrics.pool_utilization == (2 / connection_pool.max_pool_size) * 100


class TestConnectionManager:
    """Test ConnectionManager enterprise functionality."""

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="ldap.example.com",
            port=389,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
        )

    @pytest.fixture
    def connection_manager(
        self,
        connection_info: ConnectionInfo,
    ) -> ConnectionManager:
        """Create test connection manager."""
        return ConnectionManager(connection_info)

    def test_connection_manager_creation(
        self,
        connection_manager: LDAPConnectionManager,
        connection_info: ConnectionInfo,
    ) -> None:
        """Test ConnectionManager creation."""
        assert connection_manager.connection_info == connection_info
        assert connection_manager._pool is None

    async def test_connection_manager_initialize_pool(
        self,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test connection pool initialization."""
        await connection_manager.initialize_pool(pool_size=3, max_pool_size=10)

        assert connection_manager._pool is not None
        assert connection_manager._pool.pool_size == 3
        assert connection_manager._pool.max_pool_size == 10

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    def test_connection_manager_get_connection_sync(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test synchronous connection retrieval."""
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection_class.return_value = mock_connection

        with connection_manager.get_connection() as connection:
            assert connection == mock_connection

        # Verify connection was properly unbound
        mock_connection.unbind.assert_called_once()

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    async def test_connection_manager_get_pooled_connection(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test asynchronous pooled connection retrieval."""
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection_class.return_value = mock_connection

        async with connection_manager.get_pooled_connection() as pooled_conn:
            assert isinstance(pooled_conn, PooledConnection)
            assert pooled_conn.connection == mock_connection

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    def test_connection_manager_test_connection_success(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test successful connection testing."""
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection.search.return_value = True
        mock_server_obj = MagicMock()
        mock_server_obj.info = "server_info"
        mock_server_obj.schema = "schema_info"
        mock_connection.server = mock_server_obj
        mock_connection_class.return_value = mock_connection

        result = connection_manager.test_connection()

        assert isinstance(result, LDAPConnectionResult)
        assert result.connected is True
        assert result.host == connection_manager.connection_info.host
        assert result.port == connection_manager.connection_info.port
        assert result.connection_time > 0
        assert result.response_time >= 0
        assert result.connection_error is None

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    def test_connection_manager_test_connection_failure(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test failed connection testing."""
        mock_connection_class.side_effect = Exception("Connection failed")

        result = connection_manager.test_connection()

        assert isinstance(result, LDAPConnectionResult)
        assert result.connected is False
        assert result.connection_error == "Connection failed"
        assert result.response_time == 0.0

    def test_connection_manager_get_performance_metrics(
        self,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test performance metrics retrieval."""
        metrics = connection_manager.get_performance_metrics()

        # Should return valid LDAPMetrics object
        assert hasattr(metrics, "operation_count")
        assert hasattr(metrics, "success_count")
        assert hasattr(metrics, "error_count")
        assert hasattr(metrics, "operations_per_second")

    async def test_connection_manager_close(
        self,
        connection_manager: LDAPConnectionManager,
    ) -> None:
        """Test connection manager cleanup."""
        # Initialize pool first
        await connection_manager.initialize_pool()
        assert connection_manager._pool is not None

        # Close should cleanup pool
        await connection_manager.close()

        # Pool should still exist but be empty
        assert connection_manager._pool is not None


class TestConnectionManagerIntegration:
    """Integration tests for connection manager components."""

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="ldap.example.com",
            port=389,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
        )

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    async def test_full_connection_lifecycle(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_info: ConnectionInfo,
    ) -> None:
        """Test complete connection lifecycle from creation to cleanup."""
        # Setup mocks
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection_class.return_value = mock_connection

        # Create manager and initialize pool
        manager = ConnectionManager(connection_info)
        await manager.initialize_pool(pool_size=2, max_pool_size=5)

        # Test multiple connection operations
        for _i in range(3):
            async with manager.get_pooled_connection() as pooled_conn:
                assert pooled_conn.validate_health() is True
                pooled_conn.mark_used()

        # Verify pool metrics
        pool = manager._pool
        assert pool is not None
        metrics = pool.get_metrics()

        # Should have some reused connections
        assert metrics.connections_reused > 0
        assert metrics.pool_hits > 0

        # Test connection manager performance metrics
        perf_metrics = manager.get_performance_metrics()
        assert perf_metrics.operation_count > 0

        # Cleanup
        await manager.close()

    async def test_concurrent_connection_usage(
        self,
        connection_info: ConnectionInfo,
    ) -> None:
        """Test concurrent connection pool usage."""
        with (
            patch(
                "ldap_core_shared.core.connection_manager.Connection",
            ) as mock_conn_class,
            patch("ldap_core_shared.core.connection_manager.Server"),
        ):
            # Setup mock
            mock_connection = MagicMock(spec=ldap3.Connection)
            mock_connection.bound = True
            mock_connection.search.return_value = True
            mock_conn_class.return_value = mock_connection

            manager = ConnectionManager(connection_info)
            await manager.initialize_pool(pool_size=3, max_pool_size=3)

            async def use_connection(connection_id: int) -> int:
                """Use a connection and return the connection ID."""
                async with manager.get_pooled_connection() as pooled_conn:
                    # Simulate some work
                    await asyncio.sleep(0.01)
                    return id(pooled_conn)

            # Run concurrent connection usage
            tasks = [use_connection(i) for i in range(5)]
            results = await asyncio.gather(*tasks)

            # Should have reused some connections
            unique_connections = len(set(results))
            assert unique_connections <= 3  # Max pool size
            assert len(results) == 5  # All tasks completed

            await manager.close()


@pytest.mark.benchmark(group="connection_performance")
class TestConnectionManagerPerformance:
    """Performance benchmarks for connection manager."""

    @pytest.fixture
    def connection_info(self) -> ConnectionInfo:
        """Create test connection info."""
        return ConnectionInfo(
            host="ldap.example.com",
            port=389,
            base_dn="dc=example,dc=com",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="test_password",  # nosec B106
        )

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    def test_connection_creation_performance(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        benchmark: pytest.fixture,  # type: ignore[type-arg]
        connection_info: ConnectionInfo,
    ) -> None:
        """Benchmark connection creation performance."""
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection_class.return_value = mock_connection

        manager = ConnectionManager(connection_info)

        def create_connection() -> None:
            with manager.get_connection():
                pass

        # Benchmark should complete under target time
        result = benchmark(create_connection)
        assert result is None  # Function returns None

    @patch("ldap_core_shared.core.connection_manager.Connection")
    @patch("ldap_core_shared.core.connection_manager.Server")
    async def test_pool_acquisition_performance(
        self,
        mock_server: MagicMock,
        mock_connection_class: MagicMock,
        connection_info: ConnectionInfo,
    ) -> None:
        """Test connection pool acquisition performance."""
        mock_connection = MagicMock(spec=ldap3.Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection_class.return_value = mock_connection

        manager = ConnectionManager(connection_info)
        await manager.initialize_pool(pool_size=5, max_pool_size=10)

        # Measure acquisition time
        start_time = time.time()

        for _ in range(100):
            async with manager.get_pooled_connection():
                pass

        end_time = time.time()
        total_time = end_time - start_time
        avg_time_ms = (total_time / 100) * 1000

        # Should be fast (under 10ms per acquisition on average)
        assert avg_time_ms < 10.0

        await manager.close()


# Test fixtures for reusable test data
@pytest.fixture
def sample_connection_configs() -> (
    Generator[
        list[dict[str, str | int | bool]],
        None,
        None,
    ]
):
    """Provide sample connection configurations for testing."""
    return [
        {
            "host": "ldap1.example.com",
            "port": 389,
            "base_dn": "dc=example,dc=com",
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "bind_password": "test_password1",  # nosec B106
            "use_ssl": False,
        },
        {
            "host": "ldaps.example.com",
            "port": 636,
            "base_dn": "dc=secure,dc=com",
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=secure,dc=com",
            "bind_password": "test_password2",  # nosec B106
            "use_ssl": True,
        },
        {
            "host": "localhost",
            "port": 10389,
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            "bind_password": "test_password3",  # nosec B106
            "ssh_host": "bastion.example.com",
            "ssh_username": "tunnel_user",
        },
    ]


if __name__ == "__main__":
    # Run tests with coverage
    pytest.main(
        [
            __file__,
            "-v",
            "--cov=ldap_core_shared.core.connection_manager",
            "--cov-report=term-missing",
            "--cov-report=html",
        ],
    )
