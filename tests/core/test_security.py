"""Tests for Enterprise LDAP Security Module.

This module provides comprehensive test coverage for the LDAP security
system including SSH tunnels, authentication management, and security
monitoring with enterprise-grade validation.

Test Coverage:
    - SSHTunnelConfig: Configuration validation and security settings
    - SSHTunnel: SSH tunnel creation, management, and lifecycle
    - AuthenticationManager: LDAP authentication with lockout protection
    - SecurityManager: Comprehensive security orchestration
    - SSL certificate validation and security monitoring
    - Global security manager instance management

Security Testing:
    - SSH tunnel security and connection validation
    - Authentication attempt monitoring and lockout protection
    - SSL/TLS certificate validation
    - Security event logging and audit trails
    - Resource management and cleanup validation

Performance Testing:
    - SSH tunnel connection performance
    - Authentication response times
    - Security event processing efficiency
    - Memory usage for long-running security operations
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import Mock, patch

import pytest

from ldap_core_shared.core.security import (
    AuthenticationManager,
    SecurityManager,
    SSHTunnel,
    SSHTunnelConfig,
    close_ssh_tunnel,
    create_ssh_tunnel,
    get_security_manager,
)
from ldap_core_shared.utils.constants import (
    DEFAULT_LARGE_LIMIT,
    SSH_LOCAL_PORT_RANGE,
    SSH_TUNNEL_TIMEOUT,
)


class MockSSHTunnelForwarder:
    """Mock SSH tunnel forwarder for testing."""

    def __init__(self, *args, **kwargs) -> None:
        self.local_bind_port = kwargs.get("local_bind_address", (None, 0))[1]
        self.is_alive = False
        self._started = False

    def start(self) -> None:
        """Start mock tunnel."""
        self._started = True
        self.is_alive = True

    def stop(self) -> None:
        """Stop mock tunnel."""
        self._started = False
        self.is_alive = False


class MockLDAPConnection:
    """Mock LDAP connection for testing."""

    def __init__(self, bind_success: bool = True, bind_exception: Any = None) -> None:
        self.bind_success = bind_success
        self.bind_exception = bind_exception
        self.bind_calls = []

    def bind(self, dn: str, password: str) -> None:
        """Mock bind operation."""
        self.bind_calls.append((dn, password))

        if self.bind_exception:
            raise self.bind_exception

        return self.bind_success


class TestSSHTunnelConfig:
    """Test cases for SSHTunnelConfig."""

    def test_basic_config_creation(self) -> None:
        """Test basic SSH tunnel configuration creation."""
        config = SSHTunnelConfig(
            ssh_host="example.com",
            ssh_username="user",
            ssh_password="password",
        )

        assert config.ssh_host == "example.com"
        assert config.ssh_port == 22
        assert config.ssh_username == "user"
        assert config.ssh_password == "password"
        assert config.ssh_key_file is None
        assert config.remote_host == "localhost"
        assert config.remote_port == 22
        assert config.timeout == SSH_TUNNEL_TIMEOUT

    def test_config_with_key_authentication(self) -> None:
        """Test configuration with SSH key authentication."""
        config = SSHTunnelConfig(
            ssh_host="secure.example.com",
            ssh_username="keyuser",
            ssh_key_file="/path/to/key",
            ssh_key_password="keypass",
            remote_port=389,
        )

        assert config.ssh_host == "secure.example.com"
        assert config.ssh_username == "keyuser"
        assert config.ssh_password is None
        assert config.ssh_key_file == "/path/to/key"
        assert config.ssh_key_password == "keypass"
        assert config.remote_port == 389

    def test_config_with_custom_ports(self) -> None:
        """Test configuration with custom port settings."""
        config = SSHTunnelConfig(
            ssh_host="custom.example.com",
            ssh_port=2222,
            ssh_username="user",
            ssh_password="pass",
            local_bind_port=3389,
            remote_port=636,
        )

        assert config.ssh_port == 2222
        assert config.local_bind_port == 3389
        assert config.remote_port == 636

    def test_config_validation_ssh_port(self) -> None:
        """Test SSH port validation."""
        with pytest.raises(ValueError):
            SSHTunnelConfig(
                ssh_host="example.com",
                ssh_port=0,  # Invalid port
                ssh_username="user",
                ssh_password="pass",
            )

        with pytest.raises(ValueError):
            SSHTunnelConfig(
                ssh_host="example.com",
                ssh_port=65536,  # Port too high
                ssh_username="user",
                ssh_password="pass",
            )

    def test_config_validation_local_port(self) -> None:
        """Test local port validation."""
        with pytest.raises(ValueError):
            SSHTunnelConfig(
                ssh_host="example.com",
                ssh_username="user",
                ssh_password="pass",
                local_bind_port=-1,  # Invalid port
            )

    def test_config_immutability(self) -> None:
        """Test configuration immutability."""
        config = SSHTunnelConfig(
            ssh_host="example.com",
            ssh_username="user",
            ssh_password="pass",
        )

        with pytest.raises(ValueError):
            config.ssh_host = "modified.com"

    def test_config_security_settings(self) -> None:
        """Test security-related configuration settings."""
        config = SSHTunnelConfig(
            ssh_host="example.com",
            ssh_username="user",
            ssh_password="pass",
            compression=True,
            timeout=60,
        )

        assert config.compression is True
        assert config.timeout == 60


class TestSSHTunnel:
    """Test cases for SSHTunnel."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config = SSHTunnelConfig(
            ssh_host="test.example.com",
            ssh_username="testuser",
            ssh_password="testpass",
            remote_port=389,
        )

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_tunnel_start_success(self) -> None:
        """Test successful tunnel start."""
        tunnel = SSHTunnel(self.config)

        with patch.object(tunnel, "_find_free_port", return_value=12345):
            port = tunnel.start()

        assert port == 12345
        assert tunnel.is_active is True
        assert tunnel.local_port == 12345

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder")
    def test_tunnel_start_with_sshtunnel_unavailable(self, mock_forwarder: Any) -> None:
        """Test tunnel start when sshtunnel module is unavailable."""
        # Simulate ImportError for sshtunnel
        with patch(
            "builtins.__import__", side_effect=ImportError("sshtunnel not available")
        ):
            tunnel = SSHTunnel(self.config)

            with patch.object(tunnel, "_find_free_port", return_value=12345):
                port = tunnel.start()

            assert port == 12345
            # Should still work with stub implementation

    def test_tunnel_start_failure(self) -> None:
        """Test tunnel start failure handling."""
        tunnel = SSHTunnel(self.config)

        with patch(
            "ldap_core_shared.core.security.SSHTunnelForwarder",
            side_effect=Exception("Connection failed"),
        ):
            with pytest.raises(RuntimeError, match="Failed to start SSH tunnel"):
                tunnel.start()

            assert tunnel.is_active is False
            assert tunnel.local_port is None

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_tunnel_stop(self) -> None:
        """Test tunnel stop functionality."""
        tunnel = SSHTunnel(self.config)

        with patch.object(tunnel, "_find_free_port", return_value=12345):
            tunnel.start()

        assert tunnel.is_active is True

        tunnel.stop()

        assert tunnel.is_active is False
        assert tunnel.local_port is None

    def test_tunnel_find_free_port(self) -> None:
        """Test finding free port functionality."""
        tunnel = SSHTunnel(self.config)

        # Mock successful socket binding
        with patch("socket.socket") as mock_socket:
            mock_sock = mock_socket.return_value.__enter__.return_value
            mock_sock.bind.return_value = None

            port = tunnel._find_free_port()

            start_port, end_port = SSH_LOCAL_PORT_RANGE
            assert start_port <= port <= end_port

    def test_tunnel_find_free_port_exhausted(self) -> None:
        """Test port exhaustion scenario."""
        tunnel = SSHTunnel(self.config)

        # Mock all ports as occupied
        with patch("socket.socket") as mock_socket:
            mock_sock = mock_socket.return_value.__enter__.return_value
            mock_sock.bind.side_effect = OSError("Port in use")

            with pytest.raises(RuntimeError, match="No free ports available"):
                tunnel._find_free_port()

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_tunnel_context_manager(self) -> None:
        """Test tunnel as context manager."""
        tunnel = SSHTunnel(self.config)

        with patch.object(tunnel, "_find_free_port", return_value=12345):
            with tunnel as active_tunnel:
                assert active_tunnel.is_active is True
                assert active_tunnel.local_port == 12345

            # Should be stopped after context exit
            assert tunnel.is_active is False

    def test_tunnel_authentication_password(self) -> None:
        """Test tunnel with password authentication."""
        config = SSHTunnelConfig(
            ssh_host="example.com",
            ssh_username="user",
            ssh_password="secret123",
        )
        tunnel = SSHTunnel(config)

        with patch(
            "ldap_core_shared.core.security.SSHTunnelForwarder"
        ) as mock_forwarder:
            mock_instance = Mock()
            mock_forwarder.return_value = mock_instance
            mock_instance.local_bind_port = 12345

            with patch.object(tunnel, "_find_free_port", return_value=12345):
                tunnel.start()

            # Verify password was passed to tunnel
            call_kwargs = mock_forwarder.call_args[1]
            assert call_kwargs["ssh_password"] == "secret123"

    def test_tunnel_authentication_key(self) -> None:
        """Test tunnel with key authentication."""
        config = SSHTunnelConfig(
            ssh_host="example.com",
            ssh_username="user",
            ssh_key_file="/path/to/key",
            ssh_key_password="keypass",
        )
        tunnel = SSHTunnel(config)

        with patch(
            "ldap_core_shared.core.security.SSHTunnelForwarder"
        ) as mock_forwarder:
            mock_instance = Mock()
            mock_forwarder.return_value = mock_instance
            mock_instance.local_bind_port = 12345

            with patch.object(tunnel, "_find_free_port", return_value=12345):
                tunnel.start()

            # Verify key authentication parameters
            call_kwargs = mock_forwarder.call_args[1]
            assert call_kwargs["ssh_pkey"] == "/path/to/key"
            assert call_kwargs["ssh_private_key_password"] == "keypass"


class TestAuthenticationManager:
    """Test cases for AuthenticationManager."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.auth_manager = AuthenticationManager()
        self.mock_connection = MockLDAPConnection()

    def test_successful_authentication(self) -> None:
        """Test successful LDAP authentication."""
        success, message = self.auth_manager.authenticate(
            "cn=testuser,dc=example,dc=com",
            "password123",
            self.mock_connection,
        )

        assert success is True
        assert message == "Authentication successful"
        assert len(self.mock_connection.bind_calls) == 1

    def test_failed_authentication(self) -> None:
        """Test failed LDAP authentication."""
        self.mock_connection.bind_success = False

        success, message = self.auth_manager.authenticate(
            "cn=testuser,dc=example,dc=com",
            "wrongpass",
            self.mock_connection,
        )

        assert success is False
        assert message == "Authentication failed"

    def test_authentication_exception_handling(self) -> None:
        """Test authentication exception handling."""
        self.mock_connection.bind_exception = Exception("Connection error")

        success, message = self.auth_manager.authenticate(
            "cn=testuser,dc=example,dc=com",
            "password123",
            self.mock_connection,
        )

        assert success is False
        assert "Authentication error" in message

    def test_account_lockout_mechanism(self) -> None:
        """Test account lockout after multiple failures."""
        dn = "cn=testuser,dc=example,dc=com"
        self.mock_connection.bind_success = False

        # Attempt authentication multiple times to trigger lockout
        for _ in range(5):
            self.auth_manager.authenticate(dn, "wrongpass", self.mock_connection)

        # Next attempt should be locked out
        success, message = self.auth_manager.authenticate(
            dn, "wrongpass", self.mock_connection
        )

        assert success is False
        assert "temporarily locked" in message.lower()

    def test_lockout_clearance_on_success(self) -> None:
        """Test lockout clearance after successful authentication."""
        dn = "cn=testuser,dc=example,dc=com"

        # Record some failed attempts
        self.mock_connection.bind_success = False
        for _ in range(3):
            self.auth_manager.authenticate(dn, "wrongpass", self.mock_connection)

        # Successful authentication should clear attempts
        self.mock_connection.bind_success = True
        success, message = self.auth_manager.authenticate(
            dn, "correctpass", self.mock_connection
        )

        assert success is True
        assert message == "Authentication successful"

        # Should not be locked out after success
        self.mock_connection.bind_success = False
        success, message = self.auth_manager.authenticate(
            dn, "wrongpass", self.mock_connection
        )
        assert "locked" not in message.lower()

    def test_lockout_expiration(self) -> None:
        """Test lockout expiration after timeout."""
        dn = "cn=testuser,dc=example,dc=com"
        self.mock_connection.bind_success = False

        # Mock time to simulate lockout expiration
        with patch("time.time") as mock_time:
            # Initial failed attempts
            mock_time.return_value = 1000
            for _ in range(5):
                self.auth_manager.authenticate(dn, "wrongpass", self.mock_connection)

            # Should be locked out
            _success, message = self.auth_manager.authenticate(
                dn, "wrongpass", self.mock_connection
            )
            assert "locked" in message.lower()

            # Advance time beyond lockout duration
            mock_time.return_value = 1000 + 400  # Exceed 300s lockout

            # Should no longer be locked out
            _success, message = self.auth_manager.authenticate(
                dn, "wrongpass", self.mock_connection
            )
            assert "locked" not in message.lower()

    def test_authentication_statistics(self) -> None:
        """Test authentication statistics collection."""
        dn = "cn=testuser,dc=example,dc=com"

        # Mix of successful and failed attempts
        self.mock_connection.bind_success = True
        self.auth_manager.authenticate(dn, "correct", self.mock_connection)

        self.mock_connection.bind_success = False
        self.auth_manager.authenticate(dn, "wrong1", self.mock_connection)
        self.auth_manager.authenticate(dn, "wrong2", self.mock_connection)

        stats = self.auth_manager.get_auth_stats()

        assert stats["total_auth_attempts"] == 3
        assert stats["successful_auths"] == 1
        assert stats["failed_auths"] == 2
        assert stats["success_rate"] == pytest.approx(1 / 3, rel=1e-2)
        assert "average_auth_time" in stats
        assert "locked_accounts" in stats

    def test_multiple_user_lockout_tracking(self) -> None:
        """Test lockout tracking for multiple users."""
        user1 = "cn=user1,dc=example,dc=com"
        user2 = "cn=user2,dc=example,dc=com"

        self.mock_connection.bind_success = False

        # Lock out user1
        for _ in range(5):
            self.auth_manager.authenticate(user1, "wrong", self.mock_connection)

        # User1 should be locked
        _success, message = self.auth_manager.authenticate(
            user1, "wrong", self.mock_connection
        )
        assert "locked" in message.lower()

        # User2 should not be locked
        _success, message = self.auth_manager.authenticate(
            user2, "wrong", self.mock_connection
        )
        assert "locked" not in message.lower()


class TestSecurityManager:
    """Test cases for SecurityManager."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.security_manager = SecurityManager()
        self.ssh_config = SSHTunnelConfig(
            ssh_host="secure.example.com",
            ssh_username="user",
            ssh_password="pass",
        )

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_secure_tunnel_context_manager(self) -> None:
        """Test secure tunnel context manager."""
        with patch.object(SSHTunnel, "_find_free_port", return_value=12345):
            with self.security_manager.secure_tunnel(
                self.ssh_config, "test_tunnel"
            ) as tunnel:
                assert tunnel.is_active is True
                assert tunnel.local_port == 12345
                assert "test_tunnel" in self.security_manager._active_tunnels

            # Tunnel should be closed and removed after context
            assert "test_tunnel" not in self.security_manager._active_tunnels

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_create_and_close_tunnel(self) -> None:
        """Test manual tunnel creation and closure."""
        with patch.object(SSHTunnel, "_find_free_port", return_value=12345):
            tunnel = self.security_manager.create_tunnel(self.ssh_config)

        assert tunnel.is_active is True
        assert len(self.security_manager._active_tunnels) == 1

        self.security_manager.close_tunnel(tunnel)

        assert tunnel.is_active is False
        assert len(self.security_manager._active_tunnels) == 0

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_close_all_tunnels(self) -> None:
        """Test closing all active tunnels."""
        with patch.object(SSHTunnel, "_find_free_port", return_value=12345):
            tunnel1 = self.security_manager.create_tunnel(self.ssh_config)
            tunnel2 = self.security_manager.create_tunnel(self.ssh_config)

        assert len(self.security_manager._active_tunnels) == 2

        self.security_manager.close_all_tunnels()

        assert len(self.security_manager._active_tunnels) == 0
        assert tunnel1.is_active is False
        assert tunnel2.is_active is False

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_get_active_tunnels_info(self) -> None:
        """Test getting active tunnel information."""
        with patch.object(SSHTunnel, "_find_free_port", return_value=12345):
            self.security_manager.create_tunnel(self.ssh_config)

        active_info = self.security_manager.get_active_tunnels()

        assert len(active_info) == 1
        tunnel_info = next(iter(active_info.values()))

        assert tunnel_info["is_active"] is True
        assert tunnel_info["local_port"] == 12345
        assert tunnel_info["ssh_host"] == "secure.example.com"
        assert tunnel_info["remote_port"] == 22

    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_ssl_certificate_validation_success(
        self, mock_ssl_context: Any, mock_socket: Any
    ) -> None:
        """Test successful SSL certificate validation."""
        # Mock SSL certificate
        mock_cert = {
            "subject": [("CN", "example.com")],
            "issuer": [("CN", "Test CA")],
            "notBefore": "Jan 1 00:00:00 2024 GMT",
            "notAfter": "Jan 1 00:00:00 2025 GMT",
            "serialNumber": "123456789",
            "version": 3,
        }

        mock_ssl_sock = Mock()
        mock_ssl_sock.getpeercert.return_value = mock_cert

        mock_context = Mock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context

        result = self.security_manager.validate_ssl_certificate("example.com", 636)

        assert result["valid"] is True
        assert result["subject"]["CN"] == "example.com"
        assert result["issuer"]["CN"] == "Test CA"
        assert result["serial_number"] == "123456789"

    def test_ssl_certificate_validation_failure(self) -> None:
        """Test SSL certificate validation failure."""
        with patch(
            "socket.create_connection", side_effect=Exception("Connection failed")
        ):
            result = self.security_manager.validate_ssl_certificate("invalid.com", 636)

        assert result["valid"] is False
        assert "error" in result

    def test_security_event_logging(self) -> None:
        """Test security event logging."""
        self.security_manager._log_security_event(
            "test_event",
            {"detail1": "value1", "detail2": "value2"},
        )

        events = self.security_manager.get_security_events()
        assert len(events) == 1

        event = events[0]
        assert event["event_type"] == "test_event"
        assert event["details"]["detail1"] == "value1"
        assert "timestamp" in event

    def test_security_event_limit(self) -> None:
        """Test security event limit enforcement."""
        # Generate more events than the limit
        for i in range(DEFAULT_LARGE_LIMIT + 100):
            self.security_manager._log_security_event(
                f"event_{i}",
                {"counter": i},
            )

        events = self.security_manager.get_security_events(limit=None)

        # Should not exceed the limit
        assert len(events) <= DEFAULT_LARGE_LIMIT

    def test_security_summary(self) -> None:
        """Test security summary generation."""
        summary = self.security_manager.get_security_summary()

        assert "active_tunnels" in summary
        assert "security_events" in summary
        assert "authentication" in summary
        assert "tunnel_info" in summary

        # Check authentication stats structure
        auth_stats = summary["authentication"]
        assert "total_auth_attempts" in auth_stats
        assert "success_rate" in auth_stats

    def test_get_security_events_with_limit(self) -> None:
        """Test getting security events with limit."""
        # Add multiple events
        for i in range(10):
            self.security_manager._log_security_event(f"event_{i}", {"id": i})

        events = self.security_manager.get_security_events(limit=5)
        assert len(events) == 5

        # Should return the most recent events
        assert events[-1]["details"]["id"] == 9


class TestGlobalSecurityManager:
    """Test cases for global security manager functions."""

    def test_get_security_manager_singleton(self) -> None:
        """Test global security manager singleton pattern."""
        manager1 = get_security_manager()
        manager2 = get_security_manager()

        assert manager1 is manager2
        assert isinstance(manager1, SecurityManager)

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_create_ssh_tunnel_global(self) -> None:
        """Test global SSH tunnel creation function."""
        config = SSHTunnelConfig(
            ssh_host="global.example.com",
            ssh_username="user",
            ssh_password="pass",
        )

        with patch.object(SSHTunnel, "_find_free_port", return_value=12345):
            tunnel = create_ssh_tunnel(config)

        assert tunnel.is_active is True
        assert tunnel.local_port == 12345

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_close_ssh_tunnel_global(self) -> None:
        """Test global SSH tunnel closure function."""
        config = SSHTunnelConfig(
            ssh_host="global.example.com",
            ssh_username="user",
            ssh_password="pass",
        )

        with patch.object(SSHTunnel, "_find_free_port", return_value=12345):
            tunnel = create_ssh_tunnel(config)

        assert tunnel.is_active is True

        close_ssh_tunnel(tunnel)

        assert tunnel.is_active is False


class TestSecurityIntegration:
    """Integration test cases for security components."""

    def setup_method(self) -> None:
        """Set up integration test fixtures."""
        self.security_manager = SecurityManager()

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_full_secure_connection_workflow(self) -> None:
        """Test complete secure connection workflow."""
        # 1. Create SSH tunnel
        ssh_config = SSHTunnelConfig(
            ssh_host="secure.ldap.com",
            ssh_username="admin",
            ssh_password="secure123",
            remote_port=389,
        )

        with patch.object(SSHTunnel, "_find_free_port", return_value=13389):
            tunnel = self.security_manager.create_tunnel(ssh_config)

        assert tunnel.is_active is True

        # 2. Simulate LDAP authentication through tunnel
        mock_connection = MockLDAPConnection()
        success, _message = self.security_manager.auth_manager.authenticate(
            "cn=admin,dc=company,dc=com",
            "adminpass",
            mock_connection,
        )

        assert success is True

        # 3. Check security summary
        summary = self.security_manager.get_security_summary()
        assert summary["active_tunnels"] == 1
        assert summary["authentication"]["successful_auths"] == 1

        # 4. Clean up
        self.security_manager.close_tunnel(tunnel)
        assert tunnel.is_active is False

    def test_security_event_audit_trail(self) -> None:
        """Test security event audit trail."""
        # Generate various security events
        events = [
            ("user_login", {"user": "admin", "source": "192.168.1.100"}),
            ("tunnel_created", {"host": "secure.ldap.com", "port": 12345}),
            ("auth_failure", {"user": "hacker", "attempts": 5}),
            ("tunnel_closed", {"host": "secure.ldap.com"}),
        ]

        for event_type, details in events:
            self.security_manager._log_security_event(event_type, details)

        # Verify audit trail
        audit_events = self.security_manager.get_security_events()
        assert len(audit_events) == len(events)

        # Check event ordering (should be chronological)
        timestamps = [event["timestamp"] for event in audit_events]
        assert timestamps == sorted(timestamps)

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_concurrent_tunnel_management(self) -> None:
        """Test concurrent tunnel management."""
        configs = [
            SSHTunnelConfig(
                ssh_host=f"server{i}.example.com",
                ssh_username="user",
                ssh_password="pass",
                remote_port=389 + i,
            )
            for i in range(3)
        ]

        tunnels = []
        for i, config in enumerate(configs):
            with patch.object(SSHTunnel, "_find_free_port", return_value=12000 + i):
                tunnel = self.security_manager.create_tunnel(config)
                tunnels.append(tunnel)

        # All tunnels should be active
        assert len(self.security_manager._active_tunnels) == 3
        for tunnel in tunnels:
            assert tunnel.is_active is True

        # Close all tunnels
        self.security_manager.close_all_tunnels()

        # All should be closed
        for tunnel in tunnels:
            assert tunnel.is_active is False
        assert len(self.security_manager._active_tunnels) == 0


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_authentication_performance_tracking(self) -> None:
        """Test authentication performance tracking."""
        auth_manager = AuthenticationManager()
        mock_connection = MockLDAPConnection()

        # Perform multiple authentications
        for i in range(100):
            auth_manager.authenticate(
                f"cn=user{i},dc=example,dc=com",
                "password",
                mock_connection,
            )

        stats = auth_manager.get_auth_stats()
        assert stats["total_auth_attempts"] == 100
        assert "average_auth_time" in stats
        assert stats["average_auth_time"] >= 0

    @patch("ldap_core_shared.core.security.SSHTunnelForwarder", MockSSHTunnelForwarder)
    def test_tunnel_creation_performance(self) -> None:
        """Test tunnel creation performance."""
        security_manager = SecurityManager()
        config = SSHTunnelConfig(
            ssh_host="perf.example.com",
            ssh_username="user",
            ssh_password="pass",
        )

        start_time = time.time()

        with patch.object(SSHTunnel, "_find_free_port", return_value=12345):
            tunnel = security_manager.create_tunnel(config)

        creation_time = time.time() - start_time

        assert tunnel.is_active is True
        assert creation_time < 1.0  # Should be fast in test environment

    def test_security_event_processing_performance(self) -> None:
        """Test security event processing performance."""
        security_manager = SecurityManager()

        start_time = time.time()

        # Generate large number of events
        for i in range(1000):
            security_manager._log_security_event(
                "performance_test",
                {"iteration": i, "data": f"test_data_{i}"},
            )

        processing_time = time.time() - start_time

        assert processing_time < 5.0  # Should process quickly
        assert len(security_manager.get_security_events()) <= DEFAULT_LARGE_LIMIT


class TestErrorHandling:
    """Error handling test cases."""

    def test_tunnel_creation_with_invalid_config(self) -> None:
        """Test tunnel creation with invalid configuration."""
        # Test with missing required fields - should fail at Pydantic level
        with pytest.raises(ValueError):
            SSHTunnelConfig(
                ssh_host="example.com",
                # Missing required ssh_username
            )

    def test_authentication_with_none_connection(self) -> None:
        """Test authentication with None connection."""
        auth_manager = AuthenticationManager()

        with pytest.raises(AttributeError):
            auth_manager.authenticate(
                "cn=test,dc=example,dc=com",
                "password",
                None,  # Invalid connection
            )

    def test_security_manager_resilience(self) -> None:
        """Test security manager resilience to errors."""
        security_manager = SecurityManager()

        # Test with malformed tunnel reference
        fake_tunnel = Mock()
        fake_tunnel.stop.side_effect = Exception("Stop failed")

        # Should not raise exception
        security_manager.close_tunnel(fake_tunnel)

        # Should continue operating normally
        summary = security_manager.get_security_summary()
        assert isinstance(summary, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
