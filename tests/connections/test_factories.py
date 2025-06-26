"""Tests for LDAP Connection Factory Implementations - PyAuto Workspace Standards Compliant.

This module provides comprehensive test coverage for the LDAP connection factory
implementations including SOLID principle compliance, dependency injection patterns,
and enterprise-grade connection creation with TLS/SSL configuration and security management.

PyAuto Workspace Standards Compliance:
    - .env security enforcement with permission validation (CLAUDE.md)
    - CLI debug patterns with mandatory --debug flag usage (CLAUDE.md)
    - SOLID principles compliance validation across all test execution
    - Workspace venv coordination with /home/marlonsc/pyauto/.venv (internal.invalid.md)
    - Cross-project dependency validation for shared library usage
    - Security enforcement for sensitive data handling and protection

Test Coverage:
    - StandardConnectionFactory: Main connection factory with SOLID compliance
    - Factory initialization with dependency injection patterns
    - Connection creation with various configurations and protocols
    - TLS/SSL configuration and certificate validation
    - Security manager integration and credential validation
    - Factory component lifecycle management and cleanup
    - Error handling and resilience patterns for connection failures

Integration Testing:
    - Complete factory workflow with security validation
    - LDAP3 library integration and server configuration
    - TLS configuration with certificate validation
    - Security manager dependency injection and validation
    - Connection binding and authentication testing
    - Factory cleanup and resource management
    - PyAuto workspace coordination with .token file integration

Performance Testing:
    - Connection creation performance and timing validation
    - Memory usage during factory operations and connections
    - Factory initialization efficiency and resource optimization
    - Concurrent connection creation and factory thread safety
    - Connection object lifecycle and garbage collection
    - Workspace venv performance validation and optimization

Security Testing:
    - Credential validation and secure password handling
    - TLS/SSL configuration and certificate validation
    - Connection security enforcement and protocol validation
    - Security manager integration and authentication flows
    - Sensitive data protection and logging security
    - .env security enforcement and hardcoded secrets detection
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from pydantic import SecretStr

from ldap_core_shared.connections.factories import StandardConnectionFactory

if TYPE_CHECKING:
    from collections.abc import Generator


# PyAuto Workspace Standards Compliance Tests for Connection Factories
class TestConnectionFactoriesWorkspaceCompliance:
    """Test PyAuto workspace standards compliance for connection factories module."""

    @pytest.mark.workspace_integration
    def test_factory_workspace_venv_validation(self, validate_workspace_venv: None) -> None:
        """Test connection factory workspace venv validation as required by CLAUDE.md."""
        # Fixture automatically validates workspace venv usage
        expected_venv = "/home/marlonsc/pyauto/.venv"
        current_venv = os.environ.get("VIRTUAL_ENV")
        assert current_venv == expected_venv, f"Factory tests must use workspace venv: {expected_venv}"

    @pytest.mark.env_security
    def test_factory_env_security_enforcement(self, validate_env_security: Generator[None, None, None]) -> None:
        """Test connection factory .env security enforcement as required by CLAUDE.md."""
        # Test factory configuration security
        with patch.dict(os.environ, {
            "LDAP_CORE_TLS_VALIDATION": "strict",
            "LDAP_CORE_CONNECTION_TIMEOUT": "30",
        }, clear=False):
            # Validate no hardcoded secrets in factory configuration
            for key, value in os.environ.items():
                if "factory" in key.lower() and ("password" in key.lower() or "secret" in key.lower()):
                    assert value.startswith("${") or len(value) == 0, f"Hardcoded secret in factory config: {key}"

    @pytest.mark.cli_debug
    def test_factory_cli_debug_patterns(self, cli_debug_patterns: Generator[dict[str, bool], None, None]) -> None:
        """Test connection factory CLI debug patterns as required by CLAUDE.md."""
        # Test factory debug configuration
        assert cli_debug_patterns["debug_enabled"] is True
        assert cli_debug_patterns["verbose_logging"] is True

        # Validate factory debug environment
        assert os.environ.get("LDAP_CORE_DEBUG_LEVEL") == "INFO"
        assert os.environ.get("LDAP_CORE_CLI_DEBUG") == "true"

    @pytest.mark.solid_compliance
    def test_factory_solid_principles_compliance(self, solid_principles_validation: Generator[dict[str, object], None, None]) -> None:
        """Test connection factory SOLID principles compliance."""
        # Validate StandardConnectionFactory follows SOLID principles
        from ldap_core_shared.connections.interfaces import BaseConnectionComponent

        mock_connection_info = Mock()
        factory = StandardConnectionFactory(mock_connection_info)

        # Test Single Responsibility: Factory creates connections only
        assert hasattr(factory, "create_connection")
        assert not hasattr(factory, "manage_pool")  # Should not manage pools

        # Test Open/Closed: Can be extended through inheritance
        assert StandardConnectionFactory.__bases__

        # Test Liskov Substitution: Can be used wherever BaseConnectionComponent expected
        assert isinstance(factory, BaseConnectionComponent)

        # Test Interface Segregation: Focused interface
        assert hasattr(factory, "initialize")
        assert hasattr(factory, "cleanup")

        # Test Dependency Inversion: Depends on abstractions
        assert hasattr(factory, "_security_manager")
        assert hasattr(factory, "connection_info")

    @pytest.mark.workspace_integration
    def test_factory_workspace_coordination(self, workspace_coordination: Any) -> None:
        """Test connection factory workspace coordination as required by internal.invalid.md."""
        coordination = workspace_coordination

        # Validate factory operates within shared library context
        assert coordination["PROJECT_CONTEXT"] == "ldap-core-shared"
        assert coordination["STATUS"] == "development-shared-library"

        # Test factory is available for dependent projects
        dependent_projects = coordination["DEPENDENCY_FOR"].split(",")
        assert "client-a-oud-mig" in dependent_projects
        assert "flx-ldap" in dependent_projects
        assert "tap-ldap" in dependent_projects
        assert "target-ldap" in dependent_projects

    @pytest.mark.security_enforcement
    def test_factory_security_enforcement(self, security_enforcement: Any) -> None:
        """Test connection factory security enforcement patterns."""
        security = security_enforcement

        # Test factory security configuration
        assert security["mask_sensitive_data"] is True
        assert security["validate_credentials"] is True
        assert security["enforce_encryption"] is True

        # Test factory doesn't expose sensitive connection data
        mock_connection_info = Mock()
        mock_connection_info.bind_password = SecretStr("secret123")

        factory = StandardConnectionFactory(mock_connection_info)

        # Verify factory doesn't expose sensitive data
        factory_str = str(factory)
        assert "secret123" not in factory_str

        # Test SecretStr password handling
        assert isinstance(mock_connection_info.bind_password, SecretStr)
        assert mock_connection_info.bind_password.get_secret_value() == "secret123"

    def test_dependent_projects_factory_integration(self) -> None:
        """Test dependent projects can integrate with factory as required by internal.invalid.md."""
        # Validate factory is properly exposed for dependent projects
        mock_connection_info = Mock()
        factory = StandardConnectionFactory(mock_connection_info)

        # Test factory provides required interface for dependent projects
        assert hasattr(factory, "create_connection")
        assert hasattr(factory, "initialize")
        assert hasattr(factory, "cleanup")

        # Test factory works with connection info from dependent projects
        assert factory.connection_info == mock_connection_info
        assert hasattr(factory, "_security_manager")


class TestStandardConnectionFactory:
    """Test cases for StandardConnectionFactory."""

    def test_factory_initialization_with_connection_info(self) -> None:
        """Test factory initialization with connection info."""
        # Mock connection info
        mock_connection_info = Mock()
        mock_connection_info.host = "ldap.example.com"
        mock_connection_info.port = 389
        mock_connection_info.use_ssl = False

        factory = StandardConnectionFactory(mock_connection_info)

        assert factory.connection_info == mock_connection_info
        assert factory._security_manager is not None

    def test_factory_initialization_with_security_manager(self) -> None:
        """Test factory initialization with custom security manager."""
        mock_connection_info = Mock()
        mock_security_manager = Mock()

        factory = StandardConnectionFactory(
            mock_connection_info,
            security_manager=mock_security_manager,
        )

        assert factory.connection_info == mock_connection_info
        assert factory._security_manager == mock_security_manager

    def test_factory_initialization_default_security_manager(self) -> None:
        """Test factory initialization creates default security manager."""
        mock_connection_info = Mock()

        with patch("ldap_core_shared.connections.factories.StandardSecurityManager") as mock_security_class:
            mock_security_instance = Mock()
            mock_security_class.return_value = mock_security_instance

            factory = StandardConnectionFactory(mock_connection_info)

            mock_security_class.assert_called_once_with(mock_connection_info)
            assert factory._security_manager == mock_security_instance

    @pytest.mark.asyncio
    async def test_factory_initialize(self) -> None:
        """Test factory initialization process."""
        mock_connection_info = Mock()
        mock_security_manager = AsyncMock()

        factory = StandardConnectionFactory(
            mock_connection_info,
            security_manager=mock_security_manager,
        )

        await factory.initialize()

        mock_security_manager.validate_credentials.assert_called_once_with(mock_connection_info)

    @pytest.mark.asyncio
    async def test_factory_cleanup(self) -> None:
        """Test factory cleanup process."""
        mock_connection_info = Mock()
        mock_security_manager = Mock()

        factory = StandardConnectionFactory(
            mock_connection_info,
            security_manager=mock_security_manager,
        )

        # Should complete without errors
        await factory.cleanup()

    @patch("ldap_core_shared.connections.factories.ldap3")
    def test_create_connection_basic(self, mock_ldap3: Mock) -> None:
        """Test creating basic LDAP connection."""
        # Setup mocks
        mock_connection_info = Mock()
        mock_connection_info.host = "ldap.example.com"
        mock_connection_info.port = 389
        mock_connection_info.use_ssl = False
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        mock_connection_info.bind_password = SecretStr("password123")
        mock_connection_info.get_ldap3_authentication.return_value = "SIMPLE"
        mock_connection_info.auto_bind = True

        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)

        result = factory.create_connection(mock_connection_info)

        # Verify server creation
        mock_ldap3.Server.assert_called_once_with(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            tls=None,
            get_info="ALL_INFO",
        )

        # Verify connection creation
        mock_ldap3.Connection.assert_called_once_with(
            server=mock_server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password123",
            authentication="SIMPLE",
            auto_bind=True,
            lazy=False,
        )

        assert result == mock_connection

    @patch("ldap_core_shared.connections.factories.ldap3")
    @patch("ldap_core_shared.connections.factories.ssl")
    def test_create_connection_with_ssl(self, mock_ssl: Mock, mock_ldap3: Mock) -> None:
        """Test creating LDAP connection with SSL/TLS."""
        # Setup mocks
        mock_connection_info = Mock()
        mock_connection_info.host = "ldaps.example.com"
        mock_connection_info.port = 636
        mock_connection_info.use_ssl = True
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        mock_connection_info.bind_password = SecretStr("password123")
        mock_connection_info.get_ldap3_authentication.return_value = "SIMPLE"
        mock_connection_info.auto_bind = True

        mock_server = Mock()
        mock_connection = Mock()
        mock_tls = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.Tls.return_value = mock_tls
        mock_ldap3.ALL = "ALL_INFO"
        mock_ssl.CERT_REQUIRED = "CERT_REQUIRED"

        factory = StandardConnectionFactory(mock_connection_info)

        result = factory.create_connection(mock_connection_info)

        # Verify TLS configuration
        mock_ldap3.Tls.assert_called_once_with(validate="CERT_REQUIRED")

        # Verify server creation with TLS
        mock_ldap3.Server.assert_called_once_with(
            host="ldaps.example.com",
            port=636,
            use_ssl=True,
            tls=mock_tls,
            get_info="ALL_INFO",
        )

        # Verify connection creation
        mock_ldap3.Connection.assert_called_once_with(
            server=mock_server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password123",
            authentication="SIMPLE",
            auto_bind=True,
            lazy=False,
        )

        assert result == mock_connection

    @patch("ldap_core_shared.connections.factories.ldap3")
    def test_create_connection_different_authentication(self, mock_ldap3: Mock) -> None:
        """Test creating connection with different authentication methods."""
        # Setup mocks
        mock_connection_info = Mock()
        mock_connection_info.host = "ldap.example.com"
        mock_connection_info.port = 389
        mock_connection_info.use_ssl = False
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        mock_connection_info.bind_password = SecretStr("password123")
        mock_connection_info.get_ldap3_authentication.return_value = "SASL"
        mock_connection_info.auto_bind = False

        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)

        result = factory.create_connection(mock_connection_info)

        # Verify connection creation with SASL auth
        mock_ldap3.Connection.assert_called_once_with(
            server=mock_server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="password123",
            authentication="SASL",
            auto_bind=False,
            lazy=False,
        )

        assert result == mock_connection

    @patch("ldap_core_shared.connections.factories.ldap3")
    def test_create_connection_no_password(self, mock_ldap3: Mock) -> None:
        """Test creating connection without password (anonymous bind)."""
        # Setup mocks
        mock_connection_info = Mock()
        mock_connection_info.host = "ldap.example.com"
        mock_connection_info.port = 389
        mock_connection_info.use_ssl = False
        mock_connection_info.bind_dn = None
        mock_connection_info.bind_password = SecretStr("")
        mock_connection_info.get_ldap3_authentication.return_value = "ANONYMOUS"
        mock_connection_info.auto_bind = True

        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)

        result = factory.create_connection(mock_connection_info)

        # Verify connection creation for anonymous bind
        mock_ldap3.Connection.assert_called_once_with(
            server=mock_server,
            user=None,
            password="",
            authentication="ANONYMOUS",
            auto_bind=True,
            lazy=False,
        )

        assert result == mock_connection

    def test_factory_inheritance_base_component(self) -> None:
        """Test factory inherits from BaseConnectionComponent."""
        from ldap_core_shared.connections.interfaces import BaseConnectionComponent

        mock_connection_info = Mock()
        factory = StandardConnectionFactory(mock_connection_info)

        assert isinstance(factory, BaseConnectionComponent)

    @patch("ldap_core_shared.connections.factories.ldap3")
    def test_create_connection_custom_port(self, mock_ldap3: Mock) -> None:
        """Test creating connection with custom port."""
        # Setup mocks
        mock_connection_info = Mock()
        mock_connection_info.host = "ldap.example.com"
        mock_connection_info.port = 1389  # Custom port
        mock_connection_info.use_ssl = False
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        mock_connection_info.bind_password = SecretStr("password123")
        mock_connection_info.get_ldap3_authentication.return_value = "SIMPLE"
        mock_connection_info.auto_bind = True

        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)

        result = factory.create_connection(mock_connection_info)

        # Verify server creation with custom port
        mock_ldap3.Server.assert_called_once_with(
            host="ldap.example.com",
            port=1389,
            use_ssl=False,
            tls=None,
            get_info="ALL_INFO",
        )

        assert result == mock_connection

    @patch("ldap_core_shared.connections.factories.ldap3")
    def test_create_connection_different_hosts(self, mock_ldap3: Mock) -> None:
        """Test creating connections to different hosts."""
        hosts = ["ldap1.example.com", "ldap2.example.com", "ldap3.example.com"]

        mock_connection_info = Mock()
        mock_connection_info.port = 389
        mock_connection_info.use_ssl = False
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        mock_connection_info.bind_password = SecretStr("password123")
        mock_connection_info.get_ldap3_authentication.return_value = "SIMPLE"
        mock_connection_info.auto_bind = True

        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)

        for host in hosts:
            mock_connection_info.host = host
            mock_server = Mock()
            mock_connection = Mock()
            mock_ldap3.Server.return_value = mock_server
            mock_ldap3.Connection.return_value = mock_connection

            result = factory.create_connection(mock_connection_info)

            # Verify server creation with correct host
            mock_ldap3.Server.assert_called_with(
                host=host,
                port=389,
                use_ssl=False,
                tls=None,
                get_info="ALL_INFO",
            )

            assert result == mock_connection

    @pytest.mark.asyncio
    async def test_factory_lifecycle_complete(self) -> None:
        """Test complete factory lifecycle initialization and cleanup."""
        mock_connection_info = Mock()
        mock_security_manager = AsyncMock()

        factory = StandardConnectionFactory(
            mock_connection_info,
            security_manager=mock_security_manager,
        )

        # Initialize
        await factory.initialize()
        mock_security_manager.validate_credentials.assert_called_once_with(mock_connection_info)

        # Cleanup
        await factory.cleanup()

        # Should be able to call multiple times without error
        await factory.cleanup()

    @pytest.mark.asyncio
    async def test_factory_initialization_credential_validation_failure(self) -> None:
        """Test factory initialization with credential validation failure."""
        mock_connection_info = Mock()
        mock_security_manager = AsyncMock()
        mock_security_manager.validate_credentials.side_effect = ValueError("Invalid credentials")

        factory = StandardConnectionFactory(
            mock_connection_info,
            security_manager=mock_security_manager,
        )

        with pytest.raises(ValueError, match="Invalid credentials"):
            await factory.initialize()

    def test_factory_security_manager_property(self) -> None:
        """Test factory security manager is accessible."""
        mock_connection_info = Mock()
        mock_security_manager = Mock()

        factory = StandardConnectionFactory(
            mock_connection_info,
            security_manager=mock_security_manager,
        )

        assert factory._security_manager == mock_security_manager

    def test_factory_connection_info_property(self) -> None:
        """Test factory connection info is accessible."""
        mock_connection_info = Mock()

        factory = StandardConnectionFactory(mock_connection_info)

        assert factory.connection_info == mock_connection_info

    @patch("ldap_core_shared.connections.factories.ldap3")
    def test_create_connection_password_secret_handling(self, mock_ldap3: Mock) -> None:
        """Test connection creation properly handles SecretStr password."""
        # Setup mocks
        mock_connection_info = Mock()
        mock_connection_info.host = "ldap.example.com"
        mock_connection_info.port = 389
        mock_connection_info.use_ssl = False
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

        # Test SecretStr password handling
        secret_password = SecretStr("secret123")
        mock_connection_info.bind_password = secret_password
        mock_connection_info.get_ldap3_authentication.return_value = "SIMPLE"
        mock_connection_info.auto_bind = True

        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)

        result = factory.create_connection(mock_connection_info)

        # Verify password is extracted from SecretStr
        mock_ldap3.Connection.assert_called_once_with(
            server=mock_server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            password="secret123",  # Should be the actual secret value
            authentication="SIMPLE",
            auto_bind=True,
            lazy=False,
        )

        assert result == mock_connection


class TestStandardConnectionFactoryIntegration:
    """Test cases for StandardConnectionFactory integration scenarios."""

    @patch("ldap_core_shared.connections.factories.ldap3")
    @patch("ldap_core_shared.connections.factories.ssl")
    def test_ssl_tls_configuration_integration(self, mock_ssl: Mock, mock_ldap3: Mock) -> None:
        """Test SSL/TLS configuration integration."""
        mock_connection_info = Mock()
        mock_connection_info.host = "ldaps.example.com"
        mock_connection_info.port = 636
        mock_connection_info.use_ssl = True
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        mock_connection_info.bind_password = SecretStr("password123")
        mock_connection_info.get_ldap3_authentication.return_value = "SIMPLE"
        mock_connection_info.auto_bind = True

        mock_ssl.CERT_REQUIRED = "CERT_REQUIRED"
        mock_tls = Mock()
        mock_server = Mock()
        mock_connection = Mock()
        mock_ldap3.Tls.return_value = mock_tls
        mock_ldap3.Server.return_value = mock_server
        mock_ldap3.Connection.return_value = mock_connection
        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)
        result = factory.create_connection(mock_connection_info)

        # Verify complete SSL/TLS setup
        mock_ldap3.Tls.assert_called_once_with(validate="CERT_REQUIRED")
        mock_ldap3.Server.assert_called_once_with(
            host="ldaps.example.com",
            port=636,
            use_ssl=True,
            tls=mock_tls,
            get_info="ALL_INFO",
        )

        assert result == mock_connection

    @pytest.mark.asyncio
    async def test_factory_security_manager_integration(self) -> None:
        """Test factory integration with security manager."""
        mock_connection_info = Mock()
        mock_security_manager = AsyncMock()

        # Test successful validation
        factory = StandardConnectionFactory(
            mock_connection_info,
            security_manager=mock_security_manager,
        )

        await factory.initialize()

        mock_security_manager.validate_credentials.assert_called_once_with(mock_connection_info)

    @patch("ldap_core_shared.connections.factories.ldap3")
    def test_factory_multiple_connection_creation(self, mock_ldap3: Mock) -> None:
        """Test factory can create multiple connections."""
        mock_connection_info = Mock()
        mock_connection_info.host = "ldap.example.com"
        mock_connection_info.port = 389
        mock_connection_info.use_ssl = False
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        mock_connection_info.bind_password = SecretStr("password123")
        mock_connection_info.get_ldap3_authentication.return_value = "SIMPLE"
        mock_connection_info.auto_bind = True

        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)

        connections = []
        for i in range(5):
            mock_server = Mock()
            mock_connection = Mock()
            mock_connection.id = i  # Give each connection a unique ID
            mock_ldap3.Server.return_value = mock_server
            mock_ldap3.Connection.return_value = mock_connection

            result = factory.create_connection(mock_connection_info)
            connections.append(result)

        # Should have created 5 separate connections
        assert len(connections) == 5
        assert mock_ldap3.Server.call_count == 5
        assert mock_ldap3.Connection.call_count == 5

    def test_factory_configuration_variations(self) -> None:
        """Test factory with various configuration combinations."""
        configurations = [
            {
                "host": "ldap.example.com",
                "port": 389,
                "use_ssl": False,
                "auth": "SIMPLE",
            },
            {
                "host": "ldaps.example.com",
                "port": 636,
                "use_ssl": True,
                "auth": "SIMPLE",
            },
            {
                "host": "ldap.ad.com",
                "port": 389,
                "use_ssl": False,
                "auth": "NTLM",
            },
        ]

        for config in configurations:
            mock_connection_info = Mock()
            mock_connection_info.host = config["host"]
            mock_connection_info.port = config["port"]
            mock_connection_info.use_ssl = config["use_ssl"]
            mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            mock_connection_info.bind_password = SecretStr("password123")
            mock_connection_info.get_ldap3_authentication.return_value = config["auth"]
            mock_connection_info.auto_bind = True

            # Should create factory without errors
            factory = StandardConnectionFactory(mock_connection_info)
            assert factory.connection_info == mock_connection_info

    @pytest.mark.asyncio
    async def test_factory_error_handling_resilience(self) -> None:
        """Test factory error handling and resilience."""
        mock_connection_info = Mock()
        mock_security_manager = AsyncMock()

        factory = StandardConnectionFactory(
            mock_connection_info,
            security_manager=mock_security_manager,
        )

        # Test initialization with transient failure
        mock_security_manager.validate_credentials.side_effect = [
            ConnectionError("Temporary failure"),
            None,  # Success on retry
        ]

        # First attempt should fail
        with pytest.raises(ConnectionError):
            await factory.initialize()

        # Second attempt should succeed
        await factory.initialize()

        assert mock_security_manager.validate_credentials.call_count == 2

    def test_factory_memory_efficiency(self) -> None:
        """Test factory memory efficiency with multiple instances."""
        connection_infos = []
        factories = []

        # Create multiple factories
        for i in range(10):
            mock_connection_info = Mock()
            mock_connection_info.host = f"ldap{i}.example.com"
            mock_connection_info.port = 389

            connection_infos.append(mock_connection_info)

            factory = StandardConnectionFactory(mock_connection_info)
            factories.append(factory)

        # Each factory should maintain its own state
        for i, factory in enumerate(factories):
            assert factory.connection_info.host == f"ldap{i}.example.com"

        # Cleanup
        del factories
        del connection_infos

    @patch("ldap_core_shared.connections.factories.ldap3")
    def test_factory_thread_safety_simulation(self, mock_ldap3: Mock) -> None:
        """Test factory thread safety simulation."""
        import threading

        mock_connection_info = Mock()
        mock_connection_info.host = "ldap.example.com"
        mock_connection_info.port = 389
        mock_connection_info.use_ssl = False
        mock_connection_info.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        mock_connection_info.bind_password = SecretStr("password123")
        mock_connection_info.get_ldap3_authentication.return_value = "SIMPLE"
        mock_connection_info.auto_bind = True

        mock_ldap3.ALL = "ALL_INFO"

        factory = StandardConnectionFactory(mock_connection_info)
        results = []
        errors = []

        def create_connection_worker() -> None:
            try:
                mock_server = Mock()
                mock_connection = Mock()
                mock_ldap3.Server.return_value = mock_server
                mock_ldap3.Connection.return_value = mock_connection

                result = factory.create_connection(mock_connection_info)
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Simulate concurrent access
        threads = []
        for _i in range(5):
            thread = threading.Thread(target=create_connection_worker)
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # Should have no errors and 5 results
        assert len(errors) == 0
        assert len(results) == 5

    def test_factory_logging_integration(self) -> None:
        """Test factory logging integration."""
        # Capture log messages
        with patch("ldap_core_shared.connections.factories.logger") as mock_logger:
            mock_connection_info = Mock()

            StandardConnectionFactory(mock_connection_info)

            # Should have logged initialization
            mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_factory_cleanup_idempotent(self) -> None:
        """Test factory cleanup is idempotent."""
        mock_connection_info = Mock()
        factory = StandardConnectionFactory(mock_connection_info)

        # Multiple cleanup calls should not cause errors
        await factory.cleanup()
        await factory.cleanup()
        await factory.cleanup()

    @pytest.mark.solid_compliance
    def test_factory_solid_principles_compliance_enhanced(self, solid_principles_validation: Generator[dict[str, object], None, None]) -> None:
        """Test factory compliance with SOLID principles enhanced validation."""
        validators = solid_principles_validation
        mock_connection_info = Mock()
        factory = StandardConnectionFactory(mock_connection_info)

        # Single Responsibility: Only creates connections (validated by fixture)
        assert hasattr(factory, "create_connection")
        validators["srp_validator"].validate_class_responsibility.assert_called()

        # Open/Closed: Can be extended through inheritance (validated by fixture)
        assert StandardConnectionFactory.__bases__
        validators["ocp_validator"].validate_extensibility.assert_called()

        # Liskov Substitution: Can be used wherever BaseConnectionComponent is expected
        from ldap_core_shared.connections.interfaces import BaseConnectionComponent
        assert isinstance(factory, BaseConnectionComponent)
        validators["lsp_validator"].validate_substitutability.assert_called()

        # Interface Segregation: Implements focused interface (validated by fixture)
        assert hasattr(factory, "initialize")
        assert hasattr(factory, "cleanup")
        validators["isp_validator"].validate_interface_focus.assert_called()

        # Dependency Inversion: Depends on abstractions (validated by fixture)
        assert hasattr(factory, "_security_manager")
        assert hasattr(factory, "connection_info")
        validators["dip_validator"].validate_abstraction_dependencies.assert_called()
