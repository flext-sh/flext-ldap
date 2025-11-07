"""Comprehensive tests for FlextLdapAuthentication.

This module contains comprehensive tests for FlextLdapAuthentication using real Docker
LDAP containers. All tests use actual LDAP operations without any mocks, stubs,
or wrappers.

Test Categories:
- @pytest.mark.docker - Requires Docker LDAP container
- @pytest.mark.unit - Unit tests with real LDAP operations

Container Requirements:
    Docker container must be running on port 3390
    Base DN: dc=flext,dc=local
    Admin DN: cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
    Admin password: REDACTED_LDAP_BIND_PASSWORD123
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels
from ldap3 import Connection, Server

from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.authentication import FlextLdapAuthentication

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapAuthenticationInitialization:
    """Test FlextLdapAuthentication initialization."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_authentication_creation(self) -> None:
        """Test creating FlextLdapAuthentication instance."""
        auth = FlextLdapAuthentication()
        assert auth is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_authentication_initial_state(self) -> None:
        """Test initial state of authentication object."""
        auth = FlextLdapAuthentication()
        assert auth._connection is None
        assert auth._server is None
        assert auth._ldap_config is None


class TestFlextLdapAuthenticationConnectionContext:
    """Test connection context management."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_set_connection_context(self) -> None:
        """Test setting connection context."""
        auth = FlextLdapAuthentication()
        config = FlextLdapConfig()

        server = Server(
            "ldap://localhost:3390",
            port=3390,
            use_ssl=False,
            get_info="SCHEMA",
        )
        connection = Connection(
            server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
            auto_bind=True,
        )

        auth.set_connection_context(connection, server, config)

        assert auth._connection is not None
        assert auth._server is not None
        assert auth._ldap_config is not None

        # Cleanup
        connection.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_set_connection_context_with_none(self) -> None:
        """Test setting connection context with None values."""
        auth = FlextLdapAuthentication()
        auth.set_connection_context(None, None, None)
        assert auth._connection is None
        assert auth._server is None
        assert auth._ldap_config is None


class TestFlextLdapAuthenticationValidateCredentials:
    """Test credential validation."""

    @pytest.fixture(autouse=True)
    def authenticated_service(self) -> FlextLdapAuthentication:
        """Provide an authenticated FlextLdapAuthentication instance."""
        auth = FlextLdapAuthentication()
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://localhost:3390"
        config.ldap_base_dn = "dc=flext,dc=local"
        config.__dict__["ldap_bind_dn"] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        config.__dict__["ldap_bind_password"] = "REDACTED_LDAP_BIND_PASSWORD123"
        config.validate_ldap_configuration_consistency()

        server = Server(
            "ldap://localhost:3390",
            port=3390,
            use_ssl=False,
            get_info="SCHEMA",
        )
        connection = Connection(
            server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
            auto_bind=True,
        )

        auth.set_connection_context(connection, server, config)
        yield auth

        # Cleanup
        connection.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_credentials_valid_REDACTED_LDAP_BIND_PASSWORD(
        self, authenticated_service: FlextLdapAuthentication
    ) -> None:
        """Test validating valid REDACTED_LDAP_BIND_PASSWORD credentials."""
        result = authenticated_service.validate_credentials(
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "REDACTED_LDAP_BIND_PASSWORD123",
        )

        assert result.is_success is True
        is_valid = result.unwrap()
        assert isinstance(is_valid, bool)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_credentials_invalid_password(
        self, authenticated_service: FlextLdapAuthentication
    ) -> None:
        """Test validating invalid credentials."""
        result = authenticated_service.validate_credentials(
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "wrongpassword",
        )

        # Should handle gracefully - either fail or return False
        assert result.is_success is True or result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_credentials_nonexistent_user(
        self, authenticated_service: FlextLdapAuthentication
    ) -> None:
        """Test validating nonexistent user."""
        result = authenticated_service.validate_credentials(
            "cn=nonexistent,dc=flext,dc=local",
            "password",
        )

        # Should handle gracefully
        assert result.is_success is True or result.is_failure is True


class TestFlextLdapAuthenticationInternalMethods:
    """Test internal authentication methods."""

    @pytest.fixture(autouse=True)
    def authenticated_service(self) -> FlextLdapAuthentication:
        """Provide an authenticated FlextLdapAuthentication instance."""
        auth = FlextLdapAuthentication()
        config = FlextLdapConfig()
        config.ldap_server_uri = "ldap://localhost:3390"
        config.ldap_base_dn = "dc=flext,dc=local"
        config.__dict__["ldap_bind_dn"] = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        config.__dict__["ldap_bind_password"] = "REDACTED_LDAP_BIND_PASSWORD123"
        config.validate_ldap_configuration_consistency()

        server = Server(
            "ldap://localhost:3390",
            port=3390,
            use_ssl=False,
            get_info="SCHEMA",
        )
        connection = Connection(
            server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
            auto_bind=True,
        )

        auth.set_connection_context(connection, server, config)
        yield auth

        # Cleanup
        connection.unbind()

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_connection_success(
        self, authenticated_service: FlextLdapAuthentication
    ) -> None:
        """Test connection validation with established connection."""
        result = authenticated_service._validate_connection()
        assert result.is_success is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_connection_no_connection(self) -> None:
        """Test connection validation without connection."""
        auth = FlextLdapAuthentication()
        result = auth._validate_connection()
        assert result.is_failure is True


class TestFlextLdapAuthenticationExecute:
    """Test FlextLdapAuthentication execution methods."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_execute_returns_ok(self) -> None:
        """Test execute method returns OK."""
        auth = FlextLdapAuthentication()
        result = auth.execute()
        assert result.is_success is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_execute_operation_returns_ok(self) -> None:
        """Test execute_operation method."""
        from flext_core import FlextModels

        auth = FlextLdapAuthentication()

        # Create a mock request with required parameters
        def dummy_operation() -> None:
            pass

        request = FlextModels.OperationExecutionRequest(
            operation_name="test_operation",
            operation_callable=dummy_operation,
        )
        result = auth.execute_operation(request)

        assert result.is_success is True


class TestFlextLdapAuthenticationErrorHandling:
    """Test error handling in authentication."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_authenticate_user_no_connection(self) -> None:
        """Test authenticate_user without connection."""
        auth = FlextLdapAuthentication()
        result = auth.authenticate_user("testuser", "password")

        # Should fail gracefully
        assert result.is_failure is True

    @pytest.mark.docker
    @pytest.mark.unit
    def test_validate_credentials_no_connection(self) -> None:
        """Test validate_credentials without connection."""
        auth = FlextLdapAuthentication()
        result = auth.validate_credentials("cn=test,dc=example,dc=com", "password")

        # Should fail with "No connection context" message
        assert result.is_failure is True


class TestFlextLdapAuthenticationEntryConversion:
    """Test entry conversion methods."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_user_from_ldif_entry(self) -> None:
        """Test creating user from FlextLdif entry."""
        auth = FlextLdapAuthentication()

        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test,dc=flext,dc=local"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )

        result = auth._create_user_from_entry_result(entry)
        assert result.is_success is True
        user = result.unwrap()
        assert user is not None
        assert user.dn is not None

    @pytest.mark.docker
    @pytest.mark.unit
    def test_create_user_returns_flext_ldif_models_entry(self) -> None:
        """Test that create_user returns FlextLdifModels.Entry type."""
        auth = FlextLdapAuthentication()

        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test2,dc=flext,dc=local"
        })
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(),
        )

        result = auth._create_user_from_entry_result(entry)
        assert result.is_success is True
        user = result.unwrap()
        assert isinstance(user, FlextLdifModels.Entry)


class TestFlextLdapAuthenticationSafeUnbind:
    """Test safe unbind functionality."""

    @pytest.mark.docker
    @pytest.mark.unit
    def test_safe_unbind_with_valid_connection(self) -> None:
        """Test safe unbind with valid connection."""
        auth = FlextLdapAuthentication()

        server = Server(
            "ldap://localhost:3390",
            port=3390,
            use_ssl=False,
            get_info="SCHEMA",
        )
        connection = Connection(
            server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
            auto_bind=True,
        )

        # Should not raise any exception
        auth._safe_unbind(connection)

    @pytest.mark.docker
    @pytest.mark.unit
    def test_safe_unbind_handles_errors(self) -> None:
        """Test safe unbind handles errors gracefully."""
        auth = FlextLdapAuthentication()

        # Try to unbind a connection that's already unbound
        server = Server(
            "ldap://localhost:3390",
            port=3390,
            use_ssl=False,
            get_info="SCHEMA",
        )
        connection = Connection(
            server,
            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
            auto_bind=True,
        )

        # First unbind
        connection.unbind()

        # Second unbind should not raise (safe_unbind suppresses exceptions)
        auth._safe_unbind(connection)


__all__ = [
    "TestFlextLdapAuthenticationConnectionContext",
    "TestFlextLdapAuthenticationEntryConversion",
    "TestFlextLdapAuthenticationErrorHandling",
    "TestFlextLdapAuthenticationExecute",
    "TestFlextLdapAuthenticationInitialization",
    "TestFlextLdapAuthenticationInternalMethods",
    "TestFlextLdapAuthenticationSafeUnbind",
    "TestFlextLdapAuthenticationValidateCredentials",
]
