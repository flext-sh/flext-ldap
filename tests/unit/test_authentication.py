"""Unit tests for FlextLdapAuthentication service.

Tests the actual FlextLdapAuthentication API including:
- Service initialization and FlextService integration
- Connection context management
- Credential validation with proper error handling
- User authentication with FlextResult patterns
- Execute methods required by FlextService

All tests use real FlextLdapAuthentication objects with no mocks for initialization
and configuration. LDAP-specific tests (validate_credentials, authenticate_user)
verify error handling when connection context is not available.

Docker-based integration tests are deferred to tests/integration/ for real LDAP operations.
"""

from __future__ import annotations

import pytest
from flext_core import FlextModels, FlextResult

from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.authentication import FlextLdapAuthentication


class TestFlextLdapAuthenticationInitialization:
    """Test FlextLdapAuthentication initialization and basic functionality."""

    @pytest.mark.unit
    def test_authentication_service_can_be_instantiated(self) -> None:
        """Test FlextLdapAuthentication can be instantiated."""
        auth = FlextLdapAuthentication()
        assert auth is not None
        assert isinstance(auth, FlextLdapAuthentication)

    @pytest.mark.unit
    def test_authentication_service_has_logger(self) -> None:
        """Test authentication service inherits logger from FlextService."""
        auth = FlextLdapAuthentication()
        assert hasattr(auth, "logger")
        assert auth.logger is not None

    @pytest.mark.unit
    def test_authentication_service_has_container(self) -> None:
        """Test authentication service has container from FlextService."""
        auth = FlextLdapAuthentication()
        assert hasattr(auth, "container")

    @pytest.mark.unit
    def test_authentication_service_connection_initially_none(self) -> None:
        """Test connection context is initially None."""
        auth = FlextLdapAuthentication()
        assert auth._connection is None
        assert auth._server is None
        assert auth._ldap_config is None


class TestConnectionContextManagement:
    """Test connection context management."""

    @pytest.mark.unit
    def test_set_connection_context_with_all_none(self) -> None:
        """Test setting connection context with all None values."""
        auth = FlextLdapAuthentication()
        auth.set_connection_context(None, None, None)
        assert auth._connection is None
        assert auth._server is None
        assert auth._ldap_config is None

    @pytest.mark.unit
    def test_set_connection_context_with_config(self) -> None:
        """Test setting connection context with config."""
        auth = FlextLdapAuthentication()
        config = FlextLdapConfig()
        auth.set_connection_context(None, None, config)
        assert auth._ldap_config is config

    @pytest.mark.unit
    def test_set_connection_context_idempotent(self) -> None:
        """Test setting connection context multiple times."""
        auth = FlextLdapAuthentication()
        config1 = FlextLdapConfig()
        config2 = FlextLdapConfig()

        auth.set_connection_context(None, None, config1)
        assert auth._ldap_config is config1

        auth.set_connection_context(None, None, config2)
        assert auth._ldap_config is config2


class TestAuthenticationExecute:
    """Test the execute method required by FlextService."""

    @pytest.mark.unit
    def test_execute_returns_flext_result(self) -> None:
        """Test execute method returns FlextResult."""
        auth = FlextLdapAuthentication()
        result = auth.execute()
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_execute_returns_success(self) -> None:
        """Test execute method returns successful result."""
        auth = FlextLdapAuthentication()
        result = auth.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_result_value_is_none(self) -> None:
        """Test execute result unwraps to None as per design."""
        auth = FlextLdapAuthentication()
        result = auth.execute()
        assert result.unwrap() is None


class TestExecuteOperation:
    """Test the execute_operation method."""

    @pytest.mark.unit
    def test_execute_operation_returns_flext_result(self) -> None:
        """Test execute_operation method returns FlextResult."""
        auth = FlextLdapAuthentication()

        def dummy_operation() -> None:
            """Dummy operation for testing."""

        request = FlextModels.OperationExecutionRequest(
            operation_name="test-op",
            operation_callable=dummy_operation,
            arguments={},
        )
        result = auth.execute_operation(request)
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_execute_operation_returns_success(self) -> None:
        """Test execute_operation method returns successful result."""
        auth = FlextLdapAuthentication()

        def dummy_operation() -> None:
            """Dummy operation for testing."""

        request = FlextModels.OperationExecutionRequest(
            operation_name="test-op",
            operation_callable=dummy_operation,
            arguments={},
        )
        result = auth.execute_operation(request)
        assert result.is_success

    @pytest.mark.unit
    def test_execute_operation_result_value_is_none(self) -> None:
        """Test execute_operation result unwraps to None."""
        auth = FlextLdapAuthentication()

        def dummy_operation() -> None:
            """Dummy operation for testing."""

        request = FlextModels.OperationExecutionRequest(
            operation_name="test-op",
            operation_callable=dummy_operation,
            arguments={},
        )
        result = auth.execute_operation(request)
        assert result.unwrap() is None


class TestValidateCredentialsWithoutConnection:
    """Test validate_credentials behavior without connection context."""

    @pytest.mark.unit
    def test_validate_credentials_without_connection_fails(self) -> None:
        """Test validate_credentials fails when no connection context is set."""
        auth = FlextLdapAuthentication()
        result = auth.validate_credentials("cn=user,dc=example,dc=com", "password")
        assert result.is_failure
        assert "connection context" in result.error.lower()

    @pytest.mark.unit
    def test_validate_credentials_returns_flext_result(self) -> None:
        """Test validate_credentials returns FlextResult[bool]."""
        auth = FlextLdapAuthentication()
        result = auth.validate_credentials("cn=user,dc=example,dc=com", "password")
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_validate_credentials_with_empty_dn_fails(self) -> None:
        """Test validate_credentials with empty DN fails gracefully."""
        auth = FlextLdapAuthentication()
        result = auth.validate_credentials("", "password")
        assert result.is_failure

    @pytest.mark.unit
    def test_validate_credentials_with_empty_password_fails(self) -> None:
        """Test validate_credentials with empty password fails gracefully."""
        auth = FlextLdapAuthentication()
        result = auth.validate_credentials("cn=user,dc=example,dc=com", "")
        assert result.is_failure


class TestAuthenticateUserWithoutConnection:
    """Test authenticate_user behavior without connection context."""

    @pytest.mark.unit
    def test_authenticate_user_without_connection_fails(self) -> None:
        """Test authenticate_user fails when no connection context is set."""
        auth = FlextLdapAuthentication()
        result = auth.authenticate_user("testuser", "password")
        assert result.is_failure
        assert "connection" in result.error.lower()

    @pytest.mark.unit
    def test_authenticate_user_returns_flext_result(self) -> None:
        """Test authenticate_user returns FlextResult[FlextLdifModels.Entry]."""
        auth = FlextLdapAuthentication()
        result = auth.authenticate_user("testuser", "password")
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_authenticate_user_with_empty_username_fails(self) -> None:
        """Test authenticate_user with empty username fails gracefully."""
        auth = FlextLdapAuthentication()
        result = auth.authenticate_user("", "password")
        assert result.is_failure

    @pytest.mark.unit
    def test_authenticate_user_with_empty_password_fails(self) -> None:
        """Test authenticate_user with empty password fails gracefully."""
        auth = FlextLdapAuthentication()
        result = auth.authenticate_user("testuser", "")
        assert result.is_failure


class TestAuthenticationIntegration:
    """Integration tests for FlextLdapAuthentication service."""

    @pytest.mark.unit
    def test_complete_authentication_service_workflow(self) -> None:
        """Test complete authentication service workflow."""
        # Create service
        auth = FlextLdapAuthentication()
        assert auth is not None

        # Set connection context
        config = FlextLdapConfig()
        auth.set_connection_context(None, None, config)
        assert auth._ldap_config is config

        # Execute service
        result = auth.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_authentication_service_with_operation_request(self) -> None:
        """Test authentication service with operation request."""
        auth = FlextLdapAuthentication()

        def dummy_operation() -> None:
            """Dummy operation for testing."""

        request = FlextModels.OperationExecutionRequest(
            operation_name="auth-test",
            operation_callable=dummy_operation,
            arguments={"username": "test"},
        )

        result = auth.execute_operation(request)
        assert isinstance(result, FlextResult)
        assert result.is_success

    @pytest.mark.unit
    def test_authentication_service_flext_result_pattern(self) -> None:
        """Test all public methods follow FlextResult railway pattern."""
        auth = FlextLdapAuthentication()

        # All should return FlextResult
        assert isinstance(auth.execute(), FlextResult)
        assert isinstance(
            auth.validate_credentials("test", "test"),
            FlextResult,
        )
        assert isinstance(
            auth.authenticate_user("test", "test"),
            FlextResult,
        )

        def dummy_operation() -> None:
            """Dummy operation for testing."""

        request = FlextModels.OperationExecutionRequest(
            operation_name="test",
            operation_callable=dummy_operation,
            arguments={},
        )
        assert isinstance(auth.execute_operation(request), FlextResult)
