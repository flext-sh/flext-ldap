"""Comprehensive tests for FlextLdapAuthentication module.

Tests cover:
- Initialization and factory methods
- Connection context management
- User authentication with various scenarios
- Credential validation
- Error handling and edge cases
"""

from unittest.mock import Mock, patch

import pytest
from flext_core import (
    FlextModels,
)
from ldap3 import Connection, Server

from flext_ldap.authentication import FlextLdapAuthentication


@pytest.fixture
def mock_connection() -> Mock:
    """Create a mock LDAP connection."""
    conn = Mock(spec=Connection)
    conn.bound = True
    conn.entries = []
    return conn


@pytest.fixture
def mock_server() -> Mock:
    """Create a mock LDAP server."""
    return Mock(spec=Server)


@pytest.fixture
def mock_config() -> Mock:
    """Create a mock LDAP configuration."""
    config = Mock()
    config.ldap_base_dn = "dc=test,dc=local"
    return config


@pytest.fixture
def auth_service() -> FlextLdapAuthentication:
    """Create an authentication service instance."""
    return FlextLdapAuthentication()


@pytest.fixture
def auth_with_context(
    auth_service: FlextLdapAuthentication,
    mock_connection: Mock,
    mock_server: Mock,
    mock_config: Mock,
) -> FlextLdapAuthentication:
    """Create authentication service with connection context."""
    auth_service.set_connection_context(mock_connection, mock_server, mock_config)
    return auth_service


class TestFlextLdapAuthenticationInitialization:
    """Test authentication service initialization."""

    def test_authentication_initialization(self) -> None:
        """Test basic authentication initialization."""
        auth = FlextLdapAuthentication()
        assert auth is not None
        assert auth._connection is None
        assert auth._server is None
        assert auth._ldap_config is None

    def test_set_connection_context(
        self,
        auth_service: FlextLdapAuthentication,
        mock_connection: Mock,
        mock_server: Mock,
        mock_config: Mock,
    ) -> None:
        """Test setting connection context."""
        auth_service.set_connection_context(mock_connection, mock_server, mock_config)
        assert auth_service._connection is mock_connection
        assert auth_service._server is mock_server
        assert auth_service._ldap_config is mock_config


class TestFlextLdapAuthenticationUserAuth:
    """Test user authentication functionality."""

    def test_authenticate_user_no_connection(
        self, auth_service: FlextLdapAuthentication
    ) -> None:
        """Test authenticate_user fails without connection."""
        result = auth_service.authenticate_user("testuser", "testpass")
        assert result.is_failure
        assert result.error and "connection not established" in result.error.lower()


class TestFlextLdapAuthenticationCredentials:
    """Test credential validation functionality."""

    def test_validate_credentials_no_connection(
        self, auth_service: FlextLdapAuthentication
    ) -> None:
        """Test validate_credentials fails without connection context."""
        result = auth_service.validate_credentials(
            "cn=test,dc=example,dc=com", "password"
        )
        assert result.is_failure
        assert result.error and "no connection context" in result.error.lower()

    def test_validate_credentials_bind_failure(
        self, auth_with_context: FlextLdapAuthentication, mock_server: Mock
    ) -> None:
        """Test validate_credentials with bind failure."""
        with patch("flext_ldap.authentication.Connection") as mock_conn_class:
            mock_test_conn = Mock(spec=Connection)
            mock_test_conn.bind.return_value = False
            mock_test_conn.bound = False
            mock_conn_class.return_value = mock_test_conn

            result = auth_with_context.validate_credentials(
                "cn=test,dc=example,dc=com", "wrongpass"
            )
            # Should succeed but return False
            assert result.is_success
            assert result.unwrap() is False

    def test_validate_credentials_success(
        self, auth_with_context: FlextLdapAuthentication, mock_server: Mock
    ) -> None:
        """Test successful credential validation."""
        with patch("flext_ldap.authentication.Connection") as mock_conn_class:
            mock_test_conn = Mock(spec=Connection)
            mock_test_conn.bind.return_value = True
            mock_test_conn.bound = True
            mock_test_conn.unbind.return_value = None
            mock_conn_class.return_value = mock_test_conn

            result = auth_with_context.validate_credentials(
                "cn=test,dc=example,dc=com", "correctpass"
            )
            assert result.is_success
            assert result.unwrap() is True


class TestFlextLdapAuthenticationHelpers:
    """Test helper methods."""

    def test_validate_connection_no_connection(
        self, auth_service: FlextLdapAuthentication
    ) -> None:
        """Test connection validation fails without connection."""
        result = auth_service._validate_connection()
        assert result.is_failure
        assert result.error and "connection not established" in result.error.lower()

    def test_validate_connection_with_connection(
        self, auth_with_context: FlextLdapAuthentication
    ) -> None:
        """Test connection validation succeeds with connection."""
        result = auth_with_context._validate_connection()
        assert result.is_success

    def test_search_user_by_username_no_connection(
        self, auth_service: FlextLdapAuthentication
    ) -> None:
        """Test user search fails without connection."""
        result = auth_service._search_user_by_username("testuser")
        assert result.is_failure
        assert result.error and "connection not established" in result.error.lower()

    def test_search_user_by_username_not_found(
        self, auth_with_context: FlextLdapAuthentication, mock_connection: Mock
    ) -> None:
        """Test user search returns failure when user not found."""
        mock_connection.entries = []
        mock_connection.search.return_value = True

        result = auth_with_context._search_user_by_username("nonexistent")
        assert result.is_failure
        assert result.error and "user not found" in result.error.lower()

    def test_search_user_by_username_found(
        self, auth_with_context: FlextLdapAuthentication, mock_connection: Mock
    ) -> None:
        """Test user search succeeds when user found."""
        mock_entry = Mock()
        mock_entry.entry_dn = "uid=testuser,ou=users,dc=test,dc=local"
        mock_connection.entries = [mock_entry]
        mock_connection.search.return_value = True

        result = auth_with_context._search_user_by_username("testuser")
        assert result.is_success
        assert result.unwrap() is mock_entry

    def test_create_user_from_entry_result(
        self, auth_service: FlextLdapAuthentication
    ) -> None:
        """Test creating user from entry result."""
        # Modern Entry API: use real Entry with DistinguishedName and LdifAttributes
        from flext_ldif import FlextLdifModels

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=testuser,ou=users,dc=test,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "uid": ["testuser"],
                    "cn": ["Test User"],
                    "sn": ["User"],
                    "mail": ["test@example.com"],
                    "objectClass": ["inetOrgPerson", "person"],
                }
            ),
        )

        result = auth_service._create_user_from_entry_result(entry)
        assert result.is_success
        user = result.unwrap()
        # Modern Entry API: access attributes via attributes.attributes dict
        assert user.attributes.attributes.get("uid") == ["testuser"]
        assert user.attributes.attributes.get("cn") == ["Test User"]
        assert user.attributes.attributes.get("sn") == ["User"]
        assert user.attributes.attributes.get("mail") == ["test@example.com"]


class TestFlextLdapAuthenticationExecute:
    """Test service execute methods."""

    def test_execute_returns_success(
        self, auth_service: FlextLdapAuthentication
    ) -> None:
        """Test execute method returns success."""
        result = auth_service.execute()
        assert result.is_success

    def test_execute_operation(self, auth_service: FlextLdapAuthentication) -> None:
        """Test execute_operation method."""

        def test_op() -> None:
            return None

        operation = FlextModels.OperationExecutionRequest(
            operation_name="test",
            operation_callable=test_op,
        )
        result = auth_service.execute_operation(operation)
        assert result.is_success
