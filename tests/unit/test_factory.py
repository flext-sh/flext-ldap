"""Unit tests for flext-ldap factory module."""

from __future__ import annotations

from flext_core import FlextModels
from flext_ldap.factory import FlextLdapFactory


class TestFlextLdapFactory:
    """Tests for FlextLdapFactory class."""

    def test_factory_initialization(self) -> None:
        """Test factory initialization."""
        config = FlextModels.CqrsConfig.Handler(
            handler_id="test_handler",
            handler_name="Test Handler",
            handler_type="command",
            command_timeout=30,
            max_command_retries=3,
        )
        factory = FlextLdapFactory(config)
        assert factory is not None
        assert factory.config == config

    def test_handle_invalid_message_type(self) -> None:
        """Test handle method with invalid message type."""
        config = FlextModels.CqrsConfig.Handler(
            handler_id="test_handler",
            handler_name="Test Handler",
            handler_type="command",
            command_timeout=30,
            max_command_retries=3,
        )
        factory = FlextLdapFactory(config)

        result = factory.handle("invalid_message")
        assert result.is_failure
        assert result.error is not None
        assert "Message must be a dictionary" in result.error

    def test_handle_missing_factory_type(self) -> None:
        """Test handle method with missing factory type."""
        config = FlextModels.CqrsConfig.Handler(
            handler_id="test_handler",
            handler_name="Test Handler",
            handler_type="command",
            command_timeout=30,
            max_command_retries=3,
        )
        factory = FlextLdapFactory(config)

        result = factory.handle({})
        assert result.is_failure
        assert result.error is not None
        assert "Factory type must be a string" in result.error

    def test_handle_invalid_factory_type(self) -> None:
        """Test handle method with invalid factory type."""
        config = FlextModels.CqrsConfig.Handler(
            handler_id="test_handler",
            handler_name="Test Handler",
            handler_type="command",
            command_timeout=30,
            max_command_retries=3,
        )
        factory = FlextLdapFactory(config)

        result = factory.handle({"factory_type": 123})
        assert result.is_failure
        assert result.error is not None
        assert "Factory type must be a string" in result.error

    def test_handle_unknown_factory_type(self) -> None:
        """Test handle method with unknown factory type."""
        config = FlextModels.CqrsConfig.Handler(
            handler_id="test_handler",
            handler_name="Test Handler",
            handler_type="command",
            command_timeout=30,
            max_command_retries=3,
        )
        factory = FlextLdapFactory(config)

        result = factory.handle({"factory_type": "unknown_type"})
        assert result.is_failure
        assert result.error is not None
        assert "Unknown factory type: unknown_type" in result.error


class TestFlextLdapFactoryCreateAdvancedService:
    """Tests for FlextLdapFactory.create_advanced_service method."""

    def test_create_advanced_service_success(self) -> None:
        """Test successful advanced service creation."""
        client_config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "password",
        }
        service_config = {
            "handler_id": "test_service",
            "handler_name": "Test Service",
            "handler_type": "command",
            "timeout": 60,
            "retry_count": 5,
        }

        result = FlextLdapFactory.create_advanced_service(client_config, service_config)
        assert result.is_success
        assert result.data is not None

    def test_create_advanced_service_invalid_server_uri(self) -> None:
        """Test advanced service creation with invalid server URI."""
        client_config = {
            "server_uri": "invalid://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "password",
        }
        service_config = {
            "handler_id": "test_service",
            "handler_name": "Test Service",
            "handler_type": "command",
        }

        result = FlextLdapFactory.create_advanced_service(client_config, service_config)
        assert result.is_failure
        assert result.error is not None
        assert "Server URI must start with ldap:// or ldaps://" in result.error

    def test_create_advanced_service_missing_server_uri(self) -> None:
        """Test advanced service creation with missing server URI."""
        client_config = {
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "password",
        }
        service_config = {
            "handler_id": "test_service",
            "handler_name": "Test Service",
            "handler_type": "command",
        }

        result = FlextLdapFactory.create_advanced_service(client_config, service_config)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required fields: ['server_uri']" in result.error

    def test_create_advanced_service_invalid_bind_dn_type(self) -> None:
        """Test advanced service creation with invalid bind DN type."""
        client_config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": 123,  # Invalid type
            "bind_password": "password",
        }
        service_config = {
            "handler_id": "test_service",
            "handler_name": "Test Service",
            "handler_type": "command",
        }

        result = FlextLdapFactory.create_advanced_service(client_config, service_config)
        assert result.is_failure
        assert result.error is not None
        assert "Bind DN must be a string" in result.error

    def test_create_advanced_service_invalid_bind_password_type(self) -> None:
        """Test advanced service creation with invalid bind password type."""
        client_config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": 123,  # Invalid type
        }
        service_config = {
            "handler_id": "test_service",
            "handler_name": "Test Service",
            "handler_type": "command",
            "timeout": 60,
            "retry_count": 5,
        }

        result = FlextLdapFactory.create_advanced_service(client_config, service_config)
        assert result.is_failure
        assert result.error is not None
        assert "Bind password must be a string" in result.error


class TestFlextLdapFactoryCreateUserRequest:
    """Tests for FlextLdapFactory.create_user_request method."""

    def test_create_user_request_success(self) -> None:
        """Test successful user request creation."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "given_name": "Test",
            "mail": "testuser@example.com",
            "telephone_number": "+1234567890",
            "department": "IT",
            "title": "Software Engineer",
            "organization": "Example Corp",
            "user_password": "testpassword",
            "description": "Test user account",
        }

        result = FlextLdapFactory.create_user_request(user_data)
        assert result.is_success
        assert result.data is not None
        assert result.data.dn == user_data["dn"]
        assert result.data.uid == user_data["uid"]
        assert result.data.cn == user_data["cn"]
        assert result.data.sn == user_data["sn"]

    def test_create_user_request_minimal_data(self) -> None:
        """Test user request creation with minimal required data."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",  # Required field
        }

        result = FlextLdapFactory.create_user_request(user_data)
        assert result.is_success
        assert result.data is not None
        assert result.data.dn == user_data["dn"]
        assert result.data.uid == user_data["uid"]
        assert result.data.cn == user_data["cn"]
        assert result.data.sn == user_data["sn"]
        assert result.data.mail == user_data["mail"]

    def test_create_user_request_missing_dn(self) -> None:
        """Test user request creation with missing DN."""
        user_data = {
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",
        }

        result = FlextLdapFactory.create_user_request(user_data)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required fields: ['dn']" in result.error

    def test_create_user_request_missing_uid(self) -> None:
        """Test user request creation with missing UID."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",
        }

        result = FlextLdapFactory.create_user_request(user_data)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required fields: ['uid']" in result.error

    def test_create_user_request_missing_cn(self) -> None:
        """Test user request creation with missing CN."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "sn": "User",
            "mail": "testuser@example.com",
        }

        result = FlextLdapFactory.create_user_request(user_data)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required fields: ['cn']" in result.error

    def test_create_user_request_missing_sn(self) -> None:
        """Test user request creation with missing SN."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "mail": "testuser@example.com",
        }

        result = FlextLdapFactory.create_user_request(user_data)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required fields: ['sn']" in result.error

    def test_create_user_request_strict_validation_empty_dn(self) -> None:
        """Test user request creation with empty DN in strict validation."""
        user_data = {
            "dn": "",  # Empty DN
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "testuser@example.com",
        }

        result = FlextLdapFactory.create_user_request(user_data, validation_strict=True)
        assert result.is_failure
        assert result.error is not None
        assert "DN must be a non-empty string" in result.error

    def test_create_user_request_strict_validation_invalid_email(self) -> None:
        """Test user request creation with invalid email in strict validation."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "invalid-email",  # Invalid email format
        }

        result = FlextLdapFactory.create_user_request(user_data, validation_strict=True)
        assert result.is_failure
        assert result.error is not None
        assert "Mail must be a valid email address" in result.error

    def test_create_user_request_non_strict_validation(self) -> None:
        """Test user request creation with non-strict validation."""
        user_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
            "sn": "User",
            "mail": "invalid-email",  # Invalid email but non-strict validation
        }

        result = FlextLdapFactory.create_user_request(
            user_data, validation_strict=False
        )
        # Note: Pydantic field validators always run regardless of validation_strict setting
        # This is expected behavior since field validators are part of the model definition
        assert result.is_failure
        assert result.error is not None
        assert "Invalid email format" in result.error
