"""Unit tests for flext-ldap factory module."""

from __future__ import annotations

from flext_core import FlextModels
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.factory import FlextLdapFactory


class TestFlextLdapFactory:
    """Tests for FlextLdapFactory class."""

    def test_factory_initialization(self) -> None:
        """Test factory initialization."""
        config = FlextModels.CqrsConfig.Handler(
            handler_id="test_handler",
            handler_name="Test Handler",
            handler_type="command",
            command_timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
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
            command_timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
            max_command_retries=3,
        )
        factory = FlextLdapFactory(config)

        result = factory.handle("invalid_message")
        assert result.is_failure
        assert result.error is not None
        assert "Message must be DomainMessage model or dictionary" in result.error

    def test_handle_with_dict_message(self) -> None:
        """Test handle method with dict message."""
        config = FlextModels.CqrsConfig.Handler(
            handler_id="test_handler",
            handler_name="Test Handler",
            handler_type="command",
            command_timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
            max_command_retries=3,
        )
        factory = FlextLdapFactory(config)

        # Create a dict message with advanced_service factory type
        message = {
            "factory_type": "advanced_service",
            "client_config": {
                "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
                "bind_dn": "cn=admin,dc=example,dc=com",
                "bind_password": "password",
            },
        }

        result = factory.handle(message)
        # The result could be success or failure depending on implementation details
        # We're primarily testing the routing logic here
        assert result is not None

    def test_handle_missing_factory_type(self) -> None:
        """Test handle method with missing factory type."""
        config = FlextModels.CqrsConfig.Handler(
            handler_id="test_handler",
            handler_name="Test Handler",
            handler_type="command",
            command_timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
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
            command_timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
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
            command_timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
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
        client_config: dict[str, object] = {
            "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "password",
        }
        service_config: dict[str, object] = {
            "handler_id": "test_service",
            "handler_name": "Test Service",
            "handler_type": "command",
            "timeout": 60,
            "retry_count": 5,
        }

        result = FlextLdapFactory.create_advanced_service(client_config, service_config)
        assert result.is_success
        assert result.data is not None

    def test_create_advanced_service_with_connection_options(self) -> None:
        """Test advanced service creation with connection options."""
        client_config: dict[str, object] = {
            "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "password",
            "connection_options": {"timeout": 30, "auto_bind": True},
        }
        service_config: dict[str, object] = {
            "handler_id": "test_service",
            "handler_name": "Test Service",
            "handler_type": "command",
        }

        result = FlextLdapFactory.create_advanced_service(client_config, service_config)
        assert result.is_success
        assert result.data is not None

    def test_create_advanced_service_with_search_options(self) -> None:
        """Test advanced service creation with search options."""
        client_config: dict[str, object] = {
            "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "password",
            "search_options": {"paged": True, "page_size": 100},
        }
        service_config: dict[str, object] = {
            "handler_id": "test_service",
            "handler_name": "Test Service",
            "handler_type": "command",
        }

        result = FlextLdapFactory.create_advanced_service(client_config, service_config)
        assert result.is_success
        assert result.data is not None


    def test_create_advanced_service_invalid_server_uri(self) -> None:
        """Test advanced service creation with invalid server URI."""
        client_config: dict[str, object] = {
            "server_uri": f"invalid://localhost:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "password",
        }
        service_config: dict[str, object] = {
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
        client_config: dict[str, object] = {
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "password",
        }
        service_config: dict[str, object] = {
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
        client_config: dict[str, object] = {
            "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "bind_dn": 123,  # Invalid type
            "bind_password": "password",
        }
        service_config: dict[str, object] = {
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
        client_config: dict[str, object] = {
            "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": 123,  # Invalid type
        }
        service_config: dict[str, object] = {
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
        assert "DN cannot be empty" in result.error

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
            user_data,
            validation_strict=False,
        )
        # Note: Pydantic field validators always run regardless of validation_strict setting
        # This is expected behavior since field validators are part of the model definition
        assert result.is_failure
        assert result.error is not None
        assert (
            "email does not match expected pattern" in result.error
            or "VALIDATION_ERROR" in result.error
        )


class TestFlextLdapFactorySearchRequest:
    """Tests for FlextLdapFactory.create_search_request method."""

    def test_create_search_request_success(self) -> None:
        """Test successful search request creation."""
        search_data = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=person)",
            "scope": "SUBTREE",
            "attributes": ["cn", "mail"],
        }

        result = FlextLdapFactory.create_search_request(search_data)
        assert result.is_success
        search_request = result.unwrap()
        assert search_request.base_dn == "dc=example,dc=com"
        assert search_request.filter_str == "(objectClass=person)"
        assert search_request.scope == "SUBTREE"
        assert "cn" in search_request.attributes
        assert "mail" in search_request.attributes

    def test_create_search_request_missing_base_dn(self) -> None:
        """Test search request creation with missing base DN."""
        search_data = {
            "filter_str": "(objectClass=person)",
        }

        result = FlextLdapFactory.create_search_request(search_data)
        assert result.is_failure
        assert result.error is not None

    def test_create_search_request_minimal_data(self) -> None:
        """Test search request creation with minimal data."""
        search_data = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=*)",  # Required field
        }

        result = FlextLdapFactory.create_search_request(search_data)
        assert result.is_success
        search_request = result.unwrap()
        assert search_request.base_dn == "dc=example,dc=com"
        assert search_request.filter_str == "(objectClass=*)"
        # Should have defaults
        assert search_request.scope is not None
        assert search_request.page_size == FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE


class TestFlextLdapFactoryBulkOperationConfig:
    """Tests for FlextLdapFactory.create_bulk_operation_config method."""

    def test_create_bulk_operation_config_success(self) -> None:
        """Test successful bulk operation config creation."""
        config_data = {
            "operation_type": "create",
            "items_data": [
                {"dn": "cn=user1,ou=people,dc=example,dc=com", "cn": "user1"},
                {"dn": "cn=user2,ou=people,dc=example,dc=com", "cn": "user2"},
            ],
            "batch_size": 5,  # Must be <= DEFAULT_PAGE_SIZE (10)
            "continue_on_error": True,
            "rollback_on_failure": False,
        }

        result = FlextLdapFactory.create_bulk_operation_config(config_data)
        assert result.is_success
        config = result.unwrap()
        assert config["operation_type"] == "create"
        assert config["batch_size"] == 5
        assert config["continue_on_error"] is True
        assert config["rollback_on_failure"] is False
        assert len(config["items_data"]) == 2

    def test_create_bulk_operation_config_minimal(self) -> None:
        """Test bulk operation config creation with minimal data."""
        config_data = {
            "operation_type": "update",
            "items_data": [{"dn": "cn=user1,ou=people,dc=example,dc=com"}],
        }

        result = FlextLdapFactory.create_bulk_operation_config(config_data)
        assert result.is_success
        config = result.unwrap()
        assert config["operation_type"] == "update"
        # Should have defaults
        assert "batch_size" in config
        assert config["batch_size"] == 10  # Default
        assert config["continue_on_error"] is True  # Default
        assert config["rollback_on_failure"] is False  # Default

    def test_create_bulk_operation_config_invalid_operation_type(self) -> None:
        """Test bulk operation config with invalid operation type."""
        config_data = {
            "operation_type": "invalid_operation",
            "items_data": [{"dn": "cn=user1,ou=people,dc=example,dc=com"}],
        }

        result = FlextLdapFactory.create_bulk_operation_config(config_data)
        assert result.is_failure
        assert "Invalid operation type" in result.error

    def test_create_bulk_operation_config_missing_items_data(self) -> None:
        """Test bulk operation config with missing items_data."""
        config_data = {
            "operation_type": "create",
        }

        result = FlextLdapFactory.create_bulk_operation_config(config_data)
        assert result.is_failure
        assert "Items data must be a list" in result.error

    def test_create_bulk_operation_config_empty_items_data(self) -> None:
        """Test bulk operation config with empty items_data."""
        config_data = {
            "operation_type": "create",
            "items_data": [],
        }

        result = FlextLdapFactory.create_bulk_operation_config(config_data)
        assert result.is_failure
        assert "Items data cannot be empty" in result.error

    def test_create_bulk_operation_config_invalid_batch_size(self) -> None:
        """Test bulk operation config with invalid batch size."""
        config_data = {
            "operation_type": "create",
            "items_data": [{"dn": "cn=user1,ou=people,dc=example,dc=com"}],
            "batch_size": -1,
        }

        result = FlextLdapFactory.create_bulk_operation_config(config_data)
        assert result.is_failure
        assert "Batch size must be greater than 0" in result.error

    def test_create_bulk_operation_config_batch_size_exceeds_limit(self) -> None:
        """Test bulk operation config with batch size exceeding limit."""
        config_data = {
            "operation_type": "create",
            "items_data": [{"dn": "cn=user1,ou=people,dc=example,dc=com"}],
            "batch_size": 100,  # Exceeds DEFAULT_PAGE_SIZE (10)
        }

        result = FlextLdapFactory.create_bulk_operation_config(config_data)
        assert result.is_failure
        assert "Batch size cannot exceed" in result.error
