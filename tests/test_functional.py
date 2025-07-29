"""Functional tests for LDAP operations."""

import pytest

from flext_ldap.config import FlextLdapSettings
from flext_ldap.domain.ports import FlextLdapUserService
from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest

# Constants
EXPECTED_DATA_COUNT = 3


class TestFlextLdapUserService:
    """Test LDAP user service functionality."""

    @pytest.mark.unit
    def test_user_service_creation(self) -> None:
        """Test that FlextLdapUserService interface exists."""
        # FlextLdapUserService is abstract, test the interface exists
        assert FlextLdapUserService is not None

    @pytest.mark.unit
    def test_create_user_request_basic(self) -> None:
        """Test basic CreateUserRequest validation."""
        request = FlextLdapCreateUserRequest(
            dn="cn=testuser,ou=people,dc=test,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="test@example.com",
        )

        if request.dn != "cn=testuser,ou=people,dc=test,dc=com":

            msg = f"Expected {"cn=testuser,ou=people,dc=test,dc=com"}, got {request.dn}"
            raise AssertionError(msg)
        assert request.uid == "testuser"
        if request.cn != "Test User":
            msg = f"Expected {"Test User"}, got {request.cn}"
            raise AssertionError(msg)

    @pytest.mark.unit
    def test_create_user_request_validation(self) -> None:
        """Test CreateUserRequest validation."""
        # Valid request
        request = FlextLdapCreateUserRequest(
            dn="cn=test,dc=test,dc=com",
            uid="test",
            cn="Test",
            sn="User",
        )
        if request.dn != "cn=test,dc=test,dc=com":
            msg = f"Expected {"cn=test,dc=test,dc=com"}, got {request.dn}"
            raise AssertionError(msg)
        assert request.uid == "test"

        # Invalid request - empty DN
        with pytest.raises(ValueError, match=".*DN.*"):
            FlextLdapCreateUserRequest(
                dn="",
                uid="test",
                cn="Test",
                sn="User",
            )


class TestFlextLdapSettings:
    """Test configuration functionality."""

    @pytest.mark.unit
    def test_settings_creation_and_conversion(self) -> None:
        """Test settings creation and conversion to client config."""
        settings = FlextLdapSettings()

        # Test default values
        if settings.connection.server != "localhost":
            msg = f"Expected {"localhost"}, got {settings.connection.server}"
            raise AssertionError(msg)
        assert settings.connection.port == 389

        # Test conversion to client config
        client_config = settings.to_ldap_client_config()
        if client_config["server"] != "localhost":
            msg = f"Expected {"localhost"}, got {client_config["server"]}"
            raise AssertionError(msg)
        assert client_config["port"] == 389
        if "timeout" not in client_config:
            msg = f"Expected {"timeout"} in {client_config}"
            raise AssertionError(msg)
        assert "base_dn" in client_config
