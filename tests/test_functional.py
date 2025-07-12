"""Functional tests for LDAP operations."""

import pytest

from flext_ldap.application.services import LDAPUserService
from flext_ldap.config import FlextLDAPSettings
from flext_ldap.domain.value_objects import CreateUserRequest


class TestLDAPUserService:
    """Test LDAP user service functionality."""

    @pytest.mark.unit
    def test_user_service_creation(self):
        """Test that LDAPUserService can be created."""
        service = LDAPUserService()
        assert service is not None

    @pytest.mark.unit
    async def test_create_user_with_request(self):
        """Test creating user with CreateUserRequest."""
        service = LDAPUserService()
        
        request = CreateUserRequest(
            dn="cn=testuser,ou=people,dc=test,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="test@example.com"
        )
        
        result = await service.create_user(request)
        
        assert result.is_success
        assert result.value is not None
        assert result.value.uid == "testuser"
        assert result.value.cn == "Test User"
        assert result.value.mail == "test@example.com"

    @pytest.mark.unit
    def test_create_user_request_validation(self):
        """Test CreateUserRequest validation."""
        # Valid request
        request = CreateUserRequest(
            dn="cn=test,dc=test,dc=com",
            uid="test",
            cn="Test",
            sn="User"
        )
        assert request.dn == "cn=test,dc=test,dc=com"
        assert request.uid == "test"
        
        # Invalid request - empty DN
        with pytest.raises(ValueError):
            CreateUserRequest(
                dn="",
                uid="test",
                cn="Test",
                sn="User"
            )


class TestFlextLDAPSettings:
    """Test configuration functionality."""

    @pytest.mark.unit
    def test_settings_creation_and_conversion(self):
        """Test settings creation and conversion to client config."""
        settings = FlextLDAPSettings()
        
        # Test default values
        assert settings.connection.server == "localhost"
        assert settings.connection.port == 389
        
        # Test conversion to client config
        client_config = settings.to_ldap_client_config()
        assert client_config["server"] == "localhost"
        assert client_config["port"] == 389
        assert "timeout" in client_config
        assert "base_dn" in client_config