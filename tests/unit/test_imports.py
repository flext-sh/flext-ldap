"""Test FLEXT LDAP Imports - Verify all public imports work correctly."""

from __future__ import annotations

import pytest

import flext_ldap
from flext_ldap import (
    FlextLDAPApi,
    FlextLDAPClient,
    FlextLDAPConnectionConfig,
    FlextLDAPCreateUserRequest,
    FlextLDAPDistinguishedName,
    FlextLDAPError,
    FlextLDAPService,
    FlextLDAPSettings,
    FlextLDAPUserError,
)
from flext_ldap.utilities import FlextLDAPUtilities


def test_main_api_imports() -> None:
    """Test that main API imports work correctly and are callable."""
    # Verify API can be instantiated directly
    api = FlextLDAPApi()
    assert isinstance(api, FlextLDAPApi)
    assert hasattr(api, "search")
    assert hasattr(api, "connection")


def test_model_imports() -> None:
    """Test that model imports work correctly and are instantiable."""
    # Test DN creation works
    dn_result = FlextLDAPDistinguishedName.create("cn=test,dc=example,dc=com")
    assert dn_result.is_success
    # Use .value for modern type-safe access (success verified above)
    assert dn_result.value is not None

    # Test user request creation works
    user_request = FlextLDAPCreateUserRequest(
        dn="cn=test,ou=users,dc=example,dc=com",
        uid="test_user",
        cn="Test User",
        sn="User",
    )
    assert user_request.uid == "test_user"
    assert user_request.cn == "Test User"


def test_config_imports() -> None:
    """Test that configuration imports work correctly and are instantiable."""
    # Test connection config creation
    config = FlextLDAPConnectionConfig(server="ldap://test.example.com", port=389)
    assert config.server == "ldap://test.example.com"
    assert config.port == 389

    # Test settings creation
    settings = FlextLDAPSettings()
    assert hasattr(settings, "connection")


def test_service_imports() -> None:
    """Test that service imports work correctly and are instantiable."""
    # Test service creation
    service = FlextLDAPService()
    assert hasattr(service, "create_user")
    assert hasattr(service, "search_users")
    assert hasattr(service, "validate_dn")


def test_infrastructure_imports() -> None:
    """Test that infrastructure imports work correctly and are instantiable."""
    # Test client creation
    client = FlextLDAPClient()
    assert hasattr(client, "connect")
    assert hasattr(client, "search")
    assert hasattr(client, "is_connected")
    assert not client.is_connected  # Should start disconnected


def test_exception_imports() -> None:
    """Test that exception imports work correctly and are proper exceptions."""
    # Test that exceptions are proper Exception subclasses
    assert issubclass(FlextLDAPError, Exception)
    assert issubclass(FlextLDAPUserError, Exception)

    # Test that exceptions can be instantiated and have expected attributes
    error_msg = "Test error"
    with pytest.raises(FlextLDAPError) as exc_info:
        raise FlextLDAPError(error_msg)

    assert isinstance(exc_info.value, Exception)
    assert hasattr(exc_info.value, "ldap_result_code")

    user_error_msg = "Test user error"
    with pytest.raises(FlextLDAPUserError) as user_exc_info:
        raise FlextLDAPUserError(user_error_msg)

    assert isinstance(user_exc_info.value, Exception)
    # UserError should be a subclass of FlextLDAPError
    assert isinstance(user_exc_info.value, FlextLDAPError)


def test_utility_imports() -> None:
    """Test that utility imports work correctly and function properly."""
    # Test attribute name sanitization
    sanitized = FlextLDAPUtilities.Validation.sanitize_attribute_name("Test@Name!")
    assert isinstance(sanitized, str)
    assert len(sanitized) > 0

    # Test DN validation with valid DN
    dn_valid = FlextLDAPUtilities.DnParser.validate_dn("cn=test,dc=example,dc=com")
    assert dn_valid is True

    # Test DN validation with invalid DN
    dn_invalid = FlextLDAPUtilities.DnParser.validate_dn("invalid-dn")
    assert dn_invalid is False

    # Test attribute name validation
    attr_name_valid = FlextLDAPUtilities.Validation.validate_attribute_name("cn")
    assert attr_name_valid is True

    # Test attribute value validation
    attr_value_valid = FlextLDAPUtilities.Validation.validate_attribute_value(
        "test_value"
    )
    assert attr_value_valid is True


def test_all_public_api() -> None:
    """Test that __all__ exports are correctly defined."""
    # Verify that __all__ exists and contains expected items
    assert hasattr(flext_ldap, "__all__")
    all_items = flext_ldap.__all__

    # Core items that should be in __all__
    expected_items = {
        "FlextLDAPApi",
        "FlextLDAPConnectionConfig",
        "FlextLDAPSettings",
        "FlextLDAPEntry",
        "FlextLDAPUser",
        "FlextLDAPGroup",
        "FlextLDAPService",
        "FlextLDAPClient",
        "FlextLDAPError",
        "FlextLDAPUserError",
    }

    # Check that expected items are in __all__
    for item in expected_items:
        assert item in all_items, f"'{item}' should be in __all__"
