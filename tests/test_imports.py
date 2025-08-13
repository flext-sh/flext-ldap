"""Test FLEXT LDAP Imports - Verify all public imports work correctly."""

from __future__ import annotations


def test_main_api_imports() -> None:
    """Test that main API imports work correctly."""
    from flext_ldap import FlextLdapApi, get_ldap_api

    assert FlextLdapApi is not None
    assert get_ldap_api is not None


def test_model_imports() -> None:
    """Test that model imports work correctly."""
    from flext_ldap import (
        FlextLdapCreateUserRequest,
        FlextLdapDistinguishedName,
        FlextLdapEntry,
        FlextLdapGroup,
        FlextLdapUser,
    )

    assert FlextLdapCreateUserRequest is not None
    assert FlextLdapDistinguishedName is not None
    assert FlextLdapEntry is not None
    assert FlextLdapGroup is not None
    assert FlextLdapUser is not None


def test_config_imports() -> None:
    """Test that configuration imports work correctly."""
    from flext_ldap import FlextLdapConnectionConfig, FlextLdapSettings

    assert FlextLdapConnectionConfig is not None
    assert FlextLdapSettings is not None


def test_service_imports() -> None:
    """Test that service imports work correctly."""
    from flext_ldap import FlextLdapService

    assert FlextLdapService is not None


def test_infrastructure_imports() -> None:
    """Test that infrastructure imports work correctly."""
    from flext_ldap import FlextLdapClient

    assert FlextLdapClient is not None


def test_exception_imports() -> None:
    """Test that exception imports work correctly."""
    from flext_ldap import FlextLdapException, FlextLdapUserError

    assert FlextLdapException is not None
    assert FlextLdapUserError is not None


def test_utility_imports() -> None:
    """Test that utility imports work correctly."""
    from flext_ldap import (
        flext_ldap_sanitize_attribute_name,
        flext_ldap_validate_attribute_name,
        flext_ldap_validate_attribute_value,
        flext_ldap_validate_dn,
    )

    assert flext_ldap_sanitize_attribute_name is not None
    assert flext_ldap_validate_attribute_name is not None
    assert flext_ldap_validate_attribute_value is not None
    assert flext_ldap_validate_dn is not None


def test_all_public_api() -> None:
    """Test that __all__ exports are correctly defined."""
    import flext_ldap

    # Verify that __all__ exists and contains expected items
    assert hasattr(flext_ldap, "__all__")
    all_items = flext_ldap.__all__

    # Core items that should be in __all__
    expected_items = {
        "FlextLdapApi",
        "get_ldap_api",
        "FlextLdapConnectionConfig",
        "FlextLdapSettings",
        "FlextLdapEntry",
        "FlextLdapUser",
        "FlextLdapGroup",
        "FlextLdapService",
        "FlextLdapClient",
        "FlextLdapException",
        "FlextLdapUserError",
    }

    # Check that expected items are in __all__
    for item in expected_items:
        assert item in all_items, f"'{item}' should be in __all__"
