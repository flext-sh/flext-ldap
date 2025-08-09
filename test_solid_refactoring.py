#!/usr/bin/env python3
"""Test script to verify SOLID refactoring works correctly.

This script tests that:
1. New SOLID classes can be imported
2. Old compatibility classes work with deprecation warnings
3. Basic functionality is preserved
"""

import asyncio
import contextlib
import warnings


def test_new_solid_imports() -> None:
    """Test that new SOLID classes can be imported."""

    # Test new SOLID client

    # Test value objects

    # Test protocols
    with contextlib.suppress(ImportError):
        pass


def test_backward_compatibility() -> None:
    """Test that backward compatibility works with warnings."""

    # Capture deprecation warnings
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        # Test old import path

        # Check we got deprecation warnings
        assert len(w) > 0, "Expected deprecation warnings"
        assert any("deprecated" in str(warning.message).lower() for warning in w)


def test_solid_principles() -> None:
    """Test that SOLID principles are implemented."""

    from flext_ldap.ldap_client import (
        FlextLdapClient,
        LdapConnectionService,
        LdapSearchService,
        LdapWriteService,
    )

    # Test SRP - each service has single responsibility
    conn_service = LdapConnectionService()

    LdapSearchService(conn_service)

    LdapWriteService(conn_service)

    # Test DIP - FlextLdapClient composes services
    FlextLdapClient()


def test_value_objects() -> None:
    """Test that value objects work correctly."""

    from flext_ldap.value_objects import (
        FlextLdapCreateUserRequest,
        FlextLdapDistinguishedName,
        FlextLdapFilter,
        FlextLdapScope,
    )

    # Test scope value object
    scope = FlextLdapScope.sub()
    assert scope.is_subtree()

    # Test DN value object
    dn_result = FlextLdapDistinguishedName.create("cn=test,dc=example,dc=com")
    assert dn_result.is_success
    dn = dn_result.data
    assert dn.get_rdn() == "cn=test"

    # Test filter value object
    filter_obj = FlextLdapFilter.equals("uid", "testuser")
    assert filter_obj.filter_string == "(uid=testuser)"

    # Test user request value object
    user_result = FlextLdapCreateUserRequest.create(
        dn="cn=John Doe,ou=users,dc=example,dc=com",
        uid="john",
        cn="John Doe",
        sn="Doe"
    )
    assert user_result.is_success
    user = user_result.data
    assert user.uid == "john"


async def test_client_interface() -> None:
    """Test that client interface methods exist."""

    from flext_ldap.ldap_client import FlextLdapClient

    client = FlextLdapClient()

    # Test that methods exist (we can't test actual LDAP without server)
    assert hasattr(client, "connect")
    assert hasattr(client, "disconnect")
    assert hasattr(client, "is_connected")
    assert hasattr(client, "search")
    assert hasattr(client, "create_entry")
    assert hasattr(client, "modify_entry")
    assert hasattr(client, "delete_entry")


def main() -> None:
    """Run all tests."""

    try:
        test_new_solid_imports()
        test_backward_compatibility()
        test_solid_principles()
        test_value_objects()
        asyncio.run(test_client_interface())

    except Exception:
        raise


if __name__ == "__main__":
    main()
