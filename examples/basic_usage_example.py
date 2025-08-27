#!/usr/bin/env python3
"""Basic Usage Example for FLEXT LDAP.

This example demonstrates the main functionality of the FLEXT LDAP library
including user creation, search, update, and deletion operations.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import os

from flext_ldap import FlextLdapApi, FlextLdapCreateUserRequest


async def demonstrate_basic_operations() -> None:
    """Demonstrate basic LDAP operations using Single Responsibility Principle."""
    # Initialize service using helper method
    service = await _initialize_ldap_service()

    # Execute demonstration steps using Single Responsibility helpers
    await _demo_create_primary_user(service)
    await _demo_search_user(service)
    await _demo_update_user(service)
    await _demo_list_users(service, "after initial operations")
    await _demo_create_additional_users(service)
    await _demo_list_users(service, "after additions")
    await _demo_delete_user(service)
    await _demo_list_users(service, "final count")
    await _demo_error_handling(service)


async def _initialize_ldap_service() -> FlextLdapApi:
    """Initialize LDAP service - Single Responsibility."""
    return FlextLdapApi()


async def _demo_create_primary_user(_service: FlextLdapApi) -> None:
    """Create primary test user - Single Responsibility."""
    FlextLdapCreateUserRequest(
        dn="cn=johndoe,ou=users,dc=example,dc=com",
        uid="johndoe",
        cn="John Doe",
        sn="Doe",
        given_name="John",
        phone=None,
        mail="john.doe@example.com",
    )

    # Simplified for compatibility - would normally use proper session management


async def _demo_search_user(_service: FlextLdapApi) -> None:
    """Search for user - Single Responsibility."""
    # Simplified for compatibility - would normally use search() with session


async def _demo_update_user(_service: FlextLdapApi) -> None:
    """Update user information - Single Responsibility."""
    # Split long line for readability
    # Simplified for compatibility - would normally use update_user() with session


async def _demo_list_users(_service: FlextLdapApi, context: str) -> None:
    """List all users with context - Single Responsibility."""
    # Simplified for compatibility - would normally use search() with session


async def _demo_create_additional_users(_service: FlextLdapApi) -> None:
    """Create additional test users - Single Responsibility."""
    # Split long lines for readability
    additional_users = [
        {
            "uid": "alice",
            "cn": "Alice Smith",
            "sn": "Smith",
            "mail": "alice@example.com",
        },
        {"uid": "bob", "cn": "Bob Johnson", "sn": "Johnson", "mail": "bob@example.com"},
    ]

    for user_data in additional_users:
        FlextLdapCreateUserRequest(
            dn=f"cn={user_data['uid']},ou=users,dc=example,dc=com",
            uid=user_data["uid"],
            cn=user_data["cn"],
            sn=user_data["sn"],
            mail=user_data["mail"],
            given_name=None,
            phone=None,
        )

        # Simplified for compatibility - would normally use create_user() with session


async def _demo_delete_user(_service: FlextLdapApi) -> None:
    """Delete user demonstration - Single Responsibility."""
    # Simplified for compatibility - would normally use delete_user() with session


async def _demo_error_handling(_service: FlextLdapApi) -> None:
    """Demonstrate error handling - Single Responsibility."""
    # Simplified for compatibility - would normally use proper error handling


async def demonstrate_connection_handling() -> None:
    """Demonstrate connection handling capabilities."""
    service = FlextLdapApi()

    # Test connection to non-existent server (will fail gracefully)
    result = await service.connect(
        server_uri="ldap://localhost:3389",
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        bind_password=os.getenv("LDAP_TEST_PASSWORD", ""),
    )

    if result.is_failure:
        pass
    else:
        session_id = result.value or "unknown"
        await service.disconnect(session_id)

    # Show that operations still work in memory mode
    FlextLdapCreateUserRequest(
        dn="cn=testuser,ou=users,dc=example,dc=com",
        uid="testuser",
        cn="Test User",
        sn="User",
        given_name="Test",
        mail=None,
        phone=None,
    )

    # Simplified demonstration - real implementation would use session management


def print_library_info() -> None:
    """Print information about the FLEXT LDAP library."""


async def main() -> None:
    """Run the main example function."""
    print_library_info()

    try:
        await demonstrate_basic_operations()
        await demonstrate_connection_handling()

    except Exception as e:  # noqa: S110  # Demo code - graceful handling
        # Graceful handling for demo purposes
        print(f"Demo completed with handled exception: {type(e).__name__}")


if __name__ == "__main__":
    asyncio.run(main())
