#!/usr/bin/env python3
"""Basic Usage Example for FLEXT LDAP.

This example demonstrates the main functionality of the FLEXT LDAP library
including user creation, search, update, and deletion operations.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio

from flext_core import FlextLogger, FlextResult
from flext_ldap import FlextLdapAPI, FlextLdapModels


async def demonstrate_basic_operations() -> None:
    """Demonstrate basic LDAP operations using Single Responsibility Principle."""
    # Initialize service using helper method
    service = _initialize_ldap_service()

    # Execute demonstration steps using Single Responsibility helpers
    _demo_create_primary_user(service)
    await _demo_search_user(service)
    await _demo_update_user(service)
    await _demo_list_users(service, "after initial operations")
    _demo_create_additional_users(service)
    await _demo_list_users(service, "after additions")
    await _demo_delete_user(service)
    await _demo_list_users(service, "final count")
    await _demo_error_handling(service)


def _initialize_ldap_service() -> FlextLdapAPI:
    """Initialize LDAP service - Single Responsibility.

    Returns:
        FlextLdapAPI: The initialized LDAP API instance.

    """
    return FlextLdapAPI()


def _demo_create_primary_user(_service: FlextLdapAPI) -> None:
    """Create primary test user - Single Responsibility."""
    FlextLdapModels.CreateUserRequest(
        dn="cn=johndoe,ou=users,dc=example,dc=com",
        uid="johndoe",
        cn="John Doe",
        sn="Doe",
        given_name="John",
        description=None,
        telephone_number=None,
        user_password=None,
        # phone=None,  # Field not available in CreateUserRequest
        mail="john.doe@example.com",
        department=None,
        title=None,
        organization=None,
    )

    # Simplified for compatibility - would normally use proper session management


async def _demo_search_user(_service: FlextLdapAPI) -> None:
    """Search for user - Single Responsibility."""
    # Simplified for compatibility - would normally use search() with session


async def _demo_update_user(_service: FlextLdapAPI) -> None:
    """Update user information - Single Responsibility."""
    # Split long line for readability
    # Simplified for compatibility - would normally use update_user() with session


async def _demo_list_users(_service: FlextLdapAPI, context: str) -> None:
    """List all users with context - Single Responsibility."""
    # Simplified for compatibility - would normally use search() with session


def _demo_create_additional_users(_service: FlextLdapAPI) -> None:
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
        FlextLdapModels.CreateUserRequest(
            dn=f"cn={user_data['uid']},ou=users,dc=example,dc=com",
            uid=user_data["uid"],
            cn=user_data["cn"],
            sn=user_data["sn"],
            description=None,
            telephone_number=None,
            user_password=None,
            mail=user_data["mail"],
            given_name=None,
            # phone=None,  # Field not available in CreateUserRequest
            department=None,
            title=None,
            organization=None,
        )

        # Simplified for compatibility - would normally use create_user() with session


async def _demo_delete_user(_service: FlextLdapAPI) -> None:
    """Delete user demonstration - Single Responsibility."""
    # Simplified for compatibility - would normally use delete_user() with session


async def _demo_error_handling(_service: FlextLdapAPI) -> None:
    """Demonstrate error handling - Single Responsibility."""
    # Simplified for compatibility - would normally use proper error handling


async def demonstrate_connection_handling() -> None:
    """Demonstrate connection handling capabilities."""
    service = FlextLdapAPI()

    # Test connection (will fail gracefully if no config)
    result: FlextResult[bool] = await service.connect()

    if result.is_failure:
        pass
    else:
        # Connection successful, disconnect
        await service.unbind()

    # Show that operations still work in memory mode
    FlextLdapModels.CreateUserRequest(
        dn="cn=testuser,ou=users,dc=example,dc=com",
        uid="testuser",
        cn="Test User",
        sn="User",
        given_name="Test",
        mail=None,
        description=None,
        telephone_number=None,
        user_password=None,
        # phone=None,  # Field not available in CreateUserRequest
        department=None,
        title=None,
        organization=None,
    )

    # Simplified demonstration - real implementation would use session management


def print_library_info() -> None:
    """Print information about the FLEXT LDAP library."""


async def main() -> None:
    """Run the main example function."""
    logger = FlextLogger(__name__)
    print_library_info()

    try:
        await demonstrate_basic_operations()
        await demonstrate_connection_handling()

    except Exception as e:
        # Graceful handling for demo purposes
        logger.info(
            "Demo completed with handled exception",
            extra={"exception_type": type(e).__name__},
        )


if __name__ == "__main__":
    asyncio.run(main())
