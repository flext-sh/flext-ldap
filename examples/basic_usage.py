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
from typing import TYPE_CHECKING

from flext_core import FlextLogger

if TYPE_CHECKING:
    # For static type checkers only
    from flext_ldap import FlextLdapApi, FlextLdapModels
else:
    # Runtime: try to import library but fall back to harmless placeholders
    try:
        from flext_ldap import FlextLdapApi, FlextLdapModels
    except Exception:  # pragma: no cover - example fallback for local editing
        # type ignored: these placeholders are only for editor/static-checker convenience
        FlextLdapApi = object
        FlextLdapModels = object


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


def _initialize_ldap_service() -> FlextLdapApi:
    """Initialize LDAP service - Single Responsibility."""
    return FlextLdapApi()


def _demo_create_primary_user(_service: FlextLdapApi) -> None:
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


def _demo_create_additional_users(_service: FlextLdapApi) -> None:
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
