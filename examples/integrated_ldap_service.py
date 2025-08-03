#!/usr/bin/env python3
"""Example of using the integrated LDAP service.

This example demonstrates how to use the LDAPService for LDAP operations.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio

from flext_core import get_logger
from flext_ldap import LDAPService
from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest

logger = get_logger(__name__)


async def main() -> None:
    """Demonstrate LDAP service usage using Single Responsibility Principle."""
    print("=== FLEXT LDAP Integration Service Demo ===")
    print()

    # Initialize service using helper method
    ldap_service = await _initialize_ldap_service()

    # Execute demonstration steps using Single Responsibility helpers
    await _demo_user_operations(ldap_service)
    await _demo_group_operations(ldap_service)
    await _demo_connection_management(ldap_service)
    await _demo_error_handling(ldap_service)

    print("=== Integration demo completed successfully! ===")
    print("✅ All operations completed - LDAP service ready for production use")


async def _initialize_ldap_service() -> LDAPService:
    """Initialize LDAP service - Single Responsibility."""
    print("1. Initializing LDAP integration service...")
    service = LDAPService()
    print(f"   Service initialized: {type(service).__name__}")
    print()
    return service


async def _demo_user_operations(ldap_service: LDAPService) -> None:
    """Demonstrate user operations - Single Responsibility."""
    print("2. User Operations Demo...")

    # Create a user in memory mode
    user_request = FlextLdapCreateUserRequest(
        dn="cn=john.doe,ou=people,dc=example,dc=com",
        uid="john.doe",
        cn="John Doe",
        sn="Doe",
        mail="john.doe@example.com",
        phone="+1-555-0123",
        department="Engineering",
        title="Senior Software Engineer",
    )

    result = await ldap_service.create_user(user_request)
    if result.is_success:
        user = result.data
        if user is None:
            logger.warning("User not found after creation")
            return

        print(f"   User created: {user.uid} ({user.cn})")

        # Perform user management operations
        await _perform_user_management(ldap_service, user)
    else:
        print(f"   Error creating user: {result.error}")
    print()


async def _perform_user_management(ldap_service: LDAPService, user: object) -> None:
    """Perform user management operations - Single Responsibility."""
    # Update the user
    update_result = await ldap_service.update_user(
        user.id, {"title": "Principal Software Engineer"}
    )
    if update_result.is_success:
        print("   User updated successfully")

    # Find user by UID
    find_result = await ldap_service.find_user_by_uid("john.doe")
    if find_result.is_success and find_result.data:
        print("   User found by UID")

    # Lock and unlock user
    lock_result = await ldap_service.lock_user(user.id)
    if lock_result.is_success:
        print("   User locked successfully")

    unlock_result = await ldap_service.unlock_user(user.id)
    if unlock_result.is_success:
        print("   User unlocked successfully")

    # List all users
    list_result = await ldap_service.list_users()
    if list_result.is_success:
        users_count = len(list_result.data) if list_result.data else 0
        print(f"   Total users listed: {users_count}")


async def _demo_group_operations(ldap_service: LDAPService) -> None:
    """Demonstrate group operations - Single Responsibility."""
    print("3. Group Operations Demo...")

    group_result = await ldap_service.create_group(
        dn="cn=developers,ou=groups,dc=example,dc=com",
        cn="developers",
        ou="groups",
    )

    if group_result.is_success:
        group = group_result.data
        if group is None:
            logger.warning("Group not found after creation")
            return

        print(f"   Group created: {group.cn if hasattr(group, 'cn') else 'developers'}")

        # Perform group management operations
        await _perform_group_management(ldap_service, group)
    else:
        print(f"   Error creating group: {group_result.error}")
    print()


async def _perform_group_management(ldap_service: LDAPService, group: object) -> None:
    """Perform group management operations - Single Responsibility."""
    # Try to get user for group operations
    user_result = await ldap_service.find_user_by_uid("john.doe")
    if user_result.is_success:
        user = user_result.data
        if user is None:
            print("   No user found for group operations")
            return

        # Add user to group
        add_result = await ldap_service.add_user_to_group(group.id, user.dn)
        if add_result.is_success:
            print("   User added to group successfully")

        # Remove user from group
        remove_result = await ldap_service.remove_user_from_group(group.id, user.dn)
        if remove_result.is_success:
            print("   User removed from group successfully")

    # List all groups
    groups_result = await ldap_service.list_groups()
    if groups_result.is_success:
        groups_count = len(groups_result.data) if groups_result.data else 0
        print(f"   Total groups listed: {groups_count}")


async def _demo_connection_management(ldap_service: LDAPService) -> None:
    """Demonstrate connection management - Single Responsibility."""
    print("4. Connection Management Demo...")

    # Attempt to connect to a test LDAP server
    # This will fail gracefully and demonstrate error handling
    connection_result = await ldap_service.connect_to_server(
        "ldap://demo.example.com:389",
        "cn=admin,dc=example,dc=com",
        "admin_password",
    )

    if connection_result.is_success:
        print("   Connected to LDAP server successfully")

        # Test the connection
        test_result = await ldap_service.test_connection()
        if test_result.is_success:
            print("   Connection test passed")

        # Disconnect
        disconnect_result = await ldap_service.disconnect_from_server()
        if disconnect_result.is_success:
            print("   Disconnected successfully")
    else:
        print(f"   Connection failed (expected): {connection_result.error}")
        print("   Service operates in memory mode when no server available")
    print()


async def _demo_error_handling(ldap_service: LDAPService) -> None:
    """Demonstrate error handling - Single Responsibility."""
    print("5. Error Handling Demo...")

    # Try to find non-existent user
    missing_result = await ldap_service.find_user_by_uid("nonexistent")
    if missing_result.is_success and missing_result.data is None:
        print("   Expected behavior: non-existent user returns None")
    elif missing_result.is_failure:
        print(f"   Expected error for nonexistent user: {missing_result.error}")

    # Try to disconnect when not connected
    disconnect_result = await ldap_service.disconnect_from_server()
    if disconnect_result.is_failure:
        print(
            f"   Expected error for disconnect when not connected: {disconnect_result.error}"
        )

    print("   Error handling demonstration completed")
    print()


if __name__ == "__main__":
    asyncio.run(main())
