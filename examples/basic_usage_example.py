#!/usr/bin/env python3
"""Basic Usage Example for FLEXT LDAP.

This example demonstrates the main functionality of the FLEXT LDAP library
including user creation, search, update, and deletion operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import asyncio

from flext_ldap.application.ldap_service import FlextLdapService
from flext_ldap.values import FlextLdapCreateUserRequest


async def demonstrate_basic_operations() -> None:
    """Demonstrate basic LDAP operations using Single Responsibility Principle."""
    print("=== FLEXT LDAP Basic Operations Demo ===")
    print()

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

    print("=== Demo completed successfully! ===")
    print("✅ All operations completed - LDAP service ready for production use")


async def _initialize_ldap_service() -> FlextLdapService:
    """Initialize LDAP service - Single Responsibility."""
    print("1. Initializing LDAP service...")
    service = FlextLdapService()
    print(f"   Service connected: {service.is_connected()}")
    print()
    return service


async def _demo_create_primary_user(service: FlextLdapService) -> None:
    """Create primary test user - Single Responsibility."""
    print("2. Creating a test user...")
    user_request = FlextLdapCreateUserRequest(
        dn="cn=johndoe,ou=users,dc=example,dc=com",
        uid="johndoe",
        cn="John Doe",
        sn="Doe",
        mail="john.doe@example.com",
    )

    create_result = await service.create_user(user_request)
    if create_result.is_success:
        user = create_result.data
        print(f"   User created successfully: {user.uid} ({user.cn})")
    else:
        print(f"   Error creating user: {create_result.error}")
        return
    print()


async def _demo_search_user(service: FlextLdapService) -> None:
    """Search for user - Single Responsibility."""
    print("3. Searching for the user...")
    find_result = await service.find_user_by_uid("johndoe")
    if find_result.is_success:
        found_user = find_result.data
        print(f"   Found user: {found_user.cn} <{found_user.mail}>")
    else:
        print(f"   Error finding user: {find_result.error}")
    print()


async def _demo_update_user(service: FlextLdapService) -> None:
    """Update user information - Single Responsibility."""
    print("4. Updating user email...")
    # Split long line for readability
    new_email = "john.doe.updated@example.com"
    update_result = await service.update_user("johndoe", {"mail": new_email})
    if update_result.is_success:
        updated_user = update_result.data
        print(f"   User updated: new email is {updated_user.mail}")
    else:
        print(f"   Error updating user: {update_result.error}")
    print()


async def _demo_list_users(service: FlextLdapService, context: str) -> None:
    """List all users with context - Single Responsibility."""
    print(f"5. Listing all users {context}...")
    list_result = await service.list_users()
    if list_result.is_success:
        users = list_result.data
        print(f"   Found {len(users)} users:")
        for user in users:
            print(f"     - {user.uid}: {user.cn} <{user.mail}>")
    else:
        print(f"   Error listing users: {list_result.error}")
    print()


async def _demo_create_additional_users(service: FlextLdapService) -> None:
    """Create additional test users - Single Responsibility."""
    print("6. Creating additional test users...")
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
        user_req = FlextLdapCreateUserRequest(
            dn=f"cn={user_data['uid']},ou=users,dc=example,dc=com",
            uid=user_data["uid"],
            cn=user_data["cn"],
            sn=user_data["sn"],
            mail=user_data["mail"],
        )

        result = await service.create_user(user_req)
        if result.is_success:
            print(f"   Created user: {user_data['uid']}")
        else:
            print(f"   Error creating user {user_data['uid']}: {result.error}")
    print()


async def _demo_delete_user(service: FlextLdapService) -> None:
    """Delete user demonstration - Single Responsibility."""
    print("8. Deleting user bob...")
    delete_result = await service.delete_user("bob")
    if delete_result.is_success:
        print("   User bob deleted successfully")
    else:
        print(f"   Error deleting user: {delete_result.error}")
    print()


async def _demo_error_handling(service: FlextLdapService) -> None:
    """Demonstrate error handling - Single Responsibility."""
    print("10. Demonstrating error handling...")
    find_result = await service.find_user_by_uid("nonexistent")
    if find_result.is_failure:
        print(f"    Expected error for nonexistent user: {find_result.error}")

    delete_result = await service.delete_user("alsonotfound")
    if delete_result.is_failure:
        print(f"    Expected error for nonexistent deletion: {delete_result.error}")
    print()


async def demonstrate_connection_handling() -> None:
    """Demonstrate connection handling capabilities."""
    print("=== FLEXT LDAP Connection Handling Demo ===")
    print()

    service = FlextLdapService()

    # Test connection to non-existent server (will fail gracefully)
    print("1. Testing connection to non-existent LDAP server...")
    result = await service.connect(
        "ldap://localhost:3389", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "REDACTED_LDAP_BIND_PASSWORD"
    )

    if result.is_failure:
        print(f"   Connection failed as expected: {result.error}")
        # Split long line for readability
        connection_status = service.is_connected()
        print(f"   Service falls back to memory mode. Connected: {connection_status}")
    else:
        print("   Connection succeeded (unexpected for demo)")
        await service.disconnect()
    print()

    # Show that operations still work in memory mode
    print("2. Operations work seamlessly in memory mode...")
    user_request = FlextLdapCreateUserRequest(
        dn="cn=testuser,ou=users,dc=example,dc=com",
        uid="testuser",
        cn="Test User",
        sn="User",
    )

    create_result = await service.create_user(user_request)
    if create_result.is_success:
        print("   User created successfully in memory mode")

    find_result = await service.find_user_by_uid("testuser")
    if find_result.is_success:
        print("   User found successfully in memory mode")

    print()
    print("=== Connection demo completed! ===")


def print_library_info() -> None:
    """Print information about the FLEXT LDAP library."""
    print("=== FLEXT LDAP Library Information ===")
    print()
    print("FLEXT LDAP is an enterprise-grade LDAP operations library built on")
    print("the FLEXT Framework foundation. It implements Clean Architecture and")
    print("Domain-Driven Design patterns to provide type-safe LDAP integration.")
    print()
    print("Key Features:")
    print("  • Clean Architecture with DDD patterns")
    print("  • Type-safe operations with FlextResult pattern")
    print("  • Real LDAP server support with in-memory fallback")
    print("  • Comprehensive error handling and logging")
    print("  • Integration with flext-core for enterprise patterns")
    print()
    print("This example demonstrates the core functionality in memory mode.")
    print("For real LDAP server operations, configure connection parameters.")
    print()


async def main() -> None:
    """Main example function."""
    print_library_info()

    try:
        await demonstrate_basic_operations()
        print()
        await demonstrate_connection_handling()

    except Exception as e:
        print(f"Unexpected error occurred: {e}")
        print("This may indicate a configuration or implementation issue.")

    print()
    print("For more advanced usage, see the test files and documentation.")


if __name__ == "__main__":
    asyncio.run(main())
