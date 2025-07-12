#!/usr/bin/env python3
"""Example of using the integrated LDAP service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

This example demonstrates how to use the LDAPService for LDAP operations.
"""

import asyncio
import sys
from pathlib import Path

# Force use of local src instead of installed package
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from flext_ldap import LDAPService
from flext_ldap.domain.value_objects import CreateUserRequest


async def main() -> None:
    """Demonstrate LDAP service usage."""
    print("=== FLEXT LDAP Service Demo ===\n")

    # Initialize the LDAP service
    ldap_service = LDAPService()
    print("✅ LDAP Service initialized")
    print(f"Connected: {ldap_service.is_connected()}\n")

    # Example 1: Work in memory mode (no LDAP server connection)
    print("--- Example 1: Memory Mode Operations ---")

    # Create a user in memory mode
    user_request = CreateUserRequest(
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
        user = result.value
        print(f"✅ Created user: {user.cn} ({user.uid})")
        print(f"   DN: {user.dn}")
        print(f"   Email: {user.mail}")
        print(f"   Title: {user.title}")

        # Update the user
        update_result = await ldap_service.update_user(
            user.id,
            {"title": "Principal Software Engineer"},
        )
        if update_result.is_success:
            updated_user = update_result.value
            print(f"✅ Updated user title: {updated_user.title}")

        # Find user by UID
        find_result = await ldap_service.find_user_by_uid("john.doe")
        if find_result.is_success and find_result.value:
            found_user = find_result.value
            print(f"✅ Found user by UID: {found_user.cn}")

        # Lock and unlock user
        lock_result = await ldap_service.lock_user(user.id)
        if lock_result.is_success:
            print("✅ User account locked")

        unlock_result = await ldap_service.unlock_user(user.id)
        if unlock_result.is_success:
            print("✅ User account unlocked")

        # List all users
        list_result = await ldap_service.list_users()
        if list_result.is_success:
            users = list_result.value
            print(f"✅ Found {len(users)} users in total")
    else:
        print(f"❌ Failed to create user: {result.error_message}")

    print()

    # Example 2: Group operations
    print("--- Example 2: Group Operations ---")

    group_result = await ldap_service.create_group(
        dn="cn=developers,ou=groups,dc=example,dc=com",
        cn="developers",
        ou="groups",
    )

    if group_result.is_success:
        group = group_result.value
        print(f"✅ Created group: {group.cn}")
        print(f"   DN: {group.dn}")

        # Add user to group
        if result.is_success:
            user = result.value
            add_result = await ldap_service.add_user_to_group(group.id, user.dn)
            if add_result.is_success:
                updated_group = add_result.value
                print(f"✅ Added user to group: {len(updated_group.members)} members")

            # Remove user from group
            remove_result = await ldap_service.remove_user_from_group(group.id, user.dn)
            if remove_result.is_success:
                updated_group = remove_result.value
                print(
                    f"✅ Removed user from group: {len(updated_group.members)} members"
                )

        # List all groups
        groups_result = await ldap_service.list_groups()
        if groups_result.is_success:
            groups = groups_result.value
            print(f"✅ Found {len(groups)} groups in total")
    else:
        print(f"❌ Failed to create group: {group_result.error_message}")

    print()

    # Example 3: Connection management (will fail without real LDAP server)
    print("--- Example 3: LDAP Server Connection (Demo) ---")

    # Attempt to connect to a test LDAP server
    # This will fail gracefully and demonstrate error handling
    connection_result = await ldap_service.connect_to_server(
        "ldap://demo.example.com:389",
        "cn=admin,dc=example,dc=com",
        "admin_password",
    )

    if connection_result.is_success:
        connection = connection_result.value
        print(f"✅ Connected to LDAP server: {connection.server_url}")
        print(f"   Bound as: {connection.bind_dn}")
        print(f"   Connected: {ldap_service.is_connected()}")

        # Test the connection
        test_result = await ldap_service.test_connection()
        if test_result.is_success:
            test_info = test_result.value
            print("✅ Connection test successful:")
            print(f"   Server: {test_info['server']}")
            print(f"   Bound: {test_info['bound']}")

        # When connected, operations would use real LDAP directory
        # User operations would add/modify/delete actual LDAP entries

        # Disconnect
        disconnect_result = await ldap_service.disconnect_from_server()
        if disconnect_result.is_success:
            print("✅ Disconnected from LDAP server")
            print(f"   Connected: {ldap_service.is_connected()}")
    else:
        print(
            f"INFO: Demo connection failed (expected): {connection_result.error_message}"
        )
        print("   This is normal - no real LDAP server is running")
        print("   In production, you would connect to your actual LDAP server")

    print()

    # Example 4: Error handling demonstration
    print("--- Example 4: Error Handling ---")

    # Try to find non-existent user
    missing_result = await ldap_service.find_user_by_uid("nonexistent")
    if missing_result.is_success:
        if missing_result.value is None:
            print("✅ Correctly handled missing user (returned None)")
        else:
            print("❌ Unexpected user found")
    else:
        print(f"❌ Error finding user: {missing_result.error_message}")

    # Try to disconnect when not connected
    disconnect_result = await ldap_service.disconnect_from_server()
    if disconnect_result.failure:
        print(
            f"✅ Correctly handled disconnect error: {disconnect_result.error_message}"
        )
    else:
        print("❌ Unexpected successful disconnect")

    print()
    print("=== Demo Complete ===")
    print("The LDAP service supports both:")
    print("• Memory mode: For testing and development")
    print("• LDAP mode: For real directory operations when connected")
    print("• Graceful fallback: Operations work in both modes")


if __name__ == "__main__":
    asyncio.run(main())
