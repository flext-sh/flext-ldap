#!/usr/bin/env python3
"""Example of using the integrated LDAP service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

This example demonstrates how to use the LDAPService for LDAP operations.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from flext_core import get_logger

from flext_ldap import LDAPService
from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest

logger = get_logger(__name__)

# Force use of local src instead of installed package
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


async def main() -> None:
    """Demonstrate LDAP service usage."""
    # Initialize the LDAP service
    ldap_service = LDAPService()

    # Example 1: Work in memory mode (no LDAP server connection)

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
    if result.success:
        user = result.data

        if user is None:
            logger.warning("User not found")
            return

        # Update the user
        update_result = await ldap_service.update_user(
            user.id,
            {"title": "Principal Software Engineer"},
        )
        if update_result.success:
            pass

        # Find user by UID
        find_result = await ldap_service.find_user_by_uid("john.doe")
        if find_result.success and find_result.data:
            pass

        # Lock and unlock user
        lock_result = await ldap_service.lock_user(user.id)
        if lock_result.success:
            pass

        unlock_result = await ldap_service.unlock_user(user.id)
        if unlock_result.success:
            pass

        # List all users
        list_result = await ldap_service.list_users()
        if list_result.success:
            pass

    # Example 2: Group operations

    group_result = await ldap_service.create_group(
        dn="cn=developers,ou=groups,dc=example,dc=com",
        cn="developers",
        ou="groups",
    )

    if group_result.success:
        group = group_result.data

        if group is None:
            logger.warning("Group not found")
            return

        # Add user to group
        if result.success:
            user = result.data
            if user is None:
                logger.warning("User not found for group operations")
                return

            add_result = await ldap_service.add_user_to_group(group.id, user.dn)
            if add_result.success:
                pass

            # Remove user from group
            remove_result = await ldap_service.remove_user_from_group(group.id, user.dn)
            if remove_result.success:
                pass

        # List all groups
        groups_result = await ldap_service.list_groups()
        if groups_result.success:
            pass

    # Example 3: Connection management (will fail without real LDAP server)

    # Attempt to connect to a test LDAP server
    # This will fail gracefully and demonstrate error handling
    connection_result = await ldap_service.connect_to_server(
        "ldap://demo.example.com:389",
        "cn=admin,dc=example,dc=com",
        "admin_password",
    )

    if connection_result.success:
        # Test the connection
        test_result = await ldap_service.test_connection()
        if test_result.success:
            pass

        # When connected, operations would use real LDAP directory
        # User operations would add/modify/delete actual LDAP entries

        # Disconnect
        disconnect_result = await ldap_service.disconnect_from_server()
        if disconnect_result.success:
            pass

    # Example 4: Error handling demonstration

    # Try to find non-existent user
    missing_result = await ldap_service.find_user_by_uid("nonexistent")
    if missing_result.success and missing_result.data is None:
        pass

    # Try to disconnect when not connected
    disconnect_result = await ldap_service.disconnect_from_server()
    if disconnect_result.is_failure:
        pass


if __name__ == "__main__":
    asyncio.run(main())
