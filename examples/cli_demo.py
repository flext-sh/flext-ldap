#!/usr/bin/env python3
"""FLEXT-LDAP CLI Demo Example.

This example demonstrates the new CLI functionality in flext-ldap,
showing the same level of isolation and organization as FlextModel and FlextCli patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import traceback

from flext_ldap import FlextLdapApi, FlextLdapModels


async def demonstrate_cli_isolation() -> None:
    """Demonstrate CLI isolation patterns similar to FlextCli."""
    # Get CLI instance using factory function (following FlextCli patterns)
    # CLI functionality removed - use FlextLdapApi directly
    cli = FlextLdapApi()

    # Show configuration
    cli.show_configuration()

    # Demonstrate connection with environment variables
    server_uri = os.getenv("LDAP_SERVER_URI", "ldap://demo.example.com:389")
    bind_dn = os.getenv("LDAP_BIND_DN", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
    bind_password = os.getenv("LDAP_BIND_PASSWORD", "demo_password")

    # Connect to LDAP
    connection_result = await cli.connect_to_ldap(server_uri, bind_dn, bind_password)
    if connection_result.is_success:
        print(f"✅ Connection successful: {connection_result.value}")
    else:
        print(f"❌ Connection failed: {connection_result.error}")

    # Demonstrate search
    search_result = await cli.search_ldap(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=person)",
        scope="subtree",
    )
    if search_result.is_success:
        print(f"✅ Search successful: {search_result.value.total_count} entries found")
    else:
        print(f"❌ Search failed: {search_result.error}")

    # Demonstrate user creation with positional arguments
    user_result = await cli.create_user(
        "cn=testuser,ou=users,dc=example,dc=com",  # dn as first positional argument
        "testuser",  # uid
        "Test User",  # cn
        "User",  # sn
        "testuser@example.com",  # mail
    )
    if user_result.is_success:
        print(f"✅ User created successfully: {user_result.value.uid}")
    else:
        print(f"❌ User creation failed: {user_result.error}")


def demonstrate_model_cli_separation() -> None:
    """Demonstrate the separation between FlextLdapModels and FlextLdapCli."""
    # Data management (FlextLdapModels) - pure data operations
    print("=== Data Management (FlextLdapModels) ===")

    # Create models directly
    search_request = FlextLdapModels.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=person)",
        scope="subtree",
    )
    print(f"Search Request: {search_request.base_dn}")

    user_request = FlextLdapModels.CreateUserRequest(
        dn="cn=testuser,ou=users,dc=example,dc=com",
        uid="testuser",
        cn="Test User",
        sn="User",
    )
    print(f"User Request: {user_request.uid}")

    # CLI operations (FlextLdapCli) - user interaction and formatting
    print("\n=== CLI Operations (FlextLdapCli) ===")

    # CLI functionality removed - use FlextLdapApi directly
    cli = FlextLdapApi()

    # CLI handles user interaction and formatting
    cli.display_message("Model vs CLI Separation Demo", "info")
    cli.display_message(
        "✅ Data models handle pure data operations",
        "info",
    )
    cli.display_message(
        "✅ CLI handles user interaction and formatting",
        "info",
    )
    cli.print_success("Perfect separation achieved!")


def demonstrate_unified_class_pattern() -> None:
    """Demonstrate the unified class pattern with nested helpers."""
    # CLI functionality removed - use FlextLdapApi directly
    cli = FlextLdapApi()

    print("=== Unified Class Pattern Demo ===")

    # Show that CLI has nested helper classes
    print("FlextLdapCli nested helper classes:")
    print(f"  - _ConnectionHelper: {hasattr(cli, '_connection_helper')}")
    print(f"  - _SearchHelper: {hasattr(cli, '_search_helper')}")
    print(f"  - _UserManagementHelper: {hasattr(cli, '_user_management_helper')}")

    # Demonstrate helper usage through public methods
    connection_info = cli.format_connection_info(
        "ldap://example.com:389",
        "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    )
    print(f"\nConnection Helper Output:\n{connection_info}")

    search_request = cli.create_search_request(
        "dc=example,dc=com",
        "(objectClass=person)",
    )
    print(f"\nSearch Helper Output: {search_request.base_dn}")

    user_request = cli.create_user_request(
        "cn=test,dc=example,dc=com",
        "test",
        "Test",
        "User",
    )
    # Convert to user entity for formatting
    user_entity = FlextLdapModels.User(
        id=f"user_{user_request.uid}",
        dn=user_request.dn,
        uid=user_request.uid,
        cn=user_request.cn,
        sn=user_request.sn,
        modified_at=None,
        given_name=None,
        mail=user_request.mail,
        user_password=None,
    )
    user_info = cli.format_user_info(user_entity)
    print(f"\nUser Management Helper Output:\n{user_info}")


if __name__ == "__main__":
    import asyncio

    print("FLEXT-LDAP CLI Isolation Demo")
    print("=" * 40)

    async def main() -> None:
        """Main async function to run demonstrations."""
        try:
            await demonstrate_cli_isolation()
            print("\n" + "=" * 40)

            demonstrate_model_cli_separation()
            print("\n" + "=" * 40)

            demonstrate_unified_class_pattern()
            print("\n" + "=" * 40)

            print("✅ All demonstrations completed successfully!")
            print("\nKey Benefits:")
            print("✅ Same level of isolation as FlextModel and FlextCli patterns")
            print("✅ Unified class pattern with nested helpers")
            print("✅ Clear separation between data management and CLI functionality")
            print("✅ Factory function pattern for CLI instance creation")
            print("✅ Comprehensive CLI operations with proper error handling")

        except Exception as e:
            print(f"❌ Error during demonstration: {e}")
            traceback.print_exc()

    asyncio.run(main())
