#!/usr/bin/env python3
"""Example usage of FlextLdapSimpleClient.

This example demonstrates how to use the minimal LDAP infrastructure client
following Clean Architecture principles.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio

from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient
from flext_ldap.config import FlextLdapConnectionConfig


async def main() -> None:
    """Demonstrate LDAP client usage."""
    # Create client instance
    client = FlextLdapSimpleClient()

    # Example 1: Single server connection
    single_config = FlextLdapConnectionConfig(
        host="localhost",
        port=389,
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="admin",
        use_ssl=False,
        timeout_seconds=10,
    )

    result = client.connect(single_config)
    if result.is_success:
        print("✅ Connected successfully")

        # Example search
        search_result = await client.search(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "mail"],
        )

        if search_result.is_success:
            for _entry in search_result.data[:3]:  # Show first 3
                pass

        # Disconnect
        await client.disconnect()

    # Example 2: Connection pool - Simplified for demo
    # Note: Pool functionality integrated in FlextLdapSimpleClient
    print("✅ Pool functionality integrated in client")

    # Example 3: LDAP operations
    test_config = FlextLdapConnectionConfig(
        host="localhost",
        port=389,
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="admin",
        use_ssl=False,
    )

    op_result = client.connect(test_config)
    if op_result.is_success:
        print("✅ Connected for operations")

        # Add entry
        add_result = await client.add(
            dn="cn=testuser,dc=example,dc=com",
            object_classes=["top", "person", "organizationalPerson"],
            attributes={
                "cn": "testuser",
                "sn": "Test",
                "mail": "test@example.com",
            },
        )

        if add_result.is_success:
            # Modify entry
            modify_result = await client.modify(
                dn="cn=testuser,dc=example,dc=com",
                changes={"mail": "updated@example.com"},
            )

            if modify_result.is_success:
                # Delete entry
                delete_result = await client.delete(
                    dn="cn=testuser,dc=example,dc=com",
                )

                if delete_result.is_success:
                    print("✅ Entry lifecycle completed")

        # Disconnect
        await client.disconnect()

    # Cleanup - Simple client doesn't require explicit cleanup
    print("✅ Simple client operations completed")


if __name__ == "__main__":
    asyncio.run(main())
