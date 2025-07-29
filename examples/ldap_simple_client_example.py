#!/usr/bin/env python3
"""Example usage of FlextLdapSimpleClient.

This example demonstrates how to use the minimal LDAP infrastructure client
following Clean Architecture principles.
"""

import asyncio

from flext_ldap.infrastructure.ldap_simple_client import (
    FlextLdapSimpleClient,
    LdapConnectionConfig,
    LdapPoolConfig,
)


async def main() -> None:
    """Demonstrate LDAP client usage."""
    # Create client instance
    client = FlextLdapSimpleClient()

    # Example 1: Single server connection
    single_config = LdapConnectionConfig(
        server_url="ldap://localhost:389",
        bind_dn="cn=admin,dc=example,dc=com",
        password="admin",
        use_ssl=False,
        connection_timeout=10,
    )

    result = await client.connect(single_config)
    if result.is_success:
        connection_id = result.data

        # Example search
        search_result = await client.search(
            connection_id=connection_id,
            search_base="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "mail"],
        )

        if search_result.is_success:
            for _entry in search_result.data[:3]:  # Show first 3
                pass

        # Disconnect
        await client.disconnect(connection_id)

    # Example 2: Connection pool
    pool_config = LdapPoolConfig(
        server_urls=["ldap://server1:389", "ldap://server2:389"],
        bind_dn="cn=admin,dc=example,dc=com",
        password="admin",
        use_ssl=False,
        connection_timeout=10,
    )

    pool_result = await client.connect_with_pool(pool_config)
    if pool_result.is_success:
        pool_id = pool_result.data

        # Check connection status
        client.is_connected(pool_id)

        # Disconnect
        await client.disconnect(pool_id)

    # Example 3: LDAP operations
    test_config = LdapConnectionConfig(
        server_url="ldap://localhost:389",
        bind_dn="cn=admin,dc=example,dc=com",
        password="admin",
        use_ssl=False,
    )

    op_result = await client.connect(test_config)
    if op_result.is_success:
        connection_id = op_result.data

        # Add entry
        add_result = await client.add(
            connection_id=connection_id,
            dn="cn=testuser,dc=example,dc=com",
            object_class=["top", "person", "organizationalPerson"],
            attributes={
                "cn": "testuser",
                "sn": "Test",
                "mail": "test@example.com",
            },
        )

        if add_result.is_success:
            # Modify entry
            modify_result = await client.modify(
                connection_id=connection_id,
                dn="cn=testuser,dc=example,dc=com",
                changes={"mail": "updated@example.com"},
            )

            if modify_result.is_success:
                # Delete entry
                delete_result = await client.delete(
                    connection_id=connection_id,
                    dn="cn=testuser,dc=example,dc=com",
                )

                if delete_result.is_success:
                    pass

        # Disconnect
        await client.disconnect(connection_id)

    # Cleanup
    await client.close_all()


if __name__ == "__main__":
    asyncio.run(main())
