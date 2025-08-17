#!/usr/bin/env python3
"""Example usage of FlextLdapClient.

This example demonstrates how to use the minimal LDAP infrastructure client
following Clean Architecture principles.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio

from flext_ldap import FlextLdapClient


async def main() -> None:
    """Demonstrate LDAP client usage."""    # Create client instance
    client = FlextLdapClient()

    # Example 1: Single server connection
    import os  # noqa: PLC0415

    result = await client.connect(
      server_uri=os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389"),
      bind_dn="cn=admin,dc=example,dc=com",
      bind_password=os.getenv("LDAP_TEST_PASSWORD", ""),
    )
    if result.success:
      print("✅ Connected successfully")

      # Example search
      search_result = await client.search(
          base_dn="dc=example,dc=com",
          search_filter="(objectClass=person)",
          attributes=["cn", "mail"],
      )

      if search_result.success:
          for _entry in search_result.data[:3]:  # Show first 3
              pass

      # Disconnect
      await client.disconnect()

    # Example 2: Connection pool - Simplified for demo
    # Note: Pool functionality integrated in FlextLdapClient
    print("✅ Pool functionality integrated in client")

    # Example 3: LDAP operations
    op_result = await client.connect(
      server_uri=os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389"),
      bind_dn="cn=admin,dc=example,dc=com",
      bind_password=os.getenv("LDAP_TEST_PASSWORD", ""),
    )
    if op_result.success:
      print("✅ Connected for operations")

      # Add entry
      add_result = await client.add_entry(
          dn="cn=testuser,dc=example,dc=com",
          attributes={
              "objectClass": ["top", "person", "organizationalPerson"],
              "cn": ["testuser"],
              "sn": ["Test"],
              "mail": ["test@example.com"],
          },
      )

      if add_result.success:
          # Modify entry
          modify_result = await client.modify_entry(
              dn="cn=testuser,dc=example,dc=com",
              modifications={"mail": ["updated@example.com"]},
          )

          if modify_result.success:
              # Delete entry
              delete_result = await client.delete_entry("cn=testuser,dc=example,dc=com")

              if delete_result.success:
                  print("✅ Entry lifecycle completed")

      # Disconnect
      await client.disconnect()

    # Cleanup - Simple client doesn't require explicit cleanup
    print("✅ Simple client operations completed")


if __name__ == "__main__":
    asyncio.run(main())
