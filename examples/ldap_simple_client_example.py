#!/usr/bin/env python3
"""Example usage of FlextLdapClient.

This example demonstrates how to use the minimal LDAP infrastructure client
following Clean Architecture principles.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import os

from flext_ldap import FlextLdapClient, FlextLdapSearchRequest


async def main() -> None:
    """Demonstrate LDAP client usage."""
    # Create client instance
    client = FlextLdapClient()

    # Example 1: Single server connection
    server_uri = os.getenv("LDAP_TEST_SERVER", "ldap://localhost:389")
    bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
    bind_password = os.getenv("LDAP_TEST_PASSWORD", "")

    result = await client.connect(
        uri=server_uri,
        bind_dn=bind_dn,
        password=bind_password,
    )
    if result.is_success:

        # Example search using FlextLdapSearchRequest
        search_request = FlextLdapSearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            attributes=["cn", "mail"],
            scope="subtree",
            size_limit=1000,
            time_limit=30,
        )
        search_result = await client.search(request=search_request)

        if search_result.is_success:
            # Use proper type for FlextResult unwrapping
            from flext_ldap.entities import FlextLdapSearchResponse

            empty_response = FlextLdapSearchResponse(entries=[], total_count=0)
            response = search_result.unwrap_or(empty_response)
            for entry in response.entries[:3]:  # Show first 3
                dn_value = entry.get("dn", "N/A")
                (
                    dn_value.decode() if isinstance(dn_value, bytes) else str(dn_value)
                )

        # Note: No disconnect method - connection managed automatically

    # Example 2: LDAP operations
    op_result = await client.connect(
        uri=server_uri,
        bind_dn=bind_dn,
        password=bind_password,
    )
    if op_result.is_success:

        # Add entry
        add_result = await client.add(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "objectClass": ["top", "person", "organizationalPerson"],
                "cn": ["testuser"],
                "sn": ["Test"],
                "mail": ["test@example.com"],
            },
        )

        if add_result.is_success:

            # Modify entry
            modify_result = await client.modify(
                dn="cn=testuser,dc=example,dc=com",
                attributes={"mail": ["updated@example.com"]},
            )

            if modify_result.is_success:

                # Delete entry
                delete_result = await client.delete(dn="cn=testuser,dc=example,dc=com")

                if delete_result.is_success:
                    pass


if __name__ == "__main__":
    asyncio.run(main())
