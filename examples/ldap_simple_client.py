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

from flext_core import FlextConstants, FlextResult
from flext_ldap import (
    FlextLdapClient,
    FlextLdapConstants,
    FlextLdapModels,
    FlextLdapTypes,
)


async def main() -> None:
    """Demonstrate LDAP client usage."""
    # Create client instance
    client = FlextLdapClient()

    # Example 1: Single server connection
    server_uri = os.getenv(
        "LDAP_TEST_SERVER",
        f"ldap://{FlextConstants.Platform.DEFAULT_HOST}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
    )
    bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
    bind_password = os.getenv("LDAP_TEST_PASSWORD", "")

    result: FlextResult[bool] = await client.connect(
        server_uri=server_uri,
        bind_dn=bind_dn,
        password=bind_password,
    )
    if result.is_success:
        # Example search using FlextLdapModels.SearchRequest
        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            attributes=["cn", "mail"],
            scope="subtree",
            size_limit=1000,
            time_limit=30,
            page_size=0,
            paged_cookie=None,
        )
        search_result = await client.search_with_request(search_request)

        if search_result.is_success:
            # Use proper type for FlextResult unwrapping
            empty_response = FlextLdapModels.SearchResponse(
                entries=[],
                total_count=0,
                result_code=0,
                result_description="",
                matched_dn="",
                next_cookie=None,
                entries_returned=0,
                time_elapsed=0.0,
            )
            response = search_result.unwrap_or(empty_response)
            for entry in response.entries[:3]:  # Show first 3
                dn_value = entry.get("dn", "N/A")
                (dn_value.decode() if isinstance(dn_value, bytes) else str(dn_value))

        # Note: No disconnect method - connection managed automatically

    # Example 2: LDAP operations
    op_result: FlextResult[bool] = await client.connect(
        server_uri=server_uri,
        bind_dn=bind_dn,
        password=bind_password,
    )
    if op_result.is_success:
        # Add entry
        add_result: FlextResult[None] = await client.add(
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
            modify_result: FlextResult[None] = await client.modify(
                dn="cn=testuser,dc=example,dc=com",
                changes={
                    "mail": [(FlextLdapTypes.MODIFY_REPLACE, ["updated@example.com"])]
                },
            )

            if modify_result.is_success:
                # Delete entry
                delete_result: FlextResult[None] = client.delete(
                    dn="cn=testuser,dc=example,dc=com"
                )

                if delete_result.is_success:
                    pass


if __name__ == "__main__":
    asyncio.run(main())
