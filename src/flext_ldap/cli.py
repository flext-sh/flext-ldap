# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""Simple CLI interface for FLEXT LDAP."""

from __future__ import annotations

import asyncio
import sys

from flext_ldap.client import LDAPClient, LDAPConfig

# Constants
DEFAULT_LDAP_PORT = 389
MINIMUM_ARGS_FOR_COMMAND = 2
MINIMUM_ARGS_FOR_CONNECTION = 3
MINIMUM_ARGS_FOR_SEARCH = 4
PORT_ARG_INDEX = 3
FILTER_ARG_INDEX = 4
SEARCH_PORT_ARG_INDEX = 5
MAX_DISPLAY_ENTRIES = 10


async def test_connection(server: str, port: int) -> None:
    """Test LDAP connection."""
    config = LDAPConfig(server=server, port=port)

    try:
        async with LDAPClient(config):
            pass
    except (ConnectionError, OSError, ValueError):
        sys.exit(1)


async def search_entries(
    server: str,
    base_dn: str,
    filter_str: str = "(objectClass=*)",
    port: int = DEFAULT_LDAP_PORT,
) -> None:
    """Search LDAP entries."""
    config = LDAPConfig(server=server, port=port, base_dn=base_dn)

    try:
        async with LDAPClient(config) as client:
            result = await client.search(filter_obj=filter_str)

            if result.is_success:
                entries = result.value
                for entry in entries[:MAX_DISPLAY_ENTRIES]:  # Limit to first 10
                    for _attr, _values in entry.attributes.items():
                        pass  # First 3 values
                if len(entries) > MAX_DISPLAY_ENTRIES:
                    pass
            else:
                sys.exit(1)
    except (ConnectionError, OSError, ValueError):
        sys.exit(1)


def main() -> None:
    """Provide CLI entry point."""
    if len(sys.argv) < MINIMUM_ARGS_FOR_COMMAND:
        sys.exit(1)

    command = sys.argv[1]

    if command == "test-connection":
        if len(sys.argv) < MINIMUM_ARGS_FOR_CONNECTION:
            sys.exit(1)

        server = sys.argv[2]
        port = (
            int(sys.argv[PORT_ARG_INDEX])
            if len(sys.argv) > PORT_ARG_INDEX
            else DEFAULT_LDAP_PORT
        )
        asyncio.run(test_connection(server, port))

    elif command == "search":
        if len(sys.argv) < MINIMUM_ARGS_FOR_SEARCH:
            sys.exit(1)

        server = sys.argv[2]
        base_dn = sys.argv[3]
        filter_str = (
            sys.argv[FILTER_ARG_INDEX]
            if len(sys.argv) > FILTER_ARG_INDEX
            else "(objectClass=*)"
        )
        port = (
            int(sys.argv[SEARCH_PORT_ARG_INDEX])
            if len(sys.argv) > SEARCH_PORT_ARG_INDEX
            else DEFAULT_LDAP_PORT
        )

        asyncio.run(search_entries(server, base_dn, filter_str, port))

    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
