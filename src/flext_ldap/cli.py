# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""Simple CLI interface for FLEXT LDAP."""

from __future__ import annotations

import asyncio
import sys

from flext_ldap.client import FlextLdapClient
from flext_ldap.config import FlextLdapConnectionConfig

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
    """Test LDAP connection to server."""
    config = FlextLdapConnectionConfig(server=server, port=port)
    try:
        async with FlextLdapClient(config):
            pass
    except (OSError, ValueError):
        sys.exit(1)


async def search_entries(
    server: str,
    base_dn: str,
    filter_str: str = "(objectClass=*)",
    port: int = DEFAULT_LDAP_PORT,
) -> None:
    """Search LDAP entries."""
    config = FlextLdapConnectionConfig(server=server, port=port)
    try:
        async with FlextLdapClient(config) as client:
            result = await client.search(
                "",
                filter_str,
            )  # Need base_dn as first parameter

            if result.is_success:
                entries = result.data or []

                for _i, entry in enumerate(entries[:MAX_DISPLAY_ENTRIES]):
                    for attr_values in entry.attributes.values():
                        # Show first 3 values for each attribute
                        values_display = attr_values[:3]
                        if len(attr_values) > 3:
                            values_display.append("...")

                if len(entries) > MAX_DISPLAY_ENTRIES:
                    pass
            else:
                sys.exit(1)

    except (OSError, ValueError):
        sys.exit(1)


def handle_command(args: list[str]) -> None:
    """Handle CLI commands."""
    if len(args) < MINIMUM_ARGS_FOR_COMMAND:
        sys.exit(1)

    command = args[1]

    if command == "test":
        if len(args) < MINIMUM_ARGS_FOR_CONNECTION:
            sys.exit(1)

        server = args[2]
        port = (
            int(args[PORT_ARG_INDEX])
            if len(args) > PORT_ARG_INDEX
            else DEFAULT_LDAP_PORT
        )
        asyncio.run(test_connection(server, port))

    elif command == "search":
        if len(args) < MINIMUM_ARGS_FOR_SEARCH:
            sys.exit(1)

        server = args[2]
        base_dn = args[3]
        filter_str = (
            args[FILTER_ARG_INDEX]
            if len(args) > FILTER_ARG_INDEX
            else "(objectClass=*)"
        )
        port = (
            int(args[SEARCH_PORT_ARG_INDEX])
            if len(args) > SEARCH_PORT_ARG_INDEX
            else DEFAULT_LDAP_PORT
        )

        asyncio.run(search_entries(server, base_dn, filter_str, port))

    else:
        sys.exit(1)


def main() -> None:
    """Handle main CLI entry point."""
    handle_command(sys.argv)


if __name__ == "__main__":
    main()
