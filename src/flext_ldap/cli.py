"""FLEXT LDAP CLI - Single class using flext-cli exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import sys

from flext_cli import (
    FlextCliApi,
    FlextCliConfig,
    FlextCliMain,
)
from flext_core import FlextLogger, FlextResult, FlextTypes

from flext_ldap.api import FlextLDAPApi

logger = FlextLogger(__name__)


class FlextLDAPCli:
    """Single FLEXT LDAP CLI class using flext-cli exclusively."""

    def __init__(self) -> None:
        """Initialize unified LDAP CLI using flext-cli exclusively."""
        self._api = FlextLDAPApi()
        self._cli_api = FlextCliApi()
        self._config = FlextCliConfig()

    def test_connection(
        self,
        server: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[FlextTypes.Core.Dict]:
        """Test LDAP connection.

        Args:
            server: The server to connect to.
            bind_dn: The bind DN to use.
            bind_password: The bind password to use.

        Returns:
            FlextResult[FlextTypes.Core.Dict]: Connection test result.

        """

        async def _test() -> FlextResult[FlextTypes.Core.Dict]:
            try:
                connection_result = await self._api.connect(
                    server,
                    bind_dn,
                    bind_password,
                )
                if not connection_result.is_success:
                    return FlextResult.fail(
                        f"Connection failed: {connection_result.error}",
                    )

                await self._api.disconnect(connection_result.value)
                return FlextResult.ok(
                    {"status": "connected", "server": server, "bind_dn": bind_dn},
                )
            except Exception as e:
                logger.exception("LDAP connection test failed")
                return FlextResult.fail(f"Connection error: {e}")

        return asyncio.run(_test())

    def create_cli_interface(self) -> FlextResult[FlextCliMain]:
        """Create CLI interface using flext-cli patterns.

        If flext-cli lacks functionality, IMPROVE flext-cli first.
        NEVER work around flext-cli limitations with direct Click usage.
        """
        main_cli = FlextCliMain()

        # Register commands through flext-cli using available methods
        try:
            main_cli.register_commands()
            return FlextResult[FlextCliMain].ok(main_cli)
        except Exception as e:
            return FlextResult[FlextCliMain].fail(f"Command registration failed: {e}")


    def run_command(self, command: str, **kwargs: object) -> None:
        """Execute CLI command using flext-cli patterns."""
        if command == "test":
            result = self.test_connection(
                str(kwargs["server"]),
                str(kwargs["bind_dn"]),
                str(kwargs["bind_password"]),
            )

            # Use flext-cli for output formatting - NO direct print/rich usage
            if result.is_success:
                formatted_result = self._cli_api.format_data({"status": "success", "data": result.value}, "json")
                if formatted_result.is_success:
                    logger.info(formatted_result.value)
                else:
                    logger.error(f"Format error: {formatted_result.error}")
            else:
                formatted_result = self._cli_api.format_data({"status": "error", "error": result.error}, "json")
                if formatted_result.is_success:
                    logger.error(formatted_result.value)
                else:
                    logger.error(f"Format error: {formatted_result.error}")


def main() -> None:
    """Main CLI entry point - uses flext-cli exclusively."""
    cli_service = FlextLDAPCli()
    cli_result = cli_service.create_cli_interface()

    if cli_result.is_failure:
        # Proper error handling - no silent failures using logger
        logger.error(f"CLI initialization failed: {cli_result.error}")
        sys.exit(1)

    # CLI argument constants
    min_args_for_command = 2
    min_args_for_test_cmd = 8

    # Execute CLI through flext-cli exclusively - handle arguments
    if len(sys.argv) < min_args_for_command:
        # Use flext-cli for help/usage output
        help_result = cli_service._cli_api.format_data({
            "command": "flext-ldap",
            "usage": "flext-ldap test --server <server> --bind-dn <dn> --bind-password <password>",
            "description": "FLEXT LDAP CLI - Enterprise LDAP operations",
            "examples": [
                "flext-ldap test --server ldap://localhost:389 --bind-dn 'cn=admin,dc=example,dc=com' --bind-password password"
            ]
        }, "json")

        if help_result.is_success:
            logger.info(help_result.value)
        else:
            logger.error("Failed to format help output")
        return

    command = sys.argv[1]

    # Parse arguments using flext-cli patterns (simplified for demonstration)
    if command == "test" and len(sys.argv) >= min_args_for_test_cmd:
        # Extract arguments
        try:
            server_idx = sys.argv.index("--server") + 1
            bind_dn_idx = sys.argv.index("--bind-dn") + 1
            bind_password_idx = sys.argv.index("--bind-password") + 1

            cli_service.run_command(
                "test",
                server=sys.argv[server_idx],
                bind_dn=sys.argv[bind_dn_idx],
                bind_password=sys.argv[bind_password_idx]
            )
        except (ValueError, IndexError):
            error_result = cli_service._cli_api.format_data({
                "error": "Invalid arguments for test command",
                "usage": "flext-ldap test --server <server> --bind-dn <dn> --bind-password <password>"
            }, "json")

            if error_result.is_success:
                logger.exception(error_result.value)
            sys.exit(1)
    else:
        error_result = cli_service._cli_api.format_data({
            "error": f"Unknown command: {command}",
            "available_commands": ["test"]
        }, "json")

        if error_result.is_success:
            logger.error(error_result.value)
        sys.exit(1)


__all__ = [
    "FlextLDAPCli",
    "main",
]
