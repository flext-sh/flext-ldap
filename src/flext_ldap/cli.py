"""FLEXT LDAP CLI - Single class using flext-cli exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import sys
from typing import cast, final

from flext_cli import (
    FlextCliApi,
    FlextCliConfig,
)
from flext_core import FlextMixins, FlextResult, FlextTypes

from flext_ldap.api import FlextLDAPApi

# Python 3.13 type aliases for CLI operations
type CliCommandResult = FlextResult[FlextTypes.Core.Dict]
type LdapServerUrl = str
type LdapBindDn = str


@final
class FlextLDAPCli(FlextMixins.Service):
    """Single FLEXT LDAP CLI class using flext-cli exclusively with ZERO TOLERANCE."""

    def __init__(self, **data: object) -> None:
        """Initialize unified LDAP CLI using flext-cli exclusively."""
        super().__init__(**data)
        self._api = FlextLDAPApi()
        self._cli_api = FlextCliApi()
        self._config = FlextCliConfig()
        self.log_debug("LDAP CLI initialized with flext-cli exclusively")

    def test_connection(
        self,
        server: LdapServerUrl,
        bind_dn: LdapBindDn,
        bind_password: str,
    ) -> CliCommandResult:
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
                self.log_error("LDAP connection test failed", error=str(e))
                return FlextResult.fail(f"Connection error: {e}")

        return asyncio.run(_test())

    def create_cli_interface(self) -> FlextResult[dict[str, object]]:
        """Create CLI interface using flext-cli patterns.

        If flext-cli lacks functionality, IMPROVE flext-cli first.
        NEVER work around flext-cli limitations with direct Click usage.

        Returns:
            FlextResult containing CLI command registry

        """
        # Register commands through flext-cli API
        try:
            # Mock command structure for compatibility
            commands = {
                "test": {
                    "name": "test",
                    "description": "Test LDAP connection",
                    "handler": self._handle_test_command,
                }
            }

            # Cast to dict[str, object] for type compatibility
            typed_commands = cast("dict[str, object]", commands)
            return FlextResult[dict[str, object]].ok(typed_commands)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Command registration failed: {e}"
            )

    def _handle_test_command(self, **kwargs: object) -> CliCommandResult:
        """Handle test command through flext-cli patterns."""
        server = kwargs.get("server", "")
        bind_dn = kwargs.get("bind_dn", "")
        bind_password = kwargs.get("bind_password", "")

        if not all([server, bind_dn, bind_password]):
            return FlextResult[FlextTypes.Core.Dict].fail(
                "Missing required parameters: server, bind_dn, bind_password"
            )

        # Execute test connection
        return self.test_connection(str(server), str(bind_dn), str(bind_password))

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
                formatted_result = self._cli_api.format_data(
                    {"status": "success", "data": result.value}, "json"
                )
                if formatted_result.is_success:
                    self.log_info("CLI output", result=formatted_result.value)
                else:
                    self.log_error("Format error", error=formatted_result.error)
            else:
                formatted_result = self._cli_api.format_data(
                    {"status": "error", "error": result.error}, "json"
                )
                if formatted_result.is_success:
                    self.log_error("CLI error output", error=formatted_result.value)
                else:
                    self.log_error("Format error", error=formatted_result.error)


def main() -> None:
    """Main CLI entry point - uses flext-cli exclusively."""
    cli_service = FlextLDAPCli()
    cli_result = cli_service.create_cli_interface()

    if cli_result.is_failure:
        # Proper error handling - use cli_service instance for logging
        cli_service.log_error("CLI initialization failed", error=cli_result.error)
        sys.exit(1)

    commands = cli_result.value

    # CLI argument constants
    min_args_for_command = 2
    min_args_for_test_cmd = 8

    # Execute CLI through flext-cli exclusively - handle arguments
    if len(sys.argv) < min_args_for_command:
        # Use flext-cli for help/usage output
        help_result = cli_service._cli_api.format_data(
            {
                "command": "flext-ldap",
                "usage": "flext-ldap test --server <server> --bind-dn <dn> --bind-password <password>",
                "description": "FLEXT LDAP CLI - Enterprise LDAP operations",
                "available_commands": list(commands.keys()),
                "examples": [
                    "flext-ldap test --server ldap://localhost:389 --bind-dn 'cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com' --bind-password password"
                ],
            },
            "json",
        )

        if help_result.is_success:
            cli_service.log_info("CLI help", help=help_result.value)
        else:
            cli_service.log_error("Failed to format help output")
        return

    command = sys.argv[1]

    # Validate command exists
    if command not in commands:
        error_result = cli_service._cli_api.format_data(
            {
                "error": f"Unknown command: {command}",
                "available_commands": list(commands.keys()),
            },
            "json",
        )

        if error_result.is_success:
            cli_service.log_error("Unknown command", error=error_result.value)
        sys.exit(1)

    # Parse arguments using flext-cli patterns (simplified for demonstration)
    if command == "test" and len(sys.argv) >= min_args_for_test_cmd:
        # Extract arguments
        try:
            server_idx = sys.argv.index("--server") + 1
            bind_dn_idx = sys.argv.index("--bind-dn") + 1
            bind_password_idx = sys.argv.index("--bind-password") + 1

            # Execute through flext-cli command handler
            handler_result = cli_service._handle_test_command(
                server=sys.argv[server_idx],
                bind_dn=sys.argv[bind_dn_idx],
                bind_password=sys.argv[bind_password_idx],
            )

            # Use flext-cli for output formatting
            if handler_result.is_success:
                output_result = cli_service._cli_api.format_data(
                    {"status": "success", "data": handler_result.value}, "json"
                )
                if output_result.is_success:
                    cli_service.log_info(
                        "Test completed successfully", result=output_result.value
                    )
                else:
                    cli_service.log_error(
                        "Output formatting failed", error=output_result.error
                    )
            else:
                error_result = cli_service._cli_api.format_data(
                    {"status": "error", "error": handler_result.error}, "json"
                )
                if error_result.is_success:
                    cli_service.log_error("Test failed", error=error_result.value)
                else:
                    cli_service.log_error("Test failed", error=handler_result.error)
                sys.exit(1)

        except (ValueError, IndexError):
            error_result = cli_service._cli_api.format_data(
                {
                    "error": "Invalid arguments for test command",
                    "usage": "flext-ldap test --server <server> --bind-dn <dn> --bind-password <password>",
                },
                "json",
            )

            if error_result.is_success:
                cli_service.log_error(
                    "Command execution error", error=error_result.value
                )
            sys.exit(1)
    else:
        error_result = cli_service._cli_api.format_data(
            {
                "error": f"Invalid arguments for command: {command}",
                "usage": "flext-ldap test --server <server> --bind-dn <dn> --bind-password <password>",
            },
            "json",
        )

        if error_result.is_success:
            cli_service.log_error("Invalid command usage", error=error_result.value)
        sys.exit(1)


__all__ = [
    "FlextLDAPCli",
    "main",
]
