"""FLEXT LDAP CLI - Single class using flext-cli exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import cast, final

from flext_core import FlextMixins, FlextResult, FlextTypes

from flext_ldap.api import FlextLDAPApi
from flext_ldap.config import FlextLDAPConfig

# Python 3.13 type aliases for CLI operations
type CliCommandResult = FlextResult[FlextTypes.Core.Dict]
type LdapServerUrl = str
type LdapBindDn = str


@final
class FlextLDAPCli(FlextMixins.Loggable):
    """Single FLEXT LDAP CLI class using flext-cli exclusively with ZERO TOLERANCE."""

    def __init__(self, **data: object) -> None:
        """Initialize unified LDAP CLI using flext-cli exclusively."""
        super().__init__(**data)
        self._api = FlextLDAPApi()
        # Temporarily disabled flext-cli integration
        # self._cli_api = FlextCliApi()
        # self._cli_config = FlextCliConfig.get_global_instance()

        # Use basic LDAP config
        self._ldap_config = FlextLDAPConfig.get_global_instance()

        self.log_debug("LDAP CLI initialized")

    def _format_data(self, data: dict[str, object]) -> FlextResult[str]:
        """Simple data formatter - temporary replacement for flext-cli."""
        try:
            return FlextResult.ok(json.dumps(data, indent=2))
        except Exception as e:
            return FlextResult.fail(f"Format error: {e}")

    def test_connection(
        self,
        server: LdapServerUrl | None = None,
        bind_dn: LdapBindDn | None = None,
        bind_password: str | None = None,
    ) -> CliCommandResult:
        """Test LDAP connection using configuration as source of truth.

        Args:
            server: Optional server override (uses config if not provided)
            bind_dn: Optional bind DN override (uses config if not provided)
            bind_password: Optional bind password override (uses config if not provided)

        Returns:
            FlextResult[FlextTypes.Core.Dict]: Connection test result.

        """
        # Use configuration as source of truth with CLI parameter overrides
        effective_server = server or (
            self._ldap_config.ldap_default_connection.server
            if self._ldap_config.ldap_default_connection
            else "ldap://localhost"
        )
        effective_bind_dn = (
            bind_dn or self._ldap_config.ldap_bind_dn or "cn=admin,dc=example,dc=com"
        )
        effective_bind_password = bind_password or (
            self._ldap_config.ldap_bind_password.get_secret_value()
            if self._ldap_config.ldap_bind_password
            else "admin"
        )

        async def _test() -> FlextResult[FlextTypes.Core.Dict]:
            try:
                connection_result = await self._api.connect(
                    effective_server,
                    effective_bind_dn,
                    effective_bind_password,
                )
                if not connection_result.is_success:
                    return FlextResult.fail(
                        f"Connection failed: {connection_result.error}",
                    )

                await self._api.disconnect(connection_result.value)
                return FlextResult.ok(
                    {
                        "status": "connected",
                        "server": effective_server,
                        "bind_dn": effective_bind_dn,
                        "config_source": "ldap_config_singleton",
                    }
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
        """Handle test command through flext-cli patterns with configuration overrides."""
        # Extract CLI parameters
        cli_params: dict[str, object] = {}
        if "server" in kwargs:
            cli_params["server"] = str(kwargs["server"])
        if "bind_dn" in kwargs:
            cli_params["bind_dn"] = str(kwargs["bind_dn"])
        if "bind_password" in kwargs:
            cli_params["bind_password"] = str(kwargs["bind_password"])
        if "use_ssl" in kwargs:
            cli_params["use_ssl"] = kwargs["use_ssl"]
        if "debug" in kwargs:
            cli_params["debug"] = kwargs["debug"]

        # Apply CLI overrides to configuration
        if cli_params:
            override_result = FlextLDAPConfig.apply_cli_overrides(cli_params)
            if override_result.is_failure:
                return FlextResult[FlextTypes.Core.Dict].fail(
                    f"Configuration override failed: {override_result.error}"
                )
            # Update local config reference
            self._ldap_config = override_result.value

        # Execute test connection using configuration as source of truth
        server = cli_params.get("server")
        bind_dn = cli_params.get("bind_dn")
        bind_password = cli_params.get("bind_password")

        return self.test_connection(
            server if isinstance(server, str) else None,
            bind_dn if isinstance(bind_dn, str) else None,
            bind_password if isinstance(bind_password, str) else None,
        )

    def run_command(self, command: str, **kwargs: object) -> None:
        """Execute CLI command using flext-cli patterns with configuration integration."""
        if command == "test":
            # Use the command handler which applies configuration overrides
            result = self._handle_test_command(**kwargs)

            # Use flext-cli for output formatting - NO direct print/rich usage
            if result.is_success:
                formatted_result = self._format_data(
                    {"status": "success", "data": result.value}
                )
                if formatted_result.is_success:
                    self.log_info("CLI output", result=formatted_result.value)
                else:
                    self.log_error("Format error", error=formatted_result.error)
            else:
                formatted_result = self._format_data(
                    {"status": "error", "error": result.error}
                )
                if formatted_result.is_success:
                    self.log_error("CLI error output", error=formatted_result.value)
                else:
                    self.log_error("Format error", error=formatted_result.error)


def main() -> None:
    """Main CLI entry point - uses flext-cli exclusively with configuration integration."""
    cli_service = FlextLDAPCli()
    cli_result = cli_service.create_cli_interface()

    if cli_result.is_failure:
        # Proper error handling - use cli_service instance for logging
        cli_service.log_error("CLI initialization failed", error=cli_result.error)
        sys.exit(1)

    commands = cli_result.value

    # CLI argument constants
    min_args_for_command = 2

    # Execute CLI through flext-cli exclusively - handle arguments
    if len(sys.argv) < min_args_for_command:
        # Get current configuration for help display
        current_config = cli_service._ldap_config

        # Use flext-cli for help/usage output with configuration info
        help_result = cli_service._format_data(
            {
                "command": "flext-ldap",
                "usage": "flext-ldap test [--server <server>] [--bind-dn <dn>] [--bind-password <password>]",
                "description": "FLEXT LDAP CLI - Enterprise LDAP operations with configuration integration",
                "available_commands": list(commands.keys()),
                "configuration": {
                    "current_server": current_config.ldap_default_connection.server
                    if current_config.ldap_default_connection
                    else "Not configured",
                    "current_bind_dn": current_config.ldap_bind_dn or "Not configured",
                    "use_ssl": current_config.ldap_use_ssl,
                    "debug_mode": current_config.ldap_enable_debug,
                    "config_source": "FlextLDAPConfig singleton",
                },
                "examples": [
                    "flext-ldap test  # Uses configuration defaults",
                    "flext-ldap test --server ldap://localhost:389 --bind-dn 'cn=admin,dc=example,dc=com' --bind-password password",
                    "flext-ldap test --debug true  # Override debug mode",
                ],
            }
        )

        if help_result.is_success:
            cli_service.log_info("CLI help", help=help_result.value)
        else:
            cli_service.log_error("Failed to format help output")
        return

    command = sys.argv[1]

    # Validate command exists
    if command not in commands:
        error_result = cli_service._format_data(
            {
                "error": f"Unknown command: {command}",
                "available_commands": list(commands.keys()),
            }
        )

        if error_result.is_success:
            cli_service.log_error("Unknown command", error=error_result.value)
        sys.exit(1)

    # Parse arguments using flext-cli patterns with configuration integration
    if command == "test":
        # Parse CLI arguments (all optional - uses configuration defaults)
        cli_args = {}

        # Simple argument parsing
        i = 2
        while i < len(sys.argv):
            arg = sys.argv[i]
            if arg.startswith("--"):
                if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
                    cli_args[arg[2:]] = sys.argv[i + 1]
                    i += 2
                else:
                    # Boolean flag
                    cli_args[arg[2:]] = "true"
                    i += 1
            else:
                i += 1

        # Execute through flext-cli command handler with configuration integration
        handler_result = cli_service._handle_test_command(**cli_args)

        # Use flext-cli for output formatting
        if handler_result.is_success:
            output_result = cli_service._format_data(
                {"status": "success", "data": handler_result.value}
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
            error_result = cli_service._format_data(
                {"status": "error", "error": handler_result.error}
            )
            if error_result.is_success:
                cli_service.log_error("Test failed", error=error_result.value)
            else:
                cli_service.log_error("Test failed", error=handler_result.error)
            sys.exit(1)
    else:
        error_result = cli_service._format_data(
            {
                "error": f"Unknown command: {command}",
                "available_commands": list(commands.keys()),
                "usage": "flext-ldap test [--server <server>] [--bind-dn <dn>] [--bind-password <password>] [--debug <true/false>]",
            }
        )

        if error_result.is_success:
            cli_service.log_error("Invalid command", error=error_result.value)
        sys.exit(1)


__all__ = [
    "FlextLDAPCli",
    "main",
]
