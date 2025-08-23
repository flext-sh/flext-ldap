"""FLEXT LDAP CLI - Built with flext-cli integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import time
from typing import cast, override

import click
from flext_cli import (
    FlextCliCommandService,
    FlextCliExecutionContext,
    FlextCliFormatterService,
    FormatterFactory,
    create_cli_container,
    get_cli_config,
)
from flext_core import (
    FlextContainer,
    FlextResult,
    FlextTypes,
    get_flext_container,
    get_logger,
)
from rich.console import Console
from rich.table import Table

from flext_ldap.api import get_ldap_api
from flext_ldap.entities import FlextLdapEntry

logger = get_logger(__name__)


# =============================================================================
# CLI SERVICES - Using flext-cli patterns
# =============================================================================


class FlextLdapCliCommandService(FlextCliCommandService[object]):
    """Command service for FLEXT LDAP CLI operations.

    Extends FlextCliCommandService to provide LDAP-specific
    command execution capabilities.
    """

    def __init__(self) -> None:
        """Initialize LDAP CLI command service."""
        super().__init__(service_name="flext-ldap-cli")
        self._api = get_ldap_api()
        self._config = get_cli_config()

    # Decorators removed due to type incompatibilities - functionality implemented inline
    @override
    def execute_command(
        self,
        command: str,
        args: dict[str, object] | None = None,
        **kwargs: object,
    ) -> FlextResult[object]:
        """Execute LDAP command with given arguments - sync wrapper for async operations.

        Args:
            command: Command name to execute
            args: Command arguments dictionary
            **kwargs: Additional execution parameters

        Returns:
            Result of command execution

        """
        # Inline implementation of timing and retry logic for type safety
        start_time = time.time()
        max_attempts = 2

        logger.info(f"Executing command: {command}")

        if not args:
            args = {}

        for attempt in range(max_attempts):
            try:
                if command == "test":
                    return asyncio.run(self._execute_test_command(args))
                if command == "search":
                    return asyncio.run(self._execute_search_command(args))
                if command == "user_info":
                    return asyncio.run(self._execute_user_info_command(args))
                return FlextResult[object].fail(
                    f"Unknown command: {command}",
                )
            except Exception as e:
                if attempt == max_attempts - 1:  # Last attempt
                    elapsed = time.time() - start_time
                    logger.exception(f"Command {command} failed after {elapsed:.3f}s")
                    return FlextResult[object].fail(str(e))
                # Retry on next attempt
                logger.warning(
                    f"Command {command} attempt {attempt + 1} failed, retrying: {e}"
                )
                time.sleep(0.1)  # Brief delay before retry
                continue

        # Should never reach here due to max_attempts logic
        return FlextResult[object].fail("Unexpected execution path")

    # Spinner functionality implemented inline for type safety
    async def _execute_test_command(
        self,
        args: dict[str, object],
    ) -> FlextResult[object]:
        """Execute LDAP test command."""
        logger.info("Testing LDAP connection...")

        server = str(args.get("server", ""))
        port_value = args.get("port", 389)
        port = int(port_value) if isinstance(port_value, (int, str)) else 389
        use_ssl = bool(args.get("use_ssl"))
        bind_dn = args.get("bind_dn")
        bind_password = args.get("bind_password")

        server_uri = f"{'ldaps' if use_ssl else 'ldap'}://{server}:{port}"
        bind_dn_str = str(bind_dn) if bind_dn else ""
        bind_password_str = str(bind_password) if bind_password else ""

        try:
            async with self._api.connection(
                server_uri, bind_dn_str, bind_password_str
            ) as session:
                if session:
                    return FlextResult[object].ok(
                        {
                            "status": "success",
                            "message": f"Successfully connected to {server}:{port}",
                        }
                    )
                return FlextResult[object].fail(
                    "Connection failed",
                )
        except Exception as e:
            return FlextResult[object].fail(f"Connection error: {e}")

    # Spinner functionality implemented inline for type safety
    async def _execute_search_command(
        self,
        args: dict[str, object],
    ) -> FlextResult[object]:
        """Execute LDAP search command."""
        logger.info("Searching LDAP directory...")

        server = str(args.get("server", ""))
        port_value = args.get("port", 389)
        port = int(port_value) if isinstance(port_value, (int, str)) else 389
        use_ssl = bool(args.get("use_ssl"))
        base_dn = str(args.get("base_dn", ""))
        filter_str = str(args.get("filter_str", "(objectClass=*)"))
        limit_value = args.get("limit", 10)
        limit = int(limit_value) if isinstance(limit_value, (int, str)) else 10
        bind_dn = args.get("bind_dn")
        bind_password = args.get("bind_password")

        server_uri = f"{'ldaps' if use_ssl else 'ldap'}://{server}:{port}"
        bind_dn_str = str(bind_dn) if bind_dn else ""
        bind_password_str = str(bind_password) if bind_password else ""

        try:
            async with self._api.connection(
                server_uri, bind_dn_str, bind_password_str
            ) as connection:
                if connection:
                    result = await self._api.search(
                        base_dn=base_dn,
                        search_filter=filter_str,
                        attributes=None,
                        scope="subtree",
                        size_limit=limit,
                        time_limit=30,
                    )
                    if result.is_success:
                        entries: list[FlextLdapEntry] = result.value or []
                        # Convert entries to dict format for display
                        entry_dicts: list[dict[str, object]] = [
                            entry.to_dict() for entry in entries
                        ]

                        return FlextResult[object].ok(
                            {
                                "status": "success",
                                "entries": entry_dicts,
                                "count": len(entry_dicts),
                            }
                        )
                    return FlextResult[object].fail(
                        result.error or "Search failed",
                    )
                return FlextResult[object].fail(
                    "Connection failed",
                )
        except Exception as e:
            return FlextResult[object].fail(f"Search error: {e}")

    # Spinner functionality implemented inline for type safety
    async def _execute_user_info_command(
        self,
        args: dict[str, object],
    ) -> FlextResult[object]:
        """Execute user info command."""
        logger.info("Looking up user information...")

        uid = str(args.get("uid", ""))
        server = str(args.get("server", "localhost"))

        server_uri = f"ldap://{server}:389"
        bind_dn_str = ""
        bind_password_str = ""  # nosec B105 - empty string default

        try:
            async with self._api.connection(
                server_uri, bind_dn_str, bind_password_str
            ) as connection:
                if connection:
                    result = await self._api.search(
                        base_dn="dc=example,dc=com",
                        search_filter=f"(uid={uid})",
                        attributes=["uid", "cn", "sn", "mail", "dn"],
                        scope="subtree",
                        size_limit=1,
                        time_limit=30,
                    )
                    if result.is_success:
                        entries = result.value
                        if entries and isinstance(entries, list) and entries:
                            entry = entries[0]
                            user_dict = (
                                entry.to_dict()
                                if hasattr(entry, "to_dict")
                                else {"dn": str(entry)}
                            )
                            return FlextResult[object].ok(
                                {
                                    "status": "success",
                                    "user": user_dict,
                                }
                            )
                        return FlextResult[object].fail(
                            f"User {uid} not found",
                        )
                    return FlextResult[object].fail(
                        "User search failed",
                    )
                return FlextResult[object].fail(
                    "Connection failed",
                )
        except Exception as e:
            return FlextResult[object].fail(f"User lookup error: {e}")


class FlextLdapCliFormatterService(FlextCliFormatterService):
    """Formatter service for FLEXT LDAP CLI output.

    Extends FlextCliFormatterService to provide LDAP-specific
    output formatting capabilities.
    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize LDAP CLI formatter service."""
        if container is None:
            container = get_flext_container()
            # Try to get CLI container, fallback to core container
            try:
                cli_container = create_cli_container()
                if isinstance(cli_container, FlextContainer):
                    container = cli_container
            except Exception as e:
                # Silent fallback to core container - CLI container unavailable
                logger.debug(f"CLI container fallback: {e}")
        super().__init__(
            service_name="flext_ldap_cli_formatter",
            container=container,
        )
        self._config = get_cli_config()

    # Decorator removed due to type incompatibilities - functionality implemented inline
    @override
    def format_output(
        self,
        data: object,
        format_type: str | None = None,
        **_options: object,
    ) -> FlextResult[str]:
        """Format LDAP data for output.

        Args:
            data: Data to format
            format_type: Output format type
            **options: Format-specific options

        Returns:
            Formatted output string

        """
        # Inline safe execution for type safety
        if self.logger:
            self.logger.info(
                f"Formatting output as {format_type or self.default_format}"
            )

        if not format_type:
            format_type = self.default_format

        validation_result = self.validate_format(format_type)
        if validation_result.is_failure:
            return FlextResult[str].fail(
                validation_result.error or "Invalid format",
            )

        try:
            console = Console()
            formatter = FormatterFactory.create(format_type)

            # Format the data
            formatter.format(data, console)

            if self.logger:
                self.logger.info("Data formatted successfully")

            return FlextResult[str].ok("Data formatted successfully")
        except Exception as e:
            error_msg = f"Formatting failed: {e}"
            if self.logger:
                self.logger.exception(error_msg)
            return FlextResult[str].fail(error_msg)

    @override
    def execute(self) -> FlextResult[str]:
        """Execute the service operation.

        Implements abstract method from FlextDomainService.
        Default implementation returns empty string - use format_output for specific operations.
        """
        return FlextResult[str].ok("")


# =============================================================================
# GLOBAL CLI SERVICES - Singleton pattern
# =============================================================================


# Global service instances
_command_service: FlextLdapCliCommandService | None = None
_formatter_service: FlextLdapCliFormatterService | None = None


def get_command_service() -> FlextLdapCliCommandService:
    """Get or create the global command service."""
    global _command_service  # noqa: PLW0603
    if _command_service is None:
        _command_service = FlextLdapCliCommandService()
    return _command_service


def get_formatter_service() -> FlextLdapCliFormatterService:
    """Get or create the global formatter service."""
    global _formatter_service  # noqa: PLW0603
    if _formatter_service is None:
        _formatter_service = FlextLdapCliFormatterService()
    return _formatter_service


# =============================================================================
# CLI COMMAND IMPLEMENTATIONS - Using flext-cli decorators
# =============================================================================


# Helper functions for CLI display


def _display_test_result(result_data: FlextTypes.Core.Dict) -> None:
    """Display test command result."""
    console = Console()
    if result_data.get("status") == "success":
        console.print(
            f"[green]✓ {result_data.get('message', 'Success')}[/green]",
        )
    else:
        console.print(
            f"[red]✗ {result_data.get('message', 'Failed')}[/red]",
        )


def _display_search_results(result_data: FlextTypes.Core.Dict) -> None:
    """Display search command results."""
    console = Console()
    entries: list[dict[str, object]] = cast(
        "list[dict[str, object]]", result_data.get("entries", [])
    )
    count = result_data.get("count", 0)

    console.print(f"[green]Found {count} entries[/green]")

    for i, entry in enumerate(entries, 1):
        _display_single_entry(i, entry)


def _display_single_entry(entry_number: int, entry: dict[str, object]) -> None:
    """Display a single LDAP entry."""
    console = Console()
    console.print(f"\n[bold cyan]Entry {entry_number}:[/bold cyan]")

    dn = entry.get("dn", "Unknown DN")
    console.print(f"[yellow]DN:[/yellow] {dn}")

    attributes = entry.get("attributes", {})
    if attributes and isinstance(attributes, dict):
        _display_entry_attributes(cast("dict[str, object]", attributes))


def _display_entry_attributes(attributes: dict[str, object]) -> None:
    """Display LDAP entry attributes."""
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Attribute", style="cyan")
    table.add_column("Values", style="white")

    for attr_name, attr_values in attributes.items():
        if isinstance(attr_values, list):
            attr_list = cast("list[object]", attr_values)
            formatted_values = "\n".join(str(v) for v in attr_list[:3])
            max_display = 3
            if len(attr_list) > max_display:
                remaining = len(attr_list) - max_display
                formatted_values += f"\n... and {remaining} more"
        else:
            formatted_values = str(attr_values)

        table.add_row(str(attr_name), formatted_values)

    console.print(table)


def _display_user_info(result_data: FlextTypes.Core.Dict) -> None:
    """Display user info command result."""
    console = Console()
    user = result_data.get("user")

    if user and isinstance(user, dict):
        user_dict = cast("FlextTypes.Core.Dict", user)
        console.print("[green]User found[/green]")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        for key in ["uid", "cn", "sn", "mail", "dn"]:
            value = user_dict.get(key, "N/A")
            if value and value != "N/A":
                table.add_row(key.upper(), str(value))

        console.print(table)
    else:
        console.print("[yellow]User not found[/yellow]")


# =============================================================================
# CLI OPTIONS - Using flext-cli patterns
# =============================================================================


# LDAP connection options will be applied directly to commands
# to avoid complex TypeVar issues with Click decorators


# =============================================================================
# CLICK CLI - Using flext-cli integration
# =============================================================================


@click.group(
    name="flext-ldap",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(version="0.9.0", prog_name="FLEXT LDAP")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["table", "json", "yaml", "csv", "plain"]),
    default="table",
    help="Output format",
)
@click.option(
    "--debug/--no-debug",
    default=False,
    envvar="FLEXT_DEBUG",
    help="Enable debug mode",
)
@click.pass_context
def cli(
    ctx: click.Context,
    output: str,
    *,
    debug: bool,
) -> None:
    """FLEXT LDAP - Modern Enterprise LDAP Operations.

    Built with flext-cli integration and Clean Architecture patterns.
    """
    # Setup CLI context using flext-cli patterns
    ctx.ensure_object(dict)
    ctx.obj["output_format"] = output
    ctx.obj["debug"] = debug
    ctx.obj["console"] = Console()

    # Initialize services
    ctx.obj["command_service"] = get_command_service()
    ctx.obj["formatter_service"] = get_formatter_service()

    if debug:
        logger.debug("FLEXT LDAP CLI initialized with debug mode")
        console = ctx.obj["console"]
        console.print("[dim]Debug mode enabled[/dim]")


@cli.command()
@click.argument("server", type=str, required=True)
@click.option(
    "--port",
    "-p",
    default=389,
    type=int,
    help="LDAP server port",
)
@click.option("--ssl", is_flag=True, help="Use SSL/TLS connection")
@click.option("--bind-dn", type=str, help="Bind DN for authentication")
@click.option(
    "--bind-password",
    type=str,
    help="Password for authentication",
)
# Decorators removed for type safety - functionality implemented inline
@click.pass_context
def test(
    ctx: click.Context,
    server: str,
    port: int,
    *,
    ssl: bool,
    bind_dn: str | None,
    bind_password: str | None,
) -> None:
    """Test connection to LDAP server.

    Example:
      flext-ldap test ldap.example.com --port 389
      flext-ldap test ldaps.example.com --port 636 --ssl

    """
    # Inline timing and keyboard interrupt handling for type safety
    start_time = time.time()

    try:
        command_service: FlextLdapCliCommandService = ctx.obj["command_service"]
        console: Console = ctx.obj["console"]

        args: dict[str, object] = {
            "server": server,
            "port": port,
            "use_ssl": ssl,
            "bind_dn": bind_dn,
            "bind_password": bind_password,
        }

        console.print(f"[blue]Testing connection to {server}:{port}[/blue]")

        context = FlextCliExecutionContext(
            command_name="test",
            command_args=args,
        )
        result = command_service.execute_command("test", context.command_args)

        elapsed = time.time() - start_time
        console.print(f"[dim]⏱  Execution time: {elapsed:.2f}s[/dim]")

        if result.is_success:
            data = result.value
            if data and isinstance(data, dict):
                _display_test_result(cast("dict[str, object]", data))
        else:
            console.print(f"[red]Test failed: {result.error or 'Unknown error'}[/red]")
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise SystemExit(1) from None
    except Exception as e:
        console = Console()
        console.print(f"[red]Command error: {e}[/red]")
        raise


@cli.command()
@click.argument("server", type=str, required=True)
@click.argument("base_dn", type=str, required=True)
@click.option(
    "--filter",
    "-f",
    "filter_str",
    default="(objectClass=*)",
    help="LDAP search filter",
)
@click.option("--limit", "-l", default=10, type=int, help="Maximum entries to display")
@click.option(
    "--port",
    "-p",
    default=389,
    type=int,
    help="LDAP server port",
)
@click.option("--ssl", is_flag=True, help="Use SSL/TLS connection")
@click.option("--bind-dn", type=str, help="Bind DN for authentication")
@click.option(
    "--bind-password",
    type=str,
    help="Password for authentication",
)
# Decorators removed for type safety - functionality implemented inline
@click.pass_context
def search(
    ctx: click.Context,
    server: str,
    base_dn: str,
    filter_str: str,
    limit: int,
    port: int,
    *,
    ssl: bool,
    bind_dn: str | None,
    bind_password: str | None,
) -> None:
    """Search LDAP directory entries.

    Example:
      flext-ldap search ldap.example.com "dc=example,dc=com"
      flext-ldap search ldap.example.com "ou=users,dc=example,dc=com" --filter "(objectClass=person)"

    """
    # Inline timing and keyboard interrupt handling for type safety
    start_time = time.time()

    try:
        command_service: FlextLdapCliCommandService = ctx.obj["command_service"]
        console: Console = ctx.obj["console"]

        args: dict[str, object] = {
            "server": server,
            "base_dn": base_dn,
            "filter_str": filter_str,
            "port": port,
            "use_ssl": ssl,
            "bind_dn": bind_dn,
            "bind_password": bind_password,
            "limit": limit,
        }

        console.print(f"[blue]Searching {base_dn} on {server}:{port}[/blue]")

        context = FlextCliExecutionContext(
            command_name="search",
            command_args=args,
        )
        result = command_service.execute_command("search", context.command_args)

        elapsed = time.time() - start_time
        console.print(f"[dim]⏱  Execution time: {elapsed:.2f}s[/dim]")

        if result.is_success:
            data = result.value
            if data and isinstance(data, dict):
                _display_search_results(cast("dict[str, object]", data))
        else:
            console.print(
                f"[red]Search failed: {result.error or 'Unknown error'}[/red]"
            )
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise SystemExit(1) from None
    except Exception as e:
        console = Console()
        console.print(f"[red]Command error: {e}[/red]")
        raise


@cli.command()
@click.argument("uid", type=str, required=True)
@click.option("--server", "-s", default="localhost", help="LDAP server URL")
# Decorators removed for type safety - functionality implemented inline
@click.pass_context
def user_info(
    ctx: click.Context,
    uid: str,
    server: str,
) -> None:
    """Get information about a specific user.

    Example:
      flext-ldap user-info john.doe
      flext-ldap user-info john.doe --server ldap.example.com

    """
    # Inline timing and keyboard interrupt handling for type safety
    start_time = time.time()

    try:
        command_service: FlextLdapCliCommandService = ctx.obj["command_service"]
        console: Console = ctx.obj["console"]

        args: dict[str, object] = {
            "uid": uid,
            "server": server,
        }

        console.print(f"[blue]Looking up user: {uid}[/blue]")

        context = FlextCliExecutionContext(
            command_name="user_info",
            command_args=args,
        )
        result = command_service.execute_command("user_info", context.command_args)

        elapsed = time.time() - start_time
        console.print(f"[dim]⏱  Execution time: {elapsed:.2f}s[/dim]")

        if result.is_success:
            data = result.value
            if data and isinstance(data, dict):
                _display_user_info(cast("dict[str, object]", data))
        else:
            console.print(
                f"[red]User lookup failed: {result.error or 'Unknown error'}[/red]"
            )
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise SystemExit(1) from None
    except Exception as e:
        console = Console()
        console.print(f"[red]Command error: {e}[/red]")
        raise


@cli.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Show version information."""
    console: Console = ctx.obj["console"]

    console.print("FLEXT LDAP v0.9.0", style="bold green")
    console.print(
        "Modern Enterprise LDAP Operations with flext-cli integration",
        style="dim",
    )
    console.print("Built with Clean Architecture patterns", style="dim")


# Decorator removed for type safety - functionality implemented inline
def main() -> None:
    """Run CLI entry point with proper error handling using flext-cli patterns."""
    try:
        # Initialize CLI with flext-cli patterns
        _ = create_cli_container()  # Initialize CLI container
        config = get_cli_config()

        if config.debug:
            logger.debug("Starting FLEXT LDAP CLI with debug mode")

        cli()
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise SystemExit(1) from None
    except Exception as e:
        console = Console()
        console.print(f"[red]CLI Error: {e}[/red]")
        logger.exception("CLI execution failed")
        raise


if __name__ == "__main__":
    main()
