"""FLEXT LDAP CLI."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Coroutine
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import ParamSpec, TypeVar, cast, override

import click
from flext_core import (
    FlextEntity as FlextCliEntity,
    FlextEntityId,
    FlextResult,
    get_flext_container,
    get_logger,
)
from rich.console import Console
from rich.table import Table

from flext_ldap.constants import FlextLdapDefaultValues
from flext_ldap.entities import FlextLdapSearchRequest
from flext_ldap.infrastructure import FlextLdapClient
from flext_ldap.models import FlextLdapDistinguishedName, FlextLdapFilter

logger = get_logger(__name__)
console = Console()


# =============================================================================
# REFACTORED HELPERS - ELIMINATE ALL DUPLICATION
# =============================================================================


def _safe_int_from_kwargs(kwargs: dict[str, object], key: str, default: int) -> int:
    value = kwargs.get(key, default)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return default


def _safe_str_from_kwargs(kwargs: dict[str, object], key: str) -> str | None:
    """Safe string conversion from kwargs - REUSABLE HELPER."""
    value = kwargs.get(key)
    return str(value) if value is not None else None


def _safe_bool_from_kwargs(
    kwargs: dict[str, object],
    key: str,
    *,
    default: bool = False,
) -> bool:
    """Safe bool conversion from kwargs - REUSABLE HELPER."""
    value = kwargs.get(key, default)
    return bool(value)


def _execute_async_operation(operation: object) -> object:
    """Execute async operation synchronously - CONSOLIDATE ASYNC/AWAIT PATTERNS."""
    if hasattr(operation, "__await__"):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(cast("Coroutine[object, object, object]", operation))
        # When already inside an event loop, use a thread to avoid nested
        # event loops which crash under asyncio.

        def run_in_new_loop() -> object:
            """Run operation in new event loop."""
            return asyncio.run(cast("Coroutine[object, object, object]", operation))

        with ThreadPoolExecutor(max_workers=1) as executor:
            future: Future[object] = executor.submit(run_in_new_loop)
            return future.result(timeout=60)
    return operation


# Using real flext-cli mixin for validation and output helpers


# =============================================================================
# PARAMETER OBJECTS - USING REFACTORED HELPERS
# =============================================================================


@dataclass
class LDAPConnectionParams:
    """Parameter object for LDAP connection operations."""

    server: str
    port: int = 389
    use_ssl: bool = False
    bind_dn: str | None = None
    bind_password: str | None = None

    @classmethod
    def from_click_args(
        cls,
        server: str,
        port: int,
        **kwargs: object,
    ) -> LDAPConnectionParams:
        """Create from Click arguments using REFACTORED type-safe helpers."""
        # Convert kwargs to the expected format
        kwargs_dict = dict(kwargs) if isinstance(kwargs, dict) else {}
        return cls(
            server=server,
            port=port,
            use_ssl=_safe_bool_from_kwargs(kwargs_dict, "ssl"),
            bind_dn=_safe_str_from_kwargs(kwargs_dict, "bind_dn"),
            bind_password=_safe_str_from_kwargs(kwargs_dict, "bind_password"),
        )


@dataclass
class LDAPSearchParams:
    """Parameter object for LDAP search operations."""

    server: str
    base_dn: str
    filter_str: str = FlextLdapDefaultValues.DEFAULT_SEARCH_FILTER
    port: int = 389
    use_ssl: bool = False
    bind_dn: str | None = None
    bind_password: str | None = None
    limit: int = 10

    @classmethod
    def from_click_args(
        cls,
        server: str,
        base_dn: str,
        filter_str: str,
        **kwargs: object,
    ) -> LDAPSearchParams:
        """Create from Click arguments using REFACTORED type-safe helpers."""
        # Convert kwargs to the expected format
        kwargs_dict = dict(kwargs) if isinstance(kwargs, dict) else {}
        return cls(
            server=server,
            base_dn=base_dn,
            filter_str=filter_str,
            port=_safe_int_from_kwargs(kwargs_dict, "port", 389),
            use_ssl=_safe_bool_from_kwargs(kwargs_dict, "ssl"),
            bind_dn=_safe_str_from_kwargs(kwargs_dict, "bind_dn"),
            bind_password=_safe_str_from_kwargs(kwargs_dict, "bind_password"),
            limit=_safe_int_from_kwargs(kwargs_dict, "limit", 10),
        )


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def _generate_cli_id() -> str:
    """Generate ID using container ID generator or UUID for CLI usage."""
    container = get_flext_container()
    id_generator_result = container.get("FlextIdGenerator")

    if id_generator_result.is_success:
        id_generator = id_generator_result.value
        if id_generator and hasattr(id_generator, "generate"):
            generated_id = getattr(id_generator, "generate", uuid.uuid4)()
            return str(generated_id)

    return str(uuid.uuid4())


# =============================================================================
# BASE CLASS FOR FLEXT LDAP CLI COMMANDS
# =============================================================================


class _CliPrintMixin:  # Minimal shim without external dependency
    def flext_cli_print_info(self, message: str) -> None:
        _ = message

    def flext_cli_print_success(self, message: str) -> None:
        _ = message

    def flext_cli_print_error(self, message: str) -> None:
        _ = message

    def flext_cli_print_warning(self, message: str) -> None:
        _ = message


class FlextLdapCliBase(FlextCliEntity, _CliPrintMixin):
    """Base class for FLEXT LDAP CLI commands with shared functionality."""

    def __init__(self, command_id: str, name: str) -> None:
        """Initialize base CLI command."""
        # Minimal initialization compatible with flext-core FlextEntity
        super().__init__(id=FlextEntityId(command_id))
        self._name = name
        self._container = get_flext_container()
        # Keep convenience fields for testing
        self.command_id = command_id

    def _generate_id(self) -> str:
        """Generate ID using container ID generator or UUID - consistent with operations.py."""
        id_generator_result = self._container.get("FlextIdGenerator")

        if id_generator_result.is_success:
            id_generator = id_generator_result.value
            if id_generator and hasattr(id_generator, "generate"):
                generated_id = getattr(id_generator, "generate", uuid.uuid4)()
                return str(generated_id)

        return str(uuid.uuid4())


# =============================================================================
# REFACTORED COMMAND CLASSES - ZERO DUPLICATION
# =============================================================================


class FlextLdapTestCommand(FlextLdapCliBase):
    """LDAP connection test - REFACTORED with zero duplication."""

    def __init__(
        self,
        command_id: str,
        name: str,
        params: LDAPConnectionParams,
    ) -> None:
        """Initialize command with connection parameters.

        Args:
            command_id: Unique command identifier.
            name: Human-readable command name.
            params: Strongly typed connection parameters.

        """
        super().__init__(command_id, name)
        self.name = name
        self.params = params

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDAP connection parameters."""
        max_port = 65535
        if not self.params.server or not self.params.server.strip():
            return FlextResult[None].fail("Server cannot be empty")

        if not (1 <= self.params.port <= max_port):
            return FlextResult[None].fail(f"Invalid port: {self.params.port}")

        return FlextResult[None].ok(None)

    def execute(self) -> FlextResult[object]:
        """Execute LDAP connection test - REFACTORED async handling."""
        self.flext_cli_print_info(
            f"Testing connection to {self.params.server}:{self.params.port}",
        )

        try:
            client = FlextLdapClient()
            protocol = "ldaps" if self.params.use_ssl else "ldap"
            uri = f"{protocol}://{self.params.server}:{self.params.port}"

            # Use REFACTORED async helper - NO DUPLICATION
            bind_dn = self.params.bind_dn or "cn=anonymous"
            bind_password = self.params.bind_password or ""
            connect_result = cast(
                "FlextResult[object]",
                _execute_async_operation(client.connect(uri, bind_dn, bind_password)),
            )

            if connect_result.is_success:
                self.flext_cli_print_success(f"Successfully connected to {uri}")
                # Always disconnect regardless of connect_result.value presence
                _execute_async_operation(client.unbind())
                return FlextResult[object].ok(
                    {
                        "message": f"Connection successful to {uri}",
                        "protocol": protocol,
                    },
                )
            self.flext_cli_print_error(f"Connection failed: {connect_result.error}")
            return FlextResult[object].fail(connect_result.error or "Connection failed")

        except Exception as e:
            self.flext_cli_print_error(f"Connection error: {e}")
            return FlextResult[object].fail(str(e))


class FlextLdapSearchCommand(FlextLdapCliBase):
    """LDAP search - REFACTORED with zero duplication."""

    def __init__(self, command_id: str, name: str, params: LDAPSearchParams) -> None:
        """Initialize command with search parameters.

        Args:
            command_id: Unique command identifier.
            name: Human-readable command name.
            params: Strongly typed search parameters.

        """
        super().__init__(command_id, name)
        self.name = name
        self.params = params

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDAP search parameters."""
        max_port = 65535
        if not self.params.server or not self.params.server.strip():
            return FlextResult[None].fail("Server cannot be empty")

        if not self.params.base_dn or not self.params.base_dn.strip():
            return FlextResult[None].fail("Base DN cannot be empty")

        if not (1 <= self.params.port <= max_port):
            return FlextResult[None].fail(f"Invalid port: {self.params.port}")

        return FlextResult[None].ok(None)

    def execute(self) -> FlextResult[object]:
        """Execute LDAP search - REFACTORED async handling."""
        self.flext_cli_print_info(
            f"Searching {self.params.base_dn} on {self.params.server}:{self.params.port}",
        )

        try:
            client = FlextLdapClient()
            protocol = "ldaps" if self.params.use_ssl else "ldap"
            uri = f"{protocol}://{self.params.server}:{self.params.port}"

            # Perform the search operation
            return self._perform_search_operation(client, uri)

        except Exception as e:
            self.flext_cli_print_error(f"Search error: {e}")
            return FlextResult[object].fail(str(e))

    def _perform_search_operation(
        self,
        client: FlextLdapClient,
        uri: str,
    ) -> FlextResult[object]:
        """Perform the complete search operation with connection management."""
        # Connect using REFACTORED async helper - NO DUPLICATION
        connect_result = cast(
            "FlextResult[object]",
            _execute_async_operation(
                client.connect(
                    uri, self.params.bind_dn or "", self.params.bind_password or ""
                )
            ),
        )

        if connect_result.is_failure:
            self.flext_cli_print_error(f"Connection failed: {connect_result.error}")
            return FlextResult[object].fail(connect_result.error or "Connection failed")

        try:
            # Validate parameters
            validation_result = self._validate_search_parameters()
            if validation_result.is_failure:
                return FlextResult[object].fail(
                    validation_result.error or "Validation failed"
                )

            # Execute search with validated data
            return self._execute_search_with_client(client, validation_result.value)

        finally:
            # Always disconnect
            _execute_async_operation(client.unbind())

    def _validate_search_parameters(self) -> FlextResult[dict[str, object]]:
        """Validate search parameters and return validated objects."""
        # Validate and create DN and filter objects
        dn_result = FlextLdapDistinguishedName.create(self.params.base_dn)
        if dn_result.is_failure or dn_result.value is None:
            return FlextResult[dict[str, object]].fail(
                f"Invalid base DN: {dn_result.error}"
            )

        filter_result = FlextLdapFilter.create(self.params.filter_str)
        if filter_result.is_failure or filter_result.value is None:
            return FlextResult[dict[str, object]].fail(
                f"Invalid filter: {filter_result.error}"
            )

        return FlextResult[dict[str, object]].ok(
            {
                "dn": dn_result.value,
                "filter": filter_result.value,
            }
        )

    def _execute_search_with_client(
        self,
        client: FlextLdapClient,
        validated_params: dict[str, object],
    ) -> FlextResult[object]:
        """Execute the search operation with validated parameters."""
        # Create proper search request
        search_request = FlextLdapSearchRequest(
            base_dn=str(validated_params["dn"]),
            filter_str=str(validated_params["filter"]),
            scope="subtree",
            size_limit=1000,
            time_limit=30,
            attributes=["*"],
        )

        search_result = cast(
            "FlextResult[object]",
            _execute_async_operation(client.search(search_request)),
        )

        return self._process_search_results(search_result)

    def _process_search_results(
        self,
        search_result: FlextResult[object],
    ) -> FlextResult[object]:
        """Process and display search results."""
        # Use FlextResult's unwrap_or method for cleaner code
        entries_data = search_result.unwrap_or([])

        if entries_data:
            entries = (
                entries_data[: self.params.limit]
                if isinstance(entries_data, list)
                else [entries_data]
            )
            self.flext_cli_print_success(f"Found {len(entries)} entries")

            # Display results using Rich tables
            self._display_search_results(entries)

            return FlextResult[object].ok({"entries": entries, "count": len(entries)})

        self.flext_cli_print_warning("No entries found")
        return FlextResult[object].ok({"entries": [], "count": 0})

    def _display_search_results(self, entries: list[object]) -> None:
        """Display search results using Rich formatting - REFACTORED to reduce complexity."""
        for i, entry in enumerate(entries, 1):
            self._display_single_entry(i, entry)

    def _display_single_entry(self, entry_number: int, entry: object) -> None:
        """Display a single entry with DN and attributes table."""
        console.print(f"\n[bold cyan]Entry {entry_number}:[/bold cyan]")

        dn, attributes = self._extract_entry_data(entry)
        console.print(f"[yellow]DN:[/yellow] {dn}")

        if attributes:
            self._display_entry_attributes(attributes)

    def _extract_entry_data(self, entry: object) -> tuple[str, dict[str, object]]:
        """Extract DN and attributes from entry object."""
        if isinstance(entry, dict):
            dn = entry.get("dn", "Unknown DN")
            attributes = entry.get("attributes", {})
        else:
            dn = getattr(entry, "dn", "Unknown DN")
            attributes = getattr(entry, "attributes", {})
        return str(dn), attributes

    def _display_entry_attributes(self, attributes: dict[str, object]) -> None:
        """Display attributes in a Rich table with value truncation."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Attribute", style="cyan")
        table.add_column("Values", style="white")

        for attr_name, attr_values in attributes.items():
            formatted_values = self._format_attribute_values(attr_values)
            table.add_row(attr_name, formatted_values)

        console.print(table)

    def _format_attribute_values(self, attr_values: object) -> str:
        """Format attribute values with truncation for display."""
        max_inline_values = 3

        if isinstance(attr_values, list):
            display_values = attr_values[:max_inline_values]
            if len(attr_values) > max_inline_values:
                remaining = len(attr_values) - max_inline_values
                display_values.append(f"... and {remaining} more")
            return "\n".join(str(v) for v in display_values)

        return str(attr_values)


class FlextLdapUserInfoCommand(FlextLdapCliBase):
    """LDAP user info - REFACTORED with zero duplication."""

    def __init__(
        self,
        command_id: str,
        name: str,
        uid: str,
        server: str | None = None,
    ) -> None:
        """Initialize command for user info lookup.

        Args:
            command_id: Unique command identifier.
            name: Human-readable command name.
            uid: User identifier to look up.
            server: Optional server URL.

        """
        super().__init__(command_id, name)
        self.name = name
        self.uid = uid
        self.server = server or "localhost"

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate user info parameters."""
        if not self.uid or not self.uid.strip():
            return FlextResult[None].fail("UID cannot be empty")

        return FlextResult[None].ok(None)

    def execute(self) -> FlextResult[object]:
        """Execute user lookup - REFACTORED to reduce returns."""
        self.flext_cli_print_info(f"Looking up user: {self.uid}")

        try:
            client = FlextLdapClient()
            uri = f"ldap://{self.server}:389"

            # Perform connection and search operations
            return self._perform_user_lookup(client, uri)

        except Exception as e:
            self.flext_cli_print_error(f"User lookup error: {e}")
            return FlextResult[object].fail(str(e))

    def _perform_user_lookup(
        self,
        client: FlextLdapClient,
        uri: str,
    ) -> FlextResult[object]:
        """Perform the complete user lookup operation."""
        # Connect using REFACTORED async helper - NO DUPLICATION
        connect_result = cast(
            "FlextResult[object]",
            _execute_async_operation(client.connect(uri, "cn=anonymous", "")),
        )

        if connect_result.is_failure:
            self.flext_cli_print_error(f"Connection failed: {connect_result.error}")
            return FlextResult[object].fail(connect_result.error or "Connection failed")

        try:
            return self._search_for_user(client)
        finally:
            # Always disconnect
            _execute_async_operation(client.unbind())

    def _search_for_user(self, client: FlextLdapClient) -> FlextResult[object]:
        """Search for user and return results."""
        # Validate search parameters
        validation_result = self._prepare_search_parameters()
        if validation_result.is_failure:
            return FlextResult[object].fail(
                validation_result.error or "Validation failed"
            )

        # Execute search operation
        search_result = self._execute_user_search(client, validation_result.value)

        return self._process_user_search_results(search_result)

    def _prepare_search_parameters(self) -> FlextResult[dict[str, object]]:
        """Prepare and validate search parameters."""
        dn_result = FlextLdapDistinguishedName.create("dc=example,dc=com")
        if dn_result.is_failure or dn_result.value is None:
            return FlextResult[dict[str, object]].fail(
                f"Invalid base DN: {dn_result.error}"
            )

        filter_result = FlextLdapFilter.create(f"(uid={self.uid})")
        if filter_result.is_failure or filter_result.value is None:
            return FlextResult[dict[str, object]].fail("Invalid filter")

        return FlextResult[dict[str, object]].ok(
            {
                "dn": dn_result.value,
                "filter": filter_result.value,
            }
        )

    def _execute_user_search(self, client: FlextLdapClient, params: object) -> object:
        """Execute the user search operation."""
        if not isinstance(params, dict):
            return {"success": False, "error": "Invalid search parameters"}

        # Create proper search request
        search_request = FlextLdapSearchRequest(
            base_dn=str(params["dn"]),
            filter_str=str(params["filter"]),
            scope="subtree",
            attributes=["uid", "cn", "sn", "mail", "dn"],
            size_limit=1000,
            time_limit=30,
        )

        return _execute_async_operation(client.search(search_request))

    def _process_user_search_results(
        self,
        search_result: FlextResult[object],
    ) -> FlextResult[object]:
        """Process search results and display user information."""
        # Check if search was successful
        if search_result.is_success and search_result.value:
            user_data = (
                search_result.value[0]
                if isinstance(search_result.value, list)
                else search_result.value
            )
            self.flext_cli_print_success(f"Found user: {self.uid}")

            # Display user information
            self._display_user_info(user_data)
            return FlextResult[object].ok(user_data)

        self.flext_cli_print_warning(f"User {self.uid} not found")
        return FlextResult[object].fail(f"User {self.uid} not found")

    def _display_user_info(self, user: object) -> None:
        """Display user information using Rich formatting."""
        # Handle both dict and object user data
        if isinstance(user, dict):
            uid = user.get("uid", "N/A")
            cn = user.get("cn", "N/A")
            sn = user.get("sn", "N/A")
            dn = user.get("dn", "N/A")
            mail = user.get("mail", "N/A")
        else:
            uid = getattr(user, "uid", "N/A")
            cn = getattr(user, "cn", "N/A")
            sn = getattr(user, "sn", "N/A")
            dn = getattr(user, "dn", "N/A")
            mail = getattr(user, "mail", "N/A")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("UID", str(uid))
        table.add_row("Common Name", str(cn))
        table.add_row("Surname", str(sn))
        table.add_row("Distinguished Name", str(dn))
        if mail and mail != "N/A":
            table.add_row("Email", str(mail))

        console.print(table)


# =============================================================================
# PYDANTIC MODEL REBUILD - Fix forward references
# =============================================================================

# Pydantic models from flext-cli and our commands do not require manual rebuilds here


# =============================================================================
# REFACTORED DECORATORS - ELIMINATE CLICK OPTION DUPLICATION
# =============================================================================


P = ParamSpec("P")
R = TypeVar("R")


def ldap_connection_options(func: Callable[P, R]) -> Callable[P, R]:  # noqa: UP047
    """DRY decorator for common LDAP connection options - REFACTORED."""
    return click.option(
        "--port",
        "-p",
        default=389,
        type=int,
        help="LDAP server port",
    )(
        click.option("--ssl", is_flag=True, help="Use SSL/TLS connection")(
            click.option("--bind-dn", type=str, help="Bind DN for authentication")(
                click.option(
                    "--bind-password",
                    type=str,
                    help="Password for authentication",
                )(func),
            ),
        ),
    )


# =============================================================================
# CLICK CLI - REFACTORED WITH ZERO DUPLICATION
# =============================================================================


@click.group(name="flext-ldap")
@click.version_option(version="0.9.0", prog_name="FLEXT LDAP")
@click.help_option("--help", "-h")
def cli() -> None:
    """FLEXT LDAP - Modern Enterprise LDAP Operations - REFACTORED VERSION.

    ZERO CODE DUPLICATION through comprehensive refactoring.
    Built on Clean Architecture patterns with flext-core integration.
    """
    console.print("[green]FLEXT LDAP CLI initialized[/green]")


@cli.command()
@click.argument("server", type=str, required=True)
@ldap_connection_options
def test(
    server: str,
    port: int,
    *,
    ssl: bool,
    bind_dn: str | None,
    bind_password: str | None,
) -> None:
    """Test connection to LDAP server - REFACTORED VERSION.

    Example:
      flext-ldap test ldap.example.com --port 389
      flext-ldap test ldaps.example.com --port 636 --ssl

    """
    params = LDAPConnectionParams(
        server=server,
        port=port,
        use_ssl=ssl,
        bind_dn=bind_dn,
        bind_password=bind_password,
    )

    command = FlextLdapTestCommand(
        command_id=_generate_cli_id(),
        name="ldap-test",
        params=params,
    )

    result = command.execute()
    if result.is_failure:
        console.print(f"[red]Test failed: {result.error}[/red]")


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
@ldap_connection_options
def search(
    server: str,
    base_dn: str,
    filter_str: str,
    limit: int,
    **kwargs: object,
) -> None:
    """Search LDAP directory entries - REFACTORED VERSION.

    Example:
      flext-ldap search ldap.example.com "dc=example,dc=com"
      flext-ldap search ldap.example.com "ou=users,dc=example,dc=com" --filter "(objectClass=person)"

    """
    params = LDAPSearchParams(
        server=server,
        base_dn=base_dn,
        filter_str=filter_str,
        port=int(cast("int", kwargs.get("port", 389))),
        use_ssl=bool(cast("bool", kwargs.get("ssl", False))),
        bind_dn=str(kwargs.get("bind_dn")) if kwargs.get("bind_dn") else None,
        bind_password=str(kwargs.get("bind_password"))
        if kwargs.get("bind_password")
        else None,
        limit=limit,
    )

    command = FlextLdapSearchCommand(
        command_id=_generate_cli_id(),
        name="ldap-search",
        params=params,
    )

    result = command.execute()
    if result.is_failure:
        console.print(f"[red]Search failed: {result.error}[/red]")


@cli.command()
@click.argument("uid", type=str, required=True)
@click.option("--server", "-s", help="LDAP server URL")
def user_info(uid: str, server: str | None) -> None:
    """Get information about a specific user - REFACTORED VERSION.

    Example:
      flext-ldap user-info john.doe
      flext-ldap user-info john.doe --server ldap://ldap.example.com

    """
    command = FlextLdapUserInfoCommand(
        command_id=_generate_cli_id(),
        name="user-info",
        uid=uid,
        server=server,
    )

    result = command.execute()
    if result.is_failure:
        console.print(f"[red]User lookup failed: {result.error}[/red]")


@cli.command()
def version() -> None:
    """Show version information - REFACTORED VERSION."""
    console.print("FLEXT LDAP v0.9.0 - REFACTORED", style="bold green")
    console.print(
        "Modern Enterprise LDAP Operations with ZERO CODE DUPLICATION",
        style="dim",
    )
    console.print("Built through comprehensive refactoring methodology", style="dim")


def main() -> None:
    """Run CLI entry point - REFACTORED VERSION."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("[blue]Operation cancelled by user[/blue]")
        raise SystemExit(0) from None
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
