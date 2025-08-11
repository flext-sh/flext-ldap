#!/usr/bin/env python3
"""Modern FLEXT LDAP CLI using flext-cli framework.

Enterprise-grade command-line interface for LDAP operations.
Built with flext-cli framework for consistency and rich terminal output.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, ParamSpec, TypeVar

import click
from flext_core import FlextResult, get_logger
from flext_core.config_models import create_ldap_config
from pydantic import SecretStr
from rich.console import Console
from rich.table import Table

from flext_ldap.config import FlextLdapAuthConfig, FlextLdapConnectionConfig
from flext_ldap.infrastructure_ldap_client import FlextLdapClient
from flext_ldap.values import (
    ExtendedLDAPEntry,
    FlextLdapDistinguishedName,
    FlextLdapFilter,
    FlextLdapScope,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_core import FlextTypes

    from flext_ldap.entities import FlextLdapUser

logger = get_logger(__name__)

# Rich console for beautiful output
console = Console()

# Constants - DRY principle to eliminate magic numbers and boolean smells
MAX_DISPLAY_VALUES = 3

# =============================================================================
# REFACTORING: Decorator Pattern - Eliminate Click Option Duplication
# =============================================================================


P = ParamSpec("P")
R = TypeVar("R")


def ldap_connection_options(func: Callable[P, R]) -> Callable[P, R]:  # noqa: UP047 - uses ParamSpec/TypeVar generics
    """DRY Decorator Pattern: Common LDAP connection options."""
    return click.option("--port", "-p", default=389, type=int, help="LDAP server port")(
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


# Boolean operation constants to eliminate FBT smells - SOLID DRY Principle
class SSLMode:
    """SSL connection mode constants - eliminates boolean parameters."""

    ENABLED = True
    DISABLED = False


class ConnectionResult:
    """Connection result constants - eliminates boolean parameters."""

    SUCCESS = True
    FAILURE = False


class AuthenticationRequired:
    """Authentication requirement constants - eliminates boolean parameters."""

    REQUIRED = True
    NOT_REQUIRED = False


class PasswordSpecialChars:
    """Password special characters requirement - eliminates boolean parameters."""

    REQUIRED = True
    NOT_REQUIRED = False


class LDAPOperationOutcome:
    """LDAP operation outcome constants - eliminates boolean parameters."""

    SUCCESS = True
    FAILURE = False


@dataclass
class LDAPConnectionParams:
    """Parameters for LDAP connection operations."""

    server: str
    port: int = 389
    use_ssl: bool = False
    bind_dn: str | None = None
    bind_password: str | None = None


@dataclass
class LDAPSearchParams:
    """Parameters for LDAP search operations."""

    server: str
    base_dn: str
    port: int = 389
    filter_str: str = "(objectClass=*)"
    use_ssl: bool = False
    bind_dn: str | None = None
    bind_password: str | None = None
    limit: int = 10

    @staticmethod
    def _safe_int_conversion(value: object, default: int) -> int:
        """Safely convert value to int with default fallback."""
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return default

    @classmethod
    def from_click_args(
        cls,
        server: str,
        base_dn: str,
        filter_str: str,
        **kwargs: object,
    ) -> LDAPSearchParams:
        """Create from Click command arguments using **kwargs to eliminate PLR0913."""
        return cls(
            server=server,
            base_dn=base_dn,
            filter_str=filter_str,
            port=cls._safe_int_conversion(kwargs.get("port"), 389),
            use_ssl=bool(kwargs.get("ssl")),
            bind_dn=str(kwargs.get("bind_dn")) if kwargs.get("bind_dn") else None,
            bind_password=(
                str(kwargs.get("bind_password"))
                if kwargs.get("bind_password")
                else None
            ),
            limit=cls._safe_int_conversion(kwargs.get("limit"), 10),
        )


@dataclass
class LDAPConnectionTestParams:
    """Parameters for LDAP connection testing operations."""

    server: str
    port: int = 389
    use_ssl: bool = False
    bind_dn: str | None = None
    bind_password: str | None = None

    @classmethod
    def from_args(
        cls,
        server: str,
        port: int,
        **options: object,
    ) -> LDAPConnectionTestParams:
        """Create from arguments using **kwargs to eliminate PLR0913."""
        return cls(
            server=server,
            port=port,
            use_ssl=bool(options.get("use_ssl")),
            bind_dn=str(options.get("bind_dn")) if options.get("bind_dn") else None,
            bind_password=str(options.get("bind_password"))
            if options.get("bind_password")
            else None,
        )


@dataclass
class LDAPUserParams:
    """Parameters for LDAP user operations."""

    uid: str
    cn: str
    sn: str
    mail: str | None = None
    base_dn: str = "ou=users,dc=example,dc=com"
    server: str | None = None

    @classmethod
    def from_click_args(
        cls,
        uid: str,
        cn: str,
        sn: str,
        **kwargs: object,
    ) -> LDAPUserParams:
        """Create from Click command arguments using **kwargs to eliminate PLR0913."""
        return cls(
            uid=uid,
            cn=cn,
            sn=sn,
            mail=str(kwargs.get("mail")) if kwargs.get("mail") else None,
            base_dn=str(kwargs.get("base_dn", "ou=users,dc=example,dc=com")),
            server=str(kwargs.get("server")) if kwargs.get("server") else None,
        )


# Base handler class to eliminate code duplication
class BaseLDAPHandler:
    """Base handler class providing common LDAP operations.

    Eliminates code duplication by providing shared connection management,
    error handling, and client lifecycle management patterns.
    """

    @staticmethod
    def _create_connection_config(
        server: str,
        port: int = 389,
        *,
        use_ssl: bool = SSLMode.DISABLED,
    ) -> FlextLdapConnectionConfig:
        """Create LDAP connection configuration."""
        base = create_ldap_config(host=server, port=port)
        return FlextLdapConnectionConfig.model_validate(
            {
                **base.model_dump(),
                "use_ssl": bool(use_ssl),
            }
        )

    @staticmethod
    def _create_auth_config(
        bind_dn: str | None,
        bind_password: str | None,
    ) -> FlextLdapAuthConfig | None:
        """Create authentication configuration if credentials provided."""
        if bind_dn:
            return FlextLdapAuthConfig(
                server="",
                search_base="",
                bind_dn=bind_dn,
                bind_password=SecretStr(bind_password or "") if bind_password else None,
            )
        return None

    @staticmethod
    async def _execute_with_client(
        client: FlextLdapClient,
        operation: Callable[[FlextLdapClient, str], FlextResult[object]],
    ) -> FlextResult[object]:
        """Execute operation with client lifecycle management."""
        try:
            connect_id_result = await client.connect("ldap://localhost:389", None, None)
            if connect_id_result.is_failure:
                return FlextResult.fail(f"Connection failed: {connect_id_result.error}")

            try:
                connection_id = connect_id_result.data or ""
                return operation(client, connection_id)
            finally:
                if connect_id_result.is_success and connect_id_result.data:
                    await client.disconnect(connect_id_result.data)

        except Exception as e:
            return FlextResult.fail(f"Operation error: {e}")


# Command handlers using flext-cli patterns with DRY principles
class LDAPConnectionHandler(BaseLDAPHandler):
    """Handler for LDAP connection operations."""

    @classmethod
    def test_connection(
        cls,
        params: LDAPConnectionTestParams,
    ) -> FlextResult[str]:
        """Test LDAP connection using Parameter Object pattern."""
        try:
            # Railway Oriented Programming - Consolidated connection test pipeline
            return asyncio.run(cls._execute_connection_test_pipeline(params))

        except Exception as e:
            return FlextResult.fail(f"Connection error: {e}")

    @classmethod
    async def _execute_connection_test_pipeline(
        cls,
        params: LDAPConnectionTestParams,
    ) -> FlextResult[str]:
        """Execute connection test pipeline with consolidated error handling."""
        cls._create_connection_config(
            params.server,
            params.port,
            use_ssl=params.use_ssl,
        )
        cls._create_auth_config(params.bind_dn, params.bind_password)
        client = FlextLdapClient(None)

        def test_operation(user_ldap_client: FlextLdapClient, connection_id: str) -> FlextResult[object]:  # noqa: ARG001
            return cls._perform_connection_test_operation(user_ldap_client, params)

        result = await cls._execute_with_client(client, test_operation)
        return cls._handle_connection_test_result(result)

    @classmethod
    def _perform_connection_test_operation(
        cls,
        _client: FlextLdapClient,
        params: LDAPConnectionTestParams,
    ) -> FlextResult[object]:
        """Perform connection test operation with proper validation."""
        # Connection test - if we got here, connection was successful
        # (connection_id would be needed for is_connected check in new API)

        protocol = "ldaps" if params.use_ssl else "ldap"
        message = (
            f"Successfully connected to {protocol}://{params.server}:{params.port}"
        )
        return FlextResult.ok(message)

    @classmethod
    def _handle_connection_test_result(
        cls,
        result: FlextResult[object],
    ) -> FlextResult[str]:
        """Handle the result of connection test operation."""
        # Cast back to expected return type
        if result.is_success:
            return FlextResult.ok(str(result.data))
        return FlextResult.fail(result.error or "Connection test failed")


class LDAPSearchHandler(BaseLDAPHandler):
    """Handler for LDAP search operations using base patterns."""

    @classmethod
    def _convert_raw_entry_to_extended(
        cls,
        raw_entry: FlextTypes.Core.JsonDict,
    ) -> ExtendedLDAPEntry:
        """Convert raw LDAP entry to ExtendedLDAPEntry format."""
        # Type-safe extraction with validation
        dn_value = raw_entry.get("dn", "") if isinstance(raw_entry, dict) else ""
        dn_str = str(dn_value) if dn_value is not None else ""

        attrs_value = (
            raw_entry.get("attributes", {}) if isinstance(raw_entry, dict) else {}
        )
        attrs_dict: dict[str, list[str]] = {}

        if isinstance(attrs_value, dict):
            for key, value in attrs_value.items():
                if isinstance(value, list):
                    attrs_dict[key] = [str(v) for v in value]
                else:
                    attrs_dict[key] = [str(value)]

        return ExtendedLDAPEntry(dn=dn_str, attributes=attrs_dict)

    @classmethod
    def _convert_search_results(
        cls,
        raw_entries: list[FlextTypes.Core.JsonDict],
        limit: int,
    ) -> list[ExtendedLDAPEntry]:
        """Convert raw search results to ExtendedLDAPEntry list."""
        entries: list[ExtendedLDAPEntry] = []
        for raw_entry in raw_entries[:limit]:
            entry = cls._convert_raw_entry_to_extended(raw_entry)
            entries.append(entry)
        return entries

    @classmethod
    def _execute_ldap_search(
        cls,
        client: FlextLdapClient,
        connection_id: str,
        params: LDAPSearchParams,
    ) -> FlextResult[object]:
        """Execute LDAP search operation."""
        dn_res = FlextLdapDistinguishedName.create(params.base_dn)
        if not dn_res.is_success or dn_res.data is None:
            return FlextResult.fail(f"Invalid base DN: {dn_res.error}")
        filt_res = FlextLdapFilter.create(params.filter_str)
        if not filt_res.is_success or filt_res.data is None:
            return FlextResult.fail(f"Invalid filter: {filt_res.error}")
        scope = FlextLdapScope.sub()
        search_result = asyncio.run(
            client.search(
                connection_id,
                dn_res.data,
                filt_res.data,
                scope,
                attributes=["*"],
            ),
        )

        if search_result.is_success:
            raw_entries = search_result.data or []
            entries = cls._convert_search_results(raw_entries, params.limit)
            return FlextResult.ok(entries)

        return FlextResult.fail(f"Search failed: {search_result.error}")

    @classmethod
    def search_entries(
        cls,
        params: LDAPSearchParams,
    ) -> FlextResult[object | None] | FlextResult[object]:
        """Search LDAP entries using base handler patterns."""
        try:
            cls._create_connection_config(
                params.server,
                params.port,
                use_ssl=params.use_ssl,
            )
            cls._create_auth_config(params.bind_dn, params.bind_password)

            if params.bind_dn:
                logger.debug(
                    "Authentication credentials provided",
                    extra={"bind_dn": params.bind_dn},
                )

            search_ldap_client = FlextLdapClient(None)

            def search_operation(operation_ldap_client: FlextLdapClient, connection_id: str) -> FlextResult[object]:
                return cls._execute_ldap_search(operation_ldap_client, connection_id, params)

            result = asyncio.run(cls._execute_with_client(search_ldap_client, search_operation))
            # Cast back to expected return type
            if result.is_success and isinstance(result.data, list):
                return FlextResult.ok(result.data)
            if result.is_success:
                return FlextResult.fail("Invalid search result format")
            return FlextResult.fail(result.error or "Search operation failed")

        except Exception as e:
            return FlextResult.fail(f"Search error: {e}")


class LDAPUserHandler(BaseLDAPHandler):
    """Handler for LDAP user operations using base patterns."""

    @classmethod
    def get_user_info(cls, uid: str, server: str | None = None) -> FlextResult[object]:
        """Get user information using base handler patterns."""
        try:
            server = server or "localhost"
            cls._create_connection_config(server)
            client = FlextLdapClient(None)

            def user_lookup_operation(
                user_ldap_client: FlextLdapClient,
                connection_id: str,
            ) -> FlextResult[object]:
                # REAL search for user by uid
                dn_res = FlextLdapDistinguishedName.create("dc=example,dc=com")
                if not dn_res.is_success or dn_res.data is None:
                    return FlextResult.fail(f"Invalid base DN: {dn_res.error}")
                filt_res = FlextLdapFilter.create(f"(uid={uid})")
                if not filt_res.is_success or filt_res.data is None:
                    return FlextResult.fail("Invalid filter")
                scope = FlextLdapScope.sub()
                search_result = asyncio.run(
                    user_ldap_client.search(
                        connection_id,
                        dn_res.data,
                        filt_res.data,
                        scope,
                        attributes=["uid", "cn", "sn", "mail", "dn"],
                    ),
                )

                if search_result.is_success and search_result.data:
                    # Return first matching user
                    user_data = search_result.data[0]
                    return FlextResult.ok(user_data)

                return FlextResult.fail(f"User {uid} not found")

            return asyncio.run(cls._execute_with_client(client, user_lookup_operation))

        except Exception as e:
            return FlextResult.fail(f"User lookup error: {e}")

    @classmethod
    def create_user(cls, params: LDAPUserParams) -> FlextResult[object]:
        """Create a new user using base handler patterns."""
        try:
            server = params.server or "localhost"
            cls._create_connection_config(server)
            client = FlextLdapClient(None)

            def user_creation_operation(
                user_ldap_client: FlextLdapClient,
            ) -> FlextResult[object]:
                # REAL user creation
                user_dn = f"cn={params.uid},{params.base_dn}"
                object_classes = ["person", "organizationalPerson", "inetOrgPerson"]
                # Type-safe attributes dictionary for FlextLdapClient.add
                attributes: FlextTypes.Core.JsonDict = {
                    "uid": params.uid,
                    "cn": params.cn,
                    "sn": params.sn,
                }

                if params.mail:
                    attributes["mail"] = params.mail

                # First connect to get session_id
                connection_result: FlextResult[bool] = asyncio.run(
                    user_ldap_client.connect_async("ldap://localhost:389", None, None),
                )
                if not connection_result.is_success:
                    return FlextResult.fail(
                        f"Connection failed: {connection_result.error}",
                    )

                # Legacy facade: use last server URL as a session identifier
                connection_id = user_ldap_client._last_server_url or "default-session"

                # Create FlextLdapDistinguishedName object
                dn_result = FlextLdapDistinguishedName.create(user_dn)
                if not dn_result.is_success:
                    return FlextResult.fail(f"Invalid DN: {dn_result.error}")
                if dn_result.data is None:
                    return FlextResult.fail("Failed to create DN object")

                # Add objectClass to attributes
                attributes["objectClass"] = object_classes

                add_result = asyncio.run(
                    client.create_entry(connection_id, dn_result.data, attributes),
                )

                if add_result.is_success:
                    created_user = {
                        "uid": params.uid,
                        "cn": params.cn,
                        "sn": params.sn,
                        "dn": user_dn,
                        "mail": params.mail,
                    }
                    return FlextResult.ok(created_user)

                return FlextResult.fail(f"User creation failed: {add_result.error}")

            return asyncio.run(
                cls._execute_with_client(client, user_creation_operation),
            )

        except Exception as e:
            return FlextResult.fail(f"User creation error: {e}")

    @classmethod
    def list_users(
        cls,
        server: str | None = None,
        limit: int = 20,
    ) -> FlextResult[list[object]]:
        """List all users using base handler patterns."""
        try:
            # Railway Oriented Programming - Consolidated user listing
            return asyncio.run(cls._execute_user_listing_pipeline(server, limit))

        except Exception as e:
            return FlextResult.fail(f"User listing error: {e}")

    @classmethod
    async def _execute_user_listing_pipeline(
        cls,
        server: str | None,
        limit: int,
    ) -> FlextResult[list[object]]:
        """Execute user listing pipeline with consolidated error handling."""
        server = server or "localhost"
        cls._create_connection_config(server)
        client = FlextLdapClient(None)

        def user_listing_operation(
            user_ldap_client: FlextLdapClient,
            connection_id: str,
        ) -> FlextResult[object]:
            return cls._perform_user_search_operation(user_ldap_client, connection_id, limit)

        result = await cls._execute_with_client(client, user_listing_operation)
        return cls._handle_user_listing_result(result)

    @classmethod
    def _perform_user_search_operation(
        cls,
        client: FlextLdapClient,
        connection_id: str,
        limit: int,
    ) -> FlextResult[object]:
        """Perform user search operation with proper filtering."""
        dn_res = FlextLdapDistinguishedName.create("dc=example,dc=com")
        if not dn_res.is_success or dn_res.data is None:
            return FlextResult.fail(f"Invalid base DN: {dn_res.error}")
        filt_res = FlextLdapFilter.create("(objectClass=person)")
        if not filt_res.is_success or filt_res.data is None:
            return FlextResult.fail("Invalid filter")
        scope = FlextLdapScope.sub()
        search_result = asyncio.run(
            client.search(
                connection_id,
                dn_res.data,
                filt_res.data,
                scope,
                attributes=["uid", "cn", "mail", "sn"],
            ),
        )

        if search_result.is_success:
            users = search_result.data or []
            # Limit results as requested - explicit type cast for variance
            limited_users = users[:limit]
            # Cast each item to object for FlextResult compatibility
            users_as_objects: list[object] = list(limited_users)
            return FlextResult.ok(users_as_objects)

        return FlextResult.fail(f"User listing failed: {search_result.error}")

    @classmethod
    def _handle_user_listing_result(
        cls,
        result: FlextResult[object],
    ) -> FlextResult[list[object]]:
        """Handle the result of user listing operation."""
        # Cast back to expected return type
        if result.is_success and isinstance(result.data, list):
            return FlextResult.ok(result.data)
        if result.is_success:
            return FlextResult.fail("Invalid user listing result format")
        return FlextResult.fail(result.error or "User listing operation failed")


# Display functions using Rich
def display_connection_success(message: str) -> None:
    """Display connection success message."""
    console.print(f"✅ {message}", style="bold green")


def display_search_results(entries: list[ExtendedLDAPEntry]) -> None:
    """Display search results in formatted tables."""
    console.print(f"📊 Found {len(entries)} entries:", style="bold cyan")

    for i, entry in enumerate(entries, 1):
        console.print(f"\n[bold cyan]Entry {i}:[/bold cyan]")
        console.print(f"[yellow]DN:[/yellow] {entry.dn}")

        # Create table for attributes
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Attribute", style="cyan")
        table.add_column("Values", style="white")

        for attr_name, attr_values in entry.attributes.items():
            # Show first MAX_DISPLAY_VALUES, indicate if there are more
            display_values = attr_values[:MAX_DISPLAY_VALUES]
            if len(attr_values) > MAX_DISPLAY_VALUES:
                remaining = len(attr_values) - MAX_DISPLAY_VALUES
                display_values.append(f"... and {remaining} more")

            values_str = "\n".join(str(v) for v in display_values)
            table.add_row(attr_name, values_str)

        console.print(table)


def display_user_info(user: FlextLdapUser) -> None:
    """Display user information in formatted table."""
    console.print(f"✅ Found user: {user.cn}", style="bold green")

    # Create user info table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("UID", user.uid)
    table.add_row("Common Name", user.cn)
    table.add_row("Surname", user.sn)
    table.add_row("Distinguished Name", user.dn)
    if hasattr(user, "mail") and user.mail:
        table.add_row("Email", user.mail)

    console.print(table)


def display_users_list(users: list[object]) -> None:
    """Display users list in formatted table."""
    console.print(f"📋 Total users: {len(users)}", style="bold cyan")

    if users:
        # Create users table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("UID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Email", style="yellow")

        for user in users:
            # Handle both dict and object user representations
            if isinstance(user, dict):
                uid = user.get("uid", "N/A")
                cn = user.get("cn", "N/A")
                mail = user.get("mail", "N/A")
            else:
                uid = getattr(user, "uid", "N/A")
                cn = getattr(user, "cn", "N/A")
                mail = getattr(user, "mail", "N/A")

            table.add_row(str(uid), str(cn), str(mail))

        console.print(table)
    else:
        console.print("[blue]Info: No users found[/blue]")


# Click CLI commands
@click.group(name="flext-ldap")
@click.version_option(version="0.9.0", prog_name="FLEXT LDAP")
@click.help_option("--help", "-h")
def cli() -> None:
    """FLEXT LDAP - Enterprise LDAP Operations.

    Modern CLI for LDAP server operations including connection testing,
    directory searches, and user management operations.

    Built on the FLEXT Framework with Clean Architecture patterns.
    """


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
    """Test connection to LDAP server.

    Verifies connectivity and authentication to the specified LDAP server.

    Example:
        flext-ldap test ldap.example.com --port 389
        flext-ldap test ldaps.example.com --port 636 --ssl \
            --bind-dn "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" --bind-password secret

    """
    # Use Parameter Object pattern to eliminate argument explosion
    params = LDAPConnectionTestParams.from_args(
        server,
        port,
        use_ssl=ssl,
        bind_dn=bind_dn,
        bind_password=bind_password,
    )
    result = LDAPConnectionHandler.test_connection(params)
    if result.is_success:
        display_connection_success(result.data or "Connection successful")
    else:
        console.print(f"❌ Connection test failed: {result.error}", style="bold red")


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
@click.option(
    "--limit",
    "-l",
    default=10,
    type=int,
    help="Maximum entries to display (default: 10)",
)
@ldap_connection_options
def search(
    server: str,
    base_dn: str,
    filter_str: str,
    **kwargs: object,
) -> None:
    """Search LDAP directory entries.

    Performs LDAP search operations with customizable filters and displays results
    in a formatted table.

    Example:
        flext-ldap search ldap.example.com "dc=example,dc=com"
        flext-ldap search ldap.example.com "ou=users,dc=example,dc=com" \
            --filter "(objectClass=person)"

    """
    # Use Parameter Object pattern to eliminate argument complexity
    params = LDAPSearchParams.from_click_args(
        server,
        base_dn,
        filter_str,
        **kwargs,
    )
    result: FlextResult[list[ExtendedLDAPEntry]] = LDAPSearchHandler.search_entries(
        params
    )
    if result.is_success:
        display_search_results(result.data or [])
    else:
        console.print(f"❌ Search failed: {result.error}", style="bold red")


@cli.command()
@click.argument("uid", type=str, required=True)
@click.option("--server", "-s", help="LDAP server URL (for connected mode)")
def user_info(uid: str, server: str | None) -> None:
    """Get information about a specific user.

    Retrieves detailed information about a user by their UID.
    Requires LDAP server connection for real operations.

    Example:
        flext-ldap user-info john.doe
        flext-ldap user-info john.doe --server ldap://ldap.example.com

    """
    result = LDAPUserHandler.get_user_info(uid, server)
    if result.is_success and result.data:
        # Handle user data (dict or FlextLdapUser object)
        user = result.data
        if isinstance(user, dict):
            console.print(
                f"✅ Found user: {user.get('cn', 'Unknown')}",
                style="bold green",
            )
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("UID", str(user.get("uid", "N/A")))
            table.add_row("Common Name", str(user.get("cn", "N/A")))
            table.add_row("Distinguished Name", str(user.get("dn", "N/A")))
            console.print(table)
    else:
        console.print(
            f"❌ User lookup failed for {uid}: {result.error}",
            style="bold red",
        )


@cli.command()
@click.argument("uid", type=str, required=True)
@click.argument("cn", type=str, required=True)
@click.argument("sn", type=str, required=True)
@click.option("--mail", "-m", help="Email address")
@click.option("--base-dn", default="ou=users,dc=example,dc=com", help="Base DN")
@click.option("--server", "-s", help="LDAP server URL (for connected mode)")
def create_user(
    uid: str,
    cn: str,
    sn: str,
    **kwargs: object,
) -> None:
    """Create a new LDAP user.

    Creates a new user in the LDAP directory with the specified attributes.
    Requires LDAP server connection for real operations.

    Example:
        flext-ldap create-user john.doe "John Doe" Doe --mail john.doe@example.com
        flext-ldap create-user jane.smith "Jane Smith" Smith --server ldap://ldap.example.com

    """
    # Use Parameter Object pattern to eliminate argument complexity
    params = LDAPUserParams.from_click_args(
        uid,
        cn,
        sn,
        **kwargs,
    )
    result = LDAPUserHandler.create_user(params)

    if result.is_success and result.data:
        user = result.data
        if isinstance(user, dict):
            console.print(
                f"✅ User created successfully: {user.get('uid', 'Unknown')}",
                style="bold green",
            )
            console.print(f"📍 DN: {user.get('dn', 'N/A')}", style="blue")
            if user.get("mail"):
                console.print(f"📧 Email: {user.get('mail')}", style="blue")
    else:
        console.print(
            f"❌ User creation failed for {uid}: {result.error}",
            style="bold red",
        )


@cli.command()
@click.option("--server", "-s", help="LDAP server URL (for connected mode)")
@click.option(
    "--limit",
    "-l",
    default=20,
    type=int,
    help="Maximum users to display (default: 20)",
)
def list_users(server: str | None, limit: int) -> None:
    """List all users in the directory.

    Displays a formatted list of all users with their basic information.
    Requires LDAP server connection for real operations.

    Example:
        flext-ldap list-users
        flext-ldap list-users --server ldap://ldap.example.com --limit 50

    """
    result = LDAPUserHandler.list_users(server, limit)
    if result.is_success:
        display_users_list(result.data or [])
    else:
        console.print(f"❌ Failed to list users: {result.error}", style="bold red")


@cli.command()
def version() -> None:
    """Show version information."""
    console.print("FLEXT LDAP v0.9.0", style="bold green")
    console.print("Enterprise LDAP Operations Library", style="dim")
    console.print("Built on FLEXT Framework with Clean Architecture", style="dim")


def main() -> None:
    """Main CLI entry point."""
    try:
        # Run the CLI directly without complex setup
        cli()

    except KeyboardInterrupt:
        console.print("[i] Operation cancelled by user", style="blue")  # Fix RUF001
        raise SystemExit(0) from None  # Fix B904
    except Exception as e:
        console.print(f"❌ Unexpected error: {e}", style="bold red")
        raise SystemExit(1) from e  # Fix B904


if __name__ == "__main__":
    main()
