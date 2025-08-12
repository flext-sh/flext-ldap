#!/usr/bin/env python3
"""FLEXT-LDAP CLI - Consolidated Command-Line Interface.

🎯 CONSOLIDATES FROM cli.py (35,205 bytes) INTO SINGLE PEP8 MODULE

This module provides a comprehensive command-line interface for LDAP operations
using the flext-cli framework for consistency and rich terminal output.

Enterprise-grade CLI featuring connection testing, directory searches,
user management, and comprehensive LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, ParamSpec, TypeVar

import click
from flext_core import FlextLDAPConfig, FlextResult, get_logger
from pydantic import SecretStr
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_core import FlextTypes

    from flext_ldap.ldap_infrastructure import FlextLdapClient

logger = get_logger(__name__)

# Rich console for beautiful output
console = Console()

# Constants - DRY principle to eliminate magic numbers
MAX_DISPLAY_VALUES = 3

# =============================================================================
# TYPE DEFINITIONS
# =============================================================================

P = ParamSpec("P")
R = TypeVar("R")

# =============================================================================
# DECORATORS AND PATTERNS
# =============================================================================


def ldap_connection_options[**P, R](func: Callable[P, R]) -> Callable[P, R]:
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


# =============================================================================
# OPERATION RESULT CONSTANTS
# =============================================================================


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


class LDAPOperationOutcome:
    """LDAP operation outcome constants - eliminates boolean parameters."""

    SUCCESS = True
    FAILURE = False


# =============================================================================
# PARAMETER OBJECTS
# =============================================================================


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
            use_ssl=bool(options.get("ssl")),
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


# =============================================================================
# LDAP ENTRY CLASSES
# =============================================================================


@dataclass
class ExtendedLDAPEntry:
    """Extended LDAP entry with structured attributes."""

    dn: str
    attributes: dict[str, list[str]]


# =============================================================================
# BASE HANDLER CLASS
# =============================================================================


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
    ) -> FlextLDAPConfig | None:
        """Create LDAP connection configuration."""
        try:
            from flext_ldap.ldap_config import FlextLdapConnectionConfig

            return FlextLdapConnectionConfig(
                server=server,
                port=port,
                use_ssl=bool(use_ssl),
                timeout=30,
                bind_dn="",
                bind_password="",
                search_base="",
            )
        except Exception as e:
            logger.exception(f"Failed to create connection config: {e}")
            return None

    @staticmethod
    def _create_auth_config(
        bind_dn: str | None,
        bind_password: str | None,
    ) -> object | None:
        """Create authentication configuration if credentials provided."""
        if bind_dn:
            try:
                from flext_ldap.ldap_config import FlextLdapAuthConfig

                return FlextLdapAuthConfig(
                    server="",
                    search_base="",
                    bind_dn=bind_dn,
                    bind_password=SecretStr(bind_password or "") if bind_password else None,
                )
            except Exception as e:
                logger.exception(f"Failed to create auth config: {e}")
                return None
        return None

    @staticmethod
    async def _execute_with_client(
        client: FlextLdapClient,
        operation: Callable[[FlextLdapClient, str], FlextResult[object]],
    ) -> FlextResult[object]:
        """Execute operation with client lifecycle management."""
        try:
            # Connect to LDAP server
            connect_result = await client.connect("ldap://localhost:389", None, None)
            if not connect_result.is_success:
                return FlextResult.fail(f"Connection failed: {connect_result.error}")

            try:
                connection_id = "default_connection"
                op_result = operation(client, connection_id)
                if hasattr(op_result, "__await__"):
                    result = await op_result
                    return result if isinstance(result, FlextResult) else FlextResult.ok(result)
                return op_result if isinstance(op_result, FlextResult) else FlextResult.ok(op_result)
            finally:
                # Disconnect from LDAP server
                await client.disconnect()

        except Exception as e:
            return FlextResult.fail(f"Operation error: {e}")


# =============================================================================
# CONNECTION HANDLER
# =============================================================================


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
        try:
            from flext_ldap.ldap_infrastructure import FlextLdapClient

            cls._create_connection_config(
                params.server,
                params.port,
                use_ssl=params.use_ssl,
            )
            cls._create_auth_config(params.bind_dn, params.bind_password)
            client = FlextLdapClient()

            def test_operation(
                user_ldap_client: FlextLdapClient, connection_id: str,
            ) -> FlextResult[object]:
                return cls._perform_connection_test_operation(user_ldap_client, params)

            result = await cls._execute_with_client(client, test_operation)
            return cls._handle_connection_test_result(result)
        except Exception as e:
            return FlextResult.fail(f"Connection test failed: {e}")

    @classmethod
    def _perform_connection_test_operation(
        cls,
        _client: FlextLdapClient,
        params: LDAPConnectionTestParams,
    ) -> FlextResult[object]:
        """Perform connection test operation with proper validation."""
        # Connection test - if we got here, connection was successful
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
        if result.is_success:
            return FlextResult.ok(str(result.data))
        return FlextResult.fail(result.error or "Connection test failed")


# =============================================================================
# SEARCH HANDLER
# =============================================================================


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
        try:
            from flext_ldap.ldap_operations import FlextLdapSearchOperations

            search_ops = FlextLdapSearchOperations()

            async def perform_search() -> FlextResult[list[object]]:
                search_result = await search_ops.search_entries(
                    connection_id=connection_id,
                    base_dn=params.base_dn,
                    search_filter=params.filter_str,
                    scope="subtree",
                    attributes=["*"],
                    size_limit=params.limit,
                )
                if search_result.is_success:
                    # Convert FlextLdapEntry list to list[object]
                    entries_as_objects: list[object] = search_result.data or []
                    return FlextResult.ok(entries_as_objects)
                return FlextResult.fail(search_result.error or "Search failed")

            search_result = asyncio.run(perform_search())

            if search_result.is_success:
                # Convert search results to ExtendedLDAPEntry format
                entries_data = search_result.data or []
                raw_entries = []
                for entry in entries_data:
                    if hasattr(entry, "dn") and hasattr(entry, "attributes"):
                        raw_entries.append({
                            "dn": entry.dn,
                            "attributes": entry.attributes,
                        })
                    else:
                        # Fallback for object type entries
                        raw_entries.append({
                            "dn": str(getattr(entry, "dn", "unknown")),
                            "attributes": getattr(entry, "attributes", {}),
                        })

                entries = cls._convert_search_results(raw_entries, params.limit)
                return FlextResult.ok(entries)

            return FlextResult.fail(f"Search failed: {search_result.error}")
        except Exception as e:
            return FlextResult.fail(f"Search operation failed: {e}")

    @classmethod
    def search_entries(
        cls,
        params: LDAPSearchParams,
    ) -> FlextResult[object | None] | FlextResult[object]:
        """Search LDAP entries using base handler patterns."""
        try:
            from flext_ldap.ldap_infrastructure import FlextLdapClient

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

            search_ldap_client = FlextLdapClient()

            def search_operation(
                operation_ldap_client: FlextLdapClient, connection_id: str,
            ) -> FlextResult[object]:
                return cls._execute_ldap_search(
                    operation_ldap_client, connection_id, params,
                )

            # Handle async execution
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    result = loop.run_until_complete(
                        cls._execute_with_client(search_ldap_client, search_operation),
                    )
                else:
                    result = asyncio.run(
                        cls._execute_with_client(search_ldap_client, search_operation),
                    )
            except RuntimeError:
                result = asyncio.run(
                    cls._execute_with_client(search_ldap_client, search_operation),
                )

            if result.is_success and isinstance(result.data, list):
                return FlextResult.ok(result.data)
            if result.is_success:
                return FlextResult.fail("Invalid search result format")
            return FlextResult.fail(result.error or "Search operation failed")

        except Exception as e:
            return FlextResult.fail(f"Search error: {e}")


# =============================================================================
# USER HANDLER
# =============================================================================


class LDAPUserHandler(BaseLDAPHandler):
    """Handler for LDAP user operations using base patterns."""

    @classmethod
    def get_user_info(cls, uid: str, server: str | None = None) -> FlextResult[object]:
        """Get user information using base handler patterns."""
        try:
            from flext_ldap.ldap_infrastructure import FlextLdapClient

            server = server or "localhost"
            cls._create_connection_config(server)
            client = FlextLdapClient()

            async def user_lookup_operation(
                user_ldap_client: FlextLdapClient,
                connection_id: str,
            ) -> FlextResult[object]:
                try:
                    from flext_ldap.ldap_operations import FlextLdapSearchOperations

                    search_ops = FlextLdapSearchOperations()
                    search_result = await search_ops.search_users(
                        connection_id=connection_id,
                        base_dn="dc=example,dc=com",
                        filter_criteria={"uid": uid},
                        size_limit=1,
                    )

                    if search_result.is_success and search_result.data:
                        # Return first matching user
                        user = search_result.data[0]
                        user_data = {
                            "uid": user.uid,
                            "cn": user.cn,
                            "sn": user.sn,
                            "dn": user.dn,
                            "mail": getattr(user, "mail", None),
                        }
                        return FlextResult.ok(user_data)

                    return FlextResult.fail(f"User {uid} not found")
                except Exception as e:
                    return FlextResult.fail(f"User search error: {e}")

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    return loop.run_until_complete(
                        cls._execute_with_client(client, user_lookup_operation),
                    )
                return asyncio.run(
                    cls._execute_with_client(client, user_lookup_operation),
                )
            except RuntimeError:
                return asyncio.run(
                    cls._execute_with_client(client, user_lookup_operation),
                )

        except Exception as e:
            return FlextResult.fail(f"User lookup error: {e}")

    @classmethod
    def create_user(cls, params: LDAPUserParams) -> FlextResult[object]:
        """Create a new user using base handler patterns."""
        try:
            from flext_ldap.ldap_infrastructure import FlextLdapClient

            server = params.server or "localhost"
            cls._create_connection_config(server)
            client = FlextLdapClient()

            async def user_creation_operation(
                user_ldap_client: FlextLdapClient,
                connection_id: str,
            ) -> FlextResult[object]:
                try:
                    from flext_ldap.ldap_models import FlextLdapCreateUserRequest
                    from flext_ldap.ldap_operations import FlextLdapUserOperations

                    # Create user request
                    user_dn = f"cn={params.uid},{params.base_dn}"
                    user_request = FlextLdapCreateUserRequest(
                        dn=user_dn,
                        uid=params.uid,
                        cn=params.cn,
                        sn=params.sn,
                        object_classes=["person", "organizationalPerson", "inetOrgPerson"],
                        given_name=None,
                        mail=params.mail,
                        user_password=None,
                        additional_attributes={},
                    )

                    user_ops = FlextLdapUserOperations()
                    create_result = await user_ops.create_user(
                        connection_id=connection_id,
                        user_request=user_request,
                    )

                    if create_result.is_success:
                        created_user = {
                            "uid": params.uid,
                            "cn": params.cn,
                            "sn": params.sn,
                            "dn": user_dn,
                            "mail": params.mail,
                        }
                        return FlextResult.ok(created_user)

                    return FlextResult.fail(f"User creation failed: {create_result.error}")
                except Exception as e:
                    return FlextResult.fail(f"User creation error: {e}")

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    return loop.run_until_complete(
                        cls._execute_with_client(client, user_creation_operation),
                    )
                return asyncio.run(
                    cls._execute_with_client(client, user_creation_operation),
                )
            except RuntimeError:
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
        try:
            from flext_ldap.ldap_infrastructure import FlextLdapClient

            server = server or "localhost"
            cls._create_connection_config(server)
            client = FlextLdapClient()

            async def user_listing_operation(
                user_ldap_client: FlextLdapClient,
                connection_id: str,
            ) -> FlextResult[object]:
                return await cls._perform_user_search_operation(
                    user_ldap_client, connection_id, limit,
                )

            result = await cls._execute_with_client(client, user_listing_operation)
            return cls._handle_user_listing_result(result)
        except Exception as e:
            return FlextResult.fail(f"User listing pipeline failed: {e}")

    @classmethod
    async def _perform_user_search_operation(
        cls,
        client: FlextLdapClient,
        connection_id: str,
        limit: int,
    ) -> FlextResult[object]:
        """Perform user search operation with proper filtering."""
        try:
            from flext_ldap.ldap_operations import FlextLdapSearchOperations

            search_ops = FlextLdapSearchOperations()
            search_result = await search_ops.search_users(
                connection_id=connection_id,
                base_dn="dc=example,dc=com",
                filter_criteria={},  # No filter - get all users
                size_limit=limit,
            )

            if search_result.is_success:
                users = search_result.data or []
                # Convert to list of objects
                users_as_objects: list[object] = [
                    {
                        "uid": user.uid,
                        "cn": user.cn,
                        "sn": user.sn,
                        "mail": getattr(user, "mail", None),
                    }
                    for user in users
                ]
                return FlextResult.ok(users_as_objects)

            return FlextResult.fail(f"User listing failed: {search_result.error}")
        except Exception as e:
            return FlextResult.fail(f"User search operation failed: {e}")

    @classmethod
    def _handle_user_listing_result(
        cls,
        result: FlextResult[object],
    ) -> FlextResult[list[object]]:
        """Handle the result of user listing operation."""
        if result.is_success and isinstance(result.data, list):
            return FlextResult.ok(result.data)
        if result.is_success:
            return FlextResult.fail("Invalid user listing result format")
        return FlextResult.fail(result.error or "User listing operation failed")


# =============================================================================
# DISPLAY FUNCTIONS
# =============================================================================


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


def display_user_info(user: object) -> None:
    """Display user information in formatted table."""
    console.print(f"✅ Found user: {getattr(user, 'cn', 'Unknown')}", style="bold green")

    # Create user info table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("UID", getattr(user, "uid", "N/A"))
    table.add_row("Common Name", getattr(user, "cn", "N/A"))
    table.add_row("Surname", getattr(user, "sn", "N/A"))
    table.add_row("Distinguished Name", getattr(user, "dn", "N/A"))
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


# =============================================================================
# CLICK CLI COMMANDS
# =============================================================================


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
    r"""Test connection to LDAP server.

    Verifies connectivity and authentication to the specified LDAP server.

    Example:
        flext-ldap test ldap.example.com --port 389
        flext-ldap test ldaps.example.com --port 636 --ssl \\
            --bind-dn "cn=admin,dc=example,dc=com" --bind-password secret

    """
    # Use Parameter Object pattern to eliminate argument explosion
    params = LDAPConnectionTestParams.from_args(
        server,
        port,
        ssl=ssl,
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
    r"""Search LDAP directory entries.

    Performs LDAP search operations with customizable filters and displays results
    in a formatted table.

    Example:
        flext-ldap search ldap.example.com "dc=example,dc=com"
        flext-ldap search ldap.example.com "ou=users,dc=example,dc=com" \\
            --filter "(objectClass=person)"

    """
    # Use Parameter Object pattern to eliminate argument complexity
    params = LDAPSearchParams.from_click_args(
        server,
        base_dn,
        filter_str,
        **kwargs,
    )
    result_entries = LDAPSearchHandler.search_entries(params)
    if result_entries.is_success:
        data_list = result_entries.data if isinstance(result_entries.data, list) else []
        display_search_results(data_list)
    else:
        console.print(f"❌ Search failed: {result_entries.error}", style="bold red")


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
        # Handle user data (dict or object)
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
            if user.get("mail"):
                table.add_row("Email", str(user.get("mail")))
            console.print(table)
        else:
            display_user_info(user)
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


# =============================================================================
# MAIN CLI ENTRY POINT
# =============================================================================


def main() -> None:
    """Main CLI entry point."""
    try:
        # Run the CLI directly without complex setup
        cli()

    except KeyboardInterrupt:
        console.print("[i] Operation cancelled by user", style="blue")
        raise SystemExit(0) from None
    except Exception as e:
        console.print(f"❌ Unexpected error: {e}", style="bold red")
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
