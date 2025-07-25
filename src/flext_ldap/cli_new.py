"""Command-line interface for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import asyncio
from typing import Any

import click

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports
from ldap3.core.exceptions import LDAPException

from flext_ldap.client import FlextLdapClient
from flext_ldap.config import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapSettings,
)

# Backward compatibility aliases
LDAPClient = FlextLdapClient
FlextLDAPSettings = FlextLdapSettings
LDAPAuthConfig = FlextLdapAuthConfig
LDAPConnectionConfig = FlextLdapConnectionConfig


# Use DomainError pattern locally
class FlextConnectionError(Exception):
    """Connection error - local exception class."""


def run_async(func: Any) -> Any:
    """Run async functions in click commands."""
    import functools

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: object) -> Any:
        return asyncio.run(func(*args, **kwargs))

    return wrapper


@click.group(name="flext-infrastructure.databases.flext-ldap")
@click.version_option("0.6.0")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """FLEXT LDAP - Enterprise LDAP Operations."""
    ctx.ensure_object(dict)


@cli.command()
@click.argument("server")
@click.option("--port", default=389, help="LDAP server port")
@click.option("--tls", is_flag=True, help="Use StartTLS")
@click.option("--bind-dn", help="Bind DN for authentication")
@click.option("--bind-password", help="Bind password for authentication")
@click.pass_context
@run_async
async def test(
    ctx: click.Context,
    server: str,
    port: int,
    tls: bool,
    bind_dn: str | None,
    bind_password: str | None,
) -> None:
    """Test LDAP connection with authentication."""
    try:
        # Create settings and configure connection/auth
        settings = FlextLDAPSettings()
        # Use model_copy to update the settings with new connection config
        connection_config = FlextLdapConnectionConfig(
            server=server,
            port=port,
            use_ssl=tls,
        )
        auth_config = FlextLdapAuthConfig(
            bind_dn=bind_dn or "",
            bind_password=bind_password or "",
        )
        settings = settings.model_copy(
            update={
                "connection": connection_config,
                "auth": auth_config,
            },
        )

        # Use ConnectionProtocol pattern with context manager
        async with LDAPClient(settings) as client:
            # Connection is automatically managed by context manager
            if client.is_connected():
                click.echo(f"✅ Successfully connected to {server}:{port}")
            else:
                click.echo("❌ Connection failed")
                ctx.exit(1)

    except (
        OSError,
        ValueError,
        RuntimeError,
        FlextConnectionError,
        LDAPException,
    ) as e:
        click.echo(f"❌ Error: {e}")
        ctx.exit(1)


@cli.command()
@click.argument("server")
@click.argument("base_dn")
@click.option("--port", default=389, help="LDAP server port")
@click.option(
    "--filter",
    "search_filter",
    default="(objectClass=*)",
    help="Search filter",
)
@click.option("--bind-dn", help="Bind DN for authentication")
@click.option("--bind-password", help="Bind password for authentication")
@click.pass_context
@run_async
async def search(
    ctx: click.Context,
    server: str,
    base_dn: str,
    port: int,
    search_filter: str,
    bind_dn: str | None,
    bind_password: str | None,
) -> None:
    """Search LDAP entries with filter."""
    try:
        # Create settings and configure connection/auth
        settings = FlextLDAPSettings()
        # Use model_copy to update the settings with new connection config
        connection_config = FlextLdapConnectionConfig(
            server=server,
            port=port,
        )
        auth_config = FlextLdapAuthConfig(
            bind_dn=bind_dn or "",
            bind_password=bind_password or "",
        )
        settings = settings.model_copy(
            update={
                "connection": connection_config,
                "auth": auth_config,
            },
        )

        client = LDAPClient(settings)

        async with client:
            # Use string filter directly as adapter expects
            result = await client.search(base_dn, search_filter)

            if result.success:
                entries = result.data or []
                click.echo(f"Found {len(entries)} entries:")
                for entry in entries[:10]:  # Show first 10
                    click.echo(f"  DN: {entry.dn}")
                if len(entries) > 10:
                    click.echo(f"  ... and {len(entries) - 10} more")
            else:
                click.echo(f"❌ Search failed: {result.error}")
                msg = "Search operation failed"
                raise click.ClickException(msg)

    except (
        OSError,
        ValueError,
        RuntimeError,
        FlextConnectionError,
        LDAPException,
    ) as e:
        click.echo(f"❌ Error: {e}")
        ctx.exit(1)


if __name__ == "__main__":
    cli()
