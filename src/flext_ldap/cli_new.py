"""Command-line interface for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import asyncio
from typing import Any

import click

from flext_ldap.client import LDAPClient
from flext_ldap.config import FlextLDAPSettings, LDAPAuthConfig, LDAPConnectionConfig


def run_async(func: Any) -> Any:
    """Run async functions in click commands."""
    import functools

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
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
        settings = FlextLDAPSettings(
            connection=LDAPConnectionConfig(
                server=server,
                port=port,
                use_ssl=tls,
            ),
            auth=LDAPAuthConfig(
                bind_dn=bind_dn or "",
                bind_password=bind_password or "",
            ),
        )

        client = LDAPClient(settings)
        result = await client.connect()

        if result.is_success:
            click.echo(f"✅ Successfully connected to {server}:{port}")
            await client.disconnect()
        else:
            click.echo(f"❌ Connection failed: {result.error}")
            ctx.exit(1)

    except (OSError, ValueError, RuntimeError) as e:
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
        settings = FlextLDAPSettings(
            connection=LDAPConnectionConfig(
                server=server,
                port=port,
            ),
            auth=LDAPAuthConfig(
                bind_dn=bind_dn or "",
                bind_password=bind_password or "",
            ),
        )

        client = LDAPClient(settings)

        async with client:
            # Use string filter directly as adapter expects
            result = await client.search(base_dn, search_filter)

            if result.is_success:
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

    except (OSError, ValueError, RuntimeError) as e:
        click.echo(f"❌ Error: {e}")
        ctx.exit(1)


if __name__ == "__main__":
    cli()
