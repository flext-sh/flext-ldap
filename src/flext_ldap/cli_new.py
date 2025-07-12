"""Command-line interface for FLEXT LDAP using centralized CLI framework.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import click
from flext_cli.core import (
    PORT,
    FormatterFactory,
    async_command,
    create_cli_group,
    handle_errors,
    standard_options,
)

from flext_ldap.client import LDAPClient, LDAPConfig

# Create the main CLI group
cli, cli_instance = create_cli_group(
    name="FLEXT LDAP",
    version="0.6.0",
    description="Enterprise LDAP Operations",
)


@cli.command()
@click.argument("server")
@click.option(
    "--port",
    type=PORT,
    default=389,
    help="LDAP server port",
)
@click.option(
    "--bind-dn",
    help="Bind DN for authentication",
)
@click.option(
    "--bind-password",
    help="Bind password (use environment variable for security)",
)
@click.option(
    "--use-ssl",
    is_flag=True,
    help="Use LDAPS (SSL/TLS)",
)
@standard_options
@handle_errors
@async_command
@click.pass_context
async def test(
    ctx,
    server,
    port,
    bind_dn,
    bind_password,
    use_ssl,
    output,
    quiet,
    verbose,
    debug,
    no_color,
) -> None:
    """Test LDAP connection to server."""
    cli = ctx.obj["cli"]

    # Update settings
    cli.settings.output_format = output
    cli.settings.quiet = quiet
    cli.settings.verbose = verbose
    cli.settings.debug = debug
    cli.settings.no_color = no_color

    # Adjust port for SSL if needed
    if use_ssl and port == 389:
        port = 636

    config = LDAPConfig(
        server=server,
        port=port,
        bind_dn=bind_dn,
        bind_password=bind_password,
        use_ssl=use_ssl,
    )

    cli.print_info(f"Testing connection to {server}:{port}")

    try:
        async with LDAPClient(config) as client:
            # Connection successful if we reach here
            connection_info = {
                "server": server,
                "port": port,
                "ssl": use_ssl,
                "status": "connected",
                "authenticated": bool(bind_dn),
            }

            # Try to get server info
            try:
                # Get root DSE
                result = await client.search(
                    base_dn="",
                    filter_obj="(objectClass=*)",
                    scope="base",
                )
                if result.is_success and result.value:
                    entry = result.value[0]
                    connection_info["server_info"] = {
                        "naming_contexts": entry.attributes.get("namingContexts", []),
                        "supported_ldap_version": entry.attributes.get(
                            "supportedLDAPVersion",
                            [],
                        ),
                        "vendor": entry.attributes.get("vendorName", ["Unknown"])[0],
                    }
            except Exception:
                # Server info is optional
                pass

            formatter = FormatterFactory.create(output)
            formatter.format(connection_info, cli.console)

            cli.print_success("Connection successful!")

    except (OSError, ValueError) as e:
        cli.print_error(f"Connection failed: {e}")
        ctx.exit(1)


@cli.command()
@click.argument("server")
@click.argument("base_dn")
@click.option(
    "--filter",
    "-f",
    default="(objectClass=*)",
    help="LDAP search filter",
)
@click.option(
    "--port",
    type=PORT,
    default=389,
    help="LDAP server port",
)
@click.option(
    "--bind-dn",
    help="Bind DN for authentication",
)
@click.option(
    "--bind-password",
    help="Bind password (use environment variable for security)",
)
@click.option(
    "--use-ssl",
    is_flag=True,
    help="Use LDAPS (SSL/TLS)",
)
@click.option(
    "--scope",
    type=click.Choice(["base", "one", "sub"]),
    default="sub",
    help="Search scope",
)
@click.option(
    "--limit",
    type=int,
    default=10,
    help="Maximum entries to return",
)
@click.option(
    "--attributes",
    "-a",
    multiple=True,
    help="Attributes to retrieve (can be specified multiple times)",
)
@standard_options
@handle_errors
@async_command
@click.pass_context
async def search(
    ctx,
    server,
    base_dn,
    filter,
    port,
    bind_dn,
    bind_password,
    use_ssl,
    scope,
    limit,
    attributes,
    output,
    quiet,
    verbose,
    debug,
    no_color,
) -> None:
    """Search LDAP entries."""
    cli = ctx.obj["cli"]

    # Update settings
    cli.settings.output_format = output
    cli.settings.quiet = quiet
    cli.settings.verbose = verbose
    cli.settings.debug = debug
    cli.settings.no_color = no_color

    # Adjust port for SSL if needed
    if use_ssl and port == 389:
        port = 636

    config = LDAPConfig(
        server=server,
        port=port,
        base_dn=base_dn,
        bind_dn=bind_dn,
        bind_password=bind_password,
        use_ssl=use_ssl,
    )

    cli.print_info(f"Searching in {base_dn} with filter: {filter}")

    try:
        async with LDAPClient(config) as client:
            result = await client.search(
                base_dn=base_dn,
                filter_obj=filter,
                scope=scope,
                attributes=list(attributes) if attributes else None,
            )

            if result.is_success:
                entries = result.value[:limit]

                # Convert entries to serializable format
                output_data = []
                for entry in entries:
                    entry_data = {
                        "dn": entry.dn,
                        "attributes": {},
                    }

                    # Convert attributes
                    for attr, values in entry.attributes.items():
                        # Limit displayed values for readability
                        if len(values) > 3:
                            entry_data["attributes"][attr] = [
                                *values[:3],
                                f"... and {len(values) - 3} more",
                            ]
                        else:
                            entry_data["attributes"][attr] = values

                    output_data.append(entry_data)

                formatter = FormatterFactory.create(output)
                formatter.format(output_data, cli.console)

                if not quiet:
                    total = len(result.value)
                    shown = len(entries)
                    cli.print_info(f"Found {total} entries, showing {shown}")

                    if total > shown:
                        cli.print_info("Use --limit to see more entries")

            else:
                cli.print_error(f"Search failed: {result.error}")
                ctx.exit(1)

    except (OSError, ValueError) as e:
        cli.print_error(f"Connection failed: {e}")
        ctx.exit(1)


@cli.command()
@click.pass_context
def examples(ctx) -> None:
    """Show usage examples."""
    cli = ctx.obj["cli"]

    examples_text = """
[bold cyan]FLEXT LDAP CLI - Usage Examples[/bold cyan]

[bold]Connection Testing:[/bold]
  flext-ldap test ldap.example.com
  flext-ldap test ldap.example.com --port 636 --use-ssl
  flext-ldap test ldap.example.com --bind-dn "cn=admin,dc=example,dc=com"

[bold]Searching:[/bold]
  # Search all entries
  flext-ldap search ldap.example.com "dc=example,dc=com"

  # Search with filter
  flext-ldap search ldap.example.com "ou=users,dc=example,dc=com" --filter "(objectClass=person)"

  # Authenticated search
  flext-ldap search ldap.example.com "dc=example,dc=com" \\
    --bind-dn "cn=admin,dc=example,dc=com" \\
    --bind-password "secret"

  # Search specific attributes
  flext-ldap search ldap.example.com "dc=example,dc=com" \\
    --filter "(uid=jdoe)" \\
    --attributes cn --attributes mail --attributes uid

  # Limited scope search
  flext-ldap search ldap.example.com "dc=example,dc=com" \\
    --scope one --limit 50

[bold]Output Formats:[/bold]
  flext-ldap search ldap.example.com "dc=example,dc=com" --output json
  flext-ldap test ldap.example.com --output yaml
  flext-ldap search ldap.example.com "dc=example,dc=com" --output csv --quiet

[bold]Environment Variables:[/bold]
  export LDAP_BIND_DN="cn=admin,dc=example,dc=com"
  export LDAP_BIND_PASSWORD="secret"
  flext-ldap search ldap.example.com "dc=example,dc=com"
    """

    cli.console.print(examples_text)


if __name__ == "__main__":
    cli()
