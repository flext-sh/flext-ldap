"""Main CLI Entry Point for LDAP Core Shared Tools.

This module provides the main command-line interface entry point with
subcommands for schema management, ASN.1 processing, and SASL testing.

The CLI is built using Click framework for modern command-line experience
with comprehensive help, validation, and error handling.

Usage:
    $ python -m ldap_core_shared.cli --help
    $ python -m ldap_core_shared.cli schema2ldif --help
    $ python -m ldap_core_shared.cli ldap-schema-manager --help
    $ python -m ldap_core_shared.cli sasl-test --help

Example Commands:
    $ python -m ldap_core_shared.cli schema2ldif input.schema output.ldif
    $ python -m ldap_core_shared.cli ldap-schema-manager install custom.ldif
    $ python -m ldap_core_shared.cli sasl-test --mechanism PLAIN --username test
"""

from __future__ import annotations

import logging
import sys
import traceback

try:
    import click

    CLICK_AVAILABLE = True
except ImportError:
    CLICK_AVAILABLE = False

# CLI module imports
from ldap_core_shared.cli.asn1 import run_asn1_tool
from ldap_core_shared.cli.sasl import run_sasl_test
from ldap_core_shared.cli.schema import run_schema2ldif, run_schema_manager

if CLICK_AVAILABLE:

    @click.group()
    @click.version_option()
    @click.option(
        "--verbose",
        "-v",
        count=True,
        help="Increase verbosity (can be used multiple times)",
    )
    @click.option(
        "--quiet",
        "-q",
        is_flag=True,
        help="Suppress output except errors",
    )
    @click.option(
        "--config",
        type=click.Path(exists=True),
        help="Configuration file path",
    )
    @click.pass_context
    def main(
        ctx: click.Context,
        verbose: int,
        quiet: bool,
        config: str | None,
    ) -> None:
        """LDAP Core Shared - Schema, ASN.1, and SASL Tools.

        This toolkit provides command-line utilities for LDAP schema management,
        ASN.1 encoding/decoding, and SASL authentication testing equivalent to
        the Perl tools but with enhanced functionality.

        Use --help with any subcommand for detailed information.
        """
        # Ensure context exists
        ctx.ensure_object(dict)

        # Configure logging level based on verbosity
        if quiet:
            log_level = "ERROR"
        elif verbose == 0:
            log_level = "WARNING"
        elif verbose == 1:
            log_level = "INFO"
        else:
            log_level = "DEBUG"

        ctx.obj["log_level"] = log_level
        ctx.obj["config"] = config

        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

    @main.command("schema2ldif")
    @click.argument("input_file", type=click.Path(exists=True))
    @click.argument("output_file", type=click.Path())
    @click.option(
        "--format",
        "-f",
        type=click.Choice(["schema", "ldif", "auto"]),
        default="auto",
        help="Input format (auto-detected if not specified)",
    )
    @click.option(
        "--validate",
        "-V",
        is_flag=True,
        help="Validate schema before conversion",
    )
    @click.option(
        "--pretty",
        "-p",
        is_flag=True,
        help="Pretty-print output with formatting",
    )
    @click.option(
        "--include-comments",
        is_flag=True,
        help="Include comments in output",
    )
    @click.pass_context
    def schema2ldif_command(
        ctx: click.Context,
        input_file: str,
        output_file: str,
        format: str,
        validate: bool,
        pretty: bool,
        include_comments: bool,
    ) -> None:
        """Convert schema files between .schema and .ldif formats.

        This command converts LDAP schema files between OpenLDAP .schema format
        and LDIF format, equivalent to the schema2ldif-perl-converter tool.

        Examples:
          Convert .schema to .ldif:
          $ ldap-core-shared schema2ldif input.schema output.ldif

          Convert with validation:
          $ ldap-core-shared schema2ldif -V input.schema output.ldif

          Pretty-print output:
          $ ldap-core-shared schema2ldif -p input.schema output.ldif

        """
        try:
            success = run_schema2ldif(
                input_file=input_file,
                output_file=output_file,
                input_format=format,
                validate=validate,
                pretty_print=pretty,
                include_comments=include_comments,
                verbose=ctx.obj.get("log_level") == "DEBUG",
            )

            if not success:
                sys.exit(1)

        except ImportError:
            click.echo("Error: Schema conversion functionality not available", err=True)
            click.echo("Please ensure all dependencies are installed", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            if ctx.obj.get("log_level") == "DEBUG":
                traceback.print_exc()
            sys.exit(1)

    @main.command("ldap-schema-manager")
    @click.argument(
        "action",
        type=click.Choice(["install", "remove", "list", "validate", "backup"]),
    )
    @click.option(
        "--file",
        "-f",
        type=click.Path(exists=True),
        help="Schema file to process",
    )
    @click.option(
        "--name",
        "-n",
        help="Schema name for operations",
    )
    @click.option(
        "--server",
        "-s",
        help="LDAP server URL",
    )
    @click.option(
        "--bind-dn",
        "-D",
        help="Bind DN for LDAP operations",
    )
    @click.option(
        "--bind-password",
        "-w",
        help="Bind password (use -W for prompt)",
    )
    @click.option(
        "--bind-password-prompt",
        "-W",
        is_flag=True,
        help="Prompt for bind password",
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        help="Show what would be done without making changes",
    )
    @click.option(
        "--force",
        is_flag=True,
        help="Force operation even if dangerous",
    )
    @click.pass_context
    def ldap_schema_manager_command(
        ctx: click.Context,
        action: str,
        file: str | None,
        name: str | None,
        server: str | None,
        bind_dn: str | None,
        bind_password: str | None,
        bind_password_prompt: bool,
        dry_run: bool,
        force: bool,
    ) -> None:
        """Manage LDAP schemas on OpenLDAP servers.

        This command provides comprehensive schema management operations
        including installation, removal, validation, and backup.

        Examples:
          Install schema from file:
          $ ldap-core-shared ldap-schema-manager install -f custom.ldif

          List installed schemas:
          $ ldap-core-shared ldap-schema-manager list -s ldap://server

          Remove schema:
          $ ldap-core-shared ldap-schema-manager remove -n custom

          Validate schema file:
          $ ldap-core-shared ldap-schema-manager validate -f schema.ldif

        """
        try:
            # Handle password prompt
            if bind_password_prompt:
                bind_password = click.prompt("Bind password", hide_input=True)

            success = run_schema_manager(
                action=action,
                file=file,
                name=name,
                server=server,
                bind_dn=bind_dn,
                bind_password=bind_password,
                dry_run=dry_run,
                force=force,
                verbose=ctx.obj.get("log_level") == "DEBUG",
            )

            if not success:
                sys.exit(1)

        except ImportError:
            click.echo("Error: Schema management functionality not available", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            if ctx.obj.get("log_level") == "DEBUG":
                traceback.print_exc()
            sys.exit(1)

    @main.command("asn1-tool")
    @click.argument(
        "action",
        type=click.Choice(["encode", "decode", "dump", "validate"]),
    )
    @click.option(
        "--input",
        "-i",
        type=click.Path(exists=True),
        help="Input file (stdin if not specified)",
    )
    @click.option(
        "--output",
        "-o",
        type=click.Path(),
        help="Output file (stdout if not specified)",
    )
    @click.option(
        "--format",
        "-f",
        type=click.Choice(["ber", "der", "hex", "base64"]),
        default="der",
        help="Encoding format",
    )
    @click.option(
        "--schema",
        type=click.Path(exists=True),
        help="ASN.1 schema file for validation",
    )
    @click.pass_context
    def asn1_tool_command(
        ctx: click.Context,
        action: str,
        input: str | None,
        output: str | None,
        format: str,
        schema: str | None,
    ) -> None:
        """ASN.1 encoding, decoding, and analysis tools.

        This command provides ASN.1 processing capabilities equivalent
        to perl-Convert-ASN1 functionality with additional utilities.

        Examples:
          Decode ASN.1 file:
          $ ldap-core-shared asn1-tool decode -i data.der -o data.txt

          Encode data:
          $ ldap-core-shared asn1-tool encode -i data.txt -o data.der

          Dump ASN.1 structure:
          $ ldap-core-shared asn1-tool dump -i data.der

        """
        try:
            success = run_asn1_tool(
                action=action,
                input_file=input,
                output_file=output,
                format=format,
                schema_file=schema,
                verbose=ctx.obj.get("log_level") == "DEBUG",
            )

            if not success:
                sys.exit(1)

        except ImportError:
            click.echo("Error: ASN.1 functionality not available", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            if ctx.obj.get("log_level") == "DEBUG":
                traceback.print_exc()
            sys.exit(1)

    @main.command("sasl-test")
    @click.option(
        "--mechanism",
        "-m",
        type=click.Choice(["PLAIN", "DIGEST-MD5", "EXTERNAL", "ANONYMOUS"]),
        required=True,
        help="SASL mechanism to test",
    )
    @click.option(
        "--username",
        "-u",
        help="Username for authentication",
    )
    @click.option(
        "--password",
        "-p",
        help="Password for authentication",
    )
    @click.option(
        "--password-prompt",
        "-P",
        is_flag=True,
        help="Prompt for password",
    )
    @click.option(
        "--realm",
        "-r",
        help="Authentication realm",
    )
    @click.option(
        "--server",
        "-s",
        default="localhost",
        help="Server hostname",
    )
    @click.option(
        "--service",
        default="ldap",
        help="Service name",
    )
    @click.option(
        "--interactive",
        "-I",
        is_flag=True,
        help="Interactive mode for callbacks",
    )
    @click.pass_context
    def sasl_test_command(
        ctx: click.Context,
        mechanism: str,
        username: str | None,
        password: str | None,
        password_prompt: bool,
        realm: str | None,
        server: str,
        service: str,
        interactive: bool,
    ) -> None:
        """Test SASL authentication mechanisms.

        This command provides SASL authentication testing equivalent
        to perl-Authen-SASL functionality with debugging capabilities.

        Examples:
          Test PLAIN mechanism:
          $ ldap-core-shared sasl-test -m PLAIN -u user -P

          Test DIGEST-MD5:
          $ ldap-core-shared sasl-test -m DIGEST-MD5 -u user -r example.com

          Interactive testing:
          $ ldap-core-shared sasl-test -m DIGEST-MD5 -I

        """
        try:
            # Handle password prompt
            if password_prompt:
                password = click.prompt("Password", hide_input=True)

            success = run_sasl_test(
                mechanism=mechanism,
                username=username,
                password=password,
                realm=realm,
                server=server,
                service=service,
                interactive=interactive,
                verbose=ctx.obj.get("log_level") == "DEBUG",
            )

            if not success:
                sys.exit(1)

        except ImportError:
            click.echo("Error: SASL functionality not available", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            if ctx.obj.get("log_level") == "DEBUG":
                traceback.print_exc()
            sys.exit(1)

    if __name__ == "__main__":
        main()

else:
    # Fallback implementation without Click
    def main() -> None:
        """Fallback main function when Click is not available."""
        sys.exit(1)


# CLI entry point for python -m usage
def cli_main() -> None:
    """Entry point for python -m ldap_core_shared.cli."""
    if CLICK_AVAILABLE:
        main()
    else:
        sys.exit(1)
