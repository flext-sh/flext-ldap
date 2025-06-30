"""Command-Line Interface Tools for LDAP Core Shared.

This package provides command-line utilities for LDAP schema management,
ASN.1 processing, and SASL authentication testing, equivalent to the
Perl tools but with enhanced functionality and modern CLI features.

Available Commands:
    - schema2ldif: Convert schema files between formats
    - ldap-schema-manager: Manage LDAP schemas
    - asn1-tool: ASN.1 encoding/decoding utilities
    - sasl-test: SASL authentication testing

Architecture:
    - Click-based CLI framework for modern command-line experience
    - Rich output formatting with colors and progress bars
    - Comprehensive error handling and validation
    - Configuration file support
    - Logging and debugging capabilities

Usage Example:
    $ python -m flext_ldap.cli schema2ldif --input schema.schema --output schema.ldif
    $ python -m flext_ldaphema-manager install --file custom.ldif
    $ python -m flext_ldapst --mechanism DIGEST-MD5 --username user

References:
    - schema2ldif-perl-converter: Schema conversion tool equivalent
    - ldap-schema-manager: Schema management utilities
    - ASN.1 and SASL testing tools
"""

from __future__ import annotations

# Import CLI modules when available
try:
    from flext_ldap.cli import asn1_cli, main, sasl_cli, schema_cli
    from flext_ldap.enterprise_tools import cli as enterprise_cli

    __all__ = [
        "asn1_cli",
        "enterprise_cli",
        "main",
        "sasl_cli",
        "schema_cli",
    ]

except ImportError:
    # Import only available modules
    try:
        from flext_ldapise_tools import cli as enterprise_cli

        __all__ = ["enterprise_cli"]
    except ImportError:
        __all__ = []


def get_version() -> str:
    """Get package version for CLI tools.

    Returns:
        Version string
    """
    try:
        from flext_ldap import __version__

        return __version__
    except ImportError:
        return "0.1.0-dev"


# TODO: Integration points for complete CLI functionality:
#
# 1. Schema Management CLI:
#    - schema2ldif: Schema format conversion tool
#    - ldap-schema-manager: Complete schema management
#    - Schema validation and testing utilities
#    - Batch processing capabilities
#
# 2. ASN.1 Processing CLI:
#    - ASN.1 encoding/decoding tools
#    - Structure analysis and validation
#    - Hex dump and debugging utilities
#    - Schema definition parsing
#
# 3. SASL Testing CLI:
#    - SASL mechanism testing
#    - Authentication flow simulation
#    - Security layer testing
#    - Performance benchmarking
#
# 4. Configuration Management:
#    - Configuration file support
#    - Environment variable integration
#    - Profile management
#    - Default settings
#
# 5. Output Formatting:
#    - Rich console output with colors
#    - Progress bars for long operations
#    - JSON/YAML output formats
#    - Structured logging
#
# 6. Error Handling:
#    - User-friendly error messages
#    - Debug mode with stack traces
#    - Exit codes and error reporting
#    - Help system and documentation
