"""Main entry point for ldap-core-shared CLI.

This module provides the main entry point for running ldap-core-shared
as a Python module with command-line interface.

Usage:
    python -m ldap_core_shared --help
    python -m ldap_core_shared schema2ldif input.schema output.ldif
    python -m ldap_core_shared ldap-schema-manager install schema.ldif
    python -m ldap_core_shared asn1-tool dump data.der
    python -m ldap_core_shared sasl-test -m PLAIN -u user
"""

from __future__ import annotations

import sys

try:
    from ldap_core_shared.cli.main import cli_main

    if __name__ == "__main__":
        cli_main()
except ImportError:
    sys.exit(1)
except KeyboardInterrupt:
    sys.exit(130)
except Exception:  # noqa: BLE001
    # Catch-all for unexpected errors to prevent crashes
    sys.exit(1)
