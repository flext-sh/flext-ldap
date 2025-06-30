"""Main entry point for ldap-core-shared CLI.

This module provides the main entry point for running ldap-core-shared
as a Python module with command-line interface.

Usage:
    python -m flext_ldap --help
    python -m flext_ldap input.schema output.ldif
    python -m flext_ldap-manager install schema.ldif
    python -m flext_ldapump data.der
    python -m flext_ldapm PLAIN -u user
"""

from __future__ import annotations

import sys

try:
    from flext_ldap.cli import cli_main

    if __name__ == "__main__":
        cli_main()
except ImportError:
    sys.exit(1)
except KeyboardInterrupt:
    sys.exit(130)
except Exception:  # noqa: BLE001
    # Catch-all for unexpected errors to prevent crashes
    sys.exit(1)
