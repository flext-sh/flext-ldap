"""Project-local wrapper for shared FLEXT LDAP documentation sync utilities."""

from __future__ import annotations

import os
from pathlib import Path

from flext_quality.docs_maintenance.profiles.advanced.sync import main

_PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
os.environ.setdefault("FLEXT_DOC_PROJECT_ROOT", _PROJECT_ROOT)
os.environ.setdefault("FLEXT_DOC_PROFILE", "advanced")

from flext_quality.docs_maintenance.profiles.advanced.sync import *  # noqa: F403,E402


def _run_cli() -> None:
    """Execute the shared CLI entry point."""
    main()


if __name__ == "__main__":
    _run_cli()
