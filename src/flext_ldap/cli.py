"""CLI entrypoint for flext-ldap — preserves the declared console script."""

from __future__ import annotations

from flext_ldap import t


def main(args: t.StrSequence | None = None) -> int:
    """Console-script entry point — commands are not implemented yet."""
    _ = args
    return 0


__all__: list[str] = ["main"]
