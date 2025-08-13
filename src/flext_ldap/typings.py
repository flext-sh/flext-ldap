"""Centralized typings facade for flext-ldap.

- Extends flext-core types and re-exports LDAP-specific types
- Keep `types.py` as domain-specific definitions; import here as public API
"""

from __future__ import annotations

from flext_core.typings import E, F, FlextTypes as CoreFlextTypes, U, V

# Re-export LDAP domain-specific types for a single import point
# Note: P, R, T are imported from flext_ldap.types to avoid conflicts
from flext_ldap.types import *  # noqa: F403


class FlextTypes(CoreFlextTypes):
    """LDAP domain-specific types can extend here."""


__all__ = [
    "FlextTypes",
    "U",
    "V",
    "E",
    "F",
    # T, P, R are defined in flext_ldap.types and imported via *
] + [name for name in dir() if not name.startswith("_")]
