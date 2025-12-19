"""[PACKAGE] type definitions module - PEP 695 type aliases."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TypeVar

from flext_core import r
from flext_ldif import FlextLdifTypes

# ═══════════════════════════════════════════════════════════════════════════
# TYPEVARS: Only object allowed outside the class
# ═══════════════════════════════════════════════════════════════════════════
# Reuse from t when available

# Only domain-specific TypeVars
# Bound to object to avoid circular import with protocols.py (Tier 0 rule)
# Actual constraint: FlextLdapProtocols.Ldap.LdapEntryProtocol (enforced at runtime by models/services)
FlextLdapEntryT = TypeVar("FlextLdapEntryT", bound=object)
FlextLdapDomainResultT = TypeVar("FlextLdapDomainResultT")


# ═══════════════════════════════════════════════════════════════════════════
# SINGLE CLASS WITH NESTED CLASSES
# ═══════════════════════════════════════════════════════════════════════════
class FlextLdapTypes(FlextLdifTypes):
    """[Package] type definitions extending FlextLdifTypes.

    RULES:
    ───────
    1. TypeVars outside the class (only case allowed)
    2. PEP 695 type aliases inside nested classes
    3. Complex types composed with Protocols
    4. ZERO simple aliases - use direct types
    5. Composition with t, no duplication

    NOTE: Progress callback types (MultiPhaseProgressCallback, ProgressCallbackUnion,
    LdapProgressCallback) are defined in FlextLdapModels.Types to avoid circular imports.
    Use m.Types.* for those types.
    """

    class Ldap:
        """LDAP-specific type aliases with 2-level maximum nesting.

        Architecture: 2-level maximum namespace (t.Ldap.SubDomain.Type)
        Never: t.Ldap.SubDomain.SubSub.Type (3+ levels forbidden)

        This class serves as the LDAP namespace for cross-project access.
        Usage: t.Ldap.Connection.Config, t.Ldap.Operation.Result, etc.
        """

        # Connection types
        class Connection:
            """Connection-related type aliases."""

            type Config = object  # Bounded to ConnectionConfig at runtime
            type Options = Mapping[str, object]  # Connection options

        # Operation types
        class Operation:
            """Operation-related type aliases."""

            type Result[T] = r[T]
            type Changes = dict[str, list[tuple[str, list[str]]]]
            type Attributes = Mapping[str, Sequence[str]]
            type AttributeDict = dict[str, list[str]]
            """Type alias for LDAP attribute mappings (attribute name to value list)."""
            type Ldap3EntryValue = (
                str
                | bytes
                | int
                | float
                | bool
                | Sequence[str | bytes | int | float | bool]
                | None
            )
            """Type alias for ldap3 entry attribute values."""

        # Entry types
        class Entry:
            """Entry-related type aliases."""

            type Instance = object  # Bounded to Entry at runtime
            type Collection = Sequence[object]

        # Search types
        class Search:
            """Search-related type aliases."""

            type Options = object  # Bounded to SearchOptions at runtime
            type Filter = str
            type Scope = str


# Alias for simplified usage
t = FlextLdapTypes


__all__ = [
    "FlextLdapDomainResultT",
    "FlextLdapEntryT",
    "FlextLdapTypes",
    "t",
]
