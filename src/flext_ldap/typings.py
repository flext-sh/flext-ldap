"""[PACKAGE] type definitions module - PEP 695 type aliases."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

from flext_core import r
from flext_ldif import FlextLdifTypes

from flext_ldap.constants import (
    c,  # noqa: F401 - Required by architecture rule 2: typings must import constants
)

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
        """LDAP-specific type aliases.

        NOTE: For strict type checking, use FlextLdapModels.Types which has
        typed versions:
        - m.Types.LdapProgressCallback
        - m.Types.MultiPhaseProgressCallback
        - m.Types.ProgressCallbackUnion

        This class also serves as the LDAP namespace for cross-project access.
        Usage: Other projects can reference `t.Ldap.Entry.Instance`, `t.Ldap.Operation.Result`, etc.
        """

        # Progress callback types (simplified to avoid circular imports)
        # For strict typing use m.Types.* variants in models.py
        # Use object for variadic callbacks - covers all parameter types
        # Note: This is a union that accepts both single-phase (4 params) and multi-phase (5 params) callbacks
        # The actual types are defined in models.py as m.Types.LdapProgressCallback and m.Types.MultiPhaseProgressCallback
        type ProgressCallbackUnion = (
            Callable[[object], None]
            | Callable[[object, object], None]
            | Callable[[object, object, object], None]
            | Callable[[object, object, object, object], None]
            | Callable[[object, object, object, object, object], None]
            | None
        )
        """Union type for progress callbacks (simplified for config models).

        Accepts callables with 1-5 parameters (all typed as object for flexibility).
        Actual typed versions are in models.py: m.Types.LdapProgressCallback (4 params)
        and m.Types.MultiPhaseProgressCallback (5 params).
        """

        # Operation data types (ldap3 compatibility) - defined here for direct access
        # Also defined in Operation namespace for internal consistency
        type ModifyChanges = dict[str, list[tuple[str, list[str]]]]
        """Type alias for LDAP modify changes (ldap3 compatibility).

        Format: {attribute_name: [(operation, [values])]}
        Operations: 'MODIFY_ADD', 'MODIFY_DELETE', 'MODIFY_REPLACE'
        """
        type AttributeValues = dict[str, list[str]]
        """Type alias for LDAP attribute values (multi-valued attributes)."""
        type Attributes = dict[str, list[str]]
        """Type alias for LDAP attributes (attribute name to value list mapping)."""
        type AttributesReadOnly = Mapping[str, Sequence[str]]
        """Type alias for read-only LDAP attributes mapping."""

        class Entry:
            """Entry-related type aliases.

            Extends parent Entry with LDAP-specific entry type aliases.
            Parent class provides LDIF-specific entry type aliases.

            Note: This nested class extends FlextLdifTypes.Entry to add LDAP-specific
            type aliases. Both classes contain only type aliases (PEP 695), not methods,
            so there are no method overrides to be incompatible.
            """

            # Types using object to avoid circular import with protocols.py (Tier 0 rule)
            # Actual constraint: FlextLdapProtocols.Ldap.LdapEntryProtocol (enforced at runtime by models/services)
            type Instance = object
            type Collection = Sequence[object]
            type EntryMapping = Mapping[str, object]

            # Generic types
            type Handler[T] = Callable[
                [object],
                r[T],
            ]
            type Transformer = Callable[
                [object],
                object,
            ]
            type Filter = Callable[
                [object],
                bool,
            ]
            type Processor = Callable[
                [Sequence[object]],
                r[Sequence[object]],
            ]

        class Operation:
            """Operation-related type aliases."""

            # Composition with t
            type Result[T] = r[T]
            type Callback[T] = Callable[[], r[T]]

            # Domain-specific types (using object to avoid circular import with protocols.py)
            # Actual constraint: FlextLdapProtocols.Ldap.LdapEntryProtocol (enforced at runtime)
            type EntryProcessor = Callable[
                [object],
                r[bool],
            ]
            type BatchProcessor = Callable[
                [Sequence[object]],
                r[int],
            ]

            type MultiPhaseProgressCallback = Callable[[object], None]
            """Multi-phase progress callback (variadic, type-safe callback type).

            Note: For strict typing, use m.Types.MultiPhaseProgressCallback from models.py.
            This alias is kept for backward compatibility but should not be used in new code.
            """

            # Operation data types (ldap3 compatibility)
            type ModifyChanges = dict[str, list[tuple[str, list[str]]]]
            """Type alias for LDAP modify changes (ldap3 compatibility).

            Format: {attribute_name: [(operation, [values])]}
            Operations: 'MODIFY_ADD', 'MODIFY_DELETE', 'MODIFY_REPLACE'
            """
            type AttributeValues = dict[str, list[str]]
            """Type alias for LDAP attribute values (multi-valued attributes)."""
            type Attributes = dict[str, list[str]]
            """Type alias for LDAP attributes (attribute name to value list mapping)."""
            type AttributesReadOnly = Mapping[str, Sequence[str]]
            """Type alias for read-only LDAP attributes mapping."""

            # ldap3 entry value types (for adapter conversion)
            type Ldap3EntryValue = (
                str
                | bytes
                | int
                | float
                | bool
                | Sequence[str | bytes | int | float | bool]
                | None
            )
            """Type alias for ldap3 entry attribute values.

            Supports all common LDAP attribute value types:
            - Scalar: str, bytes, int, float, bool, None
            - Multi-valued: Sequence of scalar types
            """

            type AttributeDict = dict[str, list[str]]
            """Type alias for LDIF/LDAP attribute mappings
            (attribute names to string lists)."""

            type ConversionState = tuple[list[str], list[str]]
            """Type alias for conversion state: (removed_attrs, base64_attrs)."""

            # Callables
            type AddCallable = Callable[[str, str | None, AttributeValues | None], bool]
            type ModifyCallable = Callable[[str, ModifyChanges], bool]
            type DeleteCallable = Callable[[str], bool]
            type SearchCallable = Callable[
                [
                    str,
                    str,
                    int,
                    Sequence[str] | None,
                    bool,
                    Mapping[str, str] | None,
                    int | None,
                    int | None,
                    bool,
                    Mapping[str, str] | None,
                ],
                tuple[bool, Mapping[str, Sequence[Mapping[str, Sequence[str]]]]],
            ]

            # Namespace composition via inheritance - no aliases needed
            # Access parent namespaces directly through inheritance

        class Protocol:
            """Protocol type aliases for easier access (PEP 695).

            These type aliases provide convenient access to nested protocol classes
            without needing to reference the full nested path.

            Note: All protocol types use object to avoid circular import with protocols.py (Tier 0 rule).
            Actual constraints are FlextLdapProtocols.Ldap.* (enforced at runtime by models/services).
            """

            # Configuration protocols
            type ConnectionConfig = object
            type SearchOptions = object

            # Entry protocols
            type Entry = object
            type DistinguishedName = object

            # Service protocols
            type LdapClient = object
            type LdapAdapter = object
            type LdapConnection = object

            # Result protocols
            type OperationResult = object
            type SearchResult = object


# Alias for simplified usage
t = FlextLdapTypes


__all__ = [
    "FlextLdapDomainResultT",
    "FlextLdapEntryT",
    "FlextLdapTypes",
    "t",
]
