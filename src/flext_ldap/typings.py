"""[PACKAGE] type definitions module - PEP 695 type aliases."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

from flext_core import r
from flext_ldif import FlextLdifTypes

from flext_ldap.protocols import p

# ═══════════════════════════════════════════════════════════════════════════
# TYPEVARS: Único objeto permitido fora da classe
# ═══════════════════════════════════════════════════════════════════════════
# Reutilize de t quando existir

# Apenas TypeVars específicos do domínio
# Use string forward reference for Protocol type in TypeVar bound
TLdapEntry = TypeVar("TLdapEntry", bound="p.Ldap.Entry.EntryProtocol")
TLdapDomainResult = TypeVar("TLdapDomainResult")


# ═══════════════════════════════════════════════════════════════════════════
# CLASSE ÚNICA COM NESTED CLASSES
# ═══════════════════════════════════════════════════════════════════════════
class FlextLdapTypes(FlextLdifTypes):
    """[Package] type definitions extending FlextLdifTypes.

    REGRAS:
    ───────
    1. TypeVars fora da classe (único caso permitido)
    2. Type aliases PEP 695 dentro de nested classes
    3. Tipos complexos compostos com Protocols
    4. ZERO aliases simples - use tipos diretos
    5. Composição com t, não duplicação

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

        class Entry:
            """Entry-related type aliases.

            Extends parent Entry with LDAP-specific entry type aliases.
            Parent class provides LDIF-specific entry type aliases.

            Note: This nested class extends FlextLdifTypes.Entry to add LDAP-specific
            type aliases. Both classes contain only type aliases (PEP 695), not methods,
            so there are no method overrides to be incompatible.
            """

            # Tipos usando Protocols (evita import circular)
            type Instance = p.Ldap.Entry.EntryProtocol
            type Collection = Sequence[p.Ldap.Entry.EntryProtocol]
            type EntryMapping = Mapping[str, p.Ldap.Entry.EntryProtocol]

            # Tipos genéricos
            type Handler[T] = Callable[
                [p.Ldap.Entry.EntryProtocol],
                r[T],
            ]
            type Transformer = Callable[
                [p.Ldap.Entry.EntryProtocol],
                p.Ldap.Entry.EntryProtocol,
            ]
            type Filter = Callable[[p.Ldap.Entry.EntryProtocol], bool]
            type Processor = Callable[
                [Sequence[p.Ldap.Entry.EntryProtocol]],
                r[Sequence[p.Ldap.Entry.EntryProtocol]],
            ]

        class Operation:
            """Operation-related type aliases."""

            # Composição com t
            type Result[T] = r[T]
            type Callback[T] = Callable[[], r[T]]

            # Tipos específicos do domínio
            type EntryProcessor = Callable[
                [p.Ldap.Entry.EntryProtocol],
                r[bool],
            ]
            type BatchProcessor = Callable[
                [Sequence[p.Ldap.Entry.EntryProtocol]],
                r[int],
            ]

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

            type MultiPhaseProgressCallback = Callable[[object], None]
            """Multi-phase progress callback (variadic, type-safe callback type).

            Note: For strict typing, use m.Types.MultiPhaseProgressCallback from models.py.
            This alias is kept for backward compatibility but should not be used in new code.
            """

            # Operation data types (ldap3 compatibility)
            type ModifyChanges = dict[str, list[tuple[str, list[str]]]]
            type AttributeValues = dict[str, list[str]]
            type Attributes = dict[str, list[str]]
            type AttributesReadOnly = Mapping[str, Sequence[str]]

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
            """

            # Configuration protocols
            # Use forward references to avoid pyright errors with nested protocols
            type ConnectionConfig = p.Ldap.Config.ConnectionConfigProtocol
            type SearchOptions = p.Ldap.Config.SearchOptionsProtocol

            # Entry protocols
            type Entry = p.Ldap.Entry.EntryProtocol
            type DistinguishedName = p.Ldap.Entry.DistinguishedNameProtocol

            # Service protocols
            type LdapClient = p.Ldap.Service.LdapClientProtocol
            type LdapAdapter = p.Ldap.Service.LdapAdapterProtocol
            type LdapConnection = p.Ldap.Service.LdapConnectionProtocol

            # Result protocols
            type OperationResult = p.Ldap.Result.OperationResultProtocol
            type SearchResult = p.Ldap.Result.SearchResultProtocol


# Alias for simplified usage
t = FlextLdapTypes


__all__ = [
    "FlextLdapTypes",
    "TLdapDomainResult",
    "TLdapEntry",
    "t",
]
