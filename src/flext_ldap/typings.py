"""[PACKAGE] type definitions module - PEP 695 type aliases."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

from flext_core import r
from flext_ldif import FlextLdifModels, FlextLdifTypes

from flext_ldap.protocols import FlextLdapProtocols as p

# ═══════════════════════════════════════════════════════════════════════════
# TYPEVARS: Único objeto permitido fora da classe
# ═══════════════════════════════════════════════════════════════════════════
# Reutilize de t quando existir

# Apenas TypeVars específicos do domínio
TEntry = TypeVar("TEntry", bound="p.LdapEntry.EntryProtocol")
TDomainResult = TypeVar("TDomainResult")


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

    class Entry(FlextLdifTypes.Entry):
        """Entry-related type aliases.

        Extends parent Entry with LDAP-specific entry type aliases.
        Parent class provides LDIF-specific entry type aliases.

        Note: This nested class extends FlextLdifTypes.Entry to add LDAP-specific
        type aliases. Both classes contain only type aliases (PEP 695), not methods,
        so there are no method overrides to be incompatible.
        """

        # Tipos usando Protocols (evita import circular)
        type Instance = p.LdapEntry.EntryProtocol
        type Collection = Sequence[p.LdapEntry.EntryProtocol]
        type EntryMapping = Mapping[str, p.LdapEntry.EntryProtocol]

        # Tipos genéricos
        type Handler[T] = Callable[
            [p.LdapEntry.EntryProtocol],
            r[T],
        ]
        type Transformer = Callable[
            [p.LdapEntry.EntryProtocol],
            p.LdapEntry.EntryProtocol,
        ]
        type Filter = Callable[[p.LdapEntry.EntryProtocol], bool]
        type Processor = Callable[
            [Sequence[p.LdapEntry.EntryProtocol]],
            r[Sequence[p.LdapEntry.EntryProtocol]],
        ]

    class Operation:
        """Operation-related type aliases."""

        # Composição com t
        type Result[T] = r[T]
        type Callback[T] = Callable[[], r[T]]

        # Tipos específicos do domínio
        type EntryProcessor = Callable[
            [p.LdapEntry.EntryProtocol],
            r[bool],
        ]
        type BatchProcessor = Callable[
            [Sequence[p.LdapEntry.EntryProtocol]],
            r[int],
        ]

    class Ldap:
        """LDAP-specific type aliases.

        NOTE: For strict type checking, use FlextLdapModels.Types which has
        typed versions:
        - m.Types.LdapProgressCallback
        - m.Types.MultiPhaseProgressCallback
        - m.Types.ProgressCallbackUnion
        """

        # Progress callback types (simplified to avoid circular imports)
        # For strict typing use m.Types.* variants in models.py
        type ProgressCallbackUnion = Callable[..., None] | None
        """Union type for progress callbacks (simplified for config models)."""

        type MultiPhaseProgressCallback = Callable[..., None]
        """Multi-phase progress callback (5 parameters, simplified type)."""

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

    class Protocol:
        """Protocol type aliases for easier access (PEP 695).

        These type aliases provide convenient access to nested protocol classes
        without needing to reference the full nested path.
        """

        # Configuration protocols
        type ConnectionConfig = p.Config.ConnectionConfigProtocol
        type SearchOptions = p.Config.SearchOptionsProtocol

        # Entry protocols
        type Entry = p.LdapEntry.EntryProtocol
        type DistinguishedName = p.LdapEntry.DistinguishedNameProtocol

        # Service protocols
        type LdapClient = p.LdapService.LdapClientProtocol
        type LdapAdapter = p.LdapService.LdapAdapterProtocol
        type LdapConnection = p.LdapService.LdapConnectionProtocol

        # Result protocols
        type OperationResult = p.Result.OperationResultProtocol
        type SearchResult = p.Result.SearchResultProtocol

    class Ldif:
        """LDIF model type aliases (PEP 695).

        References FlextLdifModels for LDIF types (no circular dependency).
        """

        # LDIF Entry and related types from parent library
        type Entry = FlextLdifModels.Entry
        type LdifAttributes = FlextLdifModels.LdifAttributes
        type DistinguishedName = FlextLdifModels.DistinguishedName
        type QuirkMetadata = FlextLdifModels.QuirkMetadata
        type ParseResponse = FlextLdifModels.ParseResponse

    class Migration(FlextLdifTypes.Migration):
        """Migration-related type aliases extending FlextLdifTypes.Migration."""


# Alias for simplified usage
t = FlextLdapTypes

__all__ = [
    "FlextLdapTypes",
    "TDomainResult",
    "TEntry",
    "t",
]
