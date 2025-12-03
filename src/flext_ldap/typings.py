"""[PACKAGE] type definitions module - PEP 695 type aliases."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

from flext_core import FlextResult as r, FlextTypes as t
from flext_ldif import FlextLdifModels

from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols

# ═══════════════════════════════════════════════════════════════════════════
# TYPEVARS: Único objeto permitido fora da classe
# ═══════════════════════════════════════════════════════════════════════════
# Reutilize de t quando existir

# Apenas TypeVars específicos do domínio
TEntry = TypeVar("TEntry", bound="FlextLdapProtocols.LdapEntry.EntryProtocol")


# ═══════════════════════════════════════════════════════════════════════════
# CLASSE ÚNICA COM NESTED CLASSES
# ═══════════════════════════════════════════════════════════════════════════
class FlextLdapTypes(t):
    """[Package] type definitions composing with t.

    REGRAS:
    ───────
    1. TypeVars fora da classe (único caso permitido)
    2. Type aliases PEP 695 dentro de nested classes
    3. Tipos complexos compostos com Protocols
    4. ZERO aliases simples - use tipos diretos
    5. Composição com t, não duplicação
    """

    class Entry:
        """Entry-related type aliases."""

        # Tipos usando Protocols (evita import circular)
        type Instance = FlextLdapProtocols.LdapEntry.EntryProtocol
        type Collection = Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]
        type EntryMapping = Mapping[str, FlextLdapProtocols.LdapEntry.EntryProtocol]

        # Tipos genéricos
        type Handler[T] = Callable[
            [FlextLdapProtocols.LdapEntry.EntryProtocol],
            r[T],
        ]
        type Transformer = Callable[
            [FlextLdapProtocols.LdapEntry.EntryProtocol],
            FlextLdapProtocols.LdapEntry.EntryProtocol,
        ]
        type Filter = Callable[[FlextLdapProtocols.LdapEntry.EntryProtocol], bool]
        type Processor = Callable[
            [Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]],
            r[Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]],
        ]

    class Operation:
        """Operation-related type aliases."""

        # Composição com t
        type Result[T] = r[T]
        type Callback[T] = Callable[[], r[T]]

        # Tipos específicos do domínio
        type EntryProcessor = Callable[
            [FlextLdapProtocols.LdapEntry.EntryProtocol],
            r[bool],
        ]
        type BatchProcessor = Callable[
            [Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]],
            r[int],
        ]

    class Ldap:
        """LDAP-specific type aliases."""

        # Operation data types (ldap3 compatibility)
        type ModifyChanges = dict[str, list[tuple[str, list[str]]]]
        type AttributeValues = dict[str, list[str]]
        type Attributes = dict[str, list[str]]
        type AttributesReadOnly = Mapping[str, Sequence[str]]

        # Progress callback types
        type MultiPhaseProgressCallback = Callable[
            [str, int, int, str, FlextLdapModels.LdapBatchStats],
            None,
        ]
        """Type alias for multi-phase progress callback (5 parameters)."""

        type ProgressCallbackUnion = (
            MultiPhaseProgressCallback
            | FlextLdapModels.Types.LdapProgressCallback
            | None
        )
        """Union type for progress callbacks supporting both single and multi-phase signatures."""

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
        """Type alias for LDIF/LDAP attribute mappings (attribute names to string lists)."""

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
        type ConnectionConfig = FlextLdapProtocols.Config.ConnectionConfigProtocol
        type SearchOptions = FlextLdapProtocols.Config.SearchOptionsProtocol

        # Entry protocols
        type Entry = FlextLdapProtocols.LdapEntry.EntryProtocol
        type DistinguishedName = FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol

        # Service protocols
        type LdapClient = FlextLdapProtocols.LdapService.LdapClientProtocol
        type LdapAdapter = FlextLdapProtocols.LdapService.LdapAdapterProtocol
        type LdapConnection = FlextLdapProtocols.LdapService.LdapConnectionProtocol

        # Result protocols
        type OperationResult = FlextLdapProtocols.Result.OperationResultProtocol
        type SearchResult = FlextLdapProtocols.Result.SearchResultProtocol

    class Ldif:
        """LDIF model type aliases for type hints (PEP 695).

        These type aliases provide proper type hints for FlextLdifModels types
        that are class attributes, making them usable in type annotations.
        """

        # LDIF Entry and related types
        # Direct type references - use FlextLdifModels types directly
        type Entry = FlextLdifModels.Entry
        type LdifAttributes = FlextLdifModels.LdifAttributes
        # DistinguishedName, QuirkMetadata, ParseResponse are class attribute aliases
        # Use directly: FlextLdifModels.DistinguishedName (no type alias - mypy limitation)


# Convenience alias for common usage pattern
# Note: This alias is exported via __init__.py, not used directly in type annotations
t = FlextLdapTypes  # type: ignore[misc]  # mypy limitation: cannot assign to type
