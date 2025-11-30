"""[PACKAGE] type definitions module - PEP 695 type aliases."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

from flext_core import FlextResult, FlextTypes

from flext_ldap.protocols import FlextLdapProtocols

# ═══════════════════════════════════════════════════════════════════════════
# TYPEVARS: Único objeto permitido fora da classe
# ═══════════════════════════════════════════════════════════════════════════
# Reutilize de FlextTypes quando existir

# Apenas TypeVars específicos do domínio
TEntry = TypeVar("TEntry", bound="FlextLdapProtocols.LdapEntry.EntryProtocol")


# ═══════════════════════════════════════════════════════════════════════════
# CLASSE ÚNICA COM NESTED CLASSES
# ═══════════════════════════════════════════════════════════════════════════
class FlextLdapTypes(FlextTypes):
    """[Package] type definitions composing with FlextTypes.

    REGRAS:
    ───────
    1. TypeVars fora da classe (único caso permitido)
    2. Type aliases PEP 695 dentro de nested classes
    3. Tipos complexos compostos com Protocols
    4. ZERO aliases simples - use tipos diretos
    5. Composição com FlextTypes, não duplicação
    """

    class Entry:
        """Entry-related type aliases."""

        # Tipos usando Protocols (evita import circular)
        type Instance = FlextLdapProtocols.LdapEntry.EntryProtocol
        type Collection = Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]
        type EntryMapping = Mapping[str, FlextLdapProtocols.LdapEntry.EntryProtocol]

        # Tipos genéricos
        type Handler[T] = Callable[
            [FlextLdapProtocols.LdapEntry.EntryProtocol], FlextResult[T]
        ]
        type Transformer = Callable[
            [FlextLdapProtocols.LdapEntry.EntryProtocol],
            FlextLdapProtocols.LdapEntry.EntryProtocol,
        ]
        type Filter = Callable[[FlextLdapProtocols.LdapEntry.EntryProtocol], bool]
        type Processor = Callable[
            [Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]],
            FlextResult[Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]],
        ]

    class Operation:
        """Operation-related type aliases."""

        # Composição com FlextTypes
        type Result[T] = FlextResult[T]
        type Callback[T] = Callable[[], FlextResult[T]]

        # Tipos específicos do domínio
        type EntryProcessor = Callable[
            [FlextLdapProtocols.LdapEntry.EntryProtocol],
            FlextResult[bool],
        ]
        type BatchProcessor = Callable[
            [Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]],
            FlextResult[int],
        ]

    class Ldap:
        """LDAP-specific type aliases."""

        # Operation data types (ldap3 compatibility)
        type ModifyChanges = dict[str, list[tuple[str, list[str]]]]
        type AttributeValues = dict[str, list[str]]
        type Attributes = dict[str, list[str]]
        type AttributesReadOnly = Mapping[str, Sequence[str]]

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
