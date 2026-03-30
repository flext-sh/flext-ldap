"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from typing import TypeVar

from flext_ldif import FlextLdifModels, FlextLdifTypes

from flext_ldap import FlextLdapProtocols as p


class FlextLdapTypes(FlextLdifTypes):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        # Operation types (formerly Operation.*)
        type OperationChanges = MutableMapping[
            str,
            Sequence[tuple[int, FlextLdifTypes.StrSequence]],
        ]
        type OperationAttributes = Mapping[str, FlextLdifTypes.StrSequence]
        type OperationAttributeDict = Mapping[str, FlextLdifTypes.StrSequence]
        type Ldap3EntryValue = (
            str
            | bytes
            | int
            | float
            | bool
            | Sequence[str | bytes | int | float | bool]
            | None
        )

        # Entry types (formerly Entry.*)
        type LdifEntry = FlextLdifModels.Ldif.Entry

        # Progress callback types (moved from _models/ldap.py Types class)
        LdapProgressCallback = Callable[[int, int, str, p.Ldap.LdapBatchStats], None]
        MultiPhaseProgressCallback = Callable[
            [str, int, int, str, p.Ldap.LdapBatchStats],
            None,
        ]
        ProgressCallbackUnion = LdapProgressCallback | MultiPhaseProgressCallback | None

        # Modify changes type (moved from protocols.py LdapAdapter)
        type LdapModifyChanges = Mapping[
            str,
            Sequence[tuple[str | int, FlextLdifTypes.StrSequence]],
        ]

        # Lax string type for ldap3 interop (bytes/bytearray from wire)
        type LaxStr = str | bytes | bytearray


FlextLdapDomainResultT = TypeVar("FlextLdapDomainResultT")

FlextLdapEntryT = TypeVar(
    "FlextLdapEntryT",
    bound=p.Ldap.ServiceContracts.EntryContract,
)

t = FlextLdapTypes

__all__ = [
    "FlextLdapDomainResultT",
    "FlextLdapEntryT",
    "FlextLdapTypes",
    "t",
]
