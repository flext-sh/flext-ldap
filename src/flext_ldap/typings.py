"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from typing import ParamSpec, TypeVar

from flext_ldif import FlextLdifModels, FlextLdifTypes

from flext_ldap import p


class FlextLdapTypes(FlextLdifTypes):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        # Operation types (formerly Operation.*)
        type OperationChanges = MutableMapping[str, Sequence[tuple[int, Sequence[str]]]]
        type OperationAttributes = Mapping[str, Sequence[str]]
        type OperationAttributeDict = Mapping[str, Sequence[str]]
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
        type EntryInstance = p.Ldap.ServiceContracts.EntryContract
        type EntryCollection = Sequence[p.Ldap.ServiceContracts.EntryContract]
        type LdifEntry = FlextLdifModels.Ldif.Entry

        # Search types (formerly Search.*)
        type SearchOptions = p.Ldap.ServiceContracts.SearchOptionsContract

        # Progress callback types (moved from _models/ldap.py Types class)
        LdapProgressCallback = Callable[[int, int, str, "p.Ldap.LdapBatchStats"], None]
        MultiPhaseProgressCallback = Callable[
            [str, int, int, str, "p.Ldap.LdapBatchStats"],
            None,
        ]
        ProgressCallbackUnion = LdapProgressCallback | MultiPhaseProgressCallback | None

        # Modify changes type (moved from protocols.py LdapAdapter)
        type LdapModifyChanges = Mapping[
            str,
            Sequence[tuple[str | int, Sequence[str]]],
        ]

    FlextLdapEntryT = TypeVar(
        "FlextLdapEntryT",
        bound=p.Ldap.ServiceContracts.EntryContract,
    )
    FlextLdapDomainResultT = TypeVar("FlextLdapDomainResultT")
    P = ParamSpec("P")


t = FlextLdapTypes
LdifEntry = FlextLdapTypes.Ldap.LdifEntry

__all__ = [
    "FlextLdapTypes",
    "LdifEntry",
    "p",
    "t",
]
