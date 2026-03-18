"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import ParamSpec, TypeVar

from flext_core import r, t as _core_t
from flext_ldif import FlextLdifModels, FlextLdifTypes

from flext_ldap.protocols import p


class FlextLdapTypes(FlextLdifTypes):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        class Connection:
            """Connection type aliases."""

            type Config = Mapping[str, str | int | bool]
            type Options = Mapping[str, _core_t.Scalar | None]

        class Operation:
            """Operation type aliases."""

            type Result[T] = r[T]
            type Changes = dict[str, list[tuple[int, list[str]]]]
            type Attributes = Mapping[str, Sequence[str]]
            type AttributeDict = dict[str, list[str]]
            type Ldap3EntryValue = (
                str
                | bytes
                | int
                | float
                | bool
                | Sequence[str | bytes | int | float | bool]
                | None
            )

        class Entry:
            """Entry type aliases."""

            type Instance = p.Ldap.ServiceContracts.EntryContract
            type Collection = Sequence[p.Ldap.ServiceContracts.EntryContract]
            type LdifEntry = FlextLdifModels.Ldif.Entry

        class Search:
            """Search type aliases."""

            type Options = p.Ldap.ServiceContracts.SearchOptionsContract
            type Filter = str
            type Scope = str

        # Local alias for cleaner TypeVar bounds
        _EntryContract = p.Ldap.ServiceContracts.EntryContract

    FlextLdapEntryT = TypeVar("FlextLdapEntryT", bound=Ldap._EntryContract)
    FlextLdapDomainResultT = TypeVar("FlextLdapDomainResultT")
    TDomainResult = TypeVar("TDomainResult", bound=_core_t.Container)
    P = ParamSpec("P")


t = FlextLdapTypes
LdifEntry = FlextLdapTypes.Ldap.Entry.LdifEntry

__all__ = [
    "FlextLdapTypes",
    "LdifEntry",
    "p",
    "t",
]

TDomainResult = TypeVar("TDomainResult", bound=t.Container)
