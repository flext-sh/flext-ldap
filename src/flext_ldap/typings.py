"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import ParamSpec, Protocol, TypeVar

from flext_core import FlextResult, t as _core_t
from flext_ldif import FlextLdifTypes


class LdapEntryContract(Protocol):
    """Structural LDAP entry contract for service boundaries."""

    dn: str
    attributes: Mapping[str, Sequence[str]]


class SearchOptionsContract(Protocol):
    """Structural LDAP search options contract."""

    scope: str
    filter_str: str
    attributes: Sequence[str]


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

            type Result[T] = FlextResult[T]
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

            type Instance = LdapEntryContract
            type Collection = Sequence[LdapEntryContract]

        class Search:
            """Search type aliases."""

            type Options = SearchOptionsContract
            type Filter = str
            type Scope = str

    FlextLdapEntryT = TypeVar("FlextLdapEntryT", bound=LdapEntryContract)
    FlextLdapDomainResultT = TypeVar("FlextLdapDomainResultT")
    TDomainResult = TypeVar("TDomainResult", bound=_core_t.ContainerValue)
    P = ParamSpec("P")


t = FlextLdapTypes
__all__ = [
    "FlextLdapTypes",
    "LdapEntryContract",
    "SearchOptionsContract",
    "t",
]
