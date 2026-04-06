"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from typing import Literal

from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

from flext_ldap import FlextLdapProtocols as p
from flext_ldif import FlextLdifTypes


class FlextLdapTypes(FlextLdifTypes):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        LDAPException: type[Exception] = _Ldap3LDAPException

        # ── ldap3 library interop types ──────────────────────────────
        type Ldap3SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]
        type Ldap3DerefAliases = Literal["NEVER", "SEARCH", "FINDING_BASE", "ALWAYS"]
        type Ldap3ModifyChangesDict = dict[str, list[tuple[str, list[str]]]]
        type Ldap3GetInfo = Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]

        # ldap3 attribute value types (wire-level)
        type Ldap3AttributeValues = Sequence[str | bytes]
        """Attribute value list as returned by ldap3 Entry/Attribute."""
        type Ldap3AttributeDict = Mapping[str, Sequence[str | bytes]]
        """Attribute dict as returned by ldap3 entry_attributes_as_dict."""
        type Ldap3AttributeValue = str | bytes | Sequence[str | bytes]
        """Single or multi-valued attribute from ldap3."""
        type Ldap3AddAttributes = (
            Mapping[str, str | bytes | FlextLdifTypes.StrSequence | Sequence[bytes]]
            | None
        )
        """Attribute mapping accepted by ldap3 Connection.add()."""

        # ── Operation types ──────────────────────────────────────────
        type OperationChanges = MutableMapping[
            str,
            Sequence[tuple[int, FlextLdifTypes.StrSequence]],
        ]
        type OperationAttributes = Mapping[str, FlextLdifTypes.StrSequence]
        type Ldap3EntryValue = (
            str
            | bytes
            | int
            | float
            | bool
            | Sequence[str | bytes | t.Numeric | bool]
            | None
        )

        # ── Callback types ───────────────────────────────────────────
        LdapProgressCallback = Callable[[int, int, str, p.Ldap.LdapBatchStats], None]
        MultiPhaseProgressCallback = Callable[
            [str, int, int, str, p.Ldap.LdapBatchStats],
            None,
        ]
        ProgressCallbackUnion = LdapProgressCallback | MultiPhaseProgressCallback | None

        # ── Modify changes type ──────────────────────────────────────
        type LdapModifyChanges = Mapping[
            str,
            Sequence[tuple[str | int, FlextLdifTypes.StrSequence]],
        ]

        # Lax string type for ldap3 interop (bytes/bytearray from wire)
        type LaxStr = str | bytes | bytearray


t = FlextLdapTypes

__all__ = [
    "FlextLdapTypes",
    "t",
]
