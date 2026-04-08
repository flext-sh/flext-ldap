"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Literal

from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

from flext_ldif import t

if TYPE_CHECKING:
    from flext_ldap import p


class FlextLdapTypes(t):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        LDAPException: type[Exception] = _Ldap3LDAPException

        type Ldap3SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]
        type Ldap3DerefAliases = Literal["NEVER", "SEARCH", "FINDING_BASE", "ALWAYS"]
        type Ldap3GetInfo = Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]
        type Ldap3AttributeScalar = str | bytes
        type Ldap3AttributeValues = t.SequenceOf[Ldap3AttributeScalar]
        type Ldap3AttributeDict = t.MappingKV[str, Ldap3AttributeValues]
        type Ldap3AttributeValue = Ldap3AttributeScalar | Ldap3AttributeValues
        type Ldap3AddAttributeValue = (
            Ldap3AttributeScalar | t.StrSequence | t.SequenceOf[bytes]
        )
        type Ldap3AddAttributes = t.MappingKV[str, Ldap3AddAttributeValue] | None
        type Ldap3ModifyChangeValue = t.Pair[
            str,
            t.MutableSequenceOf[str],
        ]
        type Ldap3ModifyChangesDict = t.MutableMappingKV[
            str,
            t.MutableSequenceOf[Ldap3ModifyChangeValue],
        ]
        type OperationChangeValue = t.Pair[
            int,
            t.StrSequence,
        ]
        type OperationChanges = t.MutableMappingKV[
            str,
            t.SequenceOf[OperationChangeValue],
        ]
        type OperationAttributes = t.MappingKV[
            str,
            t.StrSequence,
        ]
        type Ldap3EntrySequenceValue = t.SequenceOf[
            Ldap3AttributeScalar | t.Numeric | bool
        ]
        type Ldap3EntryValue = (
            Ldap3AttributeScalar | t.Numeric | bool | Ldap3EntrySequenceValue | None
        )
        type LdapProgressCallback = Callable[
            [int, int, str, p.Ldap.LdapBatchStats],
            None,
        ]
        type MultiPhaseProgressCallback = Callable[
            [str, int, int, str, p.Ldap.LdapBatchStats],
            None,
        ]
        type ProgressCallbackUnion = (
            LdapProgressCallback | MultiPhaseProgressCallback | None
        )
        type LdapModifyChangeValue = t.Pair[
            str | int,
            t.StrSequence,
        ]
        type LdapModifyChanges = t.MappingKV[
            str,
            t.SequenceOf[LdapModifyChangeValue],
        ]
        type LaxStr = str | bytes | bytearray


t = FlextLdapTypes

__all__ = [
    "FlextLdapTypes",
    "t",
]
