"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

from flext_ldif import h


class FlextLdapTypes(h):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        LDAPException: type[Exception] = _Ldap3LDAPException

        type Ldap3SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]
        type Ldap3DerefAliases = Literal["NEVER", "SEARCH", "FINDING_BASE", "ALWAYS"]
        type Ldap3GetInfo = Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]
        type Ldap3AttributeScalar = str | bytes
        type Ldap3AttributeValues = h.SequenceOf[Ldap3AttributeScalar]
        type Ldap3AttributeDict = h.MappingKV[str, Ldap3AttributeValues]
        type Ldap3AttributeValue = Ldap3AttributeScalar | Ldap3AttributeValues
        type Ldap3AddAttributeValue = (
            Ldap3AttributeScalar | h.StrSequence | h.SequenceOf[bytes]
        )
        type Ldap3AddAttributes = h.MappingKV[str, Ldap3AddAttributeValue] | None
        type Ldap3ModifyChangeValue = h.Pair[
            str,
            h.MutableSequenceOf[str],
        ]
        type Ldap3ModifyChangesDict = h.MutableMappingKV[
            str,
            h.MutableSequenceOf[Ldap3ModifyChangeValue],
        ]
        type OperationChangeValue = h.Pair[
            int,
            h.StrSequence,
        ]
        type OperationChanges = h.MutableMappingKV[
            str,
            h.SequenceOf[OperationChangeValue],
        ]
        type OperationAttributes = h.MappingKV[
            str,
            h.StrSequence,
        ]
        type Ldap3EntrySequenceValue = h.SequenceOf[
            Ldap3AttributeScalar | h.Numeric | bool
        ]
        type Ldap3EntryValue = (
            Ldap3AttributeScalar | h.Numeric | bool | Ldap3EntrySequenceValue | None
        )
        type LdapProgressCallback = Callable[..., None]
        type MultiPhaseProgressCallback = Callable[..., None]
        type ProgressCallbackUnion = (
            LdapProgressCallback | MultiPhaseProgressCallback | None
        )
        type LdapModifyChangeValue = h.Pair[
            str | int,
            h.StrSequence,
        ]
        type LdapModifyChanges = h.MappingKV[
            str,
            h.SequenceOf[LdapModifyChangeValue],
        ]
        type LaxStr = str | bytes | bytearray


t = FlextLdapTypes

__all__: list[str] = [
    "FlextLdapTypes",
    "t",
]
