"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

from flext_ldif import FlextLdifTypes


class FlextLdapTypes(FlextLdifTypes):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        LDAPException: type[Exception] = _Ldap3LDAPException

        type Ldap3SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]
        type Ldap3DerefAliases = Literal["NEVER", "SEARCH", "FINDING_BASE", "ALWAYS"]
        type Ldap3GetInfo = Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]
        type Ldap3AttributeScalar = str | bytes
        type Ldap3AttributeValues = FlextLdifTypes.SequenceOf[Ldap3AttributeScalar]
        type Ldap3AttributeDict = FlextLdifTypes.MappingKV[str, Ldap3AttributeValues]
        type Ldap3AttributeValue = Ldap3AttributeScalar | Ldap3AttributeValues
        type Ldap3AddAttributeValue = (
            Ldap3AttributeScalar
            | FlextLdifTypes.StrSequence
            | FlextLdifTypes.SequenceOf[bytes]
        )
        type Ldap3AddAttributes = (
            FlextLdifTypes.MappingKV[str, Ldap3AddAttributeValue] | None
        )
        type Ldap3ModifyChangeValue = FlextLdifTypes.Pair[
            str,
            FlextLdifTypes.MutableSequenceOf[str],
        ]
        type Ldap3ModifyChangesDict = FlextLdifTypes.MutableMappingKV[
            str,
            FlextLdifTypes.MutableSequenceOf[Ldap3ModifyChangeValue],
        ]
        type OperationChangeValue = FlextLdifTypes.Pair[
            int,
            FlextLdifTypes.StrSequence,
        ]
        type OperationChanges = FlextLdifTypes.MutableMappingKV[
            str,
            FlextLdifTypes.SequenceOf[OperationChangeValue],
        ]
        type OperationAttributes = FlextLdifTypes.MappingKV[
            str,
            FlextLdifTypes.StrSequence,
        ]
        type Ldap3EntrySequenceValue = FlextLdifTypes.SequenceOf[
            Ldap3AttributeScalar | FlextLdifTypes.Numeric | bool
        ]
        type Ldap3EntryValue = (
            Ldap3AttributeScalar
            | FlextLdifTypes.Numeric
            | bool
            | Ldap3EntrySequenceValue
            | None
        )
        type LdapProgressCallback = Callable[..., None]
        type MultiPhaseProgressCallback = Callable[..., None]
        type ProgressCallbackUnion = (
            LdapProgressCallback | MultiPhaseProgressCallback | None
        )
        type LdapModifyChangeValue = FlextLdifTypes.Pair[
            str | int,
            FlextLdifTypes.StrSequence,
        ]
        type LdapModifyChanges = FlextLdifTypes.MappingKV[
            str,
            FlextLdifTypes.SequenceOf[LdapModifyChangeValue],
        ]
        type LaxStr = str | bytes | bytearray


t = FlextLdapTypes

__all__: list[str] = [
    "FlextLdapTypes",
    "t",
]
