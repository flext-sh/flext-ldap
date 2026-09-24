"""FLEXT LDAP type definitions with strict direct contracts."""

from __future__ import annotations

from collections.abc import Callable

from flext_ldif import FlextLdifTypes
from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException


class FlextLdapTypes(FlextLdifTypes):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        LDAPException: type[Exception] = _Ldap3LDAPException

        type Ldap3AttributeScalar = str | bytes
        type Ldap3AttributeValues = FlextLdifTypes.SequenceOf[Ldap3AttributeScalar]
        type Ldap3AttributeDict = FlextLdifTypes.MappingKV[str, Ldap3AttributeValues]
        type Ldap3AttributeValue = Ldap3AttributeScalar | Ldap3AttributeValues
        type Ldap3AddAttributeValue = (
            Ldap3AttributeScalar
            | FlextLdifTypes.StrSequence
            | FlextLdifTypes.SequenceOf[bytes]
        )
        type Ldap3AddAttributes = FlextLdifTypes.MappingKV[str, Ldap3AddAttributeValue]
        type Ldap3ModifyChangeValue = FlextLdifTypes.Pair[
            str, FlextLdifTypes.MutableSequenceOf[str]
        ]
        type Ldap3ModifyChangesDict = FlextLdifTypes.MutableMappingKV[
            str, FlextLdifTypes.MutableSequenceOf[Ldap3ModifyChangeValue]
        ]
        type OperationChangeValue = FlextLdifTypes.Pair[int, FlextLdifTypes.StrSequence]
        type OperationChanges = FlextLdifTypes.MutableMappingKV[
            str, FlextLdifTypes.SequenceOf[OperationChangeValue]
        ]
        type OperationAttributes = FlextLdifTypes.MappingKV[
            str, FlextLdifTypes.StrSequence
        ]
        type Ldap3EntrySequenceValue = FlextLdifTypes.SequenceOf[
            Ldap3AttributeScalar | FlextLdifTypes.Numeric | bool
        ]
        type Ldap3EntryValue = (
            Ldap3AttributeScalar
            | FlextLdifTypes.Numeric
            | bool
            | Ldap3EntrySequenceValue
        )
        type LdapProgressCallback = Callable[..., None]
        type MultiPhaseProgressCallback = Callable[..., None]
        type ProgressCallbackUnion = LdapProgressCallback | MultiPhaseProgressCallback
        type LdapModifyChangeValue = FlextLdifTypes.Pair[
            str | int, FlextLdifTypes.StrSequence
        ]
        type LdapModifyChanges = FlextLdifTypes.MappingKV[
            str, FlextLdifTypes.SequenceOf[LdapModifyChangeValue]
        ]


t = FlextLdapTypes

__all__: list[str] = ["FlextLdapTypes", "t"]
