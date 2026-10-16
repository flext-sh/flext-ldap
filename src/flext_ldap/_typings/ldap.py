"""LDAP domain type alias declarations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable

from flext_ldif import FlextLdifTypes
from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

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
    str,
    FlextLdifTypes.MutableSequenceOf[str],
]
type Ldap3ModifyChangesDict = FlextLdifTypes.MutableMappingKV[
    str,
    FlextLdifTypes.MutableSequenceOf[Ldap3ModifyChangeValue],
]
type OperationChangeValue = FlextLdifTypes.Pair[int, FlextLdifTypes.StrSequence]
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
)
type LdapProgressCallback = Callable[..., None]
type MultiPhaseProgressCallback = Callable[..., None]
type ProgressCallbackUnion = LdapProgressCallback | MultiPhaseProgressCallback
type LdapModifyChangeValue = FlextLdifTypes.Pair[
    str | int,
    FlextLdifTypes.StrSequence,
]
type LdapModifyChanges = FlextLdifTypes.MappingKV[
    str,
    FlextLdifTypes.SequenceOf[LdapModifyChangeValue],
]

__all__: list[str] = [
    "LDAPException",
    "Ldap3AddAttributes",
    "Ldap3AddAttributeValue",
    "Ldap3AttributeDict",
    "Ldap3AttributeScalar",
    "Ldap3AttributeValues",
    "Ldap3AttributeValue",
    "Ldap3EntrySequenceValue",
    "Ldap3EntryValue",
    "Ldap3ModifyChangeValue",
    "Ldap3ModifyChangesDict",
    "LdapModifyChangeValue",
    "LdapModifyChanges",
    "LdapProgressCallback",
    "MultiPhaseProgressCallback",
    "OperationAttributes",
    "OperationChangeValue",
    "OperationChanges",
    "ProgressCallbackUnion",
]
