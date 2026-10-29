"""LDAP domain type alias declarations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence

from flext_ldif import FlextLdifTypes
from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException


class FlextLdapTypesLdap:
    LDAPException: type[Exception] = _Ldap3LDAPException

    type Ldap3AttributeScalar = str | bytes
    type Ldap3AttributeValues = Sequence[Ldap3AttributeScalar]
    type Ldap3AttributeDict = Mapping[str, Ldap3AttributeValues]
    type Ldap3AttributeValue = Ldap3AttributeScalar | Ldap3AttributeValues
    type Ldap3AddAttributeValue = Ldap3AttributeScalar | Sequence[str] | Sequence[bytes]
    type Ldap3AddAttributes = Mapping[str, Ldap3AddAttributeValue]
    type Ldap3ModifyChangeValue = tuple[
        str,
        MutableSequence[str],
    ]
    type Ldap3ModifyChangesDict = MutableMapping[
        str,
        MutableSequence[Ldap3ModifyChangeValue],
    ]
    type OperationChangeValue = tuple[int, Sequence[str]]
    type OperationChanges = dict[
        str,
        MutableSequence[OperationChangeValue],
    ]
    type OperationAttributes = Mapping[
        str,
        Sequence[str],
    ]
    type Ldap3EntrySequenceValue = Sequence[
        Ldap3AttributeScalar | FlextLdifTypes.Numeric | bool
    ]
    type Ldap3EntryValue = (
        Ldap3AttributeScalar | FlextLdifTypes.Numeric | bool | Ldap3EntrySequenceValue
    )
    type LdapProgressCallback = Callable[..., None]
    type MultiPhaseProgressCallback = Callable[..., None]
    type ProgressCallbackUnion = LdapProgressCallback | MultiPhaseProgressCallback
    type LdapModifyChangeValue = tuple[
        str | int,
        Sequence[str],
    ]
    type LdapModifyChanges = Mapping[
        str,
        Sequence[LdapModifyChangeValue],
    ]


__all__: list[str] = [
    "FlextLdapTypesLdap",
]
