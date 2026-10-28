"""LDAP domain type alias declarations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable

from flext_ldif import FlextLdifTypes
from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException


class FlextLdapTypesLdap:
    LDAPException: type[Exception] = _Ldap3LDAPException

    type Ldap3AttributeScalar = str | bytes
    type Ldap3AttributeValues = FlextLdifTypes.Sequence[Ldap3AttributeScalar]
    type Ldap3AttributeDict = FlextLdifTypes.Mapping[str, Ldap3AttributeValues]
    type Ldap3AttributeValue = Ldap3AttributeScalar | Ldap3AttributeValues
    type Ldap3AddAttributeValue = (
        Ldap3AttributeScalar
        | FlextLdifTypes.Sequence[str]
        | FlextLdifTypes.Sequence[bytes]
    )
    type Ldap3AddAttributes = FlextLdifTypes.Mapping[str, Ldap3AddAttributeValue]
    type Ldap3ModifyChangeValue = tuple[
        str,
        FlextLdifTypes.MutableSequence[str],
    ]
    type Ldap3ModifyChangesDict = FlextLdifTypes.MutableMapping[
        str,
        FlextLdifTypes.MutableSequence[Ldap3ModifyChangeValue],
    ]
    type OperationChangeValue = tuple[int, FlextLdifTypes.Sequence[str]]
    type OperationChanges = dict[
        str,
        FlextLdifTypes.MutableSequence[OperationChangeValue],
    ]
    type OperationAttributes = FlextLdifTypes.Mapping[
        str,
        FlextLdifTypes.Sequence[str],
    ]
    type Ldap3EntrySequenceValue = FlextLdifTypes.Sequence[
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
        FlextLdifTypes.Sequence[str],
    ]
    type LdapModifyChanges = FlextLdifTypes.Mapping[
        str,
        FlextLdifTypes.Sequence[LdapModifyChangeValue],
    ]


__all__: list[str] = [
    "FlextLdapTypesLdap",
]
