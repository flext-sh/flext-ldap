# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Typings package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._typings.ldap import (
        Ldap3AddAttributes,
        Ldap3AddAttributeValue,
        Ldap3AttributeDict,
        Ldap3AttributeScalar,
        Ldap3AttributeValue,
        Ldap3AttributeValues,
        Ldap3EntrySequenceValue,
        Ldap3EntryValue,
        Ldap3ModifyChangesDict,
        Ldap3ModifyChangeValue,
        LDAPException,
        LdapModifyChanges,
        LdapModifyChangeValue,
        LdapProgressCallback,
        MultiPhaseProgressCallback,
        OperationAttributes,
        OperationChanges,
        OperationChangeValue,
        ProgressCallbackUnion,
    )


__all__: tuple[str, ...] = (
    "LDAPException",
    "Ldap3AddAttributeValue",
    "Ldap3AddAttributes",
    "Ldap3AttributeDict",
    "Ldap3AttributeScalar",
    "Ldap3AttributeValue",
    "Ldap3AttributeValues",
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
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "LDAPException": ".ldap",
        "Ldap3AddAttributeValue": ".ldap",
        "Ldap3AddAttributes": ".ldap",
        "Ldap3AttributeDict": ".ldap",
        "Ldap3AttributeScalar": ".ldap",
        "Ldap3AttributeValue": ".ldap",
        "Ldap3AttributeValues": ".ldap",
        "Ldap3EntrySequenceValue": ".ldap",
        "Ldap3EntryValue": ".ldap",
        "Ldap3ModifyChangeValue": ".ldap",
        "Ldap3ModifyChangesDict": ".ldap",
        "LdapModifyChangeValue": ".ldap",
        "LdapModifyChanges": ".ldap",
        "LdapProgressCallback": ".ldap",
        "MultiPhaseProgressCallback": ".ldap",
        "OperationAttributes": ".ldap",
        "OperationChangeValue": ".ldap",
        "OperationChanges": ".ldap",
        "ProgressCallbackUnion": ".ldap",
    }),
    public_exports=__all__,
)
