# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Typings package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._typings.ldap import FlextLdapTypesLdap


__all__: tuple[str, ...] = ("FlextLdapTypesLdap",)

install_lazy_exports(
    __name__,
    globals(),
    {"FlextLdapTypesLdap": ".ldap"},
    public_exports=__all__,
    deferred_members={
        "FlextLdapTypesLdap": (
            "SearchControl",
            "SearchControls",
            "LDAPException",
            "Ldap3AttributeScalar",
            "Ldap3AttributeValues",
            "Ldap3AttributeDict",
            "Ldap3AttributeValue",
            "Ldap3SearchResponse",
            "Ldap3AddAttributeValue",
            "Ldap3AddAttributes",
            "Ldap3ModifyChangeValue",
            "Ldap3ModifyChangesDict",
            "OperationChangeValue",
            "OperationChanges",
            "OperationAttributes",
            "Ldap3EntrySequenceValue",
            "Ldap3EntryValue",
            "LdapProgressCallback",
            "MultiPhaseProgressCallback",
            "ProgressCallbackUnion",
            "LdapModifyChangeValue",
            "LdapModifyChanges",
        ),
    },
)
