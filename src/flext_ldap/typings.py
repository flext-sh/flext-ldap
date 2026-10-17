"""FLEXT LDAP type definitions with strict direct contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifTypes

from flext_ldap._typings import ldap as _ldap_types


class FlextLdapTypes(FlextLdifTypes):
    """LDAP-specific type namespace."""

    class Ldap:
        """LDAP type aliases."""

        LDAPException = _ldap_types.LDAPException

        Ldap3AttributeScalar = _ldap_types.Ldap3AttributeScalar
        Ldap3AttributeValues = _ldap_types.Ldap3AttributeValues
        Ldap3AttributeDict = _ldap_types.Ldap3AttributeDict
        Ldap3AttributeValue = _ldap_types.Ldap3AttributeValue
        Ldap3AddAttributeValue = _ldap_types.Ldap3AddAttributeValue
        Ldap3AddAttributes = _ldap_types.Ldap3AddAttributes
        Ldap3ModifyChangeValue = _ldap_types.Ldap3ModifyChangeValue
        Ldap3ModifyChangesDict = _ldap_types.Ldap3ModifyChangesDict
        OperationChangeValue = _ldap_types.OperationChangeValue
        OperationChanges = _ldap_types.OperationChanges
        OperationAttributes = _ldap_types.OperationAttributes
        Ldap3EntrySequenceValue = _ldap_types.Ldap3EntrySequenceValue
        Ldap3EntryValue = _ldap_types.Ldap3EntryValue
        LdapProgressCallback = _ldap_types.LdapProgressCallback
        MultiPhaseProgressCallback = _ldap_types.MultiPhaseProgressCallback
        ProgressCallbackUnion = _ldap_types.ProgressCallbackUnion
        LdapModifyChangeValue = _ldap_types.LdapModifyChangeValue
        LdapModifyChanges = _ldap_types.LdapModifyChanges


t = FlextLdapTypes

__all__: list[str] = ["FlextLdapTypes", "t"]
