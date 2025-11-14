"""LDAP Type Definitions - Type System for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Protocol, TypeVar

from flext_core import FlextResult, FlextTypes
from flext_ldif.models import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

# Generic TypeVars
ServiceT = TypeVar("ServiceT", bound=object)


class FlextLdapTypes(FlextTypes):
    """LDAP-specific type definitions extending FlextTypes.

    Domain-specific type system for LDAP operations.
    Minimal types - reuses FlextLdifTypes when possible.
    """

    # =========================================================================
    # SERVICE RETURN TYPE ALIASES
    # =========================================================================

    type EntryOrString = FlextLdifModels.Entry | str
    type DnInput = str | FlextLdifModels.DistinguishedName

    # =========================================================================
    # LDAP OPERATION TYPES
    # =========================================================================

    SearchScope = FlextLdapConstants.LiteralTypes.SearchScope
    OperationType = FlextLdapConstants.LiteralTypes.OperationType

    # =========================================================================
    # LDAP SEARCH RESULT TYPES
    # =========================================================================

    type SearchResult = list[FlextLdifModels.Entry]
    type OperationResult = dict[str, object]


# =========================================================================
# LDAP CLIENT PROTOCOLS
# =========================================================================


class LdapClientProtocol(Protocol):
    """Protocol for LDAP clients that support CRUD operations.

    This protocol defines the interface for LDAP clients used in test helpers.
    Supports both FlextLdap (uses SearchOptions) and Ldap3Adapter
    (uses individual parameters) patterns.
    """

    def search(
        self,
        *args: object,
        **kwargs: object,
    ) -> (
        FlextResult[FlextLdapModels.SearchResult]
        | FlextResult[list[FlextLdifModels.Entry]]
    ):
        """Perform LDAP search operation.

        May accept either:
        - search_options: FlextLdapModels.SearchOptions (FlextLdap)
        - base_dn, filter_str, scope, etc. (Ldap3Adapter)
        """
        ...

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult] | FlextResult[None]:
        """Add LDAP entry.

        Args:
            entry: Entry model to add

        Returns:
            FlextResult indicating success or failure

        """
        ...

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult] | FlextResult[None]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult indicating success or failure

        """
        ...

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult] | FlextResult[None]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success or failure

        """
        ...
