"""LDAP Type Definitions - Type System for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Protocol

from flext_core import FlextResult, FlextTypes
from flext_ldif.models import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


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


# =========================================================================
# LDAP CLIENT PROTOCOLS
# =========================================================================


class LdapClientProtocol(Protocol):
    """Protocol for LDAP clients that support CRUD operations.

    This protocol defines the interface for LDAP clients used in test helpers.
    Uses SearchOptions model for type safety and consistency.
    """

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Args:
            search_options: Search configuration (required)
            server_type: LDAP server type for parsing (default: RFC)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        ...

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Args:
            entry: Entry model to add

        Returns:
            FlextResult containing OperationResult

        """
        ...

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        ...

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult containing OperationResult

        """
        ...
