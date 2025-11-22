"""LDAP Type Definitions - Type System for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from flext_core import FlextResult, FlextTypes
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

__all__ = [
    "FlextLdapTypes",
    "LdapAdapterProtocol",
    "LdapClientProtocol",
    "LdapConnectionProtocol",
]


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
    # LDAP OPERATION CALLABLES
    # =========================================================================

    type LdapAddCallable = Callable[
        [str, str | None, dict[str, list[str]] | None], bool
    ]
    type LdapModifyCallable = Callable[
        [str, dict[str, list[tuple[str, list[str]]]]], bool
    ]
    type LdapDeleteCallable = Callable[[str], bool]
    type LdapSearchCallable = Callable[
        [
            str,
            str,
            int,
            list[str] | None,
            bool,
            dict[str, str] | None,
            int | None,
            int | None,
            bool,
            dict[str, str] | None,
        ],
        tuple[bool, dict[str, list[dict[str, list[str]]]]],
    ]


# =========================================================================
# LDAP CLIENT PROTOCOLS
# =========================================================================


class LdapClientProtocol(Protocol):
    """Protocol for LDAP clients that support CRUD operations.

    This protocol defines the interface for LDAP clients used in test helpers.
    Uses SearchOptions model for type safety and consistency.
    """

    def connect(
        self,
        config: FlextLdapModels.ConnectionConfig,
        **kwargs: object,
    ) -> FlextResult[bool]:
        """Connect to LDAP server.

        Args:
            config: Connection configuration (may be named 'config' or 'connection_config' in implementations)
            **kwargs: Additional keyword arguments (e.g., auto_retry, max_retries, retry_delay)

        Returns:
            FlextResult[bool] indicating connection success or failure

        """
        ...

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


class LdapAdapterProtocol(Protocol):
    """Protocol for LDAP adapters.

    This protocol defines the interface for LDAP adapters used by connection services.
    """

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation."""
        ...

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry."""
        ...

    def modify(
        self,
        dn: FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry."""
        ...

    def delete(
        self,
        dn: FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry."""
        ...

    @property
    def is_connected(self) -> bool:
        """Check if adapter is connected."""
        ...


class LdapConnectionProtocol(Protocol):
    """Protocol for LDAP connection services.

    This protocol defines the interface for LDAP connection services used
    by operations services to break circular imports.
    """

    @property
    def adapter(self) -> LdapAdapterProtocol:
        """Get LDAP adapter instance.

        Returns:
            LDAP adapter (Ldap3Adapter) instance

        """
        ...

    @property
    def is_connected(self) -> bool:
        """Check if connection is active.

        Returns:
            True if connected, False otherwise

        """
        ...
