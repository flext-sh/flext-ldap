"""LDAP connection service and operations protocol contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import FlextLdifProtocols

from flext_ldap._protocols import FlextLdapProtocolsSearch

if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_ldap import m, t


class FlextLdapProtocolsService:
    """LDAP service protocol contracts composed into ``p.Ldap``."""

    @runtime_checkable
    class LdapConnection(Protocol):
        """Protocol for LDAP connection services.

        This protocol defines the interface for LDAP connection services used
        by operations services to break circular imports.
        Uses structural types for type safety without importing models.
        """

        @property
        def is_connected(self) -> bool:
            """Whether connection is active.

            Returns:
                True if connected, False otherwise

            """
            ...

        @staticmethod
        def connect(
            connection_config: FlextLdapProtocolsSearch.ConnectionConfig,
            *,
            auto_retry: bool = False,
            max_retries: int = 3,
            retry_delay: float = 1.0,
        ) -> FlextLdifProtocols.Result[bool]:
            """Connect using the public LDAP connection service contract.

            Args:
                connection_config: Validated connection configuration for
                    the target server.
                auto_retry: Retry transient bind failures automatically.
                max_retries: Maximum connection attempts when retrying.
                retry_delay: Delay in seconds between attempts.

            Returns:
                Result[bool] indicating connection success or failure.

            """
            ...

        @staticmethod
        def disconnect() -> None:
            """Disconnect from LDAP server.

            Closes the connection and releases resources.
            Safe to call multiple times.

            """
            ...

        @staticmethod
        def execute() -> FlextLdifProtocols.Result[
            FlextLdapProtocolsSearch.SearchResult
        ]:
            """Run the connection service health check/default operation."""
            ...

    @runtime_checkable
    class LdapOperations(Protocol):
        """Protocol for LDAP operations services consumed by split handlers.

        Contract injected into the upsert and subtree-delete handlers:
        handlers declare only the members they delegate to, keeping the
        operations service substitutable (DIP) without a concrete import.
        """

        @property
        def logger(self) -> FlextLdifProtocols.Logger:
            """Logger for operation traceability."""
            ...

        @staticmethod
        def already_exists_error(error_message: str) -> bool:
            """Whether the error message indicates an existing entry.

            Args:
                error_message: Raw error text to inspect.

            Returns:
                True when the message maps to an entry-already-exists
                condition.

            """
            ...

        def find_entry(
            self,
            dn: str,
        ) -> FlextLdifProtocols.Result[m.Ldap.SearchResult]:
            """Read one entry by DN; an absent entry is an empty result.

            Args:
                dn: Distinguished name of the entry to read.

            Returns:
                Result containing SearchResult with zero or one entry.

            """
            ...

        def add(
            self,
            entry: FlextLdifProtocols.Ldif.Entry,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Add an LDAP entry, returning the operation result.

            Args:
                entry: LDIF entry to add.

            Returns:
                Result containing OperationResult.

            """
            ...

        def modify(
            self,
            dn: str,
            changes: t.Ldap.OperationChanges,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Modify an LDAP entry with the provided change set.

            Args:
                dn: Distinguished name of the entry to modify.
                changes: Modification changes in ldap3 format.

            Returns:
                Result containing OperationResult.

            """
            ...

        def delete(
            self,
            dn: str,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Delete an LDAP entry identified by DN.

            Args:
                dn: Distinguished name of the entry to delete.

            Returns:
                Result containing OperationResult.

            """
            ...

        def search(
            self,
            search_options: FlextLdapProtocolsSearch.SearchOptions,
        ) -> FlextLdifProtocols.Result[m.Ldap.SearchResult]:
            """Perform an LDAP search, returning the search result.

            Args:
                search_options: Search configuration (base, filter, scope).

            Returns:
                Result containing SearchResult with Entry models.

            """
            ...

    @runtime_checkable
    class Ldap3Connection(FlextLdifProtocols.Ldif.Ldap3Connection, Protocol):
        """Structural contract for ldap3-compatible connection objects.

        Extends the base contract from ``flext-ldif`` with LDAP-specific
        additional members (``server``, ``result``, ``start_tls``) required
        by the connection manager and operation executor adapters.
        """

        @property
        def server(self) -> FlextLdifProtocols.Ldif.Ldap3Server:
            """The ldap3 server bound to this connection."""
            ...

        @property
        def result(self) -> t.JsonMapping | None:
            """The last LDAP operation result payload."""
            ...

        @property
        def start_tls(self) -> Callable[..., bool]:
            """The callable implementing STARTTLS negotiation."""
            ...


__all__: list[str] = ["FlextLdapProtocolsService"]
