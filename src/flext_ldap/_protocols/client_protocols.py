"""LDAP client and adapter protocol contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self, runtime_checkable

from flext_ldif import FlextLdifProtocols

from flext_ldap._protocols.search_protocols import FlextLdapProtocolsSearch
from flext_ldap._protocols.service_protocols import FlextLdapProtocolsService

if TYPE_CHECKING:
    import types

    from flext_ldap import m, t


class FlextLdapProtocolsClient:
    """LDAP client protocol contracts composed into ``p.Ldap``."""

    @runtime_checkable
    class LdapClient(Protocol):
        """Protocol for LDAP clients that support CRUD operations."""

        @property
        def is_connected(self) -> bool:
            """Whether client is connected.

            Returns:
                True if connected, False otherwise

            """
            ...

        def add(
            self,
            entry: FlextLdifProtocols.Ldif.Entry,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Add LDAP entry.

            Args:
                entry: Entry model to add

            Returns:
                Result containing OperationResult

            """
            ...

        def batch_upsert(
            self,
            entries: t.SequenceOf[FlextLdifProtocols.Ldif.Entry],
            *,
            progress_callback: t.Ldap.LdapProgressCallback | None = None,
            retry_on_errors: t.StrSequence | None = None,
            max_retries: int = 1,
            stop_on_error: bool = False,
        ) -> FlextLdifProtocols.Result[m.Ldap.LdapBatchStats]:
            """Upsert multiple entries and report canonical batch statistics.

            Args:
                entries: LDIF entries to add or update.
                progress_callback: Optional callback invoked per entry with
                    ``(current, total, dn, stats)``.
                retry_on_errors: Error substrings that trigger a retry.
                max_retries: Maximum attempts per entry when retrying.
                stop_on_error: Halt the batch on the first failure.

            Returns:
                Result containing LdapBatchStats with per-entry counters.

            """
            ...

        def delete_subtree(
            self,
            dn: str | FlextLdifProtocols.Ldif.DN,
        ) -> FlextLdifProtocols.Result[m.Ldap.SubtreeDeleteResult]:
            """Delete an entry and its descendants, deepest-first.

            Args:
                dn: Distinguished name of the subtree root to delete.

            Returns:
                Result containing SubtreeDeleteResult with per-entry
                outcomes.

            """
            ...

        def plan_upsert(
            self,
            entries: t.SequenceOf[FlextLdifProtocols.Ldif.Entry],
        ) -> FlextLdifProtocols.Result[m.Ldap.UpsertPlan]:
            """Classify entries for upsert without writing (dry plan).

            Args:
                entries: LDIF entries to classify against current state.

            Returns:
                Result containing UpsertPlan with per-entry actions.

            """
            ...

        def find_entry(
            self,
            dn: str,
            *,
            attributes: t.StrSequence | None = None,
        ) -> FlextLdifProtocols.Result[m.Ldap.SearchResult]:
            """Read one entry by DN; an absent entry is an empty result.

            Args:
                dn: Distinguished name of the entry to read.
                attributes: Optional attribute names to restrict the read.

            Returns:
                Result containing SearchResult with zero or one entry.

            """
            ...

        def connect(
            self,
            connection_config: FlextLdapProtocolsSearch.ConnectionConfig,
            *,
            auto_retry: bool = False,
            max_retries: int = 1,
            retry_delay: float = 0.0,
            **kwargs: t.Scalar,
        ) -> FlextLdifProtocols.Result[bool]:
            """Connect to LDAP server.

            Args:
                connection_config: Validated connection configuration
                    (host, port, bind DN, TLS options) for this server.
                auto_retry: Reconnect automatically when the bind fails
                    transiently.
                max_retries: Maximum bind attempts when ``auto_retry`` is
                    enabled.
                retry_delay: Delay in seconds between bind attempts.
                **kwargs: Additional implementation-specific options.

            Returns:
                Result[bool] indicating connection success or failure

            """
            ...

        def __enter__(self) -> Self:
            """Enter the LDAP client context manager."""
            ...

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            """Exit the LDAP client context manager and release resources."""
            ...

        def disconnect(
            self,
        ) -> None:
            """Disconnect from LDAP server and release resources."""
            ...

        def delete(
            self,
            dn: str | FlextLdifProtocols.Ldif.DN,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Delete LDAP entry.

            Args:
                dn: Distinguished name of entry to delete

            Returns:
                Result containing OperationResult

            """
            ...

        def execute(
            self,
            **kwargs: t.Scalar,
        ) -> FlextLdifProtocols.Result[m.Ldap.Response]:
            """Execute health check or default operation.

            Args:
                **kwargs: Additional keyword arguments
                    (flexible types for extensibility)

            Returns:
                Result containing SearchResult

            """
            ...

        def modify(
            self,
            dn: str | FlextLdifProtocols.Ldif.DN,
            changes: t.Ldap.LdapModifyChanges,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Modify LDAP entry.

            Args:
                dn: Distinguished name of entry to modify
                changes: Modification changes in ldap3 format

            Returns:
                Result containing OperationResult

            """
            ...

        def search(
            self,
            search_options: FlextLdapProtocolsSearch.SearchOptions,
            server_type: str = "rfc",
        ) -> FlextLdifProtocols.Result[m.Ldap.SearchResult]:
            """Perform LDAP search operation.

            Args:
                search_options: Search configuration (required)
                server_type: LDAP server type for parsing (default: RFC)

            Returns:
                Result containing SearchResult with Entry models

            """
            ...

    @runtime_checkable
    class LdapAdapter(Protocol):
        """Protocol for LDAP adapters.

        Contract consumed by adapter hosts (DIP): signatures mirror the
        concrete ldap3 adapter so services depend on this protocol while
        the adapters package remains the sole owner of ldap3 imports.
        """

        @property
        def is_connected(self) -> bool:
            """Whether adapter is connected."""
            ...

        @property
        def connection(self) -> FlextLdapProtocolsService.Ldap3Connection | None:
            """The active ldap3 connection when one exists."""
            ...

        def connect(
            self,
            settings: m.Ldap.ConnectionConfig,
        ) -> FlextLdifProtocols.Result[bool]:
            """Establish the ldap3 server/connection pair and verify bind.

            Args:
                settings: Validated connection configuration for the server.

            Returns:
                Result[bool] indicating connection success or failure.

            """
            ...

        def disconnect(self) -> None:
            """Close any active adapter connection."""
            ...

        @staticmethod
        def add(
            entry: m.Ldif.Entry,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Add LDAP entry, returning the operation result.

            Args:
                entry: Entry model to add.

            Returns:
                Result containing OperationResult.

            """
            ...

        @staticmethod
        def delete(
            dn: str | m.Ldif.DN,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Delete LDAP entry, returning the operation result.

            Args:
                dn: Distinguished name of the entry to delete.

            Returns:
                Result containing OperationResult.

            """
            ...

        @staticmethod
        def modify(
            dn: str | m.Ldif.DN,
            changes: t.Ldap.OperationChanges,
        ) -> FlextLdifProtocols.Result[m.Ldap.OperationResult]:
            """Modify LDAP entry, returning the operation result.

            Args:
                dn: Distinguished name of the entry to delete.
                changes: Modification changes in ldap3 format.

            Returns:
                Result containing OperationResult.

            """
            ...

        @staticmethod
        def search(
            search_options: m.Ldap.SearchOptions,
            server_type: str = "rfc",
        ) -> FlextLdifProtocols.Result[m.Ldap.SearchResult]:
            """Perform LDAP search, returning the search result.

            Args:
                search_options: Search configuration (base, filter, scope).
                server_type: LDAP server type for result parsing.

            Returns:
                Result containing SearchResult with Entry models.

            """
            ...


__all__: list[str] = [
    "FlextLdapProtocolsClient",
    "LdapAdapter",
    "LdapClient",
]
