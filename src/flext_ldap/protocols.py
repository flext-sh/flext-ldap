"""LDAP Protocol Definitions - Protocol Interfaces for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Protocols use structural typing only - no model imports.
This allows protocols to remain independent of model implementations.

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult

__all__ = [
    "FlextLdapProtocols",
]


class FlextLdapProtocols(FlextProtocols):
    """LDAP-specific protocol definitions extending FlextProtocols.

    Domain-specific protocol interfaces for LDAP operations.
    All protocols are nested within this class following the single-class pattern.
    Uses structural typing only - no model imports.

    HIERARCHY:
    ──────────
    Layer 0: Domain Protocols (no internal dependencies)
    Layer 1: Service Protocols (can use Layer 0)
    Layer 2: Handler Protocols (can use Layer 0 and 1)
    """

    # =========================================================================
    # LAYER 0: DOMAIN PROTOCOLS (no internal dependencies)
    # =========================================================================

    class LdapEntry:
        """Entry-related protocols."""

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for LDAP entry (structural type).

            Accepts both simple types and complex types (models).
            DistinguishedName has __str__ method, LdifAttributes has .attributes property.
            Models are structurally compatible through attribute access.
            """

            dn: str | object  # Accepts DistinguishedName (has __str__)
            attributes: (
                Mapping[str, Sequence[str]] | object
            )  # Accepts LdifAttributes (has .attributes)
            metadata: (
                Mapping[
                    str,
                    str
                    | int
                    | float
                    | bool
                    | Sequence[str]
                    | Mapping[str, str | Sequence[str]],
                ]
                | None
            )

        @runtime_checkable
        class DistinguishedNameProtocol(Protocol):
            """Protocol for Distinguished Name (structural type)."""

            def __str__(self) -> str:
                """Return string representation of DN."""
                ...

    class Config:
        """Configuration-related protocols."""

        @runtime_checkable
        class ConnectionConfigProtocol(Protocol):
            """Protocol for LDAP connection configuration (structural type)."""

            host: str
            port: int
            use_ssl: bool
            use_tls: bool
            bind_dn: str | None
            bind_password: str | None
            timeout: int
            auto_bind: bool
            auto_range: bool

        @runtime_checkable
        class SearchOptionsProtocol(Protocol):
            """Protocol for LDAP search options (structural type).

            Accepts both simple types and complex types (StrEnum, models).
            StrEnum is compatible with str in structural typing.
            Models with scope as StrEnum are compatible.
            """

            base_dn: str
            scope: (
                str | object
            )  # Accepts StrEnum (compatible with str) or SearchScope enum
            filter_str: str
            attributes: list[str] | None
            size_limit: int
            time_limit: int

    # =========================================================================
    # LAYER 1: SERVICE PROTOCOLS (can use Layer 0)
    # =========================================================================

    class LdapService:
        """Service-related protocols."""

        @runtime_checkable
        class LdapClientProtocol(Protocol):
            """Protocol for LDAP clients that support CRUD operations.

            This protocol defines the interface for LDAP clients used in test helpers.
            Uses structural types for type safety without importing models.
            """

            def connect(
                self,
                config: FlextLdapProtocols.Config.ConnectionConfigProtocol,
                **kwargs: str | bool | float | None,
            ) -> FlextResult[bool]:
                """Connect to LDAP server.

                Args:
                    config: Connection configuration (may be named 'config' or
                        'connection_config' in implementations)
                    **kwargs: Additional keyword arguments (e.g., auto_retry: bool,
                        max_retries: int, retry_delay: float)

                Returns:
                    FlextResult[bool] indicating connection success or failure

                """
                ...

            def search(
                self,
                search_options: FlextLdapProtocols.Config.SearchOptionsProtocol,
                server_type: str = "rfc",
            ) -> FlextResult[object]:  # Returns SearchResult model (structural typing)
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
                entry: FlextLdapProtocols.LdapEntry.EntryProtocol,
            ) -> FlextResult[
                object
            ]:  # Returns OperationResult model (structural typing)
                """Add LDAP entry.

                Args:
                    entry: Entry model to add

                Returns:
                    FlextResult containing OperationResult

                """
                ...

            def modify(
                self,
                dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
                changes: Mapping[str, Sequence[tuple[str, Sequence[str]]]],
            ) -> FlextResult[
                object
            ]:  # Returns OperationResult model (structural typing)
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
                dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
            ) -> FlextResult[
                object
            ]:  # Returns OperationResult model (structural typing)
                """Delete LDAP entry.

                Args:
                    dn: Distinguished name of entry to delete

                Returns:
                    FlextResult containing OperationResult

                """
                ...

            def execute(
                self,
                **_kwargs: str | bool | float | None,
            ) -> FlextResult[object]:  # Returns SearchResult model (structural typing)
                """Execute health check or default operation.

                Args:
                    **_kwargs: Additional keyword arguments
                        (flexible types for extensibility)

                Returns:
                    FlextResult containing SearchResult

                """
                ...

            @property
            def is_connected(self) -> bool:
                """Check if client is connected.

                Returns:
                    True if connected, False otherwise

                """
                ...

        @runtime_checkable
        class LdapAdapterProtocol(Protocol):
            """Protocol for LDAP adapters.

            This protocol defines the interface for LDAP adapters used by connection services.
            Uses structural types for type safety. Return types are Models (SearchResult, OperationResult)
            but are not imported to keep Protocols independent of Models.
            """

            # Type aliases for adapter operations
            type LdapModifyChanges = Mapping[str, Sequence[tuple[str, Sequence[str]]]]

            def search(
                self,
                search_options: FlextLdapProtocols.Config.SearchOptionsProtocol
                | object,  # Accepts SearchOptions model
                server_type: str = "rfc",
            ) -> FlextResult[object]:  # Returns SearchResult model (structural typing)
                """Perform LDAP search operation.

                Returns FlextResult containing SearchResult model.
                Models are structurally compatible with SearchResultProtocol.
                """
                ...

            def add(
                self,
                entry: FlextLdapProtocols.LdapEntry.EntryProtocol
                | object,  # Accepts Entry model
            ) -> FlextResult[
                object
            ]:  # Returns OperationResult model (structural typing)
                """Add LDAP entry.

                Returns FlextResult containing OperationResult model.
                Models are structurally compatible with OperationResultProtocol.
                """
                ...

            def modify(
                self,
                dn: FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol | str,
                changes: Mapping[str, Sequence[tuple[str, Sequence[str]]]],
            ) -> FlextResult[
                object
            ]:  # Returns OperationResult model (structural typing)
                """Modify LDAP entry.

                Returns FlextResult containing OperationResult model.
                Models are structurally compatible with OperationResultProtocol.
                """
                ...

            def delete(
                self,
                dn: FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol | str,
            ) -> FlextResult[
                object
            ]:  # Returns OperationResult model (structural typing)
                """Delete LDAP entry.

                Returns FlextResult containing OperationResult model.
                Models are structurally compatible with OperationResultProtocol.
                """
                ...

            @property
            def is_connected(self) -> bool:
                """Check if adapter is connected."""
                ...

        @runtime_checkable
        class LdapConnectionProtocol(Protocol):
            """Protocol for LDAP connection services.

            This protocol defines the interface for LDAP connection services used
            by operations services to break circular imports.
            Uses structural types for type safety without importing models.
            """

            @property
            def adapter(self) -> FlextLdapProtocols.LdapService.LdapAdapterProtocol:
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

            def disconnect(self) -> None:
                """Disconnect from LDAP server.

                Closes the connection and releases resources.
                Safe to call multiple times.

                """
                ...

    # =========================================================================
    # LAYER 2: RESULT/HANDLER PROTOCOLS (can use Layer 0 and 1)
    # =========================================================================

    class Result:
        """Result-related protocols."""

        @runtime_checkable
        class OperationResultProtocol(Protocol):
            """Protocol for LDAP operation result (structural type).

            Accepts both simple types and complex types (StrEnum).
            StrEnum is compatible with str in structural typing.
            """

            success: bool
            operation_type: str  # Accepts StrEnum (compatible with str)
            message: str
            entries_affected: int

        @runtime_checkable
        class SearchResultProtocol(Protocol):
            """Protocol for LDAP search result (structural type)."""

            entries: Sequence[FlextLdapProtocols.Entry.EntryProtocol]
            search_options: FlextLdapProtocols.Config.SearchOptionsProtocol

    # =========================================================================
    # BACKWARD COMPATIBILITY ALIASES
    # =========================================================================

    ConnectionConfigProtocol = Config.ConnectionConfigProtocol
    SearchOptionsProtocol = Config.SearchOptionsProtocol
    EntryProtocol = LdapEntry.EntryProtocol
    DistinguishedNameProtocol = LdapEntry.DistinguishedNameProtocol
    OperationResultProtocol = Result.OperationResultProtocol
    SearchResultProtocol = Result.SearchResultProtocol

    LdapClient = LdapService.LdapClientProtocol
    LdapAdapter = LdapService.LdapAdapterProtocol
    LdapConnection = LdapService.LdapConnectionProtocol
