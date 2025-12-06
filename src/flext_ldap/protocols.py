"""LDAP Protocol Definitions - Protocol Interfaces for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Protocols use structural typing only - no model imports.
This allows protocols to remain independent of model implementations.

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from flext_core import p as flext_protocols
from flext_ldif import FlextLdifProtocols


class FlextLdapProtocols(FlextLdifProtocols):
    """LDAP-specific protocol definitions extending FlextLdifProtocols.

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
        class DistinguishedNameProtocol(Protocol):
            """Protocol for Distinguished Name (structural type)."""

            def __str__(self) -> str:
                """Return string representation of DN."""
                ...

            @property
            def value(self) -> str:
                """Get DN value."""
                ...

        @runtime_checkable
        class LdifAttributesProtocol(Protocol):
            """Protocol for LDIF attributes (structural type)."""

            @property
            def attributes(self) -> Mapping[str, Sequence[str]]:
                """Get attributes mapping."""
                ...

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for LDAP entry (structural type).

            Accepts both simple types and complex types (models).
            DistinguishedName has __str__ method, LdifAttributes has
            .attributes property.
            Models are structurally compatible through attribute access.
            """

            dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol
            attributes: (
                Mapping[str, Sequence[str]]
                | FlextLdapProtocols.LdapEntry.LdifAttributesProtocol
            )
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

    class Config:
        """Configuration-related protocols.

        This class namespace contains configuration-related protocol interfaces.
        It overrides the parent Config namespace to add LDAP-specific protocols
        while maintaining full compatibility with parent protocols.
        """

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
        class SearchScopeProtocol(Protocol):
            """Protocol for search scope (structural type - accepts StrEnum or str)."""

            def __str__(self) -> str:
                """Return string representation of scope."""
                ...

        @runtime_checkable
        class SearchOptionsProtocol(Protocol):
            """Protocol for LDAP search options (structural type).

            Accepts both simple types and complex types (StrEnum, models).
            StrEnum is compatible with str in structural typing.
            Models with scope as StrEnum are compatible.
            """

            base_dn: str
            scope: str  # Normalized to str after validation
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
            ) -> flext_protocols.Foundation.Result[bool]:
                """Connect to LDAP server.

                Args:
                    config: Connection configuration (may be named 'config' or
                        'connection_config' in implementations)
                    **kwargs: Additional keyword arguments (e.g., auto_retry: bool,
                        max_retries: int, retry_delay: float)

                Returns:
                    ResultProtocol[bool] indicating connection success or failure

                """
                ...

            def search(
                self,
                search_options: FlextLdapProtocols.Config.SearchOptionsProtocol,
                server_type: str = "rfc",
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.SearchResultProtocol
            ]:
                """Perform LDAP search operation.

                Args:
                    search_options: Search configuration (required)
                    server_type: LDAP server type for parsing (default: RFC)

                Returns:
                    ResultProtocol containing SearchResult with Entry models

                """
                ...

            def add(
                self,
                entry: FlextLdapProtocols.LdapEntry.EntryProtocol,
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.OperationResultProtocol
            ]:
                """Add LDAP entry.

                Args:
                    entry: Entry model to add

                Returns:
                    ResultProtocol containing OperationResult

                """
                ...

            def modify(
                self,
                dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
                changes: Mapping[str, Sequence[tuple[str, Sequence[str]]]],
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.OperationResultProtocol
            ]:
                """Modify LDAP entry.

                Args:
                    dn: Distinguished name of entry to modify
                    changes: Modification changes in ldap3 format

                Returns:
                    ResultProtocol containing OperationResult

                """
                ...

            def delete(
                self,
                dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.OperationResultProtocol
            ]:
                """Delete LDAP entry.

                Args:
                    dn: Distinguished name of entry to delete

                Returns:
                    ResultProtocol containing OperationResult

                """
                ...

            def execute(
                self,
                **_kwargs: str | bool | float | None,
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.SearchResultProtocol
            ]:
                """Execute health check or default operation.

                Args:
                    **_kwargs: Additional keyword arguments
                        (flexible types for extensibility)

                Returns:
                    ResultProtocol containing SearchResult

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

            This protocol defines the interface for LDAP adapters used
            by connection services.
            Uses structural types for type safety. Return types are Models
            (SearchResult, OperationResult) but are not imported to keep
            Protocols independent of Models.
            """

            # Type aliases for adapter operations
            type LdapModifyChanges = Mapping[str, Sequence[tuple[str, Sequence[str]]]]

            def search(
                self,
                search_options: FlextLdapProtocols.Config.SearchOptionsProtocol,
                server_type: str = "rfc",
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.SearchResultProtocol
            ]:
                """Perform LDAP search operation.

                Returns ResultProtocol containing SearchResult model.
                Models are structurally compatible with SearchResultProtocol.
                """
                ...

            def add(
                self,
                entry: FlextLdapProtocols.LdapEntry.EntryProtocol,
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.OperationResultProtocol
            ]:
                """Add LDAP entry.

                Returns ResultProtocol containing OperationResult model.
                Models are structurally compatible with OperationResultProtocol.
                """
                ...

            def modify(
                self,
                dn: FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol | str,
                changes: Mapping[str, Sequence[tuple[str, Sequence[str]]]],
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.OperationResultProtocol
            ]:
                """Modify LDAP entry.

                Returns ResultProtocol containing OperationResult model.
                Models are structurally compatible with OperationResultProtocol.
                """
                ...

            def delete(
                self,
                dn: FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol | str,
            ) -> flext_protocols.Foundation.Result[
                FlextLdapProtocols.Result.OperationResultProtocol
            ]:
                """Delete LDAP entry.

                Returns ResultProtocol containing OperationResult model.
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
        """Result-related protocols.

        This class namespace contains result-related protocol interfaces.
        It overrides the parent Result namespace to add LDAP-specific protocols
        while maintaining full compatibility with parent protocols.
        """

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

            entries: Sequence[FlextLdapProtocols.LdapEntry.EntryProtocol]
            search_options: FlextLdapProtocols.Config.SearchOptionsProtocol


# Convenience alias for common usage pattern - exported for domain usage
p = FlextLdapProtocols

__all__ = [
    "FlextLdapProtocols",
    "p",
]
