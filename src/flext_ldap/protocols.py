"""LDAP Protocol Definitions - Protocol Interfaces for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Protocols use structural typing only - no model imports.
This allows protocols to remain independent of model implementations.

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from flext_core import r
from flext_ldif import p as ldif_p


class FlextLdapProtocols(ldif_p):
    """LDAP-specific protocol definitions.

    Domain-specific protocol interfaces for LDAP operations.
    All protocols are nested within this class following the single-class pattern.
    Uses structural typing only - no model imports.

    **Namespace Structure:**
    All LDAP-specific protocols are organized under the `.Ldap` namespace
    at ROOT level to enable proper namespace separation and alignment with
    flext-ldif and flext-cli patterns.

    HIERARCHY:
    ──────────
    Layer 0: Domain Protocols (no internal dependencies)
    Layer 1: Service Protocols (can use Layer 0)
    Layer 2: Handler Protocols (can use Layer 0 and 1)
    """

    class Ldap:
        """LDAP-specific protocol namespace.

        All LDAP domain-specific protocols are organized here at ROOT level
        to enable proper namespace separation. LDIF protocols from parent
        are accessed via `.Ldif` namespace (e.g., `p.Ldif.EntryProtocol`).

        Pattern: `p.Ldap.ProtocolName` (aligned with flext-ldif, flext-cli)
        """

        # =====================================================================
        # LAYER 0: DOMAIN PROTOCOLS - Entry (no internal dependencies)
        # =====================================================================

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
        class LdapEntryProtocol(Protocol):
            """Protocol for LDAP entry (structural type).

            Accepts both simple types and complex types (models).
            DistinguishedName has __str__ method, LdifAttributes has
            .attributes property.
            Models are structurally compatible through attribute access.
            """

            dn: str | FlextLdapProtocols.Ldap.DistinguishedNameProtocol
            attributes: (
                Mapping[str, Sequence[str]]
                | FlextLdapProtocols.Ldap.LdifAttributesProtocol
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

        # =====================================================================
        # LAYER 0: DOMAIN PROTOCOLS - Config (no internal dependencies)
        # =====================================================================

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

        # =====================================================================
        # LAYER 2: RESULT PROTOCOLS (can use Layer 0)
        # =====================================================================

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

            entries: Sequence[FlextLdapProtocols.Ldap.LdapEntryProtocol]
            search_options: FlextLdapProtocols.Ldap.SearchOptionsProtocol

        @runtime_checkable
        class PhaseSyncResultProtocol(Protocol):
            """Protocol for phase sync result (structural type).

            PhaseSyncResult has total_entries, synced, failed, skipped attributes.
            """

            total_entries: int
            synced: int
            failed: int
            skipped: int

        # =====================================================================
        # LAYER 1: SERVICE PROTOCOLS (can use Layer 0)
        # =====================================================================

        @runtime_checkable
        class LdapClientProtocol(Protocol):
            """Protocol for LDAP clients that support CRUD operations.

            This protocol defines the interface for LDAP clients used in test helpers.
            Uses structural types for type safety without importing models.
            """

            def connect(
                self,
                config: FlextLdapProtocols.Ldap.ConnectionConfigProtocol,
                **kwargs: str | bool | float | None,
            ) -> r[bool]:
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
                search_options: FlextLdapProtocols.Ldap.SearchOptionsProtocol,
                server_type: str = "rfc",
            ) -> r[FlextLdapProtocols.Ldap.SearchResultProtocol]:
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
                entry: FlextLdapProtocols.Ldap.LdapEntryProtocol,
            ) -> r[FlextLdapProtocols.Ldap.OperationResultProtocol]:
                """Add LDAP entry.

                Args:
                    entry: Entry model to add

                Returns:
                    ResultProtocol containing OperationResult

                """
                ...

            def modify(
                self,
                dn: str | FlextLdapProtocols.Ldap.DistinguishedNameProtocol,
                changes: Mapping[str, Sequence[tuple[str, Sequence[str]]]],
            ) -> r[FlextLdapProtocols.Ldap.OperationResultProtocol]:
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
                dn: str | FlextLdapProtocols.Ldap.DistinguishedNameProtocol,
            ) -> r[FlextLdapProtocols.Ldap.OperationResultProtocol]:
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
            ) -> r[FlextLdapProtocols.Ldap.SearchResultProtocol]:
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
                search_options: FlextLdapProtocols.Ldap.SearchOptionsProtocol,
                server_type: str = "rfc",
            ) -> r[FlextLdapProtocols.Ldap.SearchResultProtocol]:
                """Perform LDAP search operation.

                Returns ResultProtocol containing SearchResult model.
                Models are structurally compatible with SearchResultProtocol.
                """
                ...

            def add(
                self,
                entry: FlextLdapProtocols.Ldap.LdapEntryProtocol,
            ) -> r[FlextLdapProtocols.Ldap.OperationResultProtocol]:
                """Add LDAP entry.

                Returns ResultProtocol containing OperationResult model.
                Models are structurally compatible with OperationResultProtocol.
                """
                ...

            def modify(
                self,
                dn: FlextLdapProtocols.Ldap.DistinguishedNameProtocol | str,
                changes: Mapping[str, Sequence[tuple[str, Sequence[str]]]],
            ) -> r[FlextLdapProtocols.Ldap.OperationResultProtocol]:
                """Modify LDAP entry.

                Returns ResultProtocol containing OperationResult model.
                Models are structurally compatible with OperationResultProtocol.
                """
                ...

            def delete(
                self,
                dn: FlextLdapProtocols.Ldap.DistinguishedNameProtocol | str,
            ) -> r[FlextLdapProtocols.Ldap.OperationResultProtocol]:
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
            def adapter(
                self,
            ) -> FlextLdapProtocols.Ldap.LdapAdapterProtocol:
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

        # =====================================================================
        # INFRASTRUCTURE PROTOCOLS (ldap3 library objects)
        # =====================================================================

        @runtime_checkable
        class Ldap3EntryProtocol(Protocol):
            """Protocol for ldap3.Entry objects (structural type).

            ldap3.Entry has dynamic attributes accessed via entry_dn and
            entry_attributes properties, plus attribute-specific objects.
            """

            @property
            def entry_dn(self) -> str | None:
                """Get entry distinguished name."""
                ...

            @property
            def entry_attributes(self) -> Sequence[str]:
                """Get list of attribute names."""
                ...

        @runtime_checkable
        class Ldap3AttributeProtocol(Protocol):
            """Protocol for ldap3.Attribute objects (structural type).

            ldap3.Attribute has a values property containing attribute values.
            """

            @property
            def values(self) -> Sequence[object]:
                """Get attribute values."""
                ...

        @runtime_checkable
        class Ldap3ParseResponseProtocol(Protocol):
            """Protocol for ldap3.ParseResponse objects (structural type).

            ldap3.ParseResponse has an entries property containing list of Entry.
            """

            @property
            def entries(
                self,
            ) -> Sequence[FlextLdapProtocols.Ldap.Ldap3EntryProtocol]:
                """Get list of entries."""
                ...


# Direct access: use FlextLdapProtocols directly
p = FlextLdapProtocols

__all__ = [
    "FlextLdapProtocols",
    "p",
]
