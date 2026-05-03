"""LDAP Protocol Definitions - Protocol Interfaces for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Protocols use structural typing only - no model imports.
This allows protocols to remain independent of model implementations.

"""

from __future__ import annotations

import types
from collections.abc import Callable
from typing import (
    TYPE_CHECKING,
    Protocol,
    Self,
    override,
    runtime_checkable,
)

from ldap3 import Connection as _Ldap3Connection, Server as _Ldap3Server
from ldap3.abstract.attribute import Attribute as _Ldap3Attribute
from ldap3.abstract.entry import Entry as _Ldap3Entry
from ldap3.protocol.rfc4512 import BaseServerInfo as _Ldap3ServerInfo

from flext_ldif import p

if TYPE_CHECKING:
    from flext_ldap import m as lm
    from flext_ldap.typings import FlextLdapTypes as t


class FlextLdapProtocols(p):
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

    @runtime_checkable
    class Ldap(Protocol):
        """LDAP-specific protocol namespace.

        All LDAP domain-specific protocols are organized here at ROOT level
        to enable proper namespace separation. LDIF protocols from parent
        are accessed via `.Ldif` namespace (e.g., `m.Ldif.Entry`).

        Pattern: `FlextLdapProtocols.Ldap.ProtocolName` (aligned with flext-ldif, flext-cli)
        """

        # ── Layer 0: Domain Protocols ────────────────────────────
        # DN, Attributes, Entry → use p.Ldif.DN,
        # p.Ldif.Attributes, p.Ldif.Entry
        # directly from flext-ldif (SSOT — no redefinition in Ldap namespace)

        @runtime_checkable
        class LdapBatchStats(Protocol):
            """Protocol for LDAP batch statistics (structural type)."""

            synced: int
            failed: int
            skipped: int

        @runtime_checkable
        class ConnectionConfig(Protocol):
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
        class SearchScope(Protocol):
            """Protocol for search scope (structural type - accepts StrEnum or str)."""

            @override
            def __str__(self) -> str:
                """Return string representation of scope."""
                ...

        class Parse:
            """Parse-related protocols."""

            @runtime_checkable
            class ParseResult(Protocol):
                """Protocol for parse results (structural type)."""

                failure: bool
                "Indicates if parsing failed."
                success: bool
                "Indicates if parsing succeeded."
                error: str | None
                "Error message if parsing failed."
                value: t.Scalar | None
                "Parsed value or result t.JsonValue."

        @runtime_checkable
        class SearchOptions(Protocol):
            """Protocol for LDAP search options (structural type).

            Accepts both simple types and complex types (StrEnum, models).
            StrEnum is compatible with str in structural typing.
            Models with scope as StrEnum are compatible.
            """

            base_dn: str
            scope: str
            filter_str: str
            attributes: t.StrSequence | None
            size_limit: int
            time_limit: int

        @runtime_checkable
        class OperationResult(Protocol):
            """Protocol for LDAP operation result (structural type).

            Accepts both simple types and complex types (StrEnum).
            StrEnum is compatible with str in structural typing.
            """

            success: bool
            operation_type: str
            message: str
            entries_affected: int

        @runtime_checkable
        class SearchResult(Protocol):
            """Protocol for LDAP search result (structural type)."""

            entries: t.SequenceOf[p.Ldif.Entry]
            search_options: FlextLdapProtocols.Ldap.SearchOptions

        @runtime_checkable
        class PhaseSyncResult(Protocol):
            """Protocol for phase sync result (structural type).

            PhaseSyncResult has total_entries, synced, failed, skipped attributes.
            """

            total_entries: int
            synced: int
            failed: int
            skipped: int

        # ── Layer 1: Service Protocols ───────────────────────────

        @runtime_checkable
        class LdapClient(Protocol):
            """Protocol for LDAP clients that support CRUD operations."""

            @property
            def is_connected(self) -> bool:
                """Check if client is connected.

                Returns:
                    True if connected, False otherwise

                """
                ...

            def add(
                self,
                entry: p.Ldif.Entry,
            ) -> p.Result[lm.Ldap.OperationResult]:
                """Add LDAP entry.

                Args:
                    entry: Entry model to add

                Returns:
                    Result containing OperationResult

                """
                ...

            def batch_upsert(
                self,
                entries: t.SequenceOf[p.Ldif.Entry],
                *,
                progress_callback: t.Ldap.LdapProgressCallback | None = None,
                retry_on_errors: t.StrSequence | None = None,
                max_retries: int = 1,
                stop_on_error: bool = False,
            ) -> p.Result[lm.Ldap.LdapBatchStats]:
                """Upsert multiple entries and report canonical batch statistics."""
                ...

            def connect(
                self,
                connection_config: FlextLdapProtocols.Ldap.ConnectionConfig,
                *,
                auto_retry: bool = False,
                max_retries: int = 1,
                retry_delay: float = 0.0,
                **kwargs: t.Scalar,
            ) -> p.Result[bool]:
                """Connect to LDAP server.

                Args:
                    settings: Connection configuration (may be named 'settings' or
                        'connection_config' in implementations)
                    **kwargs: Additional keyword arguments (e.g., auto_retry: bool,
                        max_retries: int, retry_delay: float)

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

            def disconnect(self) -> None:
                """Disconnect from LDAP server and release resources."""
                ...

            def delete(
                self,
                dn: str | p.Ldif.DN,
            ) -> p.Result[lm.Ldap.OperationResult]:
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
            ) -> p.Result[lm.Ldap.Response]:
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
                dn: str | p.Ldif.DN,
                changes: t.Ldap.LdapModifyChanges,
            ) -> p.Result[lm.Ldap.OperationResult]:
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
                search_options: FlextLdapProtocols.Ldap.SearchOptions,
                server_type: str = "rfc",
            ) -> p.Result[lm.Ldap.SearchResult]:
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

            This protocol defines the interface for LDAP adapters used
            by connection services.
            Uses structural types for type safety. Return types are Models
            (SearchResult, OperationResult) but are not imported to keep
            Protocols independent of Models.
            """

            @property
            def is_connected(self) -> bool:
                """Check if adapter is connected."""
                ...

            @property
            def connection(self) -> FlextLdapProtocols.Ldap.Ldap3Connection | None:
                """Return the active ldap3 connection when one exists."""
                ...

            def disconnect(self) -> None:
                """Close any active adapter connection."""
                ...

            def add(
                self,
                entry: p.Ldif.Entry,
            ) -> p.Result[lm.Ldap.OperationResult]:
                """Add LDAP entry.

                Returns Result containing OperationResult model.
                Models are structurally compatible with OperationResult.
                """
                ...

            def delete(
                self,
                dn: p.Ldif.DN | str,
            ) -> p.Result[lm.Ldap.OperationResult]:
                """Delete LDAP entry.

                Returns Result containing OperationResult model.
                Models are structurally compatible with OperationResult.
                """
                ...

            def modify(
                self,
                dn: p.Ldif.DN | str,
                changes: t.Ldap.LdapModifyChanges,
            ) -> p.Result[lm.Ldap.OperationResult]:
                """Modify LDAP entry.

                Returns Result containing OperationResult model.
                Models are structurally compatible with OperationResult.
                """
                ...

            def search(
                self,
                search_options: FlextLdapProtocols.Ldap.SearchOptions,
                server_type: str = "rfc",
            ) -> p.Result[FlextLdapProtocols.Ldap.SearchResult]:
                """Perform LDAP search operation.

                Returns Result containing SearchResult model.
                Models are structurally compatible with SearchResult.
                """
                ...

        @runtime_checkable
        class LdapConnection(Protocol):
            """Protocol for LDAP connection services.

            This protocol defines the interface for LDAP connection services used
            by operations services to break circular imports.
            Uses structural types for type safety without importing models.
            """

            @property
            def is_connected(self) -> bool:
                """Check if connection is active.

                Returns:
                    True if connected, False otherwise

                """
                ...

            def connect(
                self,
                connection_config: FlextLdapProtocols.Ldap.ConnectionConfig,
                *,
                auto_retry: bool = False,
                max_retries: int = 3,
                retry_delay: float = 1.0,
            ) -> p.Result[bool]:
                """Connect using the public LDAP connection service contract."""
                ...

            def disconnect(self) -> None:
                """Disconnect from LDAP server.

                Closes the connection and releases resources.
                Safe to call multiple times.

                """
                ...

            def execute(
                self,
            ) -> p.Result[FlextLdapProtocols.Ldap.SearchResult]:
                """Run the connection service health check/default operation."""
                ...

        # ── ldap3 Library Type Aliases ───────────────────────────
        # Direct aliases to the real ldap3 runtime classes. Avoids structural
        # Protocols whose stricter parameter annotations are not assignable
        # from ldap3's untyped (pyrefly-inferred Literal) signatures.

        Ldap3Connection: type[_Ldap3Connection] = _Ldap3Connection
        Ldap3Server: type[_Ldap3Server] = _Ldap3Server
        Ldap3ServerInfo: type[_Ldap3ServerInfo] = _Ldap3ServerInfo
        Ldap3Entry: type[_Ldap3Entry] = _Ldap3Entry
        Ldap3Attribute: type[_Ldap3Attribute] = _Ldap3Attribute

        @runtime_checkable
        class Ldap3ParseResponse(Protocol):
            """Protocol for ldap3.ParseResponse objects (structural type).

            ldap3.ParseResponse has an entries property containing list of Entry.
            """

            @property
            def entries(self) -> t.SequenceOf[FlextLdapProtocols.Ldap.Ldap3Entry]:
                """Get list of entries."""
                ...

        @runtime_checkable
        class RootDseEntry(Protocol):
            """Structural protocol for entries exposing rootDSE attributes."""

            @property
            def entry_attributes_as_dict(
                self,
            ) -> t.MappingKV[str, t.Ldap.Ldap3EntryValue]:
                """Return raw ldap3-style attribute payloads."""
                ...

        @runtime_checkable
        class RootDseConnection(Protocol):
            """Structural protocol for connections that can query rootDSE."""

            @property
            def search(
                self,
            ) -> Callable[..., bool | t.JsonValue | None] | None:
                """Return the ldap3-compatible search callable when available."""
                ...

            @property
            def result(self) -> t.MappingKV[str, t.JsonValue] | t.JsonValue | None:
                """Return the raw ldap3 result payload for the last operation."""
                ...

            @property
            def entries(
                self,
            ) -> t.SequenceOf[
                FlextLdapProtocols.Ldap.RootDseEntry | t.Ldap.Ldap3EntryValue
            ]:
                """Return the entry payloads produced by the last search."""
                ...

        # ── Structural Duck-Typing Protocols ─────────────────────

        @runtime_checkable
        class HasItemsMethod(Protocol):
            """Protocol for objects with items() method."""

            def items(self) -> t.SequenceOf[t.Pair[str, t.JsonValue]]:
                """Return items as sequence of tuples."""
                ...

        @runtime_checkable
        class HasConfigAttribute(Protocol):
            """Protocol for objects exposing configuration (duck typing for settings)."""

            @property
            def settings(self) -> None:
                """Return resolved configuration t.JsonValue."""
                ...

        @runtime_checkable
        class HasDynamicAttribute(Protocol):
            """Protocol for objects with dynamic attributes accessible via __getattr__."""

            def __getattr__(self, name: str) -> None:
                """Get dynamic attribute."""
                ...

        @runtime_checkable
        class HasAttributesProperty(Protocol):
            """Protocol for objects with 'attributes' property.

            Uses Mapping (covariant) instead of dict (invariant) to allow structural
            compatibility with dict subtypes and Sequence subtypes in values.
            """

            @property
            def attributes(
                self,
            ) -> t.MappingKV[str, t.Ldap.Ldap3EntryValue]:
                """Get attributes property - covariant Mapping for structural compatibility."""
                ...

        class ServiceContracts:
            """Service boundary contracts - stricter contracts for service interfaces."""

            @runtime_checkable
            class EntryContract(Protocol):
                """Structural LDAP entry contract for service boundaries.

                Stricter than LdapEntry - requires non-None dn and attributes.
                For use at service layer boundaries where data is validated.
                """

                dn: str
                attributes: t.MappingKV[str, t.StrSequence]

            @runtime_checkable
            class SearchOptionsContract(Protocol):
                """Structural LDAP search options contract for service boundaries.

                Minimal required fields for LDAP search operations at service layer.
                """

                scope: str
                filter_str: str
                attributes: t.StrSequence


p = FlextLdapProtocols

__all__: list[str] = ["FlextLdapProtocols", "p"]
