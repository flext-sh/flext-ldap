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
    Protocol,
    Self,
    override,
    runtime_checkable,
)

from flext_ldap import FlextLdapTypes as t, m as lm
from flext_ldif import p


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

        @runtime_checkable
        class LdapSettings(p.BaseModel, Protocol):
            """Namespaced LDAP runtime settings branch."""

            host: str
            port: int
            use_ssl: bool
            use_tls: bool
            bind_dn: str
            bind_password: str
            timeout: int
            auto_bind: bool
            auto_range: bool

        @runtime_checkable
        class Settings(p.Ldif.Settings, Protocol):
            """MRO-composed settings contract with the LDAP namespace."""

            @property
            def Ldap(self) -> FlextLdapProtocols.Ldap.LdapSettings:
                """Namespaced LDAP settings branch (read-only for covariance)."""
                ...

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

            Contract consumed by adapter hosts (DIP): signatures mirror the
            concrete ldap3 adapter so services depend on this protocol while
            the adapters package remains the sole owner of ldap3 imports.
            """

            @property
            def is_connected(self) -> bool:
                """Check if adapter is connected."""
                ...

            @property
            def connection(self) -> FlextLdapProtocols.Ldap.Ldap3Connection | None:
                """The active ldap3 connection when one exists."""
                ...

            def connect(
                self,
                settings: lm.Ldap.ConnectionConfig,
            ) -> p.Result[bool]:
                """Establish the ldap3 server/connection pair and verify bind."""
                ...

            def disconnect(self) -> None:
                """Close any active adapter connection."""
                ...

            def add(
                self,
                entry: lm.Ldif.Entry,
            ) -> p.Result[lm.Ldap.OperationResult]:
                """Add LDAP entry, returning the operation result."""
                ...

            def delete(
                self,
                dn: str | lm.Ldif.DN,
            ) -> p.Result[lm.Ldap.OperationResult]:
                """Delete LDAP entry, returning the operation result."""
                ...

            def modify(
                self,
                dn: str | lm.Ldif.DN,
                changes: t.Ldap.OperationChanges,
            ) -> p.Result[lm.Ldap.OperationResult]:
                """Modify LDAP entry, returning the operation result."""
                ...

            def search(
                self,
                search_options: lm.Ldap.SearchOptions,
                server_type: str = "rfc",
            ) -> p.Result[lm.Ldap.SearchResult]:
                """Perform LDAP search, returning the search result."""
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

        # ── LDAP runtime object contracts ────────────────────────
        # These names are intentionally structural so downstream projects type
        # against stable protocol-owned contracts rather than ldap3 classes.

        @runtime_checkable
        class Ldap3Connection(Protocol):
            """Structural contract for ldap3-compatible connection objects."""

            @property
            def server(self) -> FlextLdapProtocols.Ldap.Ldap3Server:
                """The ldap3 server bound to this connection."""
                ...

            @property
            def bound(self) -> bool:
                """Whether the connection is currently bound."""
                ...

            def bind(self) -> bool:
                """Bind the connection using the configured credentials."""
                ...

            @property
            def result(self) -> t.JsonMapping | None:
                """The last LDAP operation result payload."""
                ...

            @property
            def entries(self) -> t.SequenceOf[FlextLdapProtocols.Ldap.Ldap3Entry]:
                """The entries produced by the last LDAP operation."""
                ...

            @property
            def add(self) -> Callable[..., bool]:
                """The callable implementing the add operation."""
                ...

            @property
            def delete(self) -> Callable[..., bool]:
                """The callable implementing the delete operation."""
                ...

            @property
            def modify(self) -> Callable[..., bool]:
                """The callable implementing the modify operation."""
                ...

            @property
            def search(self) -> Callable[..., bool | t.JsonValue | None]:
                """The callable implementing the search operation."""
                ...

            @property
            def start_tls(self) -> Callable[..., bool]:
                """The callable implementing STARTTLS negotiation."""
                ...

            @property
            def unbind(self) -> Callable[..., bool]:
                """The callable implementing connection teardown."""
                ...

        class Ldap3ServerInfo(Protocol):
            """Structural marker for ldap3-compatible server info payloads."""

            @property
            def naming_contexts(self) -> t.StrSequence | None:
                """The advertised naming contexts when available."""
                ...

            @property
            def other(self) -> t.MappingKV[str, t.JsonValue]:
                """The auxiliary ldap3 server info fields."""
                ...

        class Ldap3Server(Protocol):
            """Structural contract for ldap3-compatible server objects."""

            @property
            def info(self) -> FlextLdapProtocols.Ldap.Ldap3ServerInfo | None:
                """The ldap3 server-info payload when populated."""
                ...

            @override
            def __str__(self) -> str:
                """Return the server URL-style representation."""
                ...

        @runtime_checkable
        class Ldap3Entry(Protocol):
            """Structural contract for ldap3-compatible entry objects."""

            @property
            def entry_dn(self) -> str | None:
                """The entry distinguished name."""
                ...

            @property
            def entry_attributes(self) -> t.StrSequence:
                """The attribute names present in this entry."""
                ...

            @property
            def entry_attributes_as_dict(self) -> t.Ldap.Ldap3AttributeDict:
                """The entry attributes as an LDAP attribute mapping."""
                ...

            def __getitem__(
                self,
                attribute_name: str,
            ) -> FlextLdapProtocols.Ldap.Ldap3Attribute:
                """Return one ldap3 attribute object by attribute name."""
                ...

        class Ldap3Attribute(Protocol):
            """Structural contract for ldap3-compatible attribute objects."""

            @property
            def values(self) -> t.Ldap.Ldap3AttributeValues:
                """The raw LDAP values for this attribute."""
                ...

            @property
            def value(self) -> t.Ldap.Ldap3EntryValue:
                """The resolved attribute value."""
                ...

        @runtime_checkable
        class Ldap3ParseResponse(Protocol):
            """Protocol for ldap3.ParseResponse objects (structural type).

            ldap3.ParseResponse has an entries property containing list of Entry.
            """

            @property
            def entries(self) -> t.SequenceOf[FlextLdapProtocols.Ldap.Ldap3Entry]:
                """The list of entries."""
                ...

        @runtime_checkable
        class RootDseEntry(Protocol):
            """Structural protocol for entries exposing rootDSE attributes."""

            @property
            def entry_attributes_as_dict(
                self,
            ) -> t.MappingKV[str, t.Ldap.Ldap3EntryValue]:
                """The raw ldap3-style attribute payloads."""
                ...

        @runtime_checkable
        class RootDseConnection(Protocol):
            """Structural protocol for connections that can query rootDSE."""

            @property
            def search(
                self,
            ) -> Callable[..., bool | t.JsonValue | None] | None:
                """The ldap3-compatible search callable when available."""
                ...

            @property
            def result(self) -> t.JsonMapping | None:
                """The raw ldap3 result payload for the last operation."""
                ...

            @property
            def entries(
                self,
            ) -> t.SequenceOf[
                FlextLdapProtocols.Ldap.RootDseEntry | t.Ldap.Ldap3EntryValue
            ]:
                """The entry payloads produced by the last search."""
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
                """The resolved configuration t.JsonValue."""
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
                """The attributes property - covariant Mapping for structural compatibility."""
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
