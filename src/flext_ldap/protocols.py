"""LDAP Protocol Definitions - Protocol Interfaces for FLEXT LDAP Operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Protocols use structural typing only - no model imports.
This allows protocols to remain independent of model implementations.

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, Protocol, override, runtime_checkable

from flext_core import r
from flext_ldif import FlextLdifProtocols, t

type _Ldap3SearchScope = Literal["BASE", "LEVEL", "SUBTREE"]
type _Ldap3DerefAliases = Literal["NEVER", "SEARCH", "FINDING_BASE", "ALWAYS"]
type _Ldap3ModifyChanges = dict[str, list[tuple[str, list[str]]]]


class FlextLdapProtocols(FlextLdifProtocols):
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
        are accessed via `.Ldif` namespace (e.g., `m.Ldif.Entry`).

        Pattern: `p.Ldap.ProtocolName` (aligned with flext-ldif, flext-cli)
        """

        @runtime_checkable
        class DN(Protocol):
            """Protocol for Distinguished Name (structural type)."""

            @override
            def __str__(self) -> str:
                """Return string representation of DN."""
                ...

            @property
            def value(self) -> str:
                """Get DN value."""
                ...

        @runtime_checkable
        class Attributes(Protocol):
            """Protocol for LDIF attributes (structural type)."""

            @property
            def attributes(self) -> Mapping[str, t.StrSequence]:
                """Get attributes mapping."""
                ...

        @runtime_checkable
        class LdapEntry(Protocol):
            """Protocol for LDAP entry (structural type).

            Accepts both simple types and complex types (models).
            DN has __str__ method, Attributes has
            .attributes property.
            Models are structurally compatible through attribute access.

            IMPORTANT: Allows None for dn and attributes to be compatible with
            FlextLdifModels.Ldif.Entry which allows None for RFC violation capture
            during LDIF processing. Application layer validates non-None requirement.

            Type Strategy: Accept both concrete Attributes class (from flext-ldif)
            and dict types for flexibility with structural typing.
            """

            dn: str | p.Ldap.DN | None
            attributes: Mapping[str, t.StrSequence] | p.Ldap.Attributes | None
            metadata: t.ConfigMap | None

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

                is_failure: bool
                "Indicates if parsing failed."
                is_success: bool
                "Indicates if parsing succeeded."
                error: str | None
                "Error message if parsing failed."
                value: t.Scalar | None
                "Parsed value or result t.NormalizedValue."

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

            entries: Sequence[p.Ldap.LdapEntry]
            search_options: p.Ldap.SearchOptions

        @runtime_checkable
        class PhaseSyncResult(Protocol):
            """Protocol for phase sync result (structural type).

            PhaseSyncResult has total_entries, synced, failed, skipped attributes.
            """

            total_entries: int
            synced: int
            failed: int
            skipped: int

        @runtime_checkable
        class LdapClient(Protocol):
            """Protocol for LDAP clients that support CRUD operations.

            This protocol defines the interface for LDAP clients used in test helpers.
            Uses structural types for type safety without importing models.
            """

            @property
            def is_connected(self) -> bool:
                """Check if client is connected.

                Returns:
                    True if connected, False otherwise

                """
                ...

            def add(
                self,
                entry: p.Ldap.LdapEntry,
            ) -> r[p.Ldap.OperationResult]:
                """Add LDAP entry.

                Args:
                    entry: Entry model to add

                Returns:
                    Result containing OperationResult

                """
                ...

            def connect(
                self,
                config: p.Ldap.ConnectionConfig,
                **kwargs: t.Scalar,
            ) -> r[bool]:
                """Connect to LDAP server.

                Args:
                    config: Connection configuration (may be named 'config' or
                        'connection_config' in implementations)
                    **kwargs: Additional keyword arguments (e.g., auto_retry: bool,
                        max_retries: int, retry_delay: float)

                Returns:
                    Result[bool] indicating connection success or failure

                """
                ...

            def delete(
                self,
                dn: str | p.Ldap.DN,
            ) -> r[p.Ldap.OperationResult]:
                """Delete LDAP entry.

                Args:
                    dn: Distinguished name of entry to delete

                Returns:
                    Result containing OperationResult

                """
                ...

            def execute(
                self,
                **_kwargs: t.Scalar,
            ) -> r[p.Ldap.SearchResult]:
                """Execute health check or default operation.

                Args:
                    **_kwargs: Additional keyword arguments
                        (flexible types for extensibility)

                Returns:
                    Result containing SearchResult

                """
                ...

            def modify(
                self,
                dn: str | p.Ldap.DN,
                changes: Mapping[str, Sequence[tuple[str | int, t.StrSequence]]],
            ) -> r[p.Ldap.OperationResult]:
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
                search_options: p.Ldap.SearchOptions,
                server_type: str = "rfc",
            ) -> r[p.Ldap.SearchResult]:
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

            def add(
                self,
                entry: p.Ldap.LdapEntry,
            ) -> r[p.Ldap.OperationResult]:
                """Add LDAP entry.

                Returns Result containing OperationResult model.
                Models are structurally compatible with OperationResult.
                """
                ...

            def delete(
                self,
                dn: p.Ldap.DN | str,
            ) -> r[p.Ldap.OperationResult]:
                """Delete LDAP entry.

                Returns Result containing OperationResult model.
                Models are structurally compatible with OperationResult.
                """
                ...

            def modify(
                self,
                dn: p.Ldap.DN | str,
                changes: Mapping[str, Sequence[tuple[str | int, t.StrSequence]]],
            ) -> r[p.Ldap.OperationResult]:
                """Modify LDAP entry.

                Returns Result containing OperationResult model.
                Models are structurally compatible with OperationResult.
                """
                ...

            def search(
                self,
                search_options: p.Ldap.SearchOptions,
                server_type: str = "rfc",
            ) -> r[p.Ldap.SearchResult]:
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
            def adapter(self) -> p.Ldap.LdapAdapter:
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

        @runtime_checkable
        class Ldap3Connection(Protocol):
            """Protocol for ldap3.Connection objects (structural type).

            Provides the structural interface for LDAP connections so test code
            outside flext-ldap/src and flext-ldif/src never imports ldap3 directly.
            """

            bound: bool

            @property
            def server(self) -> p.Ldap.Ldap3Server:
                """Get the server this connection is bound to."""
                ...

            @property
            def entries(self) -> Sequence[p.Ldap.Ldap3Entry]:
                """Get entries from last search operation."""
                ...

            def bind(self) -> bool:
                """Bind the connection."""
                ...

            def start_tls(self) -> bool:
                """Negotiate STARTTLS for the active connection."""
                ...

            def unbind(self) -> bool:
                """Unbind the connection."""
                ...

            def search(
                self,
                search_base: str,
                search_filter: str,
                search_scope: _Ldap3SearchScope = "SUBTREE",
                dereference_aliases: _Ldap3DerefAliases = "ALWAYS",
                attributes: t.StrSequence | str | None = None,
                size_limit: int = 0,
                time_limit: int = 0,
                *,
                types_only: bool = False,
                get_operational_attributes: bool = False,
                controls: None = None,
                paged_size: int | None = None,
                paged_criticality: bool = False,
                paged_cookie: str | bytes | None = None,
                auto_escape: bool | None = None,
            ) -> bool:
                """Perform LDAP search."""
                ...

            def add(
                self,
                dn: str,
                object_class: t.StrSequence | str | None,
                attributes: Mapping[str, str | bytes | t.StrSequence | Sequence[bytes]]
                | None,
            ) -> bool:
                """Add an LDAP entry."""
                ...

            def delete(self, dn: str) -> bool:
                """Delete an LDAP entry."""
                ...

            def modify(
                self,
                dn: str,
                changes: _Ldap3ModifyChanges,
                controls: None = None,
            ) -> bool:
                """Modify an LDAP entry."""
                ...

        @runtime_checkable
        class Ldap3Server(Protocol):
            """Protocol for ldap3.Server objects (structural type)."""

            @property
            def info(self) -> p.Ldap.Ldap3ServerInfo | None:
                """Get server info."""
                ...

        @runtime_checkable
        class Ldap3ServerInfo(Protocol):
            """Protocol for ldap3 server info objects (structural type)."""

            @property
            def naming_contexts(self) -> t.StrSequence:
                """Get naming contexts."""
                ...

        @runtime_checkable
        class Ldap3Entry(Protocol):
            """Protocol for ldap3.Entry objects (structural type).

            ldap3.Entry has dynamic attributes accessed via entry_dn,
            entry_attributes, entry_attributes_as_dict properties,
            plus attribute-specific objects via __getitem__.
            """

            @property
            def entry_attributes_as_dict(
                self,
            ) -> Mapping[str, Sequence[str | bytes]]:
                """Get attributes as dict mapping attribute names to value lists."""
                ...

            @property
            def entry_attributes(self) -> t.StrSequence:
                """Get list of attribute names present in this entry."""
                ...

            @property
            def entry_dn(self) -> str | None:
                """Get entry distinguished name."""
                ...

            def __getitem__(self, item: str) -> p.Ldap.Ldap3Attribute:
                """Get attribute object by name."""
                ...

        @runtime_checkable
        class Ldap3Attribute(Protocol):
            """Protocol for ldap3.Attribute objects (structural type).

            ldap3.Attribute has values, raw_values and value properties.
            """

            @property
            def values(self) -> Sequence[str | bytes]:
                """Get processed attribute values."""
                ...

            @property
            def raw_values(self) -> Sequence[bytes]:
                """Get unprocessed attribute values."""
                ...

            @property
            def value(self) -> str | bytes | Sequence[str | bytes]:
                """Get single value or all values."""
                ...

        @runtime_checkable
        class Ldap3ParseResponse(Protocol):
            """Protocol for ldap3.ParseResponse objects (structural type).

            ldap3.ParseResponse has an entries property containing list of Entry.
            """

            @property
            def entries(self) -> Sequence[p.Ldap.Ldap3Entry]:
                """Get list of entries."""
                ...

        @runtime_checkable
        class HasItemsMethod(Protocol):
            """Protocol for objects with items() method."""

            def items(self) -> Sequence[tuple[str, t.NormalizedValue]]:
                """Return items as sequence of tuples."""
                ...

        @runtime_checkable
        class HasConfigAttribute(Protocol):
            """Protocol for objects exposing configuration (duck typing for settings)."""

            @property
            def config(self) -> None:
                """Return resolved configuration t.NormalizedValue."""
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
            ) -> Mapping[
                str,
                str
                | bytes
                | int
                | float
                | bool
                | Sequence[str | bytes | t.Numeric | bool]
                | None,
            ]:
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
                attributes: Mapping[str, t.StrSequence]

            @runtime_checkable
            class SearchOptionsContract(Protocol):
                """Structural LDAP search options contract for service boundaries.

                Minimal required fields for LDAP search operations at service layer.
                """

                scope: str
                filter_str: str
                attributes: t.StrSequence


__all__ = ["FlextLdapProtocols", "p"]

p = FlextLdapProtocols
