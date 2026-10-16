"""LDAP structural domain and search protocol contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, override, runtime_checkable

from flext_ldif import FlextLdifProtocols

if TYPE_CHECKING:
    from flext_ldap import t


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

    entries: t.SequenceOf[FlextLdifProtocols.Ldif.Entry]
    search_options: SearchOptions


@runtime_checkable
class PhaseSyncResult(Protocol):
    """Protocol for phase sync result (structural type).

    PhaseSyncResult has total_entries, synced, failed, skipped attributes.
    """

    total_entries: int
    synced: int
    failed: int
    skipped: int


__all__: list[str] = [
    "ConnectionConfig",
    "LdapBatchStats",
    "OperationResult",
    "PhaseSyncResult",
    "SearchOptions",
    "SearchResult",
    "SearchScope",
]
