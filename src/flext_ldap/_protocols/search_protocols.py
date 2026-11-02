"""LDAP structural domain and search protocol contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, override, runtime_checkable

from flext_ldif import FlextLdifProtocols


class FlextLdapProtocolsSearch:
    """LDAP search protocol contracts composed into ``p.Ldap``."""

    @runtime_checkable
    class LdapBatchStats(FlextLdifProtocols.Model, Protocol):
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
        attributes: Sequence[str] | None
        size_limit: int
        time_limit: int

    @runtime_checkable
    class OperationResult(FlextLdifProtocols.Model, Protocol):
        """Protocol for LDAP operation result (structural type).

        Accepts both simple types and complex types (StrEnum).
        StrEnum is compatible with str in structural typing.
        """

        @property
        def success(self) -> bool: ...

        @property
        def operation_type(self) -> str: ...

        @property
        def message(self) -> str: ...

        @property
        def entries_affected(self) -> int: ...

    @runtime_checkable
    class SearchResult(FlextLdifProtocols.Model, Protocol):
        """Protocol for LDAP search result (structural type)."""

        @property
        def entries(self) -> Sequence[FlextLdifProtocols.Ldif.Entry]: ...

        @property
        def search_options(self) -> FlextLdapProtocolsSearch.SearchOptions: ...

    @runtime_checkable
    class PhaseSyncResult(Protocol):
        """Protocol for phase sync result (structural type).

        PhaseSyncResult has total_entries, synced, failed, skipped attributes.
        """

        total_entries: int
        synced: int
        failed: int
        skipped: int


__all__: list[str] = ["FlextLdapProtocolsSearch"]
