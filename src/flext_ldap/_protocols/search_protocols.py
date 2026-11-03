"""LDAP structural domain and search protocol contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, override, runtime_checkable


class FlextLdapProtocolsSearch:
    """LDAP search protocol contracts composed into ``p.Ldap``."""

    @runtime_checkable
    class SearchScope(Protocol):
        """Protocol for search scope (structural type - accepts StrEnum or str)."""

        @override
        def __str__(self) -> str:
            """Return string representation of scope."""
            ...


__all__: list[str] = ["FlextLdapProtocolsSearch"]
