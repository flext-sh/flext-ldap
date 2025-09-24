"""Type definitions for ldap3 to provide proper type safety.

This module provides proper type definitions for ldap3 Connection methods
that are not properly typed in the official types-ldap3 package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal, Protocol

from ldap3 import Connection as _Connection


# Type alias for ldap3 Entry (not properly typed in types-ldap3)
# Using object as base type since ldap3 Entry is not properly typed
class LdapAttribute(Protocol):
    """Protocol for ldap3 Attribute objects."""

    value: object


class LdapEntry(Protocol):
    """Protocol for ldap3 Entry objects."""

    entry_dn: str
    entry_attributes: dict[str, list[str]]

    def __getitem__(self, key: str) -> LdapAttribute:
        """Get entry attribute by name."""
        ...


class LdapConnectionProtocol(Protocol):
    """Protocol for ldap3 Connection with proper type annotations."""

    bound: bool
    last_error: str
    entries: list[LdapEntry]  # ldap3 Entry objects from type alias

    def modify(self, dn: str, changes: dict[str, list[tuple[str, list[str]]]]) -> bool:
        """Modify LDAP entry."""
        ...

    def delete(self, dn: str) -> bool:
        """Delete LDAP entry."""
        ...

    def add(
        self, dn: str, attributes: dict[str, str | list[str]] | None = None
    ) -> bool:
        """Add LDAP entry."""
        ...

    def compare(self, dn: str, attribute: str, value: str) -> bool:
        """Compare LDAP attribute value."""
        ...

    def extended(
        self, request_name: str, request_value: str | bytes | None = None
    ) -> bool:
        """Perform extended LDAP operation."""
        ...

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: Literal["BASE", "LEVEL", "SUBTREE"],
        attributes: list[str] | None = None,
        size_limit: int = 0,
        time_limit: int = 0,
        types_only: bool = False,  # noqa: FBT001, FBT002
        dereference_aliases: int = 0,
        controls: list[object] | None = None,
        paged_size: int | None = None,
        paged_cookie: bytes | None = None,
    ) -> bool:
        """Search LDAP directory."""
        ...

    def bind(self) -> bool:
        """Bind to LDAP server."""
        ...

    def unbind(self) -> bool:
        """Unbind from LDAP server."""
        ...


# Type alias for the actual Connection type
Connection = _Connection
