"""LDAP3 library stub definitions for flext-ldap.

This module provides stub definitions for LDAP3 library to enable
type checking without external dependencies.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# Constants
BASE: str = "BASE"
LEVEL: str = "LEVEL"
SUBTREE: str = "SUBTREE"
MODIFY_ADD: str = "MODIFY_ADD"
MODIFY_DELETE: str = "MODIFY_DELETE"
MODIFY_REPLACE: str = "MODIFY_REPLACE"


@runtime_checkable
class Connection(Protocol):
    """Protocol for LDAP3 Connection objects."""

    bound: bool
    entries: list[object]
    last_error: str | None

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: str,
        dereference_aliases: str = "ALWAYS",
        attributes: list[str] | None = None,
        size_limit: int = 0,
        time_limit: int = 0,
        *,
        types_only: bool = False,
        get_operational_attributes: bool = False,
        controls: object | None = None,
        paged_size: int | None = None,
        paged_criticality: bool = False,
        paged_cookie: str | bytes | None = None,
        auto_escape: bool | None = None,
    ) -> bool:
        """Perform LDAP search operation."""
        ...

    def bind(
        self,
        *,
        read_server_info: bool = True,
        controls: object | None = None,
    ) -> bool:
        """Bind to LDAP server."""
        ...

    def unbind(
        self,
        *,
        controls: object | None = None,
    ) -> bool:
        """Unbind from LDAP server."""
        ...

    def add(
        self,
        dn: str,
        object_class: list[str] | None = None,
        attributes: dict[str, str | list[str]] | None = None,
        *,
        controls: object | None = None,
    ) -> bool:
        """Add entry to LDAP directory."""
        ...

    def modify(
        self,
        dn: str,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        controls: object | None = None,
    ) -> bool:
        """Modify LDAP entry."""
        ...

    def delete(
        self,
        dn: str,
        *,
        controls: object | None = None,
    ) -> bool:
        """Delete LDAP entry."""
        ...


@runtime_checkable
class Server(Protocol):
    """Protocol for LDAP3 Server objects."""

    host: str
    port: int
    use_ssl: bool
    use_tls: bool


__all__ = [
    "BASE",
    "LEVEL",
    "MODIFY_ADD",
    "MODIFY_DELETE",
    "MODIFY_REPLACE",
    "SUBTREE",
    "Connection",
    "Server",
]
