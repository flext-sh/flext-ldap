"""LDAP3 library type definitions for flext-ldap.

This module provides proper type definitions for LDAP3 library objects
to enable full type checking without using object or type: ignore hints.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Ldap3Entry(Protocol):
    """Protocol for LDAP3 Entry objects."""

    entry_dn: str
    entry_attributes: dict[str, list[str]]

    def __getitem__(self, key: str) -> Ldap3Attribute:
        """Get attribute by name."""
        ...


@runtime_checkable
class Ldap3Attribute(Protocol):
    """Protocol for LDAP3 Attribute objects."""

    value: str | list[str]

    def __str__(self) -> str:
        """String representation."""
        ...


@runtime_checkable
class Ldap3Connection(Protocol):
    """Protocol for LDAP3 Connection objects."""

    bound: bool
    entries: list[Ldap3Entry]
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
class Ldap3Server(Protocol):
    """Protocol for LDAP3 Server objects."""

    host: str
    port: int
    use_ssl: bool
    use_tls: bool


# Type aliases for better readability
Ldap3AttributeValue = str | list[str]
Ldap3Attributes = dict[str, Ldap3AttributeValue]
Ldap3ModifyChanges = dict[str, list[tuple[str, list[str]]]]


__all__ = [
    "Ldap3Attribute",
    "Ldap3AttributeValue",
    "Ldap3Attributes",
    "Ldap3Connection",
    "Ldap3Entry",
    "Ldap3ModifyChanges",
    "Ldap3Server",
]
