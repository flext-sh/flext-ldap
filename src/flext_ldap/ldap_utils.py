"""FLEXT-LDAP Utils - Consolidated Utilities and Protocols.

🎯 CONSOLIDATES 2 FILES INTO SINGLE PEP8 MODULE:
- utils.py (9,399 bytes) - LDAP utilities and helper functions
- protocols.py (25,959 bytes) - Type protocols and interfaces

This module provides utility functions and protocol definitions for FLEXT-LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flext_core import FlextResult

# Type aliases para evitar Any explícito
type LdapAttributeValue = str | bytes | list[str] | list[bytes]
type LdapAttributeDict = dict[str, LdapAttributeValue]
type LdapSearchResult = dict[str, LdapAttributeValue]

# =============================================================================
# VALIDATION UTILITIES
# =============================================================================


def flext_ldap_validate_dn(dn: str) -> bool:
    """Validate Distinguished Name format."""
    if not dn or not isinstance(dn, str):
        return False

    # Basic DN validation pattern
    dn_pattern = re.compile(
        r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$",
    )

    return bool(dn_pattern.match(dn.strip()))


def flext_ldap_validate_attribute_name(name: str) -> bool:
    """Validate LDAP attribute name."""
    if not name or not isinstance(name, str):
        return False

    # LDAP attribute names: alphanumeric, hyphen, semicolon
    attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9;-]*$")
    return bool(attr_pattern.match(name))


def flext_ldap_validate_attribute_value(value: object) -> bool:
    """Validate LDAP attribute value."""
    if not isinstance(value, str):
        return False

    # Basic validation - no null characters
    return "\x00" not in value


def flext_ldap_sanitize_attribute_name(name: str) -> str:
    """Sanitize LDAP attribute name."""
    if not name:
        return ""

    # Remove invalid characters and normalize
    sanitized = re.sub(r"[^a-zA-Z0-9;-]", "", name)
    return sanitized.lower()


# =============================================================================
# PROTOCOLS AND INTERFACES
# =============================================================================

@runtime_checkable
class FlextLdapConnectionProtocol(Protocol):
    """Protocol for LDAP connection implementations."""

    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[None]:
        """Connect to LDAP server."""
        ...

    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server."""
        ...

    async def search(
        self,
        base_dn: str,
        search_filter: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Perform LDAP search."""
        ...


@runtime_checkable
class FlextLdapRepositoryProtocol(Protocol):
    """Protocol for LDAP repository implementations."""

    async def find_by_dn(self, dn: str) -> FlextResult[LdapSearchResult | None]:
        """Find entry by Distinguished Name."""
        ...

    async def save(self, entry_data: LdapAttributeDict) -> FlextResult[None]:
        """Save entry data."""
        ...

    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry by DN."""
        ...


@runtime_checkable
class FlextLdapDirectoryConnectionProtocol(Protocol):
    """Protocol for directory connection implementations."""

    def is_connected(self) -> bool:
        """Check if connection is active."""
        ...

    async def bind(self, dn: str, password: str) -> FlextResult[None]:
        """Perform LDAP bind operation."""
        ...


@runtime_checkable
class FlextLdapDirectoryEntryProtocol(Protocol):
    """Protocol for directory entry implementations."""

    @property
    def dn(self) -> str:
        """Get Distinguished Name."""
        ...

    @property
    def attributes(self) -> dict[str, list[str]]:
        """Get entry attributes."""
        ...

    def get_attribute_values(self, name: str) -> list[str]:
        """Get attribute values by name."""
        ...


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Protocols
    "FlextLdapConnectionProtocol",
    "FlextLdapDirectoryConnectionProtocol",
    "FlextLdapDirectoryEntryProtocol",
    "FlextLdapRepositoryProtocol",
    "flext_ldap_sanitize_attribute_name",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    # Validation utilities
    "flext_ldap_validate_dn",
]
