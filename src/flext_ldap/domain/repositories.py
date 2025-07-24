"""LDAP Domain Repository Interfaces - Version 0.7.0.

Abstract repository interfaces - no implementation details.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_ldap.domain.entities import FlextLdapConnection, FlextLdapUser
    from flext_ldap.domain.value_objects import FlextLdapDistinguishedName


class FlextLdapConnectionRepository:
    """Repository for LDAP connections."""

    @abstractmethod
    async def get_by_server(self, server_url: str) -> list[FlextLdapConnection]:
        """Get connections by server URL."""
        ...

    @abstractmethod
    async def get_active(self) -> list[FlextLdapConnection]:
        """Get all active connections."""
        ...

    @abstractmethod
    async def close_all(self) -> None:
        """Close all connections."""
        ...


class FlextLdapUserRepository:
    """Repository for LDAP users."""

    @abstractmethod
    async def get_by_dn(self, dn: FlextLdapDistinguishedName) -> FlextLdapUser | None:
        """Get user by distinguished name."""
        ...

    @abstractmethod
    async def get_by_uid(self, uid: str) -> FlextLdapUser | None:
        """Get user by UID."""
        ...

    @abstractmethod
    async def search(
        self,
        base_dn: FlextLdapDistinguishedName,
        filter_string: str,
        attributes: list[str] | None = None,
    ) -> list[FlextLdapUser]:
        """Search for users with filter."""
        ...

    @abstractmethod
    async def exists(self, dn: FlextLdapDistinguishedName) -> bool:
        """Check if user exists."""
        ...
