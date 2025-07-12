"""LDAP Domain Repository Interfaces - Version 0.7.0.

Abstract repository interfaces - no implementation details.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_ldap.domain.entities import LDAPConnection, LDAPUser
    from flext_ldap.domain.value_objects import DistinguishedName


class LDAPConnectionRepository:
    """Repository for LDAP connections."""

    @abstractmethod
    async def get_by_server(self, server_url: str) -> list[LDAPConnection]:
        """Get connections by server URL."""
        ...

    @abstractmethod
    async def get_active(self) -> list[LDAPConnection]:
        """Get all active connections."""
        ...

    @abstractmethod
    async def close_all(self) -> None:
        """Close all connections."""
        ...


class LDAPUserRepository:
    """Repository for LDAP users."""

    @abstractmethod
    async def get_by_dn(self, dn: DistinguishedName) -> LDAPUser | None:
        """Get user by distinguished name."""
        ...

    @abstractmethod
    async def get_by_uid(self, uid: str) -> LDAPUser | None:
        """Get user by UID."""
        ...

    @abstractmethod
    async def search(
        self,
        base_dn: DistinguishedName,
        filter_string: str,
        attributes: list[str] | None = None,
    ) -> list[LDAPUser]:
        """Search for users with filter."""
        ...

    @abstractmethod
    async def exists(self, dn: DistinguishedName) -> bool:
        """Check if user exists."""
        ...
