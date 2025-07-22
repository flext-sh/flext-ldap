"""Domain ports (service interfaces) for FLEXT-LDAP.

Using clean architecture patterns - NO duplication with flext-core.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flext_core.domain.shared_types import ServiceResult

    from flext_ldap.domain.entities import LDAPConnection


class LDAPConnectionService(ABC):
    """Abstract LDAP connection service port."""

    @abstractmethod
    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> ServiceResult[Any]:
        """Connect to LDAP server."""
        ...

    @abstractmethod
    async def disconnect(self, connection: LDAPConnection) -> ServiceResult[Any]:
        """Disconnect from LDAP server."""
        ...

    @abstractmethod
    async def bind(
        self,
        connection: LDAPConnection,
        bind_dn: str,
        password: str,
    ) -> ServiceResult[Any]:
        """Bind to LDAP server with credentials."""
        ...

    @abstractmethod
    async def unbind(self, connection: LDAPConnection) -> ServiceResult[Any]:
        """Unbind from LDAP server."""
        ...

    @abstractmethod
    async def test_connection(self, connection: LDAPConnection) -> ServiceResult[Any]:
        """Test LDAP connection health."""
        ...

    @abstractmethod
    async def get_connection_info(
        self,
        connection: LDAPConnection,
    ) -> ServiceResult[Any]:
        """Get connection information."""
        ...


class LDAPSearchService(ABC):
    """Abstract LDAP search service port."""

    @abstractmethod
    async def search(
        self,
        connection: LDAPConnection,
        base_dn: str,
        filter_string: str,
        attributes: list[str] | None = None,
        scope: str = "sub",
    ) -> ServiceResult[Any]:
        """Search LDAP entries."""
        ...

    @abstractmethod
    async def search_users(
        self,
        connection: LDAPConnection,
        base_dn: str,
        filter_string: str | None = None,
    ) -> ServiceResult[Any]:
        """Search for LDAP users."""
        ...


class LDAPUserService(ABC):
    """Abstract LDAP user service port."""

    @abstractmethod
    async def create_user(
        self,
        connection: LDAPConnection,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> ServiceResult[Any]:
        """Create a new LDAP user."""
        ...

    @abstractmethod
    async def get_user(
        self,
        connection: LDAPConnection,
        dn: str,
    ) -> ServiceResult[Any]:
        """Get user by distinguished name."""
        ...

    @abstractmethod
    async def update_user(
        self,
        connection: LDAPConnection,
        dn: str,
        modifications: dict[str, list[str]],
    ) -> ServiceResult[Any]:
        """Update user attributes."""
        ...

    @abstractmethod
    async def delete_user(
        self,
        connection: LDAPConnection,
        dn: str,
    ) -> ServiceResult[Any]:
        """Delete user."""
        ...

    @abstractmethod
    async def list_users(
        self,
        connection: LDAPConnection,
        base_dn: str,
        limit: int = 100,
    ) -> ServiceResult[Any]:
        """List users in organizational unit."""
        ...


class LDAPSchemaService(ABC):
    """Abstract LDAP schema service port."""

    @abstractmethod
    async def get_schema(
        self,
        connection: LDAPConnection,
    ) -> ServiceResult[Any]:
        """Get LDAP schema information."""
        ...

    @abstractmethod
    async def validate_entry(
        self,
        connection: LDAPConnection,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> ServiceResult[Any]:
        """Validate entry against schema."""
        ...


class LDAPMigrationService(ABC):
    """Abstract LDAP migration service port."""

    @abstractmethod
    async def export_entries(
        self,
        connection: LDAPConnection,
        base_dn: str,
        output_format: str = "ldif",
    ) -> ServiceResult[Any]:
        """Export LDAP entries."""
        ...

    @abstractmethod
    async def import_entries(
        self,
        connection: LDAPConnection,
        data: str,
        format_type: str = "ldif",
    ) -> ServiceResult[Any]:
        """Import LDAP entries."""
        ...

    @abstractmethod
    async def migrate_users(
        self,
        source_connection: LDAPConnection,
        target_connection: LDAPConnection,
        base_dn: str,
    ) -> ServiceResult[Any]:
        """Migrate users between LDAP servers."""
        ...
