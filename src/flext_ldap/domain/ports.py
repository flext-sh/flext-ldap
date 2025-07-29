"""Domain ports (service interfaces) for FLEXT-LDAP.

Using clean architecture patterns - NO duplication with flext-core.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports

if TYPE_CHECKING:
    from flext_core import FlextResult

    from flext_ldap.entities import FlextLdapConnection


class FlextLdapConnectionService(ABC):
    """Abstract LDAP connection service port."""

    @abstractmethod
    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[object]:
        """Connect to LDAP server."""
        ...

    @abstractmethod
    async def disconnect(self, connection: FlextLdapConnection) -> FlextResult[object]:
        """Disconnect from LDAP server."""
        ...

    @abstractmethod
    async def bind(
        self,
        connection: FlextLdapConnection,
        bind_dn: str,
        password: str,
    ) -> FlextResult[object]:
        """Bind to LDAP server with credentials."""
        ...

    @abstractmethod
    async def unbind(self, connection: FlextLdapConnection) -> FlextResult[object]:
        """Unbind from LDAP server."""
        ...

    @abstractmethod
    async def test_connection(
        self,
        connection: FlextLdapConnection,
    ) -> FlextResult[object]:
        """Test LDAP connection health."""
        ...

    @abstractmethod
    async def get_connection_info(
        self,
        connection: FlextLdapConnection,
    ) -> FlextResult[object]:
        """Get connection information."""
        ...


class FlextLdapSearchService(ABC):
    """Abstract LDAP search service port."""

    @abstractmethod
    async def search(
        self,
        connection: FlextLdapConnection,
        base_dn: str,
        filter_string: str,
        attributes: list[str] | None = None,
        scope: str = "sub",
    ) -> FlextResult[object]:
        """Search LDAP entries."""
        ...

    @abstractmethod
    async def search_users(
        self,
        connection: FlextLdapConnection,
        base_dn: str,
        filter_string: str | None = None,
    ) -> FlextResult[object]:
        """Search for LDAP users."""
        ...


class FlextLdapUserService(ABC):
    """Abstract LDAP user service port."""

    @abstractmethod
    async def create_user(
        self,
        connection: FlextLdapConnection,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[object]:
        """Create a new LDAP user."""
        ...

    @abstractmethod
    async def get_user(
        self,
        connection: FlextLdapConnection,
        dn: str,
    ) -> FlextResult[object]:
        """Get user by distinguished name."""
        ...

    @abstractmethod
    async def update_user(
        self,
        connection: FlextLdapConnection,
        dn: str,
        modifications: dict[str, list[str]],
    ) -> FlextResult[object]:
        """Update user attributes."""
        ...

    @abstractmethod
    async def delete_user(
        self,
        connection: FlextLdapConnection,
        dn: str,
    ) -> FlextResult[object]:
        """Delete user."""
        ...

    @abstractmethod
    async def list_users(
        self,
        connection: FlextLdapConnection,
        base_dn: str,
        limit: int = 100,
    ) -> FlextResult[object]:
        """List users in organizational unit."""
        ...


class FlextLdapSchemaService(ABC):
    """Abstract LDAP schema service port."""

    @abstractmethod
    async def get_schema(
        self,
        connection: FlextLdapConnection,
    ) -> FlextResult[object]:
        """Get LDAP schema information."""
        ...

    @abstractmethod
    async def validate_entry(
        self,
        connection: FlextLdapConnection,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[object]:
        """Validate entry against schema."""
        ...


class FlextLdapMigrationService(ABC):
    """Abstract LDAP migration service port."""

    @abstractmethod
    async def export_entries(
        self,
        connection: FlextLdapConnection,
        base_dn: str,
        output_format: str = "ldif",
    ) -> FlextResult[object]:
        """Export LDAP entries."""
        ...

    @abstractmethod
    async def import_entries(
        self,
        connection: FlextLdapConnection,
        data: str,
        format_type: str = "ldif",
    ) -> FlextResult[object]:
        """Import LDAP entries."""
        ...

    @abstractmethod
    async def migrate_users(
        self,
        source_connection: FlextLdapConnection,
        target_connection: FlextLdapConnection,
        base_dn: str,
    ) -> FlextResult[object]:
        """Migrate users between LDAP servers."""
        ...
