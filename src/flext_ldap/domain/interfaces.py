"""LDAP Domain Interfaces - Abstract Contracts.

🏗️ CLEAN ARCHITECTURE: Domain Interfaces
Built on flext-core foundation patterns.

Interfaces define contracts for infrastructure implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports

if TYPE_CHECKING:
    from flext_core import FlextResult

    from flext_ldap.domain.entities import FlextLdapEntry
    from flext_ldap.domain.values import DistinguishedName, LDAPFilter, LDAPScope


class FlextLdapConnectionManager(ABC):
    """Abstract interface for LDAP connection management."""

    @abstractmethod
    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[Any]:
        """Establish LDAP connection.

        Args:
            server_url: LDAP server URL
            bind_dn: Bind distinguished name
            password: Bind password

        Returns:
            FlextResult containing connection ID if successful

        """

    @abstractmethod
    async def disconnect(self, connection_id: str) -> FlextResult[Any]:
        """Disconnect from LDAP server.

        Args:
            connection_id: Connection identifier

        Returns:
            FlextResult indicating success

        """

    @abstractmethod
    async def ping(self, connection_id: str) -> FlextResult[Any]:
        """Test connection health.

        Args:
            connection_id: Connection identifier

        Returns:
            FlextResult indicating connection health

        """


class FlextLdapDirectoryRepository(ABC):
    """Abstract repository for LDAP directory operations."""

    @abstractmethod
    async def search(
        self,
        connection_id: str,
        base_dn: DistinguishedName,
        search_filter: LDAPFilter,
        scope: LDAPScope,
        attributes: list[str] | None = None,
    ) -> FlextResult[Any]:
        """Search LDAP directory.

        Args:
            connection_id: Active connection identifier
            base_dn: Search base distinguished name
            search_filter: LDAP search filter
            scope: Search scope
            attributes: Attributes to return

        Returns:
            FlextResult containing list of matching entries

        """

    @abstractmethod
    async def create_entry(
        self,
        connection_id: str,
        entry: FlextLdapEntry,
    ) -> FlextResult[Any]:
        """Create LDAP entry.

        Args:
            connection_id: Active connection identifier
            entry: LDAP entry to create

        Returns:
            FlextResult indicating success

        """

    @abstractmethod
    async def modify_entry(
        self,
        connection_id: str,
        dn: DistinguishedName,
        changes: dict[str, Any],
    ) -> FlextResult[Any]:
        """Modify LDAP entry.

        Args:
            connection_id: Active connection identifier
            dn: Distinguished name of entry to modify
            changes: Modifications to apply

        Returns:
            FlextResult indicating success

        """

    @abstractmethod
    async def delete_entry(
        self,
        connection_id: str,
        dn: DistinguishedName,
    ) -> FlextResult[Any]:
        """Delete LDAP entry.

        Args:
            connection_id: Active connection identifier
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success

        """


class FlextLdapSchemaValidator(ABC):
    """Abstract interface for LDAP schema validation."""

    @abstractmethod
    def validate_entry(self, entry: FlextLdapEntry) -> FlextResult[Any]:
        """Validate LDAP entry against schema.

        Args:
            entry: LDAP entry to validate

        Returns:
            FlextResult indicating validation result

        """

    @abstractmethod
    def get_required_attributes(self, object_class: str) -> list[str]:
        """Get required attributes for object class.

        Args:
            object_class: LDAP object class name

        Returns:
            List of required attribute names

        """

    @abstractmethod
    def validate_attribute_syntax(
        self,
        attribute_name: str,
        value: str,
    ) -> FlextResult[Any]:
        """Validate attribute value syntax.

        Args:
            attribute_name: Name of the attribute
            value: Value to validate

        Returns:
            FlextResult indicating validation result

        """


# FlextLdapUserRepository moved to domain.repositories for better organization


class FlextLdapGroupRepository(ABC):
    """Abstract repository for LDAP group operations."""

    @abstractmethod
    async def find_group_by_dn(
        self,
        connection_id: str,
        dn: DistinguishedName,
    ) -> FlextResult[Any]:
        """Find group by distinguished name.

        Args:
            connection_id: Active connection identifier
            dn: Group distinguished name

        Returns:
            FlextResult containing group if found

        """

    @abstractmethod
    async def get_group_members(
        self,
        connection_id: str,
        group_dn: DistinguishedName,
    ) -> FlextResult[Any]:
        """Get group members.

        Args:
            connection_id: Active connection identifier
            group_dn: Group distinguished name

        Returns:
            FlextResult containing list of member DNs

        """

    @abstractmethod
    async def add_member_to_group(
        self,
        connection_id: str,
        group_dn: DistinguishedName,
        member_dn: DistinguishedName,
    ) -> FlextResult[Any]:
        """Add member to group.

        Args:
            connection_id: Active connection identifier
            group_dn: Group distinguished name
            member_dn: Member distinguished name

        Returns:
            FlextResult indicating success

        """
