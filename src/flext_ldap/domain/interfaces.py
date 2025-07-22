"""LDAP Domain Interfaces - Abstract Contracts.

🏗️ CLEAN ARCHITECTURE: Domain Interfaces
Built on flext-core foundation patterns.

Interfaces define contracts for infrastructure implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from flext_core import AbstractRepository

if TYPE_CHECKING:
    from flext_core.domain.shared_types import ServiceResult

    from flext_ldap.domain.entities import LDAPEntry, LDAPGroup, LDAPUser
    from flext_ldap.domain.values import DistinguishedName, LDAPFilter, LDAPScope


class LDAPConnectionManager(ABC):
    """Abstract interface for LDAP connection management."""

    @abstractmethod
    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> ServiceResult[Any]:
        """Establish LDAP connection.

        Args:
            server_url: LDAP server URL
            bind_dn: Bind distinguished name
            password: Bind password

        Returns:
            ServiceResult containing connection ID if successful

        """

    @abstractmethod
    async def disconnect(self, connection_id: str) -> ServiceResult[Any]:
        """Disconnect from LDAP server.

        Args:
            connection_id: Connection identifier

        Returns:
            ServiceResult indicating success

        """

    @abstractmethod
    async def ping(self, connection_id: str) -> ServiceResult[Any]:
        """Test connection health.

        Args:
            connection_id: Connection identifier

        Returns:
            ServiceResult indicating connection health

        """


class LDAPDirectoryRepository(AbstractRepository["LDAPEntry", str]):
    """Abstract repository for LDAP directory operations."""

    @abstractmethod
    async def search(
        self,
        connection_id: str,
        base_dn: DistinguishedName,
        search_filter: LDAPFilter,
        scope: LDAPScope,
        attributes: list[str] | None = None,
    ) -> ServiceResult[Any]:
        """Search LDAP directory.

        Args:
            connection_id: Active connection identifier
            base_dn: Search base distinguished name
            search_filter: LDAP search filter
            scope: Search scope
            attributes: Attributes to return

        Returns:
            ServiceResult containing list of matching entries

        """

    @abstractmethod
    async def create_entry(
        self,
        connection_id: str,
        entry: LDAPEntry,
    ) -> ServiceResult[Any]:
        """Create LDAP entry.

        Args:
            connection_id: Active connection identifier
            entry: LDAP entry to create

        Returns:
            ServiceResult indicating success

        """

    @abstractmethod
    async def modify_entry(
        self,
        connection_id: str,
        dn: DistinguishedName,
        changes: dict[str, Any],
    ) -> ServiceResult[Any]:
        """Modify LDAP entry.

        Args:
            connection_id: Active connection identifier
            dn: Distinguished name of entry to modify
            changes: Modifications to apply

        Returns:
            ServiceResult indicating success

        """

    @abstractmethod
    async def delete_entry(
        self,
        connection_id: str,
        dn: DistinguishedName,
    ) -> ServiceResult[Any]:
        """Delete LDAP entry.

        Args:
            connection_id: Active connection identifier
            dn: Distinguished name of entry to delete

        Returns:
            ServiceResult indicating success

        """


class LDAPSchemaValidator(ABC):
    """Abstract interface for LDAP schema validation."""

    @abstractmethod
    def validate_entry(self, entry: LDAPEntry) -> ServiceResult[Any]:
        """Validate LDAP entry against schema.

        Args:
            entry: LDAP entry to validate

        Returns:
            ServiceResult indicating validation result

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
    ) -> ServiceResult[Any]:
        """Validate attribute value syntax.

        Args:
            attribute_name: Name of the attribute
            value: Value to validate

        Returns:
            ServiceResult indicating validation result

        """


class LDAPUserRepository(AbstractRepository["LDAPUser", str]):
    """Abstract repository for LDAP user operations."""

    @abstractmethod
    async def find_user_by_dn(
        self,
        connection_id: str,
        dn: DistinguishedName,
    ) -> ServiceResult[Any]:
        """Find user by distinguished name.

        Args:
            connection_id: Active connection identifier
            dn: User distinguished name

        Returns:
            ServiceResult containing user if found

        """

    @abstractmethod
    async def find_user_by_username(
        self,
        connection_id: str,
        username: str,
    ) -> ServiceResult[Any]:
        """Find user by username.

        Args:
            connection_id: Active connection identifier
            username: Username to search for

        Returns:
            ServiceResult containing user if found

        """

    @abstractmethod
    async def authenticate_user(
        self,
        connection_id: str,
        dn: DistinguishedName,
        password: str,
    ) -> ServiceResult[Any]:
        """Authenticate user credentials.

        Args:
            connection_id: Active connection identifier
            dn: User distinguished name
            password: User password

        Returns:
            ServiceResult indicating authentication result

        """


class LDAPGroupRepository(AbstractRepository["LDAPGroup", str]):
    """Abstract repository for LDAP group operations."""

    @abstractmethod
    async def find_group_by_dn(
        self,
        connection_id: str,
        dn: DistinguishedName,
    ) -> ServiceResult[Any]:
        """Find group by distinguished name.

        Args:
            connection_id: Active connection identifier
            dn: Group distinguished name

        Returns:
            ServiceResult containing group if found

        """

    @abstractmethod
    async def get_group_members(
        self,
        connection_id: str,
        group_dn: DistinguishedName,
    ) -> ServiceResult[Any]:
        """Get group members.

        Args:
            connection_id: Active connection identifier
            group_dn: Group distinguished name

        Returns:
            ServiceResult containing list of member DNs

        """

    @abstractmethod
    async def add_member_to_group(
        self,
        connection_id: str,
        group_dn: DistinguishedName,
        member_dn: DistinguishedName,
    ) -> ServiceResult[Any]:
        """Add member to group.

        Args:
            connection_id: Active connection identifier
            group_dn: Group distinguished name
            member_dn: Member distinguished name

        Returns:
            ServiceResult indicating success

        """
