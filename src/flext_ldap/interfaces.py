"""LDAP interface definitions following dependency inversion principle."""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType

from flext_core import FlextResult

from flext_ldap.entities import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
    FlextLdapUser,
)
from flext_ldap.typings import LdapAttributeDict


class IFlextLdapConnection(ABC):
    """Interface for LDAP connection management."""

    @abstractmethod
    async def connect(self, uri: str, bind_dn: str, password: str) -> FlextResult[None]:
        """Establish connection to LDAP server."""
        ...

    @abstractmethod
    async def disconnect(self) -> FlextResult[None]:
        """Close LDAP connection."""
        ...

    @abstractmethod
    async def is_connected(self) -> bool:
        """Check if connection is active."""
        ...

    @abstractmethod
    async def test_connection(self) -> FlextResult[None]:
        """Test connection health."""
        ...


class IFlextLdapRepository(ABC):
    """Interface for LDAP data access operations."""

    @abstractmethod
    async def find_by_dn(self, dn: str) -> FlextResult[FlextLdapEntry | None]:
        """Find entry by distinguished name."""
        ...

    @abstractmethod
    async def search(
        self, request: FlextLdapSearchRequest
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Search entries with criteria."""
        ...

    @abstractmethod
    async def save(self, entry: FlextLdapEntry) -> FlextResult[None]:
        """Save entry to LDAP directory."""
        ...

    @abstractmethod
    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry from LDAP directory."""
        ...

    @abstractmethod
    async def exists(self, dn: str) -> FlextResult[bool]:
        """Check if entry exists."""
        ...

    @abstractmethod
    async def update(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Update entry attributes."""
        ...


class IFlextLdapUserService(ABC):
    """Interface for user management operations."""

    @abstractmethod
    async def create_user(
        self, request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]:
        """Create new user in LDAP directory."""
        ...

    @abstractmethod
    async def get_user(self, dn: str) -> FlextResult[FlextLdapUser | None]:
        """Get user by distinguished name."""
        ...

    @abstractmethod
    async def update_user(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Update user attributes."""
        ...

    @abstractmethod
    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user from directory."""
        ...

    @abstractmethod
    async def search_users(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapUser]]:
        """Search users with filter."""
        ...

    @abstractmethod
    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists."""
        ...


class IFlextLdapGroupService(ABC):
    """Interface for group management operations."""

    @abstractmethod
    async def create_group(self, group: FlextLdapGroup) -> FlextResult[None]:
        """Create new group in LDAP directory."""
        ...

    @abstractmethod
    async def get_group(self, dn: str) -> FlextResult[FlextLdapGroup | None]:
        """Get group by distinguished name."""
        ...

    @abstractmethod
    async def update_group(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Update group attributes."""
        ...

    @abstractmethod
    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group from directory."""
        ...

    @abstractmethod
    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        ...

    @abstractmethod
    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        ...

    @abstractmethod
    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        ...

    @abstractmethod
    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists."""
        ...


class IFlextLdapValidator(ABC):
    """Interface for LDAP validation operations."""

    @abstractmethod
    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate distinguished name format."""
        ...

    @abstractmethod
    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP search filter."""
        ...

    @abstractmethod
    def validate_attributes(self, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Validate attribute dictionary."""
        ...

    @abstractmethod
    def validate_object_classes(self, object_classes: list[str]) -> FlextResult[None]:
        """Validate object class list."""
        ...


class IFlextLdapConfiguration(ABC):
    """Interface for LDAP configuration management."""

    @abstractmethod
    def get_server_uri(self) -> str:
        """Get LDAP server URI."""
        ...

    @abstractmethod
    def get_bind_dn(self) -> str:
        """Get bind DN for authentication."""
        ...

    @abstractmethod
    def get_bind_password(self) -> str:
        """Get bind password for authentication."""
        ...

    @abstractmethod
    def get_base_dn(self) -> str:
        """Get base DN for operations."""
        ...

    @abstractmethod
    def get_timeout(self) -> int:
        """Get connection timeout."""
        ...

    @abstractmethod
    def use_ssl(self) -> bool:
        """Check if SSL should be used."""
        ...


class IFlextLdapClient(ABC):
    """Interface for low-level LDAP client operations."""

    @abstractmethod
    async def connect(self, uri: str, bind_dn: str, password: str) -> FlextResult[None]:
        """Connect to LDAP server."""
        ...

    @abstractmethod
    async def search(
        self, request: FlextLdapSearchRequest
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Perform LDAP search."""
        ...

    @abstractmethod
    async def add(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Add entry to LDAP."""
        ...

    @abstractmethod
    async def modify(self, dn: str, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Modify LDAP entry."""
        ...

    @abstractmethod
    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete LDAP entry."""
        ...

    @abstractmethod
    async def bind(self, dn: str, password: str) -> FlextResult[None]:
        """Bind with credentials."""
        ...

    @abstractmethod
    async def unbind(self) -> FlextResult[None]:
        """Unbind from server."""
        ...


class IFlextLdapApiSession(ABC):
    """Interface for LDAP API session management."""

    @abstractmethod
    async def __aenter__(self) -> IFlextLdapApiSession:
        """Enter async context."""
        ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit async context."""
        ...

    @abstractmethod
    async def search(
        self, request: FlextLdapSearchRequest
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Search with session."""
        ...

    @abstractmethod
    async def create_user(
        self, request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]:
        """Create user with session."""
        ...


class IFlextLdapEventPublisher(ABC):
    """Interface for LDAP event publishing."""

    @abstractmethod
    async def publish_user_created(self, user: FlextLdapUser) -> FlextResult[None]:
        """Publish user created event."""
        ...

    @abstractmethod
    async def publish_user_updated(
        self, dn: str, attributes: LdapAttributeDict
    ) -> FlextResult[None]:
        """Publish user updated event."""
        ...

    @abstractmethod
    async def publish_user_deleted(self, dn: str) -> FlextResult[None]:
        """Publish user deleted event."""
        ...

    @abstractmethod
    async def publish_group_created(self, group: FlextLdapGroup) -> FlextResult[None]:
        """Publish group created event."""
        ...


class IFlextLdapAuditLogger(ABC):
    """Interface for LDAP audit logging."""

    @abstractmethod
    async def log_operation(
        self,
        operation: str,
        dn: str,
        user: str | None = None,
        result: str = "success",
        details: dict[str, object] | None = None,
    ) -> FlextResult[None]:
        """Log LDAP operation for audit purposes."""
        ...

    @abstractmethod
    async def log_authentication(
        self,
        user_dn: str,
        success: bool,  # noqa: FBT001
        client_ip: str | None = None,
    ) -> FlextResult[None]:
        """Log authentication attempt."""
        ...

    @abstractmethod
    async def log_authorization(
        self,
        user_dn: str,
        resource: str,
        action: str,
        granted: bool,  # noqa: FBT001
    ) -> FlextResult[None]:
        """Log authorization decision."""
        ...


# Composite interfaces for complex use cases
class IFlextLdapFullService(
    IFlextLdapUserService,
    IFlextLdapGroupService,
    IFlextLdapValidator,
):
    """Complete LDAP service interface combining all operations."""


class IFlextLdapReadOnlyService(ABC):
    """Read-only LDAP service interface."""

    @abstractmethod
    async def search(
        self, request: FlextLdapSearchRequest
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Search entries."""
        ...

    @abstractmethod
    async def get_user(self, dn: str) -> FlextResult[FlextLdapUser | None]:
        """Get user by DN."""
        ...

    @abstractmethod
    async def get_group(self, dn: str) -> FlextResult[FlextLdapGroup | None]:
        """Get group by DN."""
        ...
