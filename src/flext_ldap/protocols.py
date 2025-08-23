"""LDAP protocol definitions and interfaces following SOLID principles."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from flext_core import FlextResult, get_flext_container

from flext_ldap.entities import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
    FlextLdapUser,
)
from flext_ldap.typings import LdapAttributeDict


@runtime_checkable
class FlextLdapConnectionProtocol(Protocol):
    """Protocol for LDAP connection management."""

    async def connect(self) -> FlextResult[None]:
        """Establish LDAP connection."""
        ...

    async def disconnect(self) -> FlextResult[None]:
        """Close LDAP connection."""
        ...

    async def is_connected(self) -> bool:
        """Check if connection is active."""
        ...

    async def bind(self, dn: str, password: str) -> FlextResult[None]:
        """Bind to LDAP server."""
        ...


@runtime_checkable
class FlextLdapSearchProtocol(Protocol):
    """Protocol for LDAP search operations."""

    async def search(
        self,
        request: FlextLdapSearchRequest,
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Perform LDAP search."""
        ...

    async def search_one(self, dn: str) -> FlextResult[FlextLdapEntry | None]:
        """Search for a single entry by DN."""
        ...


@runtime_checkable
class FlextLdapEntryProtocol(Protocol):
    """Protocol for LDAP entry operations."""

    async def create_entry(self, entry: FlextLdapEntry) -> FlextResult[None]:
        """Create LDAP entry."""
        ...

    async def update_entry(
        self,
        dn: str,
        attributes: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Update LDAP entry."""
        ...

    async def delete_entry(self, dn: str) -> FlextResult[None]:
        """Delete LDAP entry."""
        ...

    async def entry_exists(self, dn: str) -> FlextResult[bool]:
        """Check if entry exists."""
        ...


@runtime_checkable
class FlextLdapUserProtocol(Protocol):
    """Protocol for LDAP user operations."""

    async def create_user(
        self,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create LDAP user."""
        ...

    async def get_user(self, dn: str) -> FlextResult[FlextLdapUser | None]:
        """Get user by DN."""
        ...

    async def update_user(
        self,
        dn: str,
        attributes: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Update user attributes."""
        ...

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user."""
        ...

    async def search_users(
        self,
        filter_str: str,
        base_dn: str,
    ) -> FlextResult[list[FlextLdapUser]]:
        """Search for users."""
        ...


@runtime_checkable
class FlextLdapGroupProtocol(Protocol):
    """Protocol for LDAP group operations."""

    async def create_group(self, group: FlextLdapGroup) -> FlextResult[None]:
        """Create LDAP group."""
        ...

    async def get_group(self, dn: str) -> FlextResult[FlextLdapGroup | None]:
        """Get group by DN."""
        ...

    async def add_member_to_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Add member to group."""
        ...

    async def remove_member_from_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Remove member from group."""
        ...

    async def get_group_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        ...


class FlextLdapRepositoryProtocol(Protocol):
    """Protocol for LDAP repository operations."""

    async def find_by_dn(self, dn: str) -> FlextResult[FlextLdapEntry | None]:
        """Find entry by DN."""
        ...

    async def save(self, entry: FlextLdapEntry) -> FlextResult[None]:
        """Save entry to LDAP."""
        ...

    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry from LDAP."""
        ...

    async def exists(self, dn: str) -> FlextResult[bool]:
        """Check if entry exists."""
        ...


class FlextLdapValidatorProtocol(Protocol):
    """Protocol for LDAP validation operations."""

    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate DN format."""
        ...

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter."""
        ...

    def validate_attributes(self, attributes: LdapAttributeDict) -> FlextResult[None]:
        """Validate attribute dictionary."""
        ...


# Abstract base classes for implementation


class FlextLdapOperationsBase(ABC):
    """Abstract base class for LDAP operations providing common functionality."""

    def __init__(self) -> None:
        """Initialize base operations."""
        self._container = get_flext_container()

    @abstractmethod
    async def connect(self) -> FlextResult[None]:
        """Connect to LDAP server."""
        ...

    @abstractmethod
    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server."""
        ...


class FlextLdapServiceBase(ABC):
    """Abstract base class for LDAP services."""

    @abstractmethod
    async def initialize(self) -> FlextResult[None]:
        """Initialize service."""
        ...

    @abstractmethod
    async def cleanup(self) -> FlextResult[None]:
        """Cleanup resources."""
        ...


class FlextLdapClientBase(ABC):
    """Abstract base class for LDAP clients."""

    @abstractmethod
    async def connect(self, uri: str, bind_dn: str, password: str) -> FlextResult[None]:
        """Connect to LDAP server."""
        ...

    @abstractmethod
    async def search(
        self,
        request: FlextLdapSearchRequest,
    ) -> FlextResult[FlextLdapSearchResponse]:
        """Perform search operation."""
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


# Protocol combinations - individual protocols should be used directly
