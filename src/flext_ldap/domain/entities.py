"""LDAP Domain Entities - Version 0.7.0.

Pure business logic, no infrastructure dependencies.
"""

from __future__ import annotations

from dataclasses import field
from datetime import UTC, datetime

from flext_core.domain.constants import EntityStatuses
from flext_core.domain.pydantic_base import DomainEntity


class LDAPConnection(DomainEntity):
    """LDAP connection entity representing a connection state."""

    server_url: str
    bind_dn: str | None = None
    is_bound: bool = False
    status: str = EntityStatuses.INACTIVE
    pool_id: str | None = None

    def bind(self, bind_dn: str) -> None:
        """Bind to LDAP server with given DN."""
        self.bind_dn = bind_dn
        self.is_bound = True
        self.status = EntityStatuses.ACTIVE
        self.updated_at = datetime.now(UTC)

    def unbind(self) -> None:
        """Unbind from LDAP server."""
        self.bind_dn = None
        self.is_bound = False
        self.status = EntityStatuses.INACTIVE
        self.updated_at = datetime.now(UTC)

    def can_search(self) -> bool:
        """Check if connection can perform search operations."""
        return self.is_bound and self.status == EntityStatuses.ACTIVE

    @property
    def is_connected(self) -> bool:
        """Check if connection is in connected state."""
        return self.status == EntityStatuses.ACTIVE

    def connect(self) -> None:
        """Mark connection as connected (domain state change)."""
        self.status = EntityStatuses.ACTIVE
        self.updated_at = datetime.now(UTC)

    def disconnect(self) -> None:
        """Mark connection as disconnected (domain state change)."""
        self.status = EntityStatuses.INACTIVE
        self.is_bound = False
        self.updated_at = datetime.now(UTC)


class LDAPUser(DomainEntity):
    """LDAP user entity."""

    dn: str
    uid: str | None = None
    cn: str | None = None
    sn: str | None = None
    mail: str | None = None
    phone: str | None = None
    ou: str | None = None
    department: str | None = None
    title: str | None = None
    object_classes: list[str] = field(default_factory=lambda: ["inetOrgPerson"])
    attributes: dict[str, str] = field(default_factory=dict)
    status: str = EntityStatuses.ACTIVE

    def add_attribute(self, name: str, value: str) -> None:
        """Add an attribute to the user."""
        self.attributes[name] = value
        self.updated_at = datetime.now(UTC)

    def remove_attribute(self, name: str) -> None:
        """Remove an attribute from the user."""
        if name in self.attributes:
            del self.attributes[name]
            self.updated_at = datetime.now(UTC)

    def get_attribute(self, name: str) -> str | None:
        """Get an attribute by name."""
        return self.attributes.get(name)

    def has_mail(self) -> bool:
        """Check if user has an email address."""
        return self.mail is not None

    def deactivate(self) -> None:
        """Deactivate the user."""
        self.status = EntityStatuses.INACTIVE
        self.updated_at = datetime.now(UTC)

    def lock_account(self) -> None:
        """Lock the user account."""
        self.status = EntityStatuses.INACTIVE
        self.updated_at = datetime.now(UTC)

    def unlock_account(self) -> None:
        """Unlock the user account."""
        self.status = EntityStatuses.ACTIVE
        self.updated_at = datetime.now(UTC)


class LDAPGroup(DomainEntity):
    """LDAP group entity."""

    dn: str
    cn: str
    ou: str | None = None
    members: list[str] = field(default_factory=list)
    owners: list[str] = field(default_factory=list)
    object_classes: list[str] = field(default_factory=lambda: ["groupOfNames"])
    status: str = EntityStatuses.ACTIVE

    def add_member(self, member_dn: str) -> None:
        """Add a member to the group."""
        if member_dn not in self.members:
            self.members.append(member_dn)
            self.updated_at = datetime.now(UTC)

    def remove_member(self, member_dn: str) -> None:
        """Remove a member from the group."""
        if member_dn in self.members:
            self.members.remove(member_dn)
            self.updated_at = datetime.now(UTC)

    def has_member(self, member_dn: str) -> bool:
        """Check if group has a specific member."""
        return member_dn in self.members

    def add_owner(self, owner_dn: str) -> None:
        """Add an owner to the group."""
        if owner_dn not in self.owners:
            self.owners.append(owner_dn)
            self.updated_at = datetime.now(UTC)

    def remove_owner(self, owner_dn: str) -> None:
        """Remove an owner from the group."""
        if owner_dn in self.owners:
            self.owners.remove(owner_dn)
            self.updated_at = datetime.now(UTC)

    def is_owner(self, owner_dn: str) -> bool:
        """Check if DN is an owner of the group."""
        return owner_dn in self.owners

    def deactivate(self) -> None:
        """Deactivate the group."""
        self.status = EntityStatuses.INACTIVE
        self.updated_at = datetime.now(UTC)


class LDAPOperation(DomainEntity):
    """LDAP operation entity for tracking operations."""

    operation_type: str
    target_dn: str
    connection_id: str
    user_dn: str | None = None
    filter_expression: str | None = None
    attributes: list[str] = field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    success: bool | None = None
    result_count: int = 0
    error_message: str | None = None
    status: str = EntityStatuses.PENDING

    def start_operation(self) -> None:
        """Mark operation as started."""
        self.started_at = datetime.now(UTC).isoformat()
        self.status = EntityStatuses.ACTIVE
        self.updated_at = datetime.now(UTC)

    def complete_operation(
        self,
        *,
        success: bool,
        result_count: int = 0,
        error_message: str | None = None,
    ) -> None:
        """Mark operation as completed."""
        self.completed_at = datetime.now(UTC).isoformat()
        self.success = success
        self.result_count = result_count
        self.error_message = error_message
        self.status = EntityStatuses.ARCHIVED if success else EntityStatuses.ERROR
        self.updated_at = datetime.now(UTC)

    def is_completed(self) -> bool:
        """Check if operation is completed."""
        return self.completed_at is not None

    def is_successful(self) -> bool:
        """Check if operation was successful."""
        return self.success is True
