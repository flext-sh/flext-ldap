"""LDAP Domain Entities - Version 0.7.0.

🚨 DEPRECATION WARNING: Complex import paths are deprecated.

❌ OLD: from flext_ldap.domain.entities import LDAPUser, LDAPGroup
✅ NEW: from flext_ldap import LDAPUser, LDAPGroup

Pure business logic, no infrastructure dependencies.
"""

from __future__ import annotations

import warnings
from datetime import UTC, datetime
from typing import Any

from flext_core import DomainEntity, EntityStatus
from pydantic import Field


class LDAPEntry(DomainEntity):
    """Base LDAP entry entity representing any LDAP directory entry."""

    dn: str  # Distinguished Name - unique identifier
    object_classes: list[str] = Field(default_factory=list)
    attributes: dict[str, list[str]] = Field(default_factory=dict)
    status: str = EntityStatus.ACTIVE
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def add_object_class(self, object_class: str) -> None:
        """Add an object class to the entry."""
        if object_class not in self.object_classes:
            self.object_classes.append(object_class)
            self.updated_at = datetime.now(UTC)

    def remove_object_class(self, object_class: str) -> None:
        """Remove an object class from the entry."""
        if object_class in self.object_classes:
            self.object_classes.remove(object_class)
            self.updated_at = datetime.now(UTC)

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has a specific object class."""
        return object_class in self.object_classes

    def add_attribute(self, name: str, value: str | list[str]) -> None:
        """Add an attribute value to the entry."""
        if name not in self.attributes:
            self.attributes[name] = []

        values_to_add = [value] if isinstance(value, str) else value
        for val in values_to_add:
            if val not in self.attributes[name]:
                self.attributes[name].append(val)

        self.updated_at = datetime.now(UTC)

    def remove_attribute(self, name: str, value: str | None = None) -> None:
        """Remove an attribute or specific value from the entry."""
        if name in self.attributes:
            if value is None:
                # Remove entire attribute
                del self.attributes[name]
            elif value in self.attributes[name]:
                # Remove specific value
                self.attributes[name].remove(value)
                # Remove attribute if no values left
                if not self.attributes[name]:
                    del self.attributes[name]
            self.updated_at = datetime.now(UTC)

    def get_attribute(self, name: str) -> list[str]:
        """Get attribute values by name."""
        return self.attributes.get(name, [])

    def get_single_attribute(self, name: str) -> str | None:
        """Get single attribute value by name."""
        values = self.get_attribute(name)
        return values[0] if values else None

    def has_attribute(self, name: str, value: str | None = None) -> bool:
        """Check if entry has an attribute or specific value."""
        if name not in self.attributes:
            return False
        if value is None:
            return True
        return value in self.attributes[name]

    def get_rdn(self) -> str:
        """Get the Relative Distinguished Name (first component of DN)."""
        return self.dn.split(",")[0] if self.dn else ""

    def get_parent_dn(self) -> str:
        """Get the parent DN (everything after the first component)."""
        components = self.dn.split(",")
        return ",".join(components[1:]) if len(components) > 1 else ""

    def is_active(self) -> bool:
        """Check if entry is active."""
        return self.status == EntityStatus.ACTIVE

    def deactivate(self) -> None:
        """Deactivate the entry."""
        self.status = EntityStatus.INACTIVE
        self.updated_at = datetime.now(UTC)

    def activate(self) -> None:
        """Activate the entry."""
        self.status = EntityStatus.ACTIVE
        self.updated_at = datetime.now(UTC)


class LDAPConnection(DomainEntity):
    """LDAP connection entity representing a connection state."""

    server_url: str
    bind_dn: str | None = None
    is_bound: bool = False
    status: str = EntityStatus.INACTIVE
    pool_id: str | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def bind(self, bind_dn: str) -> None:
        """Bind to LDAP server with given DN."""
        self.bind_dn = bind_dn
        self.is_bound = True
        self.status = EntityStatus.ACTIVE
        self.updated_at = datetime.now(UTC)

    def unbind(self) -> None:
        """Unbind from LDAP server."""
        self.bind_dn = None
        self.is_bound = False
        self.status = EntityStatus.INACTIVE
        self.updated_at = datetime.now(UTC)

    def can_search(self) -> bool:
        """Check if connection can perform search operations."""
        return self.is_bound and self.status == EntityStatus.ACTIVE

    @property
    def is_connected(self) -> bool:
        """Check if connection is in connected state."""
        return self.status == EntityStatus.ACTIVE

    def connect(self) -> None:
        """Mark connection as connected (domain state change)."""
        self.status = EntityStatus.ACTIVE
        self.updated_at = datetime.now(UTC)

    def disconnect(self) -> None:
        """Mark connection as disconnected (domain state change)."""
        self.status = EntityStatus.INACTIVE
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
    object_classes: list[str] = Field(default_factory=lambda: ["inetOrgPerson"])
    attributes: dict[str, str] = Field(default_factory=dict)
    status: str = EntityStatus.ACTIVE
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

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
        self.status = EntityStatus.INACTIVE
        self.updated_at = datetime.now(UTC)

    def lock_account(self) -> None:
        """Lock the user account."""
        self.status = EntityStatus.INACTIVE
        self.updated_at = datetime.now(UTC)

    def unlock_account(self) -> None:
        """Unlock the user account."""
        self.status = EntityStatus.ACTIVE
        self.updated_at = datetime.now(UTC)


class LDAPGroup(DomainEntity):
    """LDAP group entity."""

    dn: str
    cn: str
    ou: str | None = None
    members: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    object_classes: list[str] = Field(default_factory=lambda: ["groupOfNames"])
    status: str = EntityStatus.ACTIVE
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

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
        self.status = EntityStatus.INACTIVE
        self.updated_at = datetime.now(UTC)


class LDAPOperation(DomainEntity):
    """LDAP operation entity for tracking operations."""

    operation_type: str
    target_dn: str
    connection_id: str
    user_dn: str | None = None
    filter_expression: str | None = None
    attributes: list[str] = Field(default_factory=list)
    started_at: str | None = None
    completed_at: str | None = None
    success: bool | None = None
    result_count: int = 0
    error_message: str | None = None
    status: str = EntityStatus.PENDING
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def start_operation(self) -> None:
        """Mark operation as started."""
        self.started_at = datetime.now(UTC).isoformat()
        self.status = EntityStatus.ACTIVE
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
        self.status = EntityStatus.ARCHIVED if success else EntityStatus.INACTIVE
        self.updated_at = datetime.now(UTC)

    def is_completed(self) -> bool:
        """Check if operation is completed."""
        return self.completed_at is not None

    def is_successful(self) -> bool:
        """Check if operation was successful."""
        return self.success is True


# Deprecation warning for complex path access
warnings.warn(
    "🚨 DEPRECATED COMPLEX PATH: Importing from 'flext_ldap.domain.entities' is deprecated.\n"
    "✅ SIMPLE SOLUTION: from flext_ldap import LDAPUser, LDAPGroup, LDAPEntry\n"
    "💡 ALL entities are now available at root level for better productivity!\n"
    "📖 Complex paths will be removed in version 0.8.0.\n"
    "📚 Migration guide: https://docs.flext.dev/ldap/simple-imports",
    DeprecationWarning,
    stacklevel=2,
)


def __getattr__(name: str) -> Any:
    """Handle attribute access with deprecation warnings."""
    entity_classes = {
        "LDAPEntry": LDAPEntry,
        "LDAPConnection": LDAPConnection,
        "LDAPUser": LDAPUser,
        "LDAPGroup": LDAPGroup,
        "LDAPOperation": LDAPOperation,
    }

    if name in entity_classes:
        warnings.warn(
            f"🚨 DEPRECATED ACCESS: Using 'flext_ldap.domain.entities.{name}' is deprecated.\n"
            f"✅ SIMPLE SOLUTION: from flext_ldap import {name}\n"
            f"💡 Direct root-level imports are much simpler and more productive!\n"
            f"📖 This access pattern will be removed in version 0.8.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return entity_classes[name]

    msg = f"module 'flext_ldap.domain.entities' has no attribute '{name}'"
    raise AttributeError(msg)
