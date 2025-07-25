"""LDAP Domain Entities - Version 0.7.0.

🚨 DEPRECATION WARNING: Complex import paths are deprecated.

❌ OLD: from flext_ldap.domain.entities import LDAPUser, LDAPGroup
✅ NEW: from flext_ldap import LDAPUser, LDAPGroup

Pure business logic, no infrastructure dependencies.
"""

from __future__ import annotations

import warnings
from datetime import UTC, datetime

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root imports
from enum import StrEnum
from typing import Any

from flext_core import FlextEntity
from pydantic import Field


class FlextLdapEntityStatus(StrEnum):
    """Entity status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"


class FlextLdapEntry(FlextEntity):
    """Base LDAP entry entity representing any LDAP directory entry."""

    dn: str  # Distinguished Name - unique identifier
    object_classes: list[str] = Field(default_factory=list)
    attributes: dict[str, list[str]] = Field(default_factory=dict)
    status: str = FlextLdapEntityStatus.ACTIVE

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP entry."""
        if not self.dn:
            msg = "LDAP entry must have a distinguished name"
            raise ValueError(msg)
        if not self.object_classes:
            msg = "LDAP entry must have at least one object class"
            raise ValueError(msg)

    def add_object_class(self, object_class: str) -> None:
        """Add an object class to the entry."""
        if object_class not in self.object_classes:
            self.object_classes.append(object_class)
            # Note: timestamp updates handled by FlextEntity

    def remove_object_class(self, object_class: str) -> None:
        """Remove an object class from the entry."""
        if object_class in self.object_classes:
            self.object_classes.remove(object_class)
            # Note: timestamp updates handled by FlextEntity

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

        # Note: timestamp updates handled by FlextEntity

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
            # Note: timestamp updates handled by FlextEntity

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
        return self.status == FlextLdapEntityStatus.ACTIVE

    def deactivate(self) -> FlextLdapEntry:
        """Deactivate the entry."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextLdapEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def activate(self) -> FlextLdapEntry:
        """Activate the entry."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextLdapEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)


class FlextLdapConnection(FlextEntity):
    """LDAP connection entity representing a connection state."""

    server_url: str
    bind_dn: str | None = None
    is_bound: bool = False
    status: str = FlextLdapEntityStatus.INACTIVE
    pool_id: str | None = None

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP connection."""
        if not self.server_url:
            msg = "LDAP connection must have a server URL"
            raise ValueError(msg)

    def bind(self, bind_dn: str) -> FlextLdapConnection:
        """Bind to LDAP server with given DN."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "bind_dn": bind_dn,
                "is_bound": True,
                "status": FlextLdapEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def unbind(self) -> FlextLdapConnection:
        """Unbind from LDAP server."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "bind_dn": None,
                "is_bound": False,
                "status": FlextLdapEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def can_search(self) -> bool:
        """Check if connection can perform search operations."""
        return self.is_bound and self.status == FlextLdapEntityStatus.ACTIVE

    @property
    def is_connected(self) -> bool:
        """Check if connection is in connected state."""
        return self.status == FlextLdapEntityStatus.ACTIVE

    def connect(self) -> FlextLdapConnection:
        """Mark connection as connected (domain state change)."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextLdapEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def disconnect(self) -> FlextLdapConnection:
        """Mark connection as disconnected (domain state change)."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextLdapEntityStatus.INACTIVE,
                "is_bound": False,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)


class FlextLdapUser(FlextEntity):
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
    status: str = FlextLdapEntityStatus.ACTIVE

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP user."""
        if not self.dn:
            msg = "LDAP user must have a distinguished name"
            raise ValueError(msg)
        if self.mail and "@" not in self.mail:
            msg = "User email must be valid format"
            raise ValueError(msg)

    def add_attribute(self, name: str, value: str) -> FlextLdapUser:
        """Add an attribute to the user."""
        entity_data = self.model_dump()
        new_attributes = entity_data["attributes"].copy()
        new_attributes[name] = value
        entity_data.update(
            {
                "attributes": new_attributes,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def remove_attribute(self, name: str) -> FlextLdapUser:
        """Remove an attribute from the user."""
        entity_data = self.model_dump()
        new_attributes = entity_data["attributes"].copy()
        if name in new_attributes:
            del new_attributes[name]
        entity_data.update(
            {
                "attributes": new_attributes,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def get_attribute(self, name: str) -> str | None:
        """Get an attribute by name."""
        return self.attributes.get(name)

    def has_attribute(self, name: str) -> bool:
        """Check if user has a specific attribute."""
        if name in {"mail", "phone", "ou", "department", "title"}:
            return getattr(self, name) is not None
        return name in self.attributes

    def has_mail(self) -> bool:
        """Check if user has an email address."""
        return self.mail is not None

    def deactivate(self) -> FlextLdapUser:
        """Deactivate the user."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextLdapEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def lock_account(self) -> FlextLdapUser:
        """Lock the user account."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextLdapEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def unlock_account(self) -> FlextLdapUser:
        """Unlock the user account."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextLdapEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def is_active(self) -> bool:
        """Check if the user account is active."""
        return self.status == FlextLdapEntityStatus.ACTIVE


class FlextLdapGroup(FlextEntity):
    """LDAP group entity."""

    dn: str
    cn: str
    ou: str | None = None
    members: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    object_classes: list[str] = Field(default_factory=lambda: ["groupOfNames"])
    status: str = FlextLdapEntityStatus.ACTIVE

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP group."""
        if not self.dn:
            msg = "LDAP group must have a distinguished name"
            raise ValueError(msg)
        if not self.cn:
            msg = "LDAP group must have a common name"
            raise ValueError(msg)

    def add_member(self, member_dn: str) -> FlextLdapGroup:
        """Add a member to the group."""
        entity_data = self.model_dump()
        new_members = entity_data["members"].copy()
        if member_dn not in new_members:
            new_members.append(member_dn)
        entity_data.update(
            {
                "members": new_members,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def remove_member(self, member_dn: str) -> FlextLdapGroup:
        """Remove a member from the group."""
        entity_data = self.model_dump()
        new_members = entity_data["members"].copy()
        if member_dn in new_members:
            new_members.remove(member_dn)
        entity_data.update(
            {
                "members": new_members,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def has_member(self, member_dn: str) -> bool:
        """Check if group has a specific member."""
        return member_dn in self.members

    def add_owner(self, owner_dn: str) -> FlextLdapGroup:
        """Add an owner to the group."""
        entity_data = self.model_dump()
        new_owners = entity_data["owners"].copy()
        if owner_dn not in new_owners:
            new_owners.append(owner_dn)
        entity_data.update(
            {
                "owners": new_owners,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def remove_owner(self, owner_dn: str) -> FlextLdapGroup:
        """Remove an owner from the group."""
        entity_data = self.model_dump()
        new_owners = entity_data["owners"].copy()
        if owner_dn in new_owners:
            new_owners.remove(owner_dn)
        entity_data.update(
            {
                "owners": new_owners,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def is_owner(self, owner_dn: str) -> bool:
        """Check if DN is an owner of the group."""
        return owner_dn in self.owners

    def deactivate(self) -> FlextLdapGroup:
        """Deactivate the group."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "status": FlextLdapEntityStatus.INACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)


class FlextLdapOperation(FlextEntity):
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
    status: str = FlextLdapEntityStatus.PENDING

    def validate_domain_rules(self) -> None:
        """Validate business rules for LDAP operation."""
        if not self.operation_type:
            msg = "LDAP operation must have an operation type"
            raise ValueError(msg)
        if not self.target_dn:
            msg = "LDAP operation must have a target DN"
            raise ValueError(msg)
        if not self.connection_id:
            msg = "LDAP operation must have a connection ID"
            raise ValueError(msg)

    def start_operation(self) -> FlextLdapOperation:
        """Mark operation as started."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "started_at": datetime.now(UTC).isoformat(),
                "status": FlextLdapEntityStatus.ACTIVE,
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def complete_operation(
        self,
        *,
        success: bool,
        result_count: int = 0,
        error_message: str | None = None,
    ) -> FlextLdapOperation:
        """Mark operation as completed."""
        entity_data = self.model_dump()
        entity_data.update(
            {
                "completed_at": datetime.now(UTC).isoformat(),
                "success": success,
                "result_count": result_count,
                "error_message": error_message,
                "status": FlextLdapEntityStatus.INACTIVE,  # INACTIVE = completed
                "version": self.version + 1,
            },
        )
        return self.__class__(**entity_data)

    def is_completed(self) -> bool:
        """Check if operation is completed."""
        return self.completed_at is not None

    def is_successful(self) -> bool:
        """Check if operation was successful."""
        return self.success is True


# Backward compatibility aliases
EntityStatus = FlextLdapEntityStatus

# Deprecation warning for complex path access
warnings.warn(
    "🚨 DEPRECATED COMPLEX PATH: Importing from "
    "'flext_ldap.domain.entities' is deprecated.\n"
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
        "LDAPEntry": FlextLdapEntry,
        "LDAPConnection": FlextLdapConnection,
        "LDAPUser": FlextLdapUser,
        "LDAPGroup": FlextLdapGroup,
        "LDAPOperation": FlextLdapOperation,
    }

    if name in entity_classes:
        warnings.warn(
            f"🚨 DEPRECATED ACCESS: Using "
            f"'flext_ldap.domain.entities.{name}' is deprecated.\n"
            f"✅ SIMPLE SOLUTION: from flext_ldap import {name}\n"
            f"💡 Direct root-level imports are much simpler and more productive!\n"
            f"📖 This access pattern will be removed in version 0.8.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return entity_classes[name]

    msg = f"module 'flext_ldap.domain.entities' has no attribute '{name}'"
    raise AttributeError(msg)
