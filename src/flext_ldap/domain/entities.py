"""LDAP Domain Entities - Version 0.7.0.
Pure business logic, no infrastructure dependencies.
"""

from __future__ import annotations

from dataclasses import field
from typing import TYPE_CHECKING
from uuid import UUID

from flext_core.domain.constants import EntityStatuses
from flext_core.domain.pydantic_base import DomainEntity

if TYPE_CHECKING:
    from flext_ldap.domain.value_objects import DistinguishedName, LDAPAttribute


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
        self.updated_at = self._now()

    def unbind(self) -> None:
        """Unbind from LDAP server."""
        self.bind_dn = None
        self.is_bound = False
        self.status = EntityStatuses.INACTIVE
        self.updated_at = self._now()

    def can_search(self) -> bool:
        """Check if connection can perform search operations."""
        return self.is_bound and self.status == EntityStatuses.ACTIVE


class LDAPUser(DomainEntity):
    """LDAP user entity."""

    dn: DistinguishedName
    uid: str | None = None
    sn: str | None = None
    mail: str | None = None
    attributes: dict[str, LDAPAttribute] = field(default_factory=dict)
    status: str = EntityStatuses.ACTIVE

    def add_attribute(self, name: str, attribute: LDAPAttribute) -> None:
        """Add an attribute to the user."""
        self.attributes[name] = attribute
        self.updated_at = self._now()

    def remove_attribute(self, name: str) -> None:
        """Remove an attribute from the user."""
        if name in self.attributes:
            del self.attributes[name]
            self.updated_at = self._now()

    def get_attribute(self, name: str) -> LDAPAttribute | None:
        """Get an attribute by name."""
        return self.attributes.get(name)

    def has_mail(self) -> bool:
        """Check if user has an email address."""
        return self.mail is not None

    def deactivate(self) -> None:
        """Deactivate the user."""
        self.status = EntityStatuses.INACTIVE
        self.updated_at = self._now()
