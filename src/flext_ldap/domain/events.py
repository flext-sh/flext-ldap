"""LDAP Domain Events - Business Events.

🏗️ CLEAN ARCHITECTURE: Domain Events
Built on flext-core foundation patterns.

Events represent important business occurrences in the LDAP domain.
"""

from __future__ import annotations

from typing import Any

from flext_core import DomainEvent


class LDAPConnectionEstablished(DomainEvent):
    """Event raised when LDAP connection is established."""

    aggregate_id: str
    connection_id: str
    base_dn: str
    server_info: dict[str, Any] | None = None


class LDAPConnectionLost(DomainEvent):
    """Event raised when LDAP connection is lost."""

    aggregate_id: str
    connection_id: str
    reason: str | None = None


class LDAPEntryCreated(DomainEvent):
    """Event raised when LDAP entry is created."""

    aggregate_id: str
    entry_dn: str
    object_classes: list[str]
    attributes: dict[str, list[str]]


class LDAPEntryModified(DomainEvent):
    """Event raised when LDAP entry is modified."""

    aggregate_id: str
    entry_dn: str
    changes: dict[str, Any]
    old_values: dict[str, Any] | None = None


class LDAPEntryDeleted(DomainEvent):
    """Event raised when LDAP entry is deleted."""

    aggregate_id: str
    entry_dn: str
    object_classes: list[str]


class LDAPUserAuthenticated(DomainEvent):
    """Event raised when user authenticates successfully."""

    aggregate_id: str
    user_dn: str
    authentication_method: str


class LDAPAuthenticationFailed(DomainEvent):
    """Event raised when authentication fails."""

    aggregate_id: str
    user_dn: str
    reason: str
    attempt_count: int = 1


class LDAPGroupMemberAdded(DomainEvent):
    """Event raised when member is added to group."""

    aggregate_id: str
    group_dn: str
    member_dn: str


class LDAPGroupMemberRemoved(DomainEvent):
    """Event raised when member is removed from group."""

    aggregate_id: str
    group_dn: str
    member_dn: str
