"""LDAP Domain Events - Business Events.

🏗️ CLEAN ARCHITECTURE: Domain Events
Built on flext-core foundation patterns.

Events represent important business occurrences in the LDAP domain.
"""

from __future__ import annotations

from typing import Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root imports
from flext_core import FlextValueObject


class FlextLdapConnectionEstablished(FlextValueObject):
    """Event raised when LDAP connection is established."""

    aggregate_id: str
    connection_id: str
    base_dn: str
    server_info: dict[str, Any] | None = None

    def validate_domain_rules(self) -> None:
        """Validate domain rules for connection established event."""
        if not self.aggregate_id:
            raise ValueError("Connection established event must have aggregate_id")
        if not self.connection_id:
            raise ValueError("Connection established event must have connection_id")
        if not self.base_dn:
            raise ValueError("Connection established event must have base_dn")


class FlextLdapConnectionLost(FlextValueObject):
    """Event raised when LDAP connection is lost."""

    aggregate_id: str
    connection_id: str
    reason: str | None = None

    def validate_domain_rules(self) -> None:
        """Validate domain rules for connection lost event."""
        if not self.aggregate_id:
            raise ValueError("Connection lost event must have aggregate_id")
        if not self.connection_id:
            raise ValueError("Connection lost event must have connection_id")


class FlextLdapEntryCreated(FlextValueObject):
    """Event raised when LDAP entry is created."""

    aggregate_id: str
    entry_dn: str
    object_classes: list[str]
    attributes: dict[str, list[str]]

    def validate_domain_rules(self) -> None:
        """Validate domain rules for entry created event."""
        if not self.aggregate_id:
            raise ValueError("Entry created event must have aggregate_id")
        if not self.entry_dn:
            raise ValueError("Entry created event must have entry_dn")
        if not self.object_classes:
            raise ValueError("Entry created event must have object_classes")


class FlextLdapEntryModified(FlextValueObject):
    """Event raised when LDAP entry is modified."""

    aggregate_id: str
    entry_dn: str
    changes: dict[str, Any]
    old_values: dict[str, Any] | None = None

    def validate_domain_rules(self) -> None:
        """Validate domain rules for entry modified event."""
        if not self.aggregate_id:
            raise ValueError("Entry modified event must have aggregate_id")
        if not self.entry_dn:
            raise ValueError("Entry modified event must have entry_dn")
        if not self.changes:
            raise ValueError("Entry modified event must have changes")


class FlextLdapEntryDeleted(FlextValueObject):
    """Event raised when LDAP entry is deleted."""

    aggregate_id: str
    entry_dn: str
    object_classes: list[str]

    def validate_domain_rules(self) -> None:
        """Validate domain rules for entry deleted event."""
        if not self.aggregate_id:
            raise ValueError("Entry deleted event must have aggregate_id")
        if not self.entry_dn:
            raise ValueError("Entry deleted event must have entry_dn")
        if not self.object_classes:
            raise ValueError("Entry deleted event must have object_classes")


class FlextLdapUserAuthenticated(FlextValueObject):
    """Event raised when user authenticates successfully."""

    aggregate_id: str
    user_dn: str
    authentication_method: str

    def validate_domain_rules(self) -> None:
        """Validate domain rules for user authenticated event."""
        if not self.aggregate_id:
            raise ValueError("User authenticated event must have aggregate_id")
        if not self.user_dn:
            raise ValueError("User authenticated event must have user_dn")
        if not self.authentication_method:
            raise ValueError("User authenticated event must have authentication_method")


class FlextLdapAuthenticationFailed(FlextValueObject):
    """Event raised when authentication fails."""

    aggregate_id: str
    user_dn: str
    reason: str
    attempt_count: int = 1

    def validate_domain_rules(self) -> None:
        """Validate domain rules for authentication failed event."""
        if not self.aggregate_id:
            raise ValueError("Authentication failed event must have aggregate_id")
        if not self.user_dn:
            raise ValueError("Authentication failed event must have user_dn")
        if not self.reason:
            raise ValueError("Authentication failed event must have reason")
        if self.attempt_count <= 0:
            raise ValueError("Attempt count must be positive")


class FlextLdapGroupMemberAdded(FlextValueObject):
    """Event raised when member is added to group."""

    aggregate_id: str
    group_dn: str
    member_dn: str

    def validate_domain_rules(self) -> None:
        """Validate domain rules for group member added event."""
        if not self.aggregate_id:
            raise ValueError("Group member added event must have aggregate_id")
        if not self.group_dn:
            raise ValueError("Group member added event must have group_dn")
        if not self.member_dn:
            raise ValueError("Group member added event must have member_dn")


class FlextLdapGroupMemberRemoved(FlextValueObject):
    """Event raised when member is removed from group."""

    aggregate_id: str
    group_dn: str
    member_dn: str

    def validate_domain_rules(self) -> None:
        """Validate domain rules for group member removed event."""
        if not self.aggregate_id:
            raise ValueError("Group member removed event must have aggregate_id")
        if not self.group_dn:
            raise ValueError("Group member removed event must have group_dn")
        if not self.member_dn:
            raise ValueError("Group member removed event must have member_dn")
