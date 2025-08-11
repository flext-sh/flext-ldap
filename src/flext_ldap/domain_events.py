"""LDAP Domain Events - Business Events.

🏗️ CLEAN ARCHITECTURE: Domain Events
Built on flext-core foundation patterns.

Events represent important business occurrences in the LDAP domain.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import ABCMeta
from typing import TYPE_CHECKING

from flext_core import FlextResult, FlextValueObject

if TYPE_CHECKING:
    from flext_core import FlextTypes


class FlextLdapConnectionEstablished(FlextValueObject, metaclass=ABCMeta):
    """Event raised when LDAP connection is established."""

    aggregate_id: str
    connection_id: str
    base_dn: str
    server_info: FlextTypes.Core.JsonDict | None = None

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for connection established event."""
        if not self.aggregate_id:
            return FlextResult.fail(
                "Connection established event must have aggregate_id",
            )
        if not self.connection_id:
            return FlextResult.fail(
                "Connection established event must have connection_id",
            )
        if not self.base_dn:
            return FlextResult.fail("Connection established event must have base_dn")
        return FlextResult.ok(None)


class FlextLdapConnectionLost(FlextValueObject, metaclass=ABCMeta):
    """Event raised when LDAP connection is lost."""

    aggregate_id: str
    connection_id: str
    reason: str | None = None

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for connection lost event."""
        if not self.aggregate_id:
            return FlextResult.fail("Connection lost event must have aggregate_id")
        if not self.connection_id:
            return FlextResult.fail("Connection lost event must have connection_id")
        return FlextResult.ok(None)


class FlextLdapEntryCreated(FlextValueObject, metaclass=ABCMeta):
    """Event raised when LDAP entry is created."""

    aggregate_id: str
    entry_dn: str
    object_classes: list[str]
    attributes: dict[str, list[str]]

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for entry created event."""
        if not self.aggregate_id:
            return FlextResult.fail("Entry created event must have aggregate_id")
        if not self.entry_dn:
            return FlextResult.fail("Entry created event must have entry_dn")
        if not self.object_classes:
            return FlextResult.fail("Entry created event must have object_classes")
        return FlextResult.ok(None)


class FlextLdapEntryModified(FlextValueObject, metaclass=ABCMeta):
    """Event raised when LDAP entry is modified."""

    aggregate_id: str
    entry_dn: str
    changes: FlextTypes.Core.JsonDict
    old_values: FlextTypes.Core.JsonDict | None = None

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for entry modified event."""
        if not self.aggregate_id:
            return FlextResult.fail("Entry modified event must have aggregate_id")
        if not self.entry_dn:
            return FlextResult.fail("Entry modified event must have entry_dn")
        if not self.changes:
            return FlextResult.fail("Entry modified event must have changes")
        return FlextResult.ok(None)


class FlextLdapEntryDeleted(FlextValueObject, metaclass=ABCMeta):
    """Event raised when LDAP entry is deleted."""

    aggregate_id: str
    entry_dn: str
    object_classes: list[str]

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for entry deleted event."""
        if not self.aggregate_id:
            return FlextResult.fail("Entry deleted event must have aggregate_id")
        if not self.entry_dn:
            return FlextResult.fail("Entry deleted event must have entry_dn")
        if not self.object_classes:
            return FlextResult.fail("Entry deleted event must have object_classes")
        return FlextResult.ok(None)


# Base event class to eliminate code duplication - DRY Principle
class FlextLdapDomainEventBase(FlextValueObject, metaclass=ABCMeta):
    """Base class for LDAP domain events - eliminates code duplication."""

    aggregate_id: str

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate common domain rules - Template Method pattern."""
        # Common validation for all events
        if not self.aggregate_id:
            event_name = self.__class__.__name__
            return FlextResult.fail(f"{event_name} must have aggregate_id")

        # Delegate to specific event validation
        return self._validate_specific_rules()

    def _validate_specific_rules(self) -> FlextResult[None]:
        """Override in subclasses for specific validation - Template Method pattern."""
        return FlextResult.ok(None)


class FlextLdapUserAuthenticated(FlextLdapDomainEventBase, metaclass=ABCMeta):
    """Event raised when user authenticates successfully."""

    user_dn: str
    authentication_method: str

    def _validate_specific_rules(self) -> FlextResult[None]:
        """Validate specific rules for user authenticated event."""
        if not self.user_dn:
            return FlextResult.fail("User authenticated event must have user_dn")
        if not self.authentication_method:
            return FlextResult.fail(
                "User authenticated event must have authentication_method",
            )
        return FlextResult.ok(None)


class FlextLdapAuthenticationFailed(FlextLdapDomainEventBase, metaclass=ABCMeta):
    """Event raised when authentication fails."""

    user_dn: str
    reason: str
    attempt_count: int = 1

    def _validate_specific_rules(self) -> FlextResult[None]:
        """Validate specific rules for authentication failed event."""
        if not self.user_dn:
            return FlextResult.fail("Authentication failed event must have user_dn")
        if not self.reason:
            return FlextResult.fail("Authentication failed event must have reason")
        if self.attempt_count <= 0:
            return FlextResult.fail("Attempt count must be positive")
        return FlextResult.ok(None)


class FlextLdapGroupMemberAdded(FlextLdapDomainEventBase, metaclass=ABCMeta):
    """Event raised when member is added to group."""

    group_dn: str
    member_dn: str

    def _validate_specific_rules(self) -> FlextResult[None]:
        """Validate specific rules for group member added event."""
        if not self.group_dn:
            return FlextResult.fail("Group member added event must have group_dn")
        if not self.member_dn:
            return FlextResult.fail("Group member added event must have member_dn")
        return FlextResult.ok(None)


class FlextLdapGroupMemberRemoved(FlextLdapDomainEventBase, metaclass=ABCMeta):
    """Event raised when member is removed from group."""

    group_dn: str
    member_dn: str

    def _validate_specific_rules(self) -> FlextResult[None]:
        """Validate specific rules for group member removed event."""
        if not self.group_dn:
            return FlextResult.fail("Group member removed event must have group_dn")
        if not self.member_dn:
            return FlextResult.fail("Group member removed event must have member_dn")
        return FlextResult.ok(None)
