"""Event system for LDAP operations.

Provides domain events and event handling for consistent
event-driven architecture across LDAP projects.
"""

from flext_ldapt_handler import EventDispatcher, EventHandler

from flext_ldap.events.domain_events import (
    DomainEvent,
    ErrorEvent,
    LDAPConnectionEvent,
    LDAPOperationEvent,
    MigrationCompletedEvent,
    MigrationStageEvent,
    ValidationEvent,
)

__all__ = [
    "DomainEvent",
    "ErrorEvent",
    "EventDispatcher",
    "EventHandler",
    "LDAPConnectionEvent",
    "LDAPOperationEvent",
    "MigrationCompletedEvent",
    "MigrationStageEvent",
    "ValidationEvent",
]
