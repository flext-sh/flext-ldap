"""Event system for LDAP operations.

Provides domain events and event handling for consistent
event-driven architecture across LDAP projects.
"""

from ldap_core_shared.events.domain_events import (
    DomainEvent,
    ErrorEvent,
    LDAPConnectionEvent,
    LDAPOperationEvent,
    MigrationCompletedEvent,
    MigrationStageEvent,
    ValidationEvent,
)
from ldap_core_shared.events.event_handler import EventDispatcher, EventHandler

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
