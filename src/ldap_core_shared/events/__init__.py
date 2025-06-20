"""
Event system for LDAP operations.

Provides domain events and event handling for consistent
event-driven architecture across LDAP projects.
"""


from .domain_events import (
    DomainEvent,
    ErrorEvent,
    LDAPConnectionEvent,
    LDAPOperationEvent,
    MigrationCompletedEvent,
    MigrationStageEvent,
    ValidationEvent,
)
from .event_handler import EventDispatcher, EventHandler

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
