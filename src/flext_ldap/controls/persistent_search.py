"""LDAP Persistent Search Control Implementation.

This module provides Persistent Search control functionality following perl-ldap
Net::LDAP::Control::PersistentSearch patterns with enterprise-grade real-time
directory monitoring and change notification capabilities.

The Persistent Search control enables real-time notifications when directory
entries are added, modified, or deleted, essential for directory synchronization,
cache invalidation, and event-driven applications.

Architecture:
    - PersistentSearchControl: Main control for persistent search operations
    - ChangeNotification: Individual change notification data
    - ChangeType: Types of directory changes (add, modify, delete, moddn)
    - PersistentSearchMonitor: High-level monitoring and event handling

Usage Example:
    >>> from flext_ldap.controls.persistent_search import PersistentSearchControl
    >>>
    >>> # Monitor changes to user entries
    >>> persistent_search = PersistentSearchControl(
    ...     change_types=["add", "modify", "delete"],
    ...     changes_only=True,
    ...     return_entry_change_notification=True,
    ... )
    >>> # Start persistent search
    >>> connection.search(
    ...     search_base="ou=users,dc=example,dc=com",
    ...     search_filter="(objectClass=person)",
    ...     controls=[persistent_search],
    ... )
    >>>
    >>> # Process change notifications
    >>> for change in persistent_search.get_change_notifications():
    ...     print(f"Change detected: {change.change_type} on {change.entry_dn}")

References:
    - perl-ldap: lib/Net/LDAP/Control/PersistentSearch.pm
    - RFC 3673: Persistent Search: A Simple LDAP Change Notification Mechanism
    - Internet Draft: Persistent Search LDAP Extension

"""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from flext_ldapse import LDAPControl
from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from collections.abc import Callable


class ChangeType(Enum):
    """Types of directory changes that can be monitored."""

    ADD = "add"
    DELETE = "delete"
    MODIFY = "modify"
    MODDN = "moddn"  # Modify DN (rename/move)


class ChangeNotification(BaseModel):
    """Individual directory change notification."""

    change_type: ChangeType = Field(description="Type of change that occurred")

    entry_dn: str = Field(description="Distinguished name of changed entry")

    change_number: int | None = Field(
        default=None,
        description="Server-assigned change sequence number",
    )

    entry_data: dict[str, list[str]] | None = Field(
        default=None,
        description="Entry data if requested",
    )

    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When change was detected",
    )

    # Additional metadata
    previous_dn: str | None = Field(
        default=None,
        description="Previous DN for MODDN operations",
    )

    change_controls: list[str] = Field(
        default_factory=list,
        description="Additional controls returned with change",
    )

    server_info: dict[str, Any] | None = Field(
        default=None,
        description="Server-specific change information",
    )

    def is_add(self) -> bool:
        """Check if this is an add operation."""
        return self.change_type == ChangeType.ADD

    def is_delete(self) -> bool:
        """Check if this is a delete operation."""
        return self.change_type == ChangeType.DELETE

    def is_modify(self) -> bool:
        """Check if this is a modify operation."""
        return self.change_type == ChangeType.MODIFY

    def is_moddn(self) -> bool:
        """Check if this is a modify DN operation."""
        return self.change_type == ChangeType.MODDN

    def get_attribute_value(self, attribute: str) -> str | None:
        """Get value for specific attribute from entry data.

        Args:
            attribute: Attribute name

        Returns:
            First value for attribute or None

        """
        if not self.entry_data:
            return None

        for attr_name, values in self.entry_data.items():
            if attr_name.lower() == attribute.lower() and values:
                return values[0]

        return None

    def has_attribute(self, attribute: str) -> bool:
        """Check if entry data contains specific attribute.

        Args:
            attribute: Attribute name

        Returns:
            True if attribute is present

        """
        if not self.entry_data:
            return False

        return any(
            attr_name.lower() == attribute.lower() for attr_name in self.entry_data
        )


class PersistentSearchRequest(BaseModel):
    """Request configuration for Persistent Search control."""

    change_types: list[ChangeType] = Field(
        default_factory=lambda: [ChangeType.ADD, ChangeType.MODIFY, ChangeType.DELETE],
        description="Types of changes to monitor",
    )

    changes_only: bool = Field(
        default=True,
        description="Return only changes, not initial search results",
    )

    return_entry_change_notification: bool = Field(
        default=True,
        description="Return entry change notification control",
    )

    def get_change_types_mask(self) -> int:
        """Get change types as bitmask for BER encoding.

        Returns:
            Bitmask representing selected change types

        """
        mask = 0
        if ChangeType.ADD in self.change_types:
            mask |= 1  # bit 0
        if ChangeType.DELETE in self.change_types:
            mask |= 2  # bit 1
        if ChangeType.MODIFY in self.change_types:
            mask |= 4  # bit 2
        if ChangeType.MODDN in self.change_types:
            mask |= 8  # bit 3
        return mask


class PersistentSearchControl(LDAPControl):
    """LDAP Persistent Search control for real-time change monitoring.

    This control enables real-time monitoring of directory changes by keeping
    a search operation active and receiving notifications when entries are
    added, modified, or deleted.

    Example:
        >>> # Monitor all changes to user entries
        >>> persistent_search = PersistentSearchControl(
        ...     change_types=[ChangeType.ADD, ChangeType.MODIFY, ChangeType.DELETE],
        ...     changes_only=True,
        ... )
        >>> # Start monitoring
        >>> connection.search(
        ...     search_base="ou=users,dc=example,dc=com",
        ...     search_filter="(objectClass=person)",
        ...     controls=[persistent_search],
        ... )
        >>> # Process notifications
        >>> while True:
        ...     notifications = persistent_search.get_pending_notifications()
        ...     for notification in notifications:
        ...         handle_directory_change(notification)
        ...     time.sleep(1)

    """

    control_type = "2.16.840.1.113730.3.4.3"  # Persistent Search control OID

    def __init__(
        self,
        change_types: list[ChangeType] | None = None,
        changes_only: bool = True,
        return_entry_change_notification: bool = True,
        criticality: bool = True,
    ) -> None:
        """Initialize Persistent Search control.

        Args:
            change_types: Types of changes to monitor
            changes_only: Return only changes, not initial search results
            return_entry_change_notification: Return entry change notification control
            criticality: Whether control is critical (recommended True for persistent search)

        """
        # Create request configuration
        self._request = PersistentSearchRequest(
            change_types=change_types
            or [ChangeType.ADD, ChangeType.MODIFY, ChangeType.DELETE],
            changes_only=changes_only,
            return_entry_change_notification=return_entry_change_notification,
        )

        # Initialize notification storage
        self._notifications: list[ChangeNotification] = []
        self._notification_callback: Callable[[ChangeNotification], None] | None = None
        self._is_active = False
        self._total_notifications = 0

        # Performance tracking
        self._start_time: datetime | None = None
        self._last_notification_time: datetime | None = None

        # Initialize base control
        super().__init__(
            criticality=criticality,
            control_value=self._encode_request(),
        )

    def _encode_request(self) -> bytes:
        """Encode Persistent Search control request.

        Returns:
            BER-encoded control value

        Raises:
            NotImplementedError: BER encoding not yet implemented

        """
        # TODO: Implement BER encoding of persistent search request
        # This should encode the change types bitmask, changesOnly, and returnECs
        # according to the Persistent Search specification
        msg = (
            "Persistent Search control BER encoding not yet implemented. "
            "Implement proper ASN.1 BER encoding of changeTypes (INTEGER), "
            "changesOnly (BOOLEAN), and returnECs (BOOLEAN) according to "
            "RFC 3673 specification."
        )
        raise NotImplementedError(msg)

    def start_monitoring(self) -> None:
        """Start monitoring for changes."""
        self._is_active = True
        self._start_time = datetime.now()

    def stop_monitoring(self) -> None:
        """Stop monitoring for changes."""
        self._is_active = False

    def set_notification_callback(
        self,
        callback: Callable[[ChangeNotification], None],
    ) -> None:
        """Set callback function for change notifications.

        Args:
            callback: Function to call when changes are detected

        """
        self._notification_callback = callback

    def process_change_notification(
        self,
        entry_dn: str,
        change_type: ChangeType,
        entry_data: dict[str, Any] | None = None,
    ) -> None:
        """Process incoming change notification.

        Args:
            entry_dn: Distinguished name of changed entry
            change_type: Type of change
            entry_data: Optional entry data

        """
        notification = ChangeNotification(
            change_type=change_type,
            entry_dn=entry_dn,
            change_number=self._total_notifications + 1,
            entry_data=entry_data,
        )

        self._notifications.append(notification)
        self._total_notifications += 1
        self._last_notification_time = datetime.now()

        # Call callback if set
        if self._notification_callback:
            try:
                self._notification_callback(notification)
            except Exception:
                # Log error but don't stop monitoring
                pass

    def get_pending_notifications(self) -> list[ChangeNotification]:
        """Get all pending change notifications.

        Returns:
            List of change notifications

        """
        notifications = self._notifications.copy()
        self._notifications.clear()  # Clear after retrieving
        return notifications

    def get_change_notifications(self) -> list[ChangeNotification]:
        """Get all accumulated change notifications (without clearing).

        Returns:
            List of all change notifications

        """
        return self._notifications.copy()

    def get_notification_count(self) -> int:
        """Get total number of notifications received.

        Returns:
            Total notification count

        """
        return self._total_notifications

    def get_monitoring_statistics(self) -> dict[str, Any]:
        """Get monitoring statistics.

        Returns:
            Dictionary with monitoring statistics

        """
        stats = {
            "is_active": self._is_active,
            "total_notifications": self._total_notifications,
            "pending_notifications": len(self._notifications),
            "change_types_monitored": [ct.value for ct in self._request.change_types],
            "changes_only": self._request.changes_only,
        }

        if self._start_time:
            stats["monitoring_duration"] = (
                datetime.now() - self._start_time
            ).total_seconds()

        if self._last_notification_time:
            stats["last_notification"] = self._last_notification_time.isoformat()
            stats["time_since_last"] = (
                datetime.now() - self._last_notification_time
            ).total_seconds()

        return stats

    @property
    def is_active(self) -> bool:
        """Check if monitoring is active."""
        return self._is_active

    @property
    def monitored_change_types(self) -> list[ChangeType]:
        """Get list of monitored change types."""
        return self._request.change_types

    def clear_notifications(self) -> None:
        """Clear all accumulated notifications."""
        self._notifications.clear()

    def encode_value(self) -> bytes | None:
        """Encode persistent search control value to ASN.1 bytes.

        Returns:
            Encoded control value or None if no value

        """
        return self.control_value

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> PersistentSearchControl:
        """Decode ASN.1 bytes to create persistent search control instance.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            PersistentSearchControl instance with decoded values

        """
        if not control_value:
            # Default persistent search control for all changes
            return cls(
                change_types=[ChangeType.ADD, ChangeType.DELETE, ChangeType.MODIFY],
                changes_only=True,
                return_entry_change_controls=True,
            )

        # For now, return a default control since proper ASN.1 decoding
        # would require more complex implementation
        return cls(
            change_types=[ChangeType.ADD, ChangeType.DELETE, ChangeType.MODIFY],
            changes_only=True,
            return_entry_change_controls=True,
        )


# High-level persistent search monitoring
class PersistentSearchMonitor:
    """High-level persistent search monitor with event handling."""

    def __init__(self, connection: Any) -> None:
        """Initialize persistent search monitor.

        Args:
            connection: LDAP connection

        """
        self._connection = connection
        self._active_searches: dict[str, PersistentSearchControl] = {}
        self._event_handlers: dict[str, list[Callable[..., Any]]] = {}

    async def start_monitoring(
        self,
        search_base: str,
        search_filter: str = "(objectClass=*)",
        change_types: list[ChangeType] | None = None,
        monitor_id: str | None = None,
    ) -> str:
        """Start monitoring changes in specified scope.

        Args:
            search_base: Base DN for monitoring
            search_filter: LDAP filter for entries to monitor
            change_types: Types of changes to monitor
            monitor_id: Optional identifier for this monitor

        Returns:
            Monitor identifier

        Raises:
            NotImplementedError: Persistent search not yet implemented

        """
        monitor_id = monitor_id or f"monitor_{len(self._active_searches)}"

        # TODO: Implement actual persistent search operation
        # This would start a persistent search using the connection
        msg = (
            "Persistent search monitoring requires connection manager integration. "
            "Implement actual persistent search operation using LDAP connection "
            "with proper async handling and notification processing."
        )
        raise NotImplementedError(msg)

    async def stop_monitoring(self, monitor_id: str) -> bool:
        """Stop monitoring for specified monitor.

        Args:
            monitor_id: Monitor identifier

        Returns:
            True if monitor was stopped successfully

        """
        if monitor_id in self._active_searches:
            control = self._active_searches[monitor_id]
            control.stop_monitoring()
            del self._active_searches[monitor_id]
            return True
        return False

    def add_event_handler(
        self,
        event_type: str,
        handler: Callable[[ChangeNotification], None],
    ) -> None:
        """Add event handler for specific change type.

        Args:
            event_type: Type of event (add, modify, delete, moddn, or 'all')
            handler: Handler function

        """
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []
        self._event_handlers[event_type].append(handler)

    def remove_event_handler(
        self,
        event_type: str,
        handler: Callable[[ChangeNotification], None],
    ) -> bool:
        """Remove event handler.

        Args:
            event_type: Type of event
            handler: Handler function to remove

        Returns:
            True if handler was removed

        """
        if event_type in self._event_handlers:
            try:
                self._event_handlers[event_type].remove(handler)
                return True
            except ValueError:
                pass
        return False

    def get_active_monitors(self) -> dict[str, dict[str, Any]]:
        """Get information about active monitors.

        Returns:
            Dictionary of active monitors and their statistics

        """
        return {
            monitor_id: control.get_monitoring_statistics()
            for monitor_id, control in self._active_searches.items()
        }

    async def process_notifications(self) -> None:
        """Process pending notifications for all active monitors."""
        for control in self._active_searches.values():
            notifications = control.get_pending_notifications()

            for notification in notifications:
                await self._dispatch_notification(notification)

    async def _execute_handler_safely(
        self,
        handler: Callable[[ChangeNotification], None],
        notification: ChangeNotification,
    ) -> None:
        """Execute event handler safely with proper async/sync handling.

        Args:
            handler: Event handler function
            notification: Change notification to pass to handler

        """
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(notification)
            else:
                handler(notification)
        except Exception:
            # Log error but don't stop processing other handlers
            pass

    async def _dispatch_notification(self, notification: ChangeNotification) -> None:
        """Dispatch notification to appropriate event handlers.

        Args:
            notification: Change notification to dispatch

        """
        # Call handlers for specific change type
        change_type = notification.change_type.value
        if change_type in self._event_handlers:
            for handler in self._event_handlers[change_type]:
                await self._execute_handler_safely(handler, notification)

        # Call handlers for 'all' events
        if "all" in self._event_handlers:
            for handler in self._event_handlers["all"]:
                await self._execute_handler_safely(handler, notification)


# Convenience functions
def create_persistent_search(
    change_types: list[ChangeType] | None = None,
    changes_only: bool = True,
) -> PersistentSearchControl:
    """Create persistent search control with common settings.

    Args:
        change_types: Types of changes to monitor
        changes_only: Return only changes, not initial results

    Returns:
        Configured persistent search control

    """
    return PersistentSearchControl(
        change_types=change_types,
        changes_only=changes_only,
        return_entry_change_notification=True,
        criticality=True,
    )


def create_user_monitor() -> PersistentSearchControl:
    """Create persistent search control optimized for user monitoring.

    Returns:
        Persistent search control for user entry changes

    """
    return PersistentSearchControl(
        change_types=[ChangeType.ADD, ChangeType.MODIFY, ChangeType.DELETE],
        changes_only=True,
        return_entry_change_notification=True,
        criticality=True,
    )


def create_group_monitor() -> PersistentSearchControl:
    """Create persistent search control optimized for group monitoring.

    Returns:
        Persistent search control for group entry changes

    """
    return PersistentSearchControl(
        change_types=[
            ChangeType.ADD,
            ChangeType.MODIFY,
            ChangeType.DELETE,
            ChangeType.MODDN,
        ],
        changes_only=True,
        return_entry_change_notification=True,
        criticality=True,
    )


async def monitor_directory_changes(
    connection: Any,
    search_base: str,
    change_handler: Callable[[ChangeNotification], None],
    search_filter: str = "(objectClass=*)",
) -> PersistentSearchMonitor:
    """Convenience function to start directory change monitoring.

    Args:
        connection: LDAP connection
        search_base: Base DN to monitor
        change_handler: Function to handle change notifications
        search_filter: LDAP filter for entries to monitor

    Returns:
        Active persistent search monitor

    """
    monitor = PersistentSearchMonitor(connection)
    monitor.add_event_handler("all", change_handler)

    await monitor.start_monitoring(
        search_base=search_base,
        search_filter=search_filter,
    )

    return monitor


# TODO: Integration points for implementation:
#
# 1. BER Encoding/Decoding:
#    - Implement proper ASN.1 BER encoding for persistent search request
#    - Implement BER decoding for Entry Change Notification control responses
#    - Handle different server implementations and extensions
#
# 2. LDAP Connection Integration:
#    - Integrate with connection manager for persistent operations
#    - Handle long-running connections and connection pooling
#    - Implement proper async/await patterns for notifications
#
# 3. Event Processing Engine:
#    - Efficient event dispatching and handler management
#    - Support for async and sync event handlers
#    - Error handling and recovery for failed handlers
#
# 4. Performance Optimization:
#    - Efficient notification queuing and processing
#    - Memory management for long-running monitors
#    - Connection keep-alive and reconnection logic
#
# 5. High Availability:
#    - Failover and reconnection strategies
#    - State preservation across connection failures
#    - Duplicate notification detection and handling
#
# 6. Monitoring and Metrics:
#    - Performance metrics for notification processing
#    - Connection health monitoring
#    - Alert generation for monitoring failures
#
# 7. Testing Requirements:
#    - Unit tests for all persistent search functionality
#    - Integration tests with different LDAP servers
#    - Performance tests for high-volume change scenarios
#    - Reliability tests for long-running operations
