"""Event handling infrastructure for LDAP operations.

Provides event dispatching and handling capabilities for
domain events across LDAP projects.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flext_ldap.events.domain_events import DomainEvent

logger = logging.getLogger(__name__)


class EventHandler(ABC):
    """Base class for event handlers."""

    @abstractmethod
    async def handle(self, event: DomainEvent) -> None:
        """Handle a domain event."""

    @property
    @abstractmethod
    def handled_events(self) -> list[type[DomainEvent]]:
        """Return list of event types this handler can process."""


class EventDispatcher:
    """Event dispatcher for domain events.

    Manages event handlers and dispatches events to appropriate handlers.
    """

    def __init__(self, max_workers: int = 4) -> None:
        """Initialize event dispatcher."""
        self._handlers: dict[type[DomainEvent], list[EventHandler]] = defaultdict(list)
        self._async_handlers: dict[type[DomainEvent], list[EventHandler]] = defaultdict(
            list,
        )
        self._event_queue: asyncio.Queue[DomainEvent | None] = asyncio.Queue()
        self._logger = logging.getLogger(__name__)
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._running = False
        self._task: asyncio.Task[None] | None = None

    def register_handler(
        self,
        handler: EventHandler,
        async_handler: bool = True,
    ) -> None:
        """Register an event handler."""
        for event_type in handler.handled_events:
            if async_handler:
                self._async_handlers[event_type].append(handler)
            else:
                self._handlers[event_type].append(handler)

            self._logger.debug(
                "Registered %s handler %s for event %s",
                "async" if async_handler else "sync",
                handler.__class__.__name__,
                event_type.__name__,
            )

    def unregister_handler(self, handler: EventHandler) -> None:
        """Unregister an event handler."""
        for event_type in handler.handled_events:
            if handler in self._async_handlers[event_type]:
                self._async_handlers[event_type].remove(handler)
            if handler in self._handlers[event_type]:
                self._handlers[event_type].remove(handler)

    async def dispatch(self, event: DomainEvent) -> None:
        """Dispatch event to all registered handlers."""
        if not self._running:
            await self._process_event(event)
        else:
            await self._event_queue.put(event)

    async def dispatch_sync(self, event: DomainEvent) -> None:
        """Dispatch event synchronously (wait for all handlers to complete)."""
        await self._process_event(event)

    async def _process_event(self, event: DomainEvent) -> None:
        """Process a single event."""
        event_type = type(event)

        # Process async handlers
        async_handlers = self._async_handlers.get(event_type, [])
        if async_handlers:
            tasks = [handler.handle(event) for handler in async_handlers]
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception as e:
                self._logger.exception("Error in async event handlers: %s", e)

        # Process sync handlers (still async but treated as sync priority)
        sync_handlers = self._handlers.get(event_type, [])
        if sync_handlers:
            for handler in sync_handlers:
                try:
                    await handler.handle(event)
                except Exception as e:
                    self._logger.exception(
                        "Error in sync event handler %s: %s",
                        handler.__class__.__name__,
                        e,
                    )

        self._logger.debug(
            "Processed event %s with %d async and %d sync handlers",
            event.event_type,
            len(async_handlers),
            len(sync_handlers),
        )

    async def start(self) -> None:
        """Start the event processing loop."""
        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._event_loop())
        self._logger.info("Event dispatcher started")

    async def stop(self) -> None:
        """Stop the event processing loop."""
        if not self._running:
            return

        self._running = False

        # Signal shutdown
        await self._event_queue.put(None)

        # Wait for task to complete
        if self._task:
            await self._task

        # Shutdown thread pool
        self._executor.shutdown(wait=True)

        self._logger.info("Event dispatcher stopped")

    async def _event_loop(self) -> None:
        """Main event processing loop."""
        while self._running:
            try:
                event = await self._event_queue.get()

                # Shutdown signal
                if event is None:
                    self._running = False
                    break

                await self._process_event(event)
                self._event_queue.task_done()

            except Exception as e:
                self._logger.exception("Error in event loop: %s", e)

    def get_handler_count(self, event_type: type[DomainEvent]) -> int:
        """Get number of handlers for a specific event type."""
        return len(self._async_handlers.get(event_type, [])) + len(
            self._handlers.get(event_type, []),
        )

    def get_all_handlers(self) -> dict[str, dict[str, int]]:
        """Get summary of all registered handlers."""
        summary: dict[str, dict[str, int]] = {}

        all_event_types = set(self._async_handlers.keys() | set(self._handlers.keys()))

        for event_type in all_event_types:
            async_count = len(self._async_handlers.get(event_type, []))
            sync_count = len(self._handlers.get(event_type, []))
            summary[event_type.__name__] = {
                "async": async_count,
                "sync": sync_count,
                "total": async_count + sync_count,
            }

        return summary


class LoggingEventHandler(EventHandler):
    """Event handler that logs all events."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Initialize logging handler."""
        self.logger = logger or logging.getLogger(__name__)

    async def handle(self, event: DomainEvent) -> None:
        """Log the event."""
        self.logger.info(
            "Event: %s | Source: %s | Time: %s",
            event.event_type,
            event.source,
            event.timestamp.isoformat(),
        )

    @property
    def handled_events(self) -> list[type[DomainEvent]]:
        """Handle all event types."""
        return []  # This handler handles events dynamically


class MetricsEventHandler(EventHandler):
    """Event handler that collects metrics."""

    def __init__(self) -> None:
        """Initialize metrics handler."""
        self.event_counts: dict[str, int] = defaultdict(int)
        self.error_counts: dict[str, int] = defaultdict(int)

    async def handle(self, event: DomainEvent) -> None:
        """Collect metrics from event."""
        self.event_counts[event.event_type] += 1

        # Track errors specifically
        if hasattr(event, "success") and not event.success:
            self.error_counts[event.event_type] += 1

    @property
    def handled_events(self) -> list[type[DomainEvent]]:
        """Handle all event types."""
        return []  # This handler handles events dynamically

    def get_metrics(self) -> dict[str, Any]:
        """Get collected metrics."""
        return {
            "event_counts": dict(self.event_counts),
            "error_counts": dict(self.error_counts),
            "total_events": sum(self.event_counts.values()),
            "total_errors": sum(self.error_counts.values()),
        }

    def reset_metrics(self) -> None:
        """Reset all metrics."""
        self.event_counts.clear()
        self.error_counts.clear()


# Global event dispatcher instance
_dispatcher: EventDispatcher | None = None


def get_event_dispatcher() -> EventDispatcher:
    """Get global event dispatcher instance."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = EventDispatcher()
    return _dispatcher


async def dispatch_event(event: DomainEvent) -> None:
    """Convenience function to dispatch an event."""
    dispatcher = get_event_dispatcher()
    await dispatcher.dispatch(event)
