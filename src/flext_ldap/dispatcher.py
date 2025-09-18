"""Dispatcher integration helpers for flext-ldap."""

from __future__ import annotations

from typing import cast

from flext_core import FlextBus, FlextDispatcher, FlextDispatcherRegistry, FlextHandlers
from flext_ldap.domain import FlextLdapDomain


class FlextLdapDispatcher:
    """LDAP dispatcher integration service following FLEXT patterns.

    This class provides centralized dispatcher functionality for LDAP domain operations,
    encapsulating handler registration, dispatcher building, and caching mechanisms
    according to FLEXT Clean Architecture principles.
    """

    def __init__(self, bus: FlextBus | None = None) -> None:
        """Initialize LDAP dispatcher with optional bus.

        Args:
            bus: Optional FlextBus instance for command processing

        """
        self._bus = bus
        self._dispatcher: FlextDispatcher | None = None

    class _HandlerRegistry:
        """Nested helper for handler building and registration."""

        @staticmethod
        def build_handlers() -> list[FlextHandlers[object, object]]:
            """Build handler instances lazily to avoid circular imports."""
            # Import inside method to avoid circular import at runtime
            # For static type checking, FlextLdapDomain is imported above under TYPE_CHECKING

            # Create handlers and cast to the expected interface type
            return [
                cast(
                    "FlextHandlers[object, object]",
                    FlextLdapDomain.CreateUserCommandHandler(),
                )
            ]

    def build_dispatcher(self, bus: FlextBus | None = None) -> FlextDispatcher:
        """Create a dispatcher configured with ldap domain handlers.

        Args:
            bus: Optional FlextBus instance, uses self._bus if not provided

        Returns:
            Configured FlextDispatcher with registered LDAP handlers

        Raises:
            RuntimeError: If handler registration fails

        """
        effective_bus = bus or self._bus
        dispatcher = FlextDispatcher(bus=effective_bus)
        registry = FlextDispatcherRegistry(dispatcher)

        for handler in self._HandlerRegistry.build_handlers():
            registration = registry.register_handler(handler)
            if registration.is_failure:
                error_msg = registration.error or "Failed to register ldap handler"
                raise RuntimeError(error_msg)

        self._dispatcher = dispatcher
        return dispatcher

    def get_cached_dispatcher(self) -> FlextDispatcher:
        """Return cached dispatcher for flext-ldap domain operations.

        Returns:
            Cached FlextDispatcher instance configured for LDAP operations

        """
        if self._dispatcher is None:
            bus = FlextBus.create_command_bus()
            self._dispatcher = self.build_dispatcher(bus=bus)
        return self._dispatcher

    def reset_dispatcher_cache(self) -> None:
        """Reset dispatcher cache for tests."""
        self._dispatcher = None

    @classmethod
    def create_default(cls, bus: FlextBus | None = None) -> FlextDispatcher:
        """Create a dispatcher configured with ldap domain handlers.

        Replaces the global build_dispatcher function with class method.
        """
        instance = cls()
        return instance.build_dispatcher(bus)

    @classmethod
    def get_global_dispatcher(cls) -> FlextDispatcher:
        """Return cached dispatcher for flext-ldap domain operations.

        Replaces the global get_dispatcher function with class method.
        """
        bus = FlextBus.create_command_bus()
        return cls.create_default(bus=bus)


__all__ = [
    "FlextLdapDispatcher",
]
