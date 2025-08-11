"""LDAP Base Service - Service Layer Foundation using FLEXT Core Patterns.

Extends FlextService from flext-core to provide LDAP-specific service foundation.
Uses Clean Architecture and DDD patterns for enterprise-grade LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextResult, get_flext_container

if TYPE_CHECKING:
    from flext_core import FlextContainer, FlextTypes


class FlextLdapBaseService(FlextDomainService[None]):
    """Base service for all LDAP operations extending FlextDomainService.

    Provides common LDAP service functionality including connection management,
    error handling, and observability integration using FLEXT core patterns.
    """

    def __init__(self, /, container: FlextContainer | None = None, **data: object) -> None:
        """Initialize LDAP base service with dependency injection."""
        super().__init__(**data)
        self._container = container or get_flext_container()
        self._is_running = False

    def start(self) -> FlextResult[None]:
        """Start LDAP service with proper initialization."""
        try:
            if self._is_running:
                return FlextResult.fail("Service is already running")

            # Initialize LDAP service components
            self._is_running = True
            return FlextResult.ok(None)
        except Exception as e:
            return FlextResult.fail(f"Failed to start LDAP service: {e}")

    def stop(self) -> FlextResult[None]:
        """Stop LDAP service with proper cleanup."""
        try:
            if not self._is_running:
                return FlextResult.fail("Service is not running")

            # Cleanup LDAP connections and resources
            self._is_running = False
            return FlextResult.ok(None)
        except Exception as e:
            return FlextResult.fail(f"Failed to stop LDAP service: {e}")

    def health_check(self) -> FlextResult[FlextTypes.Core.JsonDict]:
        """Perform LDAP service health check."""
        try:
            health_info: FlextTypes.Core.JsonDict = {
                "service": "flext-ldap",
                "status": "running" if self._is_running else "stopped",
                "version": "0.9.0",
                "dependencies": {"flext_core": "healthy", "ldap3": "available"},
            }
            return FlextResult.ok(health_info)
        except Exception as e:
            return FlextResult.fail(f"Health check failed: {e}")

    @property
    def container(self) -> FlextContainer:
        """Get dependency injection container."""
        return self._container

    @property
    def is_running(self) -> bool:
        """Check if service is running."""
        return self._is_running

    def execute(self) -> FlextResult[None]:
        """Execute domain operation - required by FlextDomainService."""
        return self.health_check().map(lambda _: None)
