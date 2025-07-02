"""LDAP Connection Monitoring and Performance Tracking."""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Any

from ldap_core_shared.connections.interfaces import (
    BaseConnectionComponent,
)
from ldap_core_shared.utils.constants import DEFAULT_MAX_ITEMS

if TYPE_CHECKING:
    from ldap_core_shared.connections.base import LDAPConnectionInfo

logger = logging.getLogger(__name__)


class PerformanceTracker(BaseConnectionComponent):
    """🔥 Single Responsibility: Track performance metrics only.

    SOLID Compliance:
    - S: Only tracks performance, nothing else
    - O: Extensible through inheritance
    - L: Interchangeable with other trackers
    - I: Implements focused IPerformanceTracker
    - D: Depends on LDAPConnectionInfo abstraction
    """

    def __init__(self, connection_info: LDAPConnectionInfo) -> None:
        """Initialize performance tracker.

        Args:
            connection_info: Connection configuration

        """
        super().__init__(connection_info)
        self._operations: deque[dict[str, Any]] = deque(maxlen=DEFAULT_MAX_ITEMS)
        self._total_operations = 0
        self._total_time = 0.0

    async def initialize(self) -> None:
        """Initialize performance tracker."""
        logger.debug("PerformanceTracker initialized")

    async def cleanup(self) -> None:
        """Cleanup performance tracker."""
        self._operations.clear()

    def record_operation(
        self,
        operation_type: str,
        duration: float,
        success: bool = True,
        details: dict[str, Any] | None = None,
    ) -> None:
        """🔥 Record operation performance metrics.

        Args:
            operation_type: Type of operation (search, add, modify, etc.)
            duration: Operation duration in seconds
            success: Whether operation was successful
            details: Additional operation details

        """
        self._total_operations += 1
        self._total_time += duration

        operation_record = {
            "type": operation_type,
            "duration": duration,
            "success": success,
            "timestamp": time.time(),
            "details": details or {},
        }

        self._operations.append(operation_record)
        logger.debug(
            "Recorded %s operation: %.3fs (success: %s)",
            operation_type,
            duration,
            success,
        )

    def get_performance_stats(self) -> dict[str, Any]:
        """🔥 Get comprehensive performance statistics.

        Returns:
            Performance statistics dictionary

        """
        if not self._operations:
            return {
                "total_operations": 0,
                "average_duration": 0.0,
                "success_rate": 0.0,
                "operations_by_type": {},
            }

        successful_ops = [op for op in self._operations if op["success"]]
        failed_ops = [op for op in self._operations if not op["success"]]

        # Calculate averages
        avg_duration = sum(op["duration"] for op in self._operations) / len(
            self._operations,
        )
        success_rate = len(successful_ops) / len(self._operations) * DEFAULT_MAX_ITEMS

        # Group by operation type
        ops_by_type: dict[str, dict[str, Any]] = {}
        for op in self._operations:
            op_type = op["type"]
            if op_type not in ops_by_type:
                ops_by_type[op_type] = {
                    "count": 0,
                    "total_duration": 0.0,
                    "successful": 0,
                    "failed": 0,
                }

            ops_by_type[op_type]["count"] += 1
            ops_by_type[op_type]["total_duration"] += op["duration"]
            if op["success"]:
                ops_by_type[op_type]["successful"] += 1
            else:
                ops_by_type[op_type]["failed"] += 1

        # Calculate averages by type
        for type_stats in ops_by_type.values():
            type_stats["average_duration"] = (
                type_stats["total_duration"] / type_stats["count"]
            )
            type_stats["success_rate"] = (
                type_stats["successful"] / type_stats["count"] * DEFAULT_MAX_ITEMS
            )

        return {
            "total_operations": len(self._operations),
            "successful_operations": len(successful_ops),
            "failed_operations": len(failed_ops),
            "average_duration": avg_duration,
            "total_duration": sum(op["duration"] for op in self._operations),
            "success_rate": success_rate,
            "operations_by_type": ops_by_type,
            "recent_operations": list(self._operations)[-10:],  # Last 10 operations
        }


class StandardHealthMonitor(BaseConnectionComponent):
    """🔥 Single Responsibility: Monitor connection health only.

    SOLID Compliance:
    - S: Only monitors health, nothing else
    - O: Extensible through inheritance
    - L: Interchangeable with other monitors
    - I: Implements focused IHealthMonitor
    - D: Depends on LDAPConnectionInfo abstraction
    """

    def __init__(self, connection_info: LDAPConnectionInfo) -> None:
        """Initialize health monitor.

        Args:
            connection_info: Connection configuration

        """
        super().__init__(connection_info)
        self._last_check = 0.0
        self._check_interval = 60.0  # 1 minute
        self._consecutive_failures = 0
        self._max_failures = 3

    async def initialize(self) -> None:
        """Initialize health monitor."""
        logger.debug("StandardHealthMonitor initialized")

    async def cleanup(self) -> None:
        """Cleanup health monitor."""

    async def check_health(self) -> bool:
        """🔥 Check connection health.

        Returns:
            True if connection is healthy, False otherwise

        """
        current_time = time.time()

        # Skip check if too recent
        if current_time - self._last_check < self._check_interval:
            return self._consecutive_failures < self._max_failures

        self._last_check = current_time

        try:
            # Create test connection
            from ldap_core_shared.connections.factories import StandardConnectionFactory

            factory = StandardConnectionFactory(self.connection_info)
            connection = factory.create_connection(self.connection_info)

            if connection.bind():
                # Perform simple search to verify functionality
                success = connection.search(
                    search_base="",
                    search_filter="(objectClass=*)",
                    search_scope="BASE",
                    attributes=["*"],
                )
                connection.unbind()

                if success:
                    self._consecutive_failures = 0
                    logger.debug("Health check passed")
                    return True
                self._consecutive_failures += 1
                logger.warning("Health check failed: search operation failed")
                return False
            self._consecutive_failures += 1
            logger.warning("Health check failed: bind operation failed")
            return False

        except Exception as e:
            self._consecutive_failures += 1
            logger.warning("Health check failed with exception: %s", e)
            return False

    def get_health_status(self) -> dict[str, Any]:
        """🔥 Get detailed health status.

        Returns:
            Health status dictionary

        """
        is_healthy = self._consecutive_failures < self._max_failures

        return {
            "healthy": is_healthy,
            "last_check": self._last_check,
            "consecutive_failures": self._consecutive_failures,
            "max_failures": self._max_failures,
            "check_interval": self._check_interval,
            "status": "healthy" if is_healthy else "unhealthy",
        }
