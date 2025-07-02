"""LDAP Connection State Management."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.utils.constants import DEFAULT_MAX_ITEMS, DEFAULT_TIMEOUT_SECONDS

if TYPE_CHECKING:
    import ldap3


@dataclass
class LDAPSearchParams:
    """Parameters for LDAP search operations."""

    search_base: str
    search_filter: str = "(objectClass=*)"
    attributes: list[str] | None = None
    search_scope: str = "SUBTREE"
    size_limit: int = 0
    time_limit: int = 0


class ConnectionStats(BaseModel):
    """Connection statistics for monitoring and performance tracking."""

    model_config = ConfigDict(frozen=True)

    total_connections: int = Field(default=0, ge=0)
    active_connections: int = Field(default=0, ge=0)
    successful_operations: int = Field(default=0, ge=0)
    failed_operations: int = Field(default=0, ge=0)
    total_operation_time: float = Field(default=0.0, ge=0.0)
    average_operation_time: float = Field(default=0.0, ge=0.0)
    connection_uptime: float = Field(default=0.0, ge=0.0)
    last_health_check: float = Field(default=0.0, ge=0.0)


@dataclass
class ConnectionState:
    """Manages connection pool and runtime state."""

    connection_pool: list[ldap3.Connection] = field(default_factory=list)
    active_connections: set[ldap3.Connection] = field(default_factory=set)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # Monitoring state
    stats: ConnectionStats = field(default_factory=ConnectionStats)
    operation_times: list[float] = field(default_factory=list)
    last_health_check: float = 0.0

    # SSH tunnel support
    ssh_tunnel: Any = None

    def add_operation_time(self, duration: float) -> None:
        """Add operation timing for performance tracking.

        Args:
            duration: Operation duration in seconds
        """
        self.operation_times.append(duration)

        # Keep only recent operations (last DEFAULT_MAX_ITEMS)
        if len(self.operation_times) > DEFAULT_MAX_ITEMS:
            self.operation_times = self.operation_times[-DEFAULT_MAX_ITEMS:]

    def get_average_operation_time(self) -> float:
        """Calculate average operation time.

        Returns:
            Average operation time in seconds
        """
        if not self.operation_times:
            return 0.0
        return sum(self.operation_times) / len(self.operation_times)

    def should_perform_health_check(
        self,
        interval: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> bool:
        """Check if health check should be performed.

        Args:
            interval: Health check interval in seconds

        Returns:
            True if health check is due
        """
        current_time = time.time()
        return (current_time - self.last_health_check) >= interval

    def update_health_check_time(self) -> None:
        """Update the last health check timestamp."""
        self.last_health_check = time.time()

    def get_pool_size(self) -> int:
        """Get current connection pool size.

        Returns:
            Number of connections in pool
        """
        return len(self.connection_pool)

    def get_active_connections_count(self) -> int:
        """Get number of active connections.

        Returns:
            Number of active connections
        """
        return len(self.active_connections)

    def has_available_connections(self) -> bool:
        """Check if there are available connections in the pool.

        Returns:
            True if connections are available
        """
        return len(self.connection_pool) > 0

    def update_stats(
        self,
        successful_ops: int = 0,
        failed_ops: int = 0,
        operation_time: float = 0.0,
    ) -> ConnectionStats:
        """Update connection statistics.

        Args:
            successful_ops: Number of successful operations to add
            failed_ops: Number of failed operations to add
            operation_time: Total operation time to add

        Returns:
            Updated connection statistics
        """
        current_stats = self.stats.model_dump()

        # Update counters
        current_stats["total_connections"] = (
            self.get_pool_size() + self.get_active_connections_count()
        )
        current_stats["active_connections"] = self.get_active_connections_count()
        current_stats["successful_operations"] += successful_ops
        current_stats["failed_operations"] += failed_ops
        current_stats["total_operation_time"] += operation_time

        # Calculate average
        total_ops = (
            current_stats["successful_operations"] + current_stats["failed_operations"]
        )
        if total_ops > 0:
            current_stats["average_operation_time"] = (
                current_stats["total_operation_time"] / total_ops
            )

        current_stats["last_health_check"] = self.last_health_check

        # Create new stats object (immutable)
        self.stats = ConnectionStats(**current_stats)
        return self.stats
