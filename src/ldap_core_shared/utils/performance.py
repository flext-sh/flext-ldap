"""Enterprise LDAP performance monitoring and metrics collection."""

from __future__ import annotations

import time
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from contextlib import _GeneratorContextManager

from pydantic import BaseModel, ConfigDict, Field, computed_field

from ldap_core_shared.utils.constants import (
    DEFAULT_CONFIDENCE_PERCENT,
    DEFAULT_LARGE_LIMIT,
    DEFAULT_MAX_ITEMS,
    PERCENTAGE_CALCULATION_BASE,
    TARGET_CONNECTION_REUSE_RATE,
    TARGET_OPERATIONS_PER_SECOND,
    TARGET_POOL_EFFICIENCY_MS,
    TARGET_SUCCESS_RATE,
)


class LDAPMetrics(BaseModel):
    """Enterprise LDAP operation metrics."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    # Operation Metrics
    operation_count: int = Field(default=0, ge=0)
    success_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)

    # Timing Metrics
    total_duration: float = Field(default=0.0, ge=0.0)
    min_duration: float = Field(default=0.0, ge=0.0)
    max_duration: float = Field(default=0.0, ge=0.0)

    # Performance Metrics
    operations_per_second: float = Field(default=0.0, ge=0.0)
    average_duration: float = Field(default=0.0, ge=0.0)

    # Timestamp
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.operation_count == 0:
            return DEFAULT_MAX_ITEMS
        return (self.success_count / self.operation_count) * PERCENTAGE_CALCULATION_BASE

    @computed_field
    def error_rate(self) -> float:
        """Calculate error rate as percentage."""
        if self.operation_count == 0:
            return 0.0
        return (self.error_count / self.operation_count) * PERCENTAGE_CALCULATION_BASE

    @computed_field
    def meets_sla(self) -> bool:
        """Check if metrics meet SLA requirements."""
        target_success: float = float(TARGET_SUCCESS_RATE) * float(
            PERCENTAGE_CALCULATION_BASE,
        )
        target_ops: float = float(TARGET_OPERATIONS_PER_SECOND) * 0.8
        return (
            self.success_rate >= target_success  # type: ignore[operator]
            and self.operations_per_second >= target_ops
        )

    def __getitem__(self, key: str) -> dict[str, Any]:
        """Enable dict-like access for backward compatibility with tests."""
        if hasattr(self, "_measurements"):
            measurements: dict[str, dict[str, Any]] = self._measurements
            return measurements.get(key, {})
        return {}

    def __contains__(self, key: str) -> bool:
        """Enable 'in' operator for backward compatibility with tests."""
        if hasattr(self, "_measurements"):
            measurements = self._measurements
            return key in measurements
        return False


class ConnectionPoolMetrics(BaseModel):
    """Enterprise connection pool performance metrics."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    # Pool State
    pool_size: int = Field(default=0, ge=0)
    active_connections: int = Field(default=0, ge=0)
    idle_connections: int = Field(default=0, ge=0)

    # Usage Metrics
    connections_created: int = Field(default=0, ge=0)
    connections_reused: int = Field(default=0, ge=0)
    connections_closed: int = Field(default=0, ge=0)

    # Performance Metrics
    average_acquisition_time: float = Field(default=0.0, ge=0.0)
    max_acquisition_time: float = Field(default=0.0, ge=0.0)
    pool_utilization: float = Field(default=0.0, ge=0.0, le=1.0)

    # Timestamp
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field
    def total_connections(self) -> int:
        """Total connections in pool."""
        return self.active_connections + self.idle_connections

    @computed_field
    def reuse_rate(self) -> float:
        """Calculate connection reuse rate as percentage."""
        total_usage = self.connections_created + self.connections_reused
        if total_usage == 0:
            return 0.0
        return (self.connections_reused / total_usage) * PERCENTAGE_CALCULATION_BASE

    @computed_field
    def efficiency_grade(self) -> str:
        """Calculate pool efficiency grade."""
        target_reuse: float = float(TARGET_CONNECTION_REUSE_RATE) * float(
            PERCENTAGE_CALCULATION_BASE,
        )
        target_ms: float = float(TARGET_POOL_EFFICIENCY_MS)
        if (
            self.reuse_rate >= target_reuse  # type: ignore[operator]
            and self.average_acquisition_time <= target_ms
        ):
            return "A+"
        if (
            self.reuse_rate >= 80.0  # type: ignore[operator]  # 80% reuse rate
            and self.average_acquisition_time <= 20  # 20ms
        ):
            return "A"
        if (
            self.reuse_rate >= 60.0  # type: ignore[operator]  # 60% reuse rate
            and self.average_acquisition_time <= 50  # 50ms
        ):
            return "B"
        return "C"


class PerformanceMonitor:
    """Enterprise LDAP performance monitor with real-time tracking."""

    def __init__(self, name: str = "ldap_operations") -> None:
        """Initialize performance monitor.

        Args:
            name: Monitor name for identification and logging

        """
        self.name = name
        self.reset()
        self._measurements: dict[str, dict[str, Any]] = {}

    def reset(self) -> None:
        """Reset all performance counters."""
        self._operation_count = 0
        self._success_count = 0
        self._error_count = 0
        self._total_duration = 0.0
        self._min_duration = float("inf")
        self._max_duration = 0.0
        self._start_time = time.time()
        self._measurements = {}

    def start_measurement(self, measurement_name: str) -> None:
        """Start a named measurement.

        Args:
            measurement_name: Name of the measurement to start

        """
        self._measurements[measurement_name] = {
            "start_time": time.time(),
            "end_time": None,
            "duration": None,
        }

    def stop_measurement(self, measurement_name: str) -> None:
        """Stop a named measurement.

        Args:
            measurement_name: Name of the measurement to stop

        """
        if measurement_name in self._measurements:
            end_time = time.time()
            self._measurements[measurement_name]["end_time"] = end_time
            duration = end_time - self._measurements[measurement_name]["start_time"]
            self._measurements[measurement_name]["duration"] = duration

            # Record the operation
            self.record_operation(duration, True)

    def record_operation(self, duration: float, success: bool = True) -> None:
        """Record an LDAP operation.

        Args:
            duration: Operation duration in seconds
            success: Whether operation was successful

        """
        self._operation_count += 1
        self._total_duration += duration

        if success:
            self._success_count += 1
        else:
            self._error_count += 1

        # Update min/max duration
        self._min_duration = min(self._min_duration, duration)
        self._max_duration = max(self._max_duration, duration)

    def get_metrics(self) -> LDAPMetrics:
        """Get current performance metrics.

        Returns both the structured LDAPMetrics and raw measurements for backward compatibility.
        """
        # Calculate operations per second
        elapsed_time = time.time() - self._start_time
        ops_per_second = (
            self._operation_count / elapsed_time if elapsed_time > 0 else 0.0
        )

        # Calculate average duration
        avg_duration = (
            self._total_duration / self._operation_count
            if self._operation_count > 0
            else 0.0
        )

        # Handle case where no operations recorded yet
        min_duration = self._min_duration if self._min_duration != float("inf") else 0.0

        # Return structured metrics with raw measurements for backward compatibility
        structured_metrics = LDAPMetrics(
            operation_count=self._operation_count,
            success_count=self._success_count,
            error_count=self._error_count,
            total_duration=self._total_duration,
            min_duration=min_duration,
            max_duration=self._max_duration,
            operations_per_second=ops_per_second,
            average_duration=avg_duration,
        )

        # Add raw measurements to the metrics for backward compatibility
        structured_metrics._measurements = self._measurements  # type: ignore[attr-defined]

        return structured_metrics

    @contextmanager
    def measure_operation(
        self,
        operation_name: str = "ldap_operation",
    ) -> _GeneratorContextManager[dict[str, Any]]:
        """Context manager to measure operation performance.

        Args:
            operation_name: Name of operation being measured

        Yields:
            dict: Operation context with timing information

        Example:
            ```python
            monitor = PerformanceMonitor()

            with monitor.measure_operation("search") as ctx:
                # Perform LDAP search
                results = ldap_connection.search(...)
                ctx["success"] = len(results) > 0
            ```

        """
        start_time = time.time()
        operation_ctx = {
            "operation_name": operation_name,
            "start_time": start_time,
            "success": True,  # Default to success, can be overridden
        }

        try:
            yield operation_ctx
        except Exception as e:
            operation_ctx["success"] = False
            operation_ctx["error"] = str(e)
            raise
        finally:
            end_time = time.time()
            duration = end_time - start_time
            operation_ctx["duration"] = duration
            operation_ctx["end_time"] = end_time

            # Record the operation
            success: bool = bool(operation_ctx["success"])
            self.record_operation(duration, success)

    def track_operation(
        self,
        operation_name: str = "ldap_operation",
    ) -> _GeneratorContextManager[dict[str, Any]]:
        """Alias for measure_operation for backward compatibility.

        Args:
            operation_name: Name of operation being measured

        Yields:
            dict: Operation context with timing information

        """
        return self.measure_operation(operation_name)

    def _get_current_time(self) -> float:
        """Get current time for internal use.

        Returns:
            Current time as float timestamp

        """
        return time.time()


class PerformanceAnalyzer:
    """Analyze LDAP performance trends and detect degradation."""

    def __init__(self, window_size: int = DEFAULT_MAX_ITEMS) -> None:
        """Initialize performance analyzer.

        Args:
            window_size: Number of recent operations to analyze

        """
        self.window_size = window_size
        self._metrics_history: list[LDAPMetrics] = []

    def add_metrics(self, metrics: LDAPMetrics) -> None:
        """Add metrics to analysis window."""
        self._metrics_history.append(metrics)

        # Keep only recent metrics within window
        if len(self._metrics_history) > self.window_size:
            self._metrics_history = self._metrics_history[-self.window_size :]

    def detect_performance_degradation(self, threshold: float = 0.2) -> dict[str, Any]:
        """Detect performance degradation trends.

        Args:
            threshold: Degradation threshold (20% by default)

        Returns:
            Analysis results with degradation indicators

        """
        if len(self._metrics_history) < 10:  # Need minimum data points
            return {
                "degradation_detected": False,
                "reason": "insufficient_data",
                "data_points": len(self._metrics_history),
            }

        # Get recent and baseline metrics
        recent_metrics = self._metrics_history[-5:]  # Last 5 measurements
        baseline_metrics = self._metrics_history[:10]  # First 10 measurements

        # Calculate averages
        recent_avg_ops_per_sec = sum(
            m.operations_per_second for m in recent_metrics
        ) / len(recent_metrics)
        baseline_avg_ops_per_sec = sum(
            m.operations_per_second for m in baseline_metrics
        ) / len(baseline_metrics)

        recent_avg_duration = sum(m.average_duration for m in recent_metrics) / len(
            recent_metrics,
        )
        baseline_avg_duration = sum(m.average_duration for m in baseline_metrics) / len(
            baseline_metrics,
        )

        # Check for degradation
        ops_degradation = False
        duration_degradation = False

        if baseline_avg_ops_per_sec > 0:
            ops_change = (
                baseline_avg_ops_per_sec - recent_avg_ops_per_sec
            ) / baseline_avg_ops_per_sec
            ops_degradation = ops_change > threshold

        if baseline_avg_duration > 0:
            duration_change = (
                recent_avg_duration - baseline_avg_duration
            ) / baseline_avg_duration
            duration_degradation = duration_change > threshold

        degradation_detected = ops_degradation or duration_degradation

        return {
            "degradation_detected": degradation_detected,
            "operations_per_second": {
                "baseline": baseline_avg_ops_per_sec,
                "recent": recent_avg_ops_per_sec,
                "degraded": ops_degradation,
            },
            "average_duration": {
                "baseline": baseline_avg_duration,
                "recent": recent_avg_duration,
                "degraded": duration_degradation,
            },
            "data_points": len(self._metrics_history),
            "analysis_timestamp": datetime.now(UTC).isoformat(),
        }

    def generate_performance_report(self) -> dict[str, Any]:
        """Generate comprehensive performance report."""
        if not self._metrics_history:
            return {
                "status": "no_data",
                "message": "No performance data available",
            }

        # Calculate overall statistics
        total_operations = sum(m.operation_count for m in self._metrics_history)
        total_successes = sum(m.success_count for m in self._metrics_history)
        total_errors = sum(m.error_count for m in self._metrics_history)

        avg_ops_per_second = sum(
            m.operations_per_second for m in self._metrics_history
        ) / len(self._metrics_history)
        avg_duration = sum(m.average_duration for m in self._metrics_history) / len(
            self._metrics_history,
        )

        overall_success_rate = (
            (total_successes / total_operations * PERCENTAGE_CALCULATION_BASE)
            if total_operations > 0
            else 0
        )

        # Performance grade
        performance_grade = self._calculate_performance_grade(
            avg_ops_per_second,
            overall_success_rate,
            avg_duration,
        )

        return {
            "performance_grade": performance_grade,
            "total_operations": total_operations,
            "overall_success_rate": overall_success_rate,
            "average_operations_per_second": avg_ops_per_second,
            "average_duration_ms": avg_duration
            * DEFAULT_LARGE_LIMIT,  # Convert to milliseconds
            "total_errors": total_errors,
            "measurement_period": {
                "start": self._metrics_history[0].timestamp.isoformat(),
                "end": self._metrics_history[-1].timestamp.isoformat(),
                "data_points": len(self._metrics_history),
            },
            "degradation_analysis": self.detect_performance_degradation(),
            "report_timestamp": datetime.now(UTC).isoformat(),
        }

    def _calculate_performance_grade(
        self,
        ops_per_second: float,
        success_rate: float,
        avg_duration: float,
    ) -> str:
        """Calculate overall performance grade."""
        # A+ Grade: Exceeds all targets
        if (
            ops_per_second >= TARGET_OPERATIONS_PER_SECOND
            and success_rate >= TARGET_SUCCESS_RATE * PERCENTAGE_CALCULATION_BASE
            and avg_duration
            <= TARGET_POOL_EFFICIENCY_MS / DEFAULT_LARGE_LIMIT  # Convert to seconds
        ):
            return "A+"

        # A Grade: Meets most targets
        if (
            ops_per_second >= TARGET_OPERATIONS_PER_SECOND * 0.8
            and success_rate >= DEFAULT_CONFIDENCE_PERCENT
            and avg_duration <= 0.05  # 50ms
        ):
            return "A"

        # B Grade: Acceptable performance
        if (
            ops_per_second >= TARGET_OPERATIONS_PER_SECOND * 0.5
            and success_rate >= 90.0
            and avg_duration <= 0.1  # 100ms
        ):
            return "B"

        # C Grade: Needs improvement
        return "C"
