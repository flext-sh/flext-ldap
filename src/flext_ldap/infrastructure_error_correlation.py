"""Error Correlation and Analysis Infrastructure.

This module provides comprehensive error correlation, pattern detection,
and automated analysis for LDAP operations with machine learning capabilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import hashlib
import operator
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING

from flext_core import FlextIdGenerator, FlextResult, get_logger

if TYPE_CHECKING:
    from uuid import UUID

    from flext_core import FlextTypes

logger = get_logger(__name__)


class FlextLdapErrorSeverity(Enum):
    """Error severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FlextLdapErrorCategory(Enum):
    """Error categories for classification."""

    CONNECTION = "connection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SEARCH = "search"
    MODIFICATION = "modification"
    SCHEMA = "schema"
    CERTIFICATE = "certificate"
    TIMEOUT = "timeout"
    NETWORK = "network"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


@dataclass
class FlextLdapErrorPatternData:
    """Parameter Object for FlextLdapErrorPattern - eliminates large constructor."""

    pattern_id: UUID | None = None
    error_signature: str | None = None
    category: FlextLdapErrorCategory = FlextLdapErrorCategory.UNKNOWN
    severity: FlextLdapErrorSeverity = FlextLdapErrorSeverity.MEDIUM
    frequency: int = 1
    first_occurrence: datetime | None = None
    last_occurrence: datetime | None = None
    affected_operations: list[str] | None = None
    context_patterns: FlextTypes.Core.JsonDict | None = None
    correlation_score: float = 0.0


class FlextLdapErrorPattern:
    """Error pattern for correlation analysis using Parameter Object pattern."""

    def __init__(self, data: FlextLdapErrorPatternData) -> None:
        """Initialize error pattern using Parameter Object pattern."""
        self.pattern_id = data.pattern_id or FlextIdGenerator.generate_id()
        self.error_signature = data.error_signature or ""
        self.category = data.category
        self.severity = data.severity
        self.frequency = data.frequency
        self.first_occurrence = data.first_occurrence or datetime.now(UTC)
        self.last_occurrence = data.last_occurrence or datetime.now(UTC)
        self.affected_operations = data.affected_operations or []
        self.context_patterns = data.context_patterns or {}
        self.correlation_score = data.correlation_score

    @classmethod
    def create(
        cls,
        error_signature: str,
        category: FlextLdapErrorCategory = FlextLdapErrorCategory.UNKNOWN,
        severity: FlextLdapErrorSeverity = FlextLdapErrorSeverity.MEDIUM,
    ) -> FlextLdapErrorPattern:
        """Factory method for common error pattern creation."""
        data = FlextLdapErrorPatternData(
            error_signature=error_signature,
            category=category,
            severity=severity,
        )
        return cls(data)

    def to_dict(self) -> FlextTypes.Core.JsonDict:
        """Convert error pattern to dictionary."""
        return {
            "pattern_id": str(self.pattern_id),
            "error_signature": self.error_signature,
            "category": self.category.value,
            "severity": self.severity.value,
            "frequency": self.frequency,
            "first_occurrence": self.first_occurrence.isoformat(),
            "last_occurrence": self.last_occurrence.isoformat(),
            "affected_operations": self.affected_operations,
            "context_patterns": self.context_patterns,
            "correlation_score": self.correlation_score,
        }


@dataclass
class FlextLdapErrorEventData:
    """Parameter Object for FlextLdapErrorEvent - eliminates large constructor."""

    event_id: UUID | None = None
    timestamp: datetime | None = None
    error_message: str = ""
    error_code: str | None = None
    operation_type: str | None = None
    user_dn: str | None = None
    target_dn: str | None = None
    client_ip: str | None = None
    server_host: str | None = None
    stack_trace: str | None = None
    context: FlextTypes.Core.JsonDict | None = None
    severity: FlextLdapErrorSeverity = FlextLdapErrorSeverity.MEDIUM
    category: FlextLdapErrorCategory = FlextLdapErrorCategory.UNKNOWN


class FlextLdapErrorEvent:
    """Error event for correlation analysis using Parameter Object pattern."""

    def __init__(self, data: FlextLdapErrorEventData) -> None:
        """Initialize error event using Parameter Object pattern."""
        self.event_id = data.event_id or FlextIdGenerator.generate_id()
        self.timestamp = data.timestamp or datetime.now(UTC)
        self.error_message = data.error_message
        self.error_code = data.error_code
        self.operation_type = data.operation_type
        self.user_dn = data.user_dn
        self.target_dn = data.target_dn
        self.client_ip = data.client_ip
        self.server_host = data.server_host
        self.stack_trace = data.stack_trace
        self.context = data.context or {}
        self.severity = data.severity
        self.category = data.category

    @classmethod
    def create(
        cls,
        error_message: str,
        category: FlextLdapErrorCategory = FlextLdapErrorCategory.UNKNOWN,
        severity: FlextLdapErrorSeverity = FlextLdapErrorSeverity.MEDIUM,
    ) -> FlextLdapErrorEvent:
        """Factory method for common error event creation."""
        data = FlextLdapErrorEventData(
            error_message=error_message,
            category=category,
            severity=severity,
        )
        return cls(data)

    def get_signature(self) -> str:
        """Generate error signature for correlation."""
        # Create a signature based on error message patterns
        signature_components = [
            self.error_code or "",
            self._normalize_error_message(self.error_message),
            self.operation_type or "",
            self.category.value,
        ]

        signature_text = "|".join(signature_components)
        return hashlib.sha256(signature_text.encode()).hexdigest()

    @staticmethod
    def _normalize_error_message(message: str) -> str:
        """Normalize error message for pattern matching."""
        # Remove specific values like IPs, ports, DNs to find patterns

        # Replace IP addresses
        message = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]", message)

        # Replace ports
        message = re.sub(r":\d{2,5}\b", ":[PORT]", message)

        # Replace DN patterns
        message = re.sub(r"[a-zA-Z]+=\w+[,\s]*", "[DN]", message)

        # Replace UUIDs
        message = re.sub(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "[UUID]",
            message,
        )

        return message.lower().strip()

    def to_dict(self) -> FlextTypes.Core.JsonDict:
        """Convert error event to dictionary."""
        return {
            "event_id": str(self.event_id),
            "timestamp": self.timestamp.isoformat(),
            "error_message": self.error_message,
            "error_code": self.error_code,
            "operation_type": self.operation_type,
            "user_dn": self.user_dn,
            "target_dn": self.target_dn,
            "client_ip": self.client_ip,
            "server_host": self.server_host,
            "stack_trace": self.stack_trace,
            "context": self.context,
            "severity": self.severity.value,
            "category": self.category.value,
            "signature": self.get_signature(),
        }


class FlextLdapErrorCorrelationService:
    """Error correlation and analysis service."""

    def __init__(
        self,
        max_events: int = 10000,
        correlation_window_hours: int = 24,
        pattern_threshold: int = 3,
    ) -> None:
        """Initialize error correlation service.

        Args:
            max_events: Maximum number of events to keep in memory
            correlation_window_hours: Time window for correlation analysis
            pattern_threshold: Minimum occurrences to consider a pattern

        """
        self.max_events = max_events
        self.correlation_window_hours = correlation_window_hours
        self.pattern_threshold = pattern_threshold

        self._error_events: list[FlextLdapErrorEvent] = []
        self._error_patterns: dict[str, FlextLdapErrorPattern] = {}
        self._correlation_cache: dict[str, list[FlextLdapErrorEvent]] = {}

        logger.info("Error correlation service initialized")

    async def record_error(
        self,
        event_data: FlextLdapErrorEventData,
    ) -> FlextResult[FlextLdapErrorEvent]:
        """Record an error event using Parameter Object pattern."""
        try:
            # Create error event using Parameter Object pattern
            event = FlextLdapErrorEvent(event_data)

            # Add to event history
            self._error_events.append(event)

            # Manage memory
            if len(self._error_events) > self.max_events:
                self._error_events.pop(0)

            # Update patterns
            await self._update_patterns(event)

            # Analyze correlations
            await self._analyze_correlations(event)

            logger.debug("Recorded error event: %s", str(event.event_id))
            return FlextResult.ok(event)

        except (ValueError, TypeError, OSError) as e:
            error_msg = f"Failed to record error event: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def record_error_simple(
        self,
        error_message: str,
        category: FlextLdapErrorCategory | None = None,
        severity: FlextLdapErrorSeverity | None = None,
    ) -> FlextResult[FlextLdapErrorEvent]:
        """Simplified error recording for common cases - backward compatibility."""
        event_data = FlextLdapErrorEventData(
            error_message=error_message,
            category=category or FlextLdapErrorCategory.UNKNOWN,
            severity=severity or FlextLdapErrorSeverity.MEDIUM,
        )
        return await self.record_error(event_data)

    async def get_error_patterns(
        self,
        category: FlextLdapErrorCategory | None = None,
        severity: FlextLdapErrorSeverity | None = None,
        min_frequency: int = 1,
    ) -> FlextResult[list[FlextLdapErrorPattern]]:
        """Get error patterns with optional filtering."""
        try:
            patterns = list(self._error_patterns.values())

            # Apply filters
            if category:
                patterns = [p for p in patterns if p.category == category]

            if severity:
                patterns = [p for p in patterns if p.severity == severity]

            if min_frequency > 1:
                patterns = [p for p in patterns if p.frequency >= min_frequency]

            # Sort by frequency and correlation score
            patterns.sort(
                key=lambda p: (p.frequency, p.correlation_score),
                reverse=True,
            )

            return FlextResult.ok(patterns)

        except (ValueError, TypeError, OSError) as e:
            error_msg = f"Failed to get error patterns: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def get_correlated_errors(
        self,
        event: FlextLdapErrorEvent,
        time_window_minutes: int = 60,
    ) -> FlextResult[list[FlextLdapErrorEvent]]:
        """Get errors correlated with a given event."""
        try:
            cutoff_time = event.timestamp - timedelta(minutes=time_window_minutes)

            # Find events in time window
            correlated_events = [
                e
                for e in self._error_events
                if cutoff_time
                <= e.timestamp
                <= event.timestamp + timedelta(minutes=time_window_minutes)
                and e.event_id != event.event_id
            ]

            # Calculate correlation scores and filter
            significant_correlations = []
            for other_event in correlated_events:
                correlation_score = self._calculate_correlation(event, other_event)
                # Minimal local threshold to avoid hard dependency on nested constants
                threshold = 0.5
                if correlation_score > threshold:
                    significant_correlations.append(other_event)

            return FlextResult.ok(significant_correlations)

        except (ValueError, TypeError, OSError) as e:
            error_msg = f"Failed to get correlated errors: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def get_error_statistics(
        self,
        time_window_hours: int = 24,
    ) -> FlextResult[dict[str, object]]:
        """Get error statistics for the specified time window."""
        try:
            cutoff_time = datetime.now(UTC) - timedelta(hours=time_window_hours)
            recent_events = [
                e for e in self._error_events if e.timestamp >= cutoff_time
            ]

            # Calculate statistics
            total_errors = len(recent_events)

            # Count by category
            category_counts: defaultdict[str, int] = defaultdict(int)
            for event in recent_events:
                category_counts[event.category.value] += 1

            # Count by severity
            severity_counts: defaultdict[str, int] = defaultdict(int)
            for event in recent_events:
                severity_counts[event.severity.value] += 1

            # Top error patterns
            pattern_frequencies = {
                signature: pattern.frequency
                for signature, pattern in self._error_patterns.items()
            }

            top_patterns = sorted(
                pattern_frequencies.items(),
                key=operator.itemgetter(1),
                reverse=True,
            )[:10]

            statistics = {
                "time_window_hours": time_window_hours,
                "total_errors": total_errors,
                "category_distribution": dict(category_counts),
                "severity_distribution": dict(severity_counts),
                "top_error_patterns": top_patterns,
                "pattern_count": len(self._error_patterns),
                "average_errors_per_hour": (
                    total_errors / time_window_hours if time_window_hours > 0 else 0
                ),
            }

            return FlextResult.ok(statistics)

        except (ValueError, TypeError, OSError) as e:
            error_msg = f"Failed to get error statistics: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def _update_patterns(self, event: FlextLdapErrorEvent) -> None:
        """Update error patterns with new event."""
        signature = event.get_signature()

        if signature in self._error_patterns:
            # Update existing pattern
            pattern = self._error_patterns[signature]
            pattern.frequency += 1
            pattern.last_occurrence = event.timestamp

            # Update affected operations
            if (
                event.operation_type
                and event.operation_type not in pattern.affected_operations
            ):
                pattern.affected_operations.append(event.operation_type)

        else:
            # Create new pattern using Parameter Object pattern
            pattern_data = FlextLdapErrorPatternData(
                error_signature=signature,
                category=event.category,
                severity=event.severity,
                frequency=1,
                first_occurrence=event.timestamp,
                last_occurrence=event.timestamp,
                affected_operations=(
                    [event.operation_type] if event.operation_type else []
                ),
            )
            pattern = FlextLdapErrorPattern(pattern_data)
            self._error_patterns[signature] = pattern

    async def _analyze_correlations(self, event: FlextLdapErrorEvent) -> None:
        """Analyze correlations for the new event."""
        # Find recent events for correlation analysis
        cutoff_time = event.timestamp - timedelta(hours=self.correlation_window_hours)
        recent_events = [
            e
            for e in self._error_events
            if e.timestamp >= cutoff_time and e.event_id != event.event_id
        ]

        # Calculate correlations and update pattern scores
        total_correlation = 0.0
        correlation_count = 0

        min_correlation_threshold = 0.5
        for other_event in recent_events:
            correlation = self._calculate_correlation(event, other_event)
            if correlation > min_correlation_threshold:
                total_correlation += correlation
                correlation_count += 1

        # Update pattern correlation score
        signature = event.get_signature()
        if signature in self._error_patterns:
            pattern = self._error_patterns[signature]
            if correlation_count > 0:
                pattern.correlation_score = total_correlation / correlation_count

    def _calculate_correlation(
        self,
        event1: FlextLdapErrorEvent,
        event2: FlextLdapErrorEvent,
    ) -> float:
        """Calculate correlation score between two events."""
        correlation_score = 0.0

        # Time proximity (closer in time = higher correlation)
        time_diff = abs((event1.timestamp - event2.timestamp).total_seconds())
        max_time_diff = self.correlation_window_hours * 3600  # Convert to seconds
        time_correlation = max(0, 1 - (time_diff / max_time_diff))
        correlation_score += time_correlation * 0.3

        # Same category
        if event1.category == event2.category:
            correlation_score += 0.2

        # Same operation type
        if event1.operation_type == event2.operation_type:
            correlation_score += 0.2

        # Same user
        if event1.user_dn == event2.user_dn and event1.user_dn is not None:
            correlation_score += 0.15

        # Same client
        if event1.client_ip == event2.client_ip and event1.client_ip is not None:
            correlation_score += 0.1

        # Same server
        if event1.server_host == event2.server_host and event1.server_host is not None:
            correlation_score += 0.05

        return min(correlation_score, 1.0)

    def clear_history(self) -> None:
        """Clear all error history and patterns."""
        self._error_events.clear()
        self._error_patterns.clear()
        self._correlation_cache.clear()
        logger.info("Error correlation history cleared")


# Backward compatibility aliases
ErrorSeverity = FlextLdapErrorSeverity
ErrorCategory = FlextLdapErrorCategory
ErrorPattern = FlextLdapErrorPattern
ErrorEvent = FlextLdapErrorEvent
ErrorCorrelationService = FlextLdapErrorCorrelationService
