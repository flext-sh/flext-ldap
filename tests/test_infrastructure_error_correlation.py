"""Tests for FLEXT-LDAP Infrastructure Error Correlation Service.

Pragmatic test suite focusing on core functionality and coverage improvement.
Following SOLID principles and real API validation without over-engineering.

Test Coverage Focus:
    - Core service initialization and functionality
    - Error recording with Parameter Object pattern
    - Error pattern detection and analysis
    - FlextResult pattern compliance
    - Edge cases and error handling

Author: FLEXT Development Team

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from flext_ldap.infrastructure.error_correlation import (
    FlextLdapErrorCategory,
    FlextLdapErrorCorrelationService,
    FlextLdapErrorEvent,
    FlextLdapErrorEventData,
    FlextLdapErrorPattern,
    FlextLdapErrorPatternData,
    FlextLdapErrorSeverity,
)


class TestFlextLdapErrorCorrelationServiceCore:
    """Core test suite focusing on essential functionality."""

    def test_service_initialization(self) -> None:
        """Test service initialization with default parameters."""
        service = FlextLdapErrorCorrelationService()

        # Validate default configuration
        assert service.max_events == 10000
        assert service.correlation_window_hours == 24
        assert service.pattern_threshold == 3

        # Validate empty state
        assert len(service._error_events) == 0
        assert len(service._error_patterns) == 0
        assert len(service._correlation_cache) == 0

    def test_service_custom_initialization(self) -> None:
        """Test service initialization with custom parameters."""
        service = FlextLdapErrorCorrelationService(
            max_events=5000,
            correlation_window_hours=12,
            pattern_threshold=5
        )

        assert service.max_events == 5000
        assert service.correlation_window_hours == 12
        assert service.pattern_threshold == 5

    async def test_record_error_basic(self) -> None:
        """Test basic error recording functionality."""
        service = FlextLdapErrorCorrelationService()

        # Use Parameter Object pattern correctly
        event_data = FlextLdapErrorEventData(
            error_message="Test error",
            operation_type="search"
        )

        result = await service.record_error(event_data)

        # Validate FlextResult pattern
        assert result.is_success
        assert len(service._error_events) == 1

        # Validate recorded event
        recorded_event = service._error_events[0]
        assert recorded_event.error_message == "Test error"
        assert recorded_event.operation_type == "search"

    async def test_record_error_simple(self) -> None:
        """Test simplified error recording method."""
        service = FlextLdapErrorCorrelationService()

        result = await service.record_error_simple(
            error_message="Simple error",
            category=FlextLdapErrorCategory.AUTHENTICATION,
            severity=FlextLdapErrorSeverity.HIGH
        )

        assert result.is_success
        assert len(service._error_events) == 1

        recorded_event = service._error_events[0]
        assert recorded_event.error_message == "Simple error"
        assert recorded_event.category == FlextLdapErrorCategory.AUTHENTICATION
        assert recorded_event.severity == FlextLdapErrorSeverity.HIGH

    async def test_get_error_patterns_empty(self) -> None:
        """Test getting error patterns when none exist."""
        service = FlextLdapErrorCorrelationService()

        result = await service.get_error_patterns()

        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, list)
        assert len(result.data) == 0

    async def test_get_error_patterns_with_filtering(self) -> None:
        """Test error patterns with category filtering."""
        service = FlextLdapErrorCorrelationService()

        # Record errors of different categories
        await service.record_error_simple(
            error_message="Connection failed",
            category=FlextLdapErrorCategory.CONNECTION
        )
        await service.record_error_simple(
            error_message="Auth failed",
            category=FlextLdapErrorCategory.AUTHENTICATION
        )

        # Test filtering by category
        result = await service.get_error_patterns(
            category=FlextLdapErrorCategory.CONNECTION
        )

        assert result.is_success
        assert result.data is not None

    async def test_get_correlated_errors_basic(self) -> None:
        """Test getting correlated errors."""
        service = FlextLdapErrorCorrelationService()

        # Record an event
        event_data = FlextLdapErrorEventData(
            error_message="Test error",
            operation_type="search"
        )
        await service.record_error(event_data)

        # Get the recorded event for correlation
        recorded_event = service._error_events[0]

        result = await service.get_correlated_errors(recorded_event)

        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, list)

    async def test_get_error_statistics_basic(self) -> None:
        """Test basic error statistics."""
        service = FlextLdapErrorCorrelationService()

        result = await service.get_error_statistics()

        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, dict)
        stats = result.data
        assert "total_errors" in stats
        assert stats["total_errors"] == 0

    async def test_get_error_statistics_with_data(self) -> None:
        """Test error statistics with recorded data."""
        service = FlextLdapErrorCorrelationService()

        # Record some errors
        await service.record_error_simple(
            error_message="Connection error",
            category=FlextLdapErrorCategory.CONNECTION,
            severity=FlextLdapErrorSeverity.HIGH
        )
        await service.record_error_simple(
            error_message="Auth error",
            category=FlextLdapErrorCategory.AUTHENTICATION,
            severity=FlextLdapErrorSeverity.CRITICAL
        )

        result = await service.get_error_statistics()

        assert result.is_success
        assert result.data is not None
        stats = result.data
        assert stats["total_errors"] == 2
        assert "category_distribution" in stats
        assert "severity_distribution" in stats

    def test_error_event_creation_parameter_object(self) -> None:
        """Test error event creation using Parameter Object pattern."""
        timestamp = datetime.now(UTC)
        context = {"host": "ldap.example.com", "port": 389}

        # Test Parameter Object pattern - SOLID principle
        event_data = FlextLdapErrorEventData(
            error_message="Connection timeout",
            operation_type="connect",
            category=FlextLdapErrorCategory.CONNECTION,
            severity=FlextLdapErrorSeverity.HIGH,
            timestamp=timestamp,
            context=context
        )
        event = FlextLdapErrorEvent(event_data)

        assert event.error_message == "Connection timeout"
        assert event.operation_type == "connect"
        assert event.category == FlextLdapErrorCategory.CONNECTION
        assert event.severity == FlextLdapErrorSeverity.HIGH
        assert event.timestamp == timestamp
        assert event.context == context
        assert event.event_id is not None

    def test_error_pattern_creation_parameter_object(self) -> None:
        """Test error pattern creation using Parameter Object pattern."""
        first_occurrence = datetime.now(UTC) - timedelta(hours=2)
        last_occurrence = datetime.now(UTC)

        # Test Parameter Object pattern for reducing complexity
        pattern_data = FlextLdapErrorPatternData(
            error_signature="auth_failure_signature",
            category=FlextLdapErrorCategory.AUTHENTICATION,
            severity=FlextLdapErrorSeverity.HIGH,
            frequency=3,
            first_occurrence=first_occurrence,
            last_occurrence=last_occurrence,
            affected_operations=["bind", "search"],
            context_patterns={"common_host": "ldap.example.com"},
            correlation_score=0.85
        )
        pattern = FlextLdapErrorPattern(pattern_data)

        assert pattern.error_signature == "auth_failure_signature"
        assert pattern.category == FlextLdapErrorCategory.AUTHENTICATION
        assert pattern.frequency == 3
        assert pattern.correlation_score == 0.85

    def test_error_event_factory_method(self) -> None:
        """Test error event factory method."""
        event = FlextLdapErrorEvent.create(
            error_message="Test error",
            category=FlextLdapErrorCategory.SEARCH,
            severity=FlextLdapErrorSeverity.MEDIUM
        )

        assert event.error_message == "Test error"
        assert event.category == FlextLdapErrorCategory.SEARCH
        assert event.severity == FlextLdapErrorSeverity.MEDIUM
        assert event.event_id is not None

    def test_error_pattern_factory_method(self) -> None:
        """Test error pattern factory method."""
        pattern = FlextLdapErrorPattern.create(
            error_signature="timeout_signature",
            category=FlextLdapErrorCategory.TIMEOUT,
            severity=FlextLdapErrorSeverity.HIGH
        )

        assert pattern.error_signature == "timeout_signature"
        assert pattern.category == FlextLdapErrorCategory.TIMEOUT
        assert pattern.severity == FlextLdapErrorSeverity.HIGH

    def test_error_severity_enum(self) -> None:
        """Test error severity enumeration."""
        assert FlextLdapErrorSeverity.CRITICAL.value == "critical"
        assert FlextLdapErrorSeverity.HIGH.value == "high"
        assert FlextLdapErrorSeverity.MEDIUM.value == "medium"
        assert FlextLdapErrorSeverity.LOW.value == "low"
        assert FlextLdapErrorSeverity.INFO.value == "info"

    def test_error_category_enum(self) -> None:
        """Test error category enumeration."""
        assert FlextLdapErrorCategory.CONNECTION.value == "connection"
        assert FlextLdapErrorCategory.AUTHENTICATION.value == "authentication"
        assert FlextLdapErrorCategory.SEARCH.value == "search"
        assert FlextLdapErrorCategory.TIMEOUT.value == "timeout"
        assert FlextLdapErrorCategory.UNKNOWN.value == "unknown"

    def test_correlation_calculation(self) -> None:
        """Test correlation calculation between events."""
        service = FlextLdapErrorCorrelationService()

        event1 = FlextLdapErrorEvent.create(
            error_message="Connection error"
        )
        event2 = FlextLdapErrorEvent.create(
            error_message="Connection timeout"
        )

        correlation = service._calculate_correlation(event1, event2)

        assert isinstance(correlation, (int, float))
        assert 0.0 <= correlation <= 1.0

    def test_clear_history(self) -> None:
        """Test clearing error history."""
        service = FlextLdapErrorCorrelationService()

        # Add test data
        service._error_events.append(Mock())
        service._error_patterns["test"] = Mock()
        service._correlation_cache["test"] = [Mock()]

        # Clear history
        service.clear_history()

        # Validate cleared state
        assert len(service._error_events) == 0
        assert len(service._error_patterns) == 0
        assert len(service._correlation_cache) == 0

    async def test_memory_management(self) -> None:
        """Test memory management with max events limit."""
        service = FlextLdapErrorCorrelationService(max_events=3)

        # Record more errors than limit
        for i in range(5):
            await service.record_error_simple(
                error_message=f"Error {i}"
            )

        # Should maintain memory limits
        assert len(service._error_events) <= service.max_events
        assert len(service._error_events) == 3

    def test_serialization(self) -> None:
        """Test serialization capabilities."""
        # Test event serialization
        event = FlextLdapErrorEvent.create(
            error_message="Test error",
            category=FlextLdapErrorCategory.SEARCH
        )
        event_dict = event.to_dict()

        assert isinstance(event_dict, dict)
        assert "event_id" in event_dict
        assert "error_message" in event_dict
        assert "category" in event_dict

        # Test pattern serialization
        pattern = FlextLdapErrorPattern.create(
            error_signature="test_signature",
            category=FlextLdapErrorCategory.CONNECTION
        )
        pattern_dict = pattern.to_dict()

        assert isinstance(pattern_dict, dict)
        assert "pattern_id" in pattern_dict
        assert "error_signature" in pattern_dict
        assert "category" in pattern_dict

    async def test_edge_cases(self) -> None:
        """Test edge cases and error handling."""
        service = FlextLdapErrorCorrelationService()

        # Test with empty error message
        event_data = FlextLdapErrorEventData(
            error_message="",
            operation_type="search"
        )
        result = await service.record_error(event_data)

        # Service should handle gracefully
        assert result.is_success

        # Test statistics still work
        stats_result = await service.get_error_statistics()
        assert stats_result.is_success

    def test_signature_generation(self) -> None:
        """Test error signature generation for pattern matching."""
        event = FlextLdapErrorEvent.create(
            error_message="Connection timeout after 30 seconds"
        )

        signature = event.get_signature()

        assert isinstance(signature, str)
        assert len(signature) > 0

        # Signature should be consistent
        signature2 = event.get_signature()
        assert signature == signature2
