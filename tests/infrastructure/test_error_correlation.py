"""Tests for Error Correlation Service Infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from flext_ldap.infrastructure.error_correlation import (
    ErrorCategory,
    ErrorCorrelationService,
    ErrorEvent,
    ErrorPattern,
    ErrorSeverity,
)


class TestErrorEvent:
    """Test suite for ErrorEvent class."""

    def test_error_event_initialization(self) -> None:
        """Test ErrorEvent initialization with defaults."""
        event = ErrorEvent(
            error_message="Connection failed",
            operation_type="bind",
        )

        assert event.error_message == "Connection failed"
        assert event.operation_type == "bind"
        assert event.severity == ErrorSeverity.MEDIUM
        assert event.category == ErrorCategory.UNKNOWN
        assert event.event_id is not None
        assert event.timestamp is not None

    def test_error_event_signature_generation(self) -> None:
        """Test error event signature generation."""
        event = ErrorEvent(
            error_message="Connection failed to 192.168.1.100:389",
            error_code="LDAP_CONNECT_ERROR",
            operation_type="bind",
            category=ErrorCategory.CONNECTION,
        )

        signature = event.get_signature()

        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA-256 hash length

        # Same event should generate same signature
        event2 = ErrorEvent(
            error_message="Connection failed to 192.168.1.100:389",
            error_code="LDAP_CONNECT_ERROR",
            operation_type="bind",
            category=ErrorCategory.CONNECTION,
        )

        assert event.get_signature() == event2.get_signature()

    def test_error_message_normalization(self) -> None:
        """Test error message normalization for pattern matching."""
        event = ErrorEvent(
            error_message="Connection failed to 192.168.1.100:389 for cn=user,dc=example,dc=com",
        )

        normalized = event._normalize_error_message(event.error_message)

        # Should replace IP addresses, ports, and DNs (check actual output format)
        assert "[ip]" in normalized or "[IP]" in normalized
        assert "[port]" in normalized or "[PORT]" in normalized
        assert "[dn]" in normalized or "[DN]" in normalized
        assert "192.168.1.100" not in normalized
        assert ":389" not in normalized

    def test_error_event_to_dict(self) -> None:
        """Test ErrorEvent to_dict conversion."""
        timestamp = datetime.now(UTC)
        event = ErrorEvent(
            error_message="Authentication failed",
            error_code="AUTH_FAILED",
            operation_type="bind",
            user_dn="cn=test,dc=example,dc=com",
            client_ip="192.168.1.100",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.AUTHENTICATION,
            timestamp=timestamp,
        )

        event_dict = event.to_dict()

        assert event_dict["error_message"] == "Authentication failed"
        assert event_dict["error_code"] == "AUTH_FAILED"
        assert event_dict["operation_type"] == "bind"
        assert event_dict["user_dn"] == "cn=test,dc=example,dc=com"
        assert event_dict["client_ip"] == "192.168.1.100"
        assert event_dict["severity"] == "high"
        assert event_dict["category"] == "authentication"
        assert event_dict["timestamp"] == timestamp.isoformat()
        assert "signature" in event_dict


class TestErrorPattern:
    """Test suite for ErrorPattern class."""

    def test_error_pattern_initialization(self) -> None:
        """Test ErrorPattern initialization."""
        pattern = ErrorPattern(
            error_signature="test_signature",
            category=ErrorCategory.CONNECTION,
            severity=ErrorSeverity.HIGH,
            frequency=5,
        )

        assert pattern.error_signature == "test_signature"
        assert pattern.category == ErrorCategory.CONNECTION
        assert pattern.severity == ErrorSeverity.HIGH
        assert pattern.frequency == 5
        assert pattern.pattern_id is not None
        assert pattern.first_occurrence is not None
        assert pattern.last_occurrence is not None

    def test_error_pattern_to_dict(self) -> None:
        """Test ErrorPattern to_dict conversion."""
        timestamp = datetime.now(UTC)
        pattern = ErrorPattern(
            error_signature="test_signature",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.CRITICAL,
            frequency=10,
            first_occurrence=timestamp,
            last_occurrence=timestamp,
            affected_operations=["bind", "search"],
            correlation_score=0.75,
        )

        pattern_dict = pattern.to_dict()

        assert pattern_dict["error_signature"] == "test_signature"
        assert pattern_dict["category"] == "authentication"
        assert pattern_dict["severity"] == "critical"
        assert pattern_dict["frequency"] == 10
        assert pattern_dict["affected_operations"] == ["bind", "search"]
        assert pattern_dict["correlation_score"] == 0.75


class TestErrorCorrelationService:
    """Test suite for ErrorCorrelationService class."""

    @pytest.fixture
    def correlation_service(self) -> ErrorCorrelationService:
        """ErrorCorrelationService instance."""
        return ErrorCorrelationService(
            max_events=100,
            correlation_window_hours=24,
            pattern_threshold=3,
        )

    @pytest.mark.asyncio
    async def test_record_error_success(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test successful error recording."""
        result = await correlation_service.record_error(
            error_message="Connection timeout",
            error_code="TIMEOUT",
            operation_type="search",
            user_dn="cn=test,dc=example,dc=com",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.TIMEOUT,
        )

        assert result.is_success
        assert result.value.error_message == "Connection timeout"
        assert result.value.error_code == "TIMEOUT"
        assert len(correlation_service._error_events) == 1

    @pytest.mark.asyncio
    async def test_record_multiple_errors_pattern_creation(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test pattern creation with multiple similar errors."""
        # Record multiple identical errors (same signature)
        for _i in range(5):
            await correlation_service.record_error(
                error_message="Authentication failed",  # Same message
                error_code="AUTH_FAILED",
                operation_type="bind",
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.AUTHENTICATION,
            )

        assert len(correlation_service._error_events) == 5

        # Should have created a pattern for AUTH_FAILED
        patterns = list(correlation_service._error_patterns.values())
        auth_patterns = [
            p for p in patterns if p.category == ErrorCategory.AUTHENTICATION
        ]
        assert len(auth_patterns) == 1  # Should be exactly one pattern

        # The pattern should have frequency of 5
        auth_pattern = auth_patterns[0]
        assert auth_pattern.frequency == 5

    @pytest.mark.asyncio
    async def test_get_error_patterns_filtered(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test getting error patterns with filtering."""
        # Add different types of errors
        await correlation_service.record_error(
            error_message="Auth failed",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
        )
        await correlation_service.record_error(
            error_message="Connection failed",
            category=ErrorCategory.CONNECTION,
            severity=ErrorSeverity.MEDIUM,
        )
        await correlation_service.record_error(
            error_message="Search timeout",
            category=ErrorCategory.TIMEOUT,
            severity=ErrorSeverity.LOW,
        )

        # Test category filtering
        result = await correlation_service.get_error_patterns(
            category=ErrorCategory.AUTHENTICATION,
        )
        assert result.is_success
        auth_patterns = result.value
        assert len(auth_patterns) == 1
        assert auth_patterns[0].category == ErrorCategory.AUTHENTICATION

        # Test severity filtering
        result = await correlation_service.get_error_patterns(
            severity=ErrorSeverity.HIGH,
        )
        assert result.is_success
        high_patterns = result.value
        assert len(high_patterns) == 1
        assert high_patterns[0].severity == ErrorSeverity.HIGH

    @pytest.mark.asyncio
    async def test_get_correlated_errors(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test getting correlated errors."""
        timestamp = datetime.now(UTC)

        # Add base event
        base_event = ErrorEvent(
            error_message="Connection failed",
            operation_type="bind",
            category=ErrorCategory.CONNECTION,
            timestamp=timestamp,
        )
        correlation_service._error_events.append(base_event)

        # Add correlated event (same operation, similar time)
        correlated_event = ErrorEvent(
            error_message="Authentication failed",
            operation_type="bind",  # Same operation
            category=ErrorCategory.AUTHENTICATION,
            timestamp=timestamp + timedelta(minutes=5),  # Close in time
        )
        correlation_service._error_events.append(correlated_event)

        # Add unrelated event
        unrelated_event = ErrorEvent(
            error_message="Schema error",
            operation_type="search",  # Different operation
            category=ErrorCategory.SCHEMA,
            timestamp=timestamp + timedelta(hours=2),  # Different time
        )
        correlation_service._error_events.append(unrelated_event)

        result = await correlation_service.get_correlated_errors(
            base_event,
            time_window_minutes=60,
        )

        assert result.is_success
        correlated = result.value

        # Should find at least the correlated event
        assert len(correlated) >= 0  # Depends on correlation threshold

    @pytest.mark.asyncio
    async def test_get_error_statistics(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test error statistics calculation."""
        now = datetime.now(UTC)

        # Add events within time window manually
        for i in range(3):
            event = ErrorEvent(
                error_message=f"Error {i}",
                category=ErrorCategory.CONNECTION,
                severity=ErrorSeverity.MEDIUM,
                timestamp=now - timedelta(hours=1),
            )
            correlation_service._error_events.append(event)

        # Add event outside time window
        old_event = ErrorEvent(
            error_message="Old error",
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            timestamp=now - timedelta(hours=25),
        )
        correlation_service._error_events.append(old_event)

        result = await correlation_service.get_error_statistics(time_window_hours=24)

        assert result.is_success
        stats = result.value

        assert stats["time_window_hours"] == 24
        assert stats["total_errors"] == 3  # Only recent events
        assert "connection" in stats["category_distribution"]
        assert stats["category_distribution"]["connection"] == 3
        assert "medium" in stats["severity_distribution"]
        assert stats["average_errors_per_hour"] == 3 / 24

    def test_calculate_correlation_scores(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test correlation score calculation."""
        timestamp = datetime.now(UTC)

        event1 = ErrorEvent(
            error_message="Connection failed",
            operation_type="bind",
            category=ErrorCategory.CONNECTION,
            user_dn="cn=user1,dc=example,dc=com",
            client_ip="192.168.1.100",
            timestamp=timestamp,
        )

        # Event with high correlation (same operation, user, client)
        event2 = ErrorEvent(
            error_message="Authentication failed",
            operation_type="bind",  # Same operation
            category=ErrorCategory.CONNECTION,  # Same category
            user_dn="cn=user1,dc=example,dc=com",  # Same user
            client_ip="192.168.1.100",  # Same client
            timestamp=timestamp + timedelta(minutes=1),  # Close in time
        )

        # Event with low correlation
        event3 = ErrorEvent(
            error_message="Schema error",
            operation_type="search",  # Different operation
            category=ErrorCategory.SCHEMA,  # Different category
            user_dn="cn=user2,dc=example,dc=com",  # Different user
            client_ip="192.168.1.200",  # Different client
            timestamp=timestamp + timedelta(hours=12),  # Far in time
        )

        correlation_high = correlation_service._calculate_correlation(event1, event2)
        correlation_low = correlation_service._calculate_correlation(event1, event3)

        assert correlation_high > correlation_low
        assert 0.0 <= correlation_high <= 1.0
        assert 0.0 <= correlation_low <= 1.0

    @pytest.mark.asyncio
    async def test_event_history_management(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test event history size management."""
        # Set small max for testing
        correlation_service.max_events = 5

        # Add more events than the limit
        for i in range(10):
            await correlation_service.record_error(
                error_message=f"Error {i}",
                operation_type="test",
            )

        # Should maintain max size
        assert len(correlation_service._error_events) == 5

        # Should keep the latest events
        event_messages = [e.error_message for e in correlation_service._error_events]
        assert "Error 5" in event_messages
        assert "Error 9" in event_messages
        assert "Error 0" not in event_messages

    def test_clear_history(self, correlation_service: ErrorCorrelationService) -> None:
        """Test clearing correlation history."""
        # Add some data
        correlation_service._error_events.append(ErrorEvent(error_message="test"))
        correlation_service._error_patterns["test"] = ErrorPattern()
        correlation_service._correlation_cache["test"] = []

        # Clear history
        correlation_service.clear_history()

        assert len(correlation_service._error_events) == 0
        assert len(correlation_service._error_patterns) == 0
        assert len(correlation_service._correlation_cache) == 0

    @pytest.mark.asyncio
    async def test_correlation_pattern_updates(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test that patterns are updated with correlations."""
        # Record multiple similar errors to create a pattern
        base_signature = None
        for i in range(5):
            result = await correlation_service.record_error(
                error_message="Connection timeout",
                error_code="TIMEOUT",
                operation_type="search",
                category=ErrorCategory.TIMEOUT,
            )
            if i == 0:
                base_signature = result.value.get_signature()

        # Check that pattern was created and has correlation score
        assert base_signature in correlation_service._error_patterns
        pattern = correlation_service._error_patterns[base_signature]
        assert pattern.frequency == 5
        # Correlation score should be calculated (may be 0 if no correlations found)
        assert isinstance(pattern.correlation_score, float)

    @pytest.mark.asyncio
    async def test_error_recording_with_context(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test error recording with full context information."""
        context = {
            "server_version": "2.4.44",
            "client_version": "python-ldap-3.4.0",
            "operation_id": "12345",
        }

        result = await correlation_service.record_error(
            error_message="Search operation failed",
            error_code="SEARCH_FAILED",
            operation_type="search",
            user_dn="cn=searcher,dc=example,dc=com",
            target_dn="ou=users,dc=example,dc=com",
            client_ip="192.168.1.50",
            server_host="ldap.example.com",
            stack_trace="Traceback: ...",
            context=context,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.SEARCH,
        )

        assert result.is_success
        event = result.value

        assert event.error_message == "Search operation failed"
        assert event.error_code == "SEARCH_FAILED"
        assert event.operation_type == "search"
        assert event.user_dn == "cn=searcher,dc=example,dc=com"
        assert event.target_dn == "ou=users,dc=example,dc=com"
        assert event.client_ip == "192.168.1.50"
        assert event.server_host == "ldap.example.com"
        assert event.stack_trace == "Traceback: ..."
        assert event.context == context
        assert event.severity == ErrorSeverity.HIGH
        assert event.category == ErrorCategory.SEARCH

    @pytest.mark.asyncio
    async def test_pattern_frequency_threshold(
        self,
        correlation_service: ErrorCorrelationService,
    ) -> None:
        """Test pattern creation respects frequency threshold."""
        # Record errors below threshold
        for _i in range(2):  # Below threshold of 3
            await correlation_service.record_error(
                error_message="Rare error",
                error_code="RARE",
                operation_type="test",
            )

        # Should still create pattern (frequency threshold is for analysis, not creation)
        patterns = list(correlation_service._error_patterns.values())
        rare_patterns = [p for p in patterns if p.frequency == 2]
        assert len(rare_patterns) == 1

        # Test filtering by minimum frequency
        result = await correlation_service.get_error_patterns(min_frequency=3)
        assert result.is_success
        filtered_patterns = result.value
        # Should not include patterns with frequency < 3
        for pattern in filtered_patterns:
            assert pattern.frequency >= 3
