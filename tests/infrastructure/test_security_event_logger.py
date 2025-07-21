"""Tests for Security Event Logger Infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from flext_ldap.infrastructure.security_event_logger import (
    SecurityEvent,
    SecurityEventLogger,
    SecurityEventSeverity,
    SecurityEventStatus,
    SecurityEventType,
)


class TestSecurityEvent:
    """Test suite for SecurityEvent class."""

    def test_security_event_initialization(self) -> None:
        """Test SecurityEvent initialization with defaults."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=test,dc=example,dc=com",
        )

        assert event.event_type == SecurityEventType.AUTHENTICATION_SUCCESS
        assert event.user_dn == "cn=test,dc=example,dc=com"
        assert event.severity == SecurityEventSeverity.INFO
        assert event.status == SecurityEventStatus.INFO
        assert event.attributes == []
        assert event.additional_context == {}
        assert event.compliance_flags == []
        assert event.event_id is not None
        assert event.timestamp is not None

    def test_security_event_to_dict(self) -> None:
        """Test SecurityEvent to_dict conversion."""
        timestamp = datetime.now(UTC)
        event = SecurityEvent(
            event_type=SecurityEventType.SEARCH_OPERATION,
            severity=SecurityEventSeverity.HIGH,
            status=SecurityEventStatus.SUCCESS,
            timestamp=timestamp,
            user_dn="cn=test,dc=example,dc=com",
            target_dn="ou=users,dc=example,dc=com",
            attributes=["cn", "mail"],
            filter_expression="(objectClass=person)",
        )

        event_dict = event.to_dict()

        assert event_dict["event_type"] == "search_operation"
        assert event_dict["severity"] == "high"
        assert event_dict["status"] == "success"
        assert event_dict["timestamp"] == timestamp.isoformat()
        assert event_dict["user_dn"] == "cn=test,dc=example,dc=com"
        assert event_dict["target_dn"] == "ou=users,dc=example,dc=com"
        assert event_dict["attributes"] == ["cn", "mail"]
        assert event_dict["filter_expression"] == "(objectClass=person)"

    def test_security_event_to_json(self) -> None:
        """Test SecurityEvent to_json conversion."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_FAILURE,
            user_dn="cn=test,dc=example,dc=com",
        )

        json_str = event.to_json()

        assert isinstance(json_str, str)
        assert "auth_failure" in json_str
        assert "cn=test,dc=example,dc=com" in json_str


class TestSecurityEventLogger:
    """Test suite for SecurityEventLogger class."""

    @pytest.fixture
    def event_logger(self) -> SecurityEventLogger:
        """SecurityEventLogger instance."""
        return SecurityEventLogger(
            enable_audit_trail=True,
            enable_compliance_logging=True,
            enable_risk_scoring=True,
            max_event_history=100,
        )

    @pytest.fixture
    def mock_connection(self) -> MagicMock:
        """Mock LDAP connection."""
        connection = MagicMock()
        connection.server_url = "ldaps://ldap.example.com:636"
        connection.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        return connection

    @pytest.mark.asyncio
    async def test_log_event_success(self, event_logger: SecurityEventLogger) -> None:
        """Test successful event logging."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=test,dc=example,dc=com",
        )

        assert event.event_type is not None
        result = await event_logger.log_event(event.event_type)

        assert result.is_success
        assert len(event_logger._event_history) == 1
        assert event_logger._event_history[0] == event

    @pytest.mark.asyncio
    async def test_log_event_with_connection(
        self,
        event_logger: SecurityEventLogger,
        mock_connection: MagicMock,
    ) -> None:
        """Test event logging with connection context."""
        event = SecurityEvent(
            event_type=SecurityEventType.SEARCH_OPERATION,
            user_dn="cn=test,dc=example,dc=com",
            target_dn="ou=users,dc=example,dc=com",
        )

        assert event.event_type is not None
        result = await event_logger.log_event(
            event.event_type,
            connection=mock_connection,
        )

        assert result.is_success
        assert len(event_logger._event_history) == 1

    @pytest.mark.asyncio
    async def test_log_authentication_event_success(
        self,
        event_logger: SecurityEventLogger,
    ) -> None:
        """Test successful authentication event logging."""
        assert event_logger is not None
        # Create mock connection for the test
        mock_connection = MagicMock()
        mock_connection.server_url = "ldap://test.com"
        mock_connection.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test"
        result = await event_logger.log_authentication_event(
            user_dn="cn=test,dc=example,dc=com",
            success=True,
            connection=mock_connection,
            session_id="session123",
        )

        assert result.is_success
        assert len(event_logger._event_history) == 1
        event = event_logger._event_history[0]
        assert event.event_type == SecurityEventType.AUTHENTICATION_SUCCESS
        assert event.user_dn == "cn=test,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_log_authentication_event_failure(
        self,
        event_logger: SecurityEventLogger,
    ) -> None:
        """Test failed authentication event logging."""
        assert event_logger is not None
        # Create mock connection for the test
        mock_connection = MagicMock()
        mock_connection.id = "test-connection-id"
        mock_connection.server_url = "ldap://test.com"
        result = await event_logger.log_authentication_event(
            user_dn="cn=test,dc=example,dc=com",
            success=False,
            error_message="Invalid credentials",
            connection=mock_connection,
            session_id="session123",
        )

        assert result.is_success
        assert len(event_logger._event_history) == 1
        event = event_logger._event_history[0]
        assert event.event_type == SecurityEventType.AUTHENTICATION_FAILURE
        assert event.severity == SecurityEventSeverity.HIGH

    def test_calculate_risk_score_auth_failure(
        self,
        event_logger: SecurityEventLogger,
    ) -> None:
        """Test risk score calculation for authentication failure."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_FAILURE,
            user_dn="cn=test,dc=example,dc=com",
        )

        risk_score = event_logger._calculate_risk_score(event)

        assert risk_score > 0
        assert risk_score <= 100

    def test_calculate_risk_score_info_event(
        self,
        event_logger: SecurityEventLogger,
    ) -> None:
        """Test risk score calculation for info event."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=test,dc=example,dc=com",
        )

        risk_score = event_logger._calculate_risk_score(event)

        assert risk_score >= 0
        assert risk_score <= 100

    def test_get_compliance_flags_auth_failure(
        self,
        event_logger: SecurityEventLogger,
    ) -> None:
        """Test compliance flags for authentication failure."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_FAILURE,
            user_dn="cn=test,dc=example,dc=com",
        )

        flags = event_logger._get_compliance_flags(event)

        assert len(flags) > 0
        assert "SOX" in flags or "GDPR" in flags

    def test_get_compliance_flags_data_export(
        self,
        event_logger: SecurityEventLogger,
    ) -> None:
        """Test compliance flags for data export event."""
        event = SecurityEvent(
            event_type=SecurityEventType.DATA_EXPORT,
            user_dn="cn=test,dc=example,dc=com",
        )

        flags = event_logger._get_compliance_flags(event)

        assert len(flags) > 0
        assert "GDPR" in flags

    def test_add_to_history_management(self, event_logger: SecurityEventLogger) -> None:
        """Test adding event to management history."""
        event = SecurityEvent(
            event_type=SecurityEventType.SEARCH_OPERATION,
            user_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        )

        event_logger._add_to_history(event)

        assert len(event_logger._event_history) == 1
        assert event_logger._event_history[0] == event

    def test_add_to_session_history(self, event_logger: SecurityEventLogger) -> None:
        """Test adding event to session history."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=test,dc=example,dc=com",
            session_id="session123",
        )

        event_logger._add_to_history(event)

        assert event_logger._session_events is not None
        assert "session123" in event_logger._session_events
        assert len(event_logger._session_events["session123"]) == 1
        assert event_logger._session_events["session123"][0] == event

    def test_add_to_user_history(self, event_logger: SecurityEventLogger) -> None:
        """Test adding event to user history."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=test,dc=example,dc=com",
        )

        event_logger._add_to_history(event)

        assert event_logger._user_events is not None
        assert "cn=test,dc=example,dc=com" in event_logger._user_events
        assert len(event_logger._user_events["cn=test,dc=example,dc=com"]) == 1

    @pytest.mark.asyncio
    async def test_get_security_metrics(
        self,
        event_logger: SecurityEventLogger,
    ) -> None:
        """Test security metrics calculation."""
        # Add some test events
        events = [
            SecurityEvent(
                event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
                user_dn="cn=user1,dc=example,dc=com",
                session_id="session_1",
                timestamp=datetime.now(UTC),
            ),
            SecurityEvent(
                event_type=SecurityEventType.AUTHENTICATION_FAILURE,
                user_dn="cn=user2,dc=example,dc=com",
                session_id="session_2",
                timestamp=datetime.now(UTC),
            ),
            SecurityEvent(
                event_type=SecurityEventType.SEARCH_OPERATION,
                user_dn="cn=user1,dc=example,dc=com",
                session_id="session_1",
                timestamp=datetime.now(UTC),
            ),
        ]

        for event in events:
            event_logger._add_to_history(event)

        result = await event_logger.get_security_metrics(time_window_hours=24)

        assert result.is_success
        assert result.data is not None
        metrics = result.data

        assert metrics["total_events"] == 3
        assert metrics["authentication_failures"] == 1
        assert metrics["unique_users"] == 2
        assert metrics["unique_sessions"] == 2
        assert metrics["time_window_hours"] == 24

    @pytest.mark.asyncio
    async def test_get_security_metrics_time_filter(
        self,
        event_logger: SecurityEventLogger,
    ) -> None:
        """Test security metrics with time filtering."""
        # Add old event (beyond time window)
        old_event = SecurityEvent(
            event_type=SecurityEventType.SEARCH_OPERATION,
            timestamp=datetime.now(UTC) - timedelta(hours=25),
        )
        event_logger._add_to_history(old_event)

        # Add recent event
        recent_event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            timestamp=datetime.now(UTC),
        )
        event_logger._add_to_history(recent_event)

        result = await event_logger.get_security_metrics(time_window_hours=24)

        assert result.is_success
        metrics = result.data

        # Should only count recent event
        assert metrics["total_events"] == 1
