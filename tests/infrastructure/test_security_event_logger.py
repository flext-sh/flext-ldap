"""Tests for Security Event Logger Infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Constants
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3

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

        if event.event_type != SecurityEventType.AUTHENTICATION_SUCCESS:
            msg = f"Expected {SecurityEventType.AUTHENTICATION_SUCCESS}, got {event.event_type}"
            raise AssertionError(msg)
        assert event.user_dn == "cn=test,dc=example,dc=com"
        if event.severity != SecurityEventSeverity.INFO:
            msg = f"Expected {SecurityEventSeverity.INFO}, got {event.severity}"
            raise AssertionError(msg)
        assert event.status == SecurityEventStatus.INFO
        if event.attributes != []:
            msg = f"Expected {[]}, got {event.attributes}"
            raise AssertionError(msg)
        assert event.additional_context == {}
        if event.compliance_flags != []:
            msg = f"Expected {[]}, got {event.compliance_flags}"
            raise AssertionError(msg)
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

        if event_dict["event_type"] != "search_operation":
            msg = f"Expected {'search_operation'}, got {event_dict['event_type']}"
            raise AssertionError(msg)
        assert event_dict["severity"] == "high"
        if event_dict["status"] != "success":
            msg = f"Expected {'success'}, got {event_dict['status']}"
            raise AssertionError(msg)
        assert event_dict["timestamp"] == timestamp.isoformat()
        if event_dict["user_dn"] != "cn=test,dc=example,dc=com":
            msg = f"Expected {'cn=test,dc=example,dc=com'}, got {event_dict['user_dn']}"
            raise AssertionError(msg)
        assert event_dict["target_dn"] == "ou=users,dc=example,dc=com"
        if event_dict["attributes"] != ["cn", "mail"]:
            msg = f"Expected {['cn', 'mail']}, got {event_dict['attributes']}"
            raise AssertionError(msg)
        assert event_dict["filter_expression"] == "(objectClass=person)"

    def test_security_event_to_json(self) -> None:
        """Test SecurityEvent to_json conversion."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_FAILURE,
            user_dn="cn=test,dc=example,dc=com",
        )

        json_str = event.to_json()

        assert isinstance(json_str, str)
        if "auth_failure" not in json_str:
            msg = f"Expected {'auth_failure'} in {json_str}"
            raise AssertionError(msg)
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
        connection.bind_dn = "cn=admin,dc=example,dc=com"
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
        if len(event_logger._event_history) != 1:
            msg = f"Expected {1}, got {len(event_logger._event_history)}"
            raise AssertionError(msg)
        logged_event = event_logger._event_history[0]
        if logged_event.event_type != event.event_type:
            msg = f"Expected {event.event_type}, got {logged_event.event_type}"
            raise AssertionError(msg)
        assert logged_event.severity == event.severity
        if logged_event.status != event.status:
            msg = f"Expected {event.status}, got {logged_event.status}"
            raise AssertionError(msg)

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
        if len(event_logger._event_history) != 1:
            msg = f"Expected {1}, got {len(event_logger._event_history)}"
            raise AssertionError(msg)

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
        mock_connection.bind_dn = "cn=admin,dc=test"
        result = await event_logger.log_authentication_event(
            user_dn="cn=test,dc=example,dc=com",
            success=True,
            connection=mock_connection,
            session_id="session123",
        )

        assert result.is_success
        if len(event_logger._event_history) != 1:
            msg = f"Expected {1}, got {len(event_logger._event_history)}"
            raise AssertionError(msg)
        event = event_logger._event_history[0]
        if event.event_type != SecurityEventType.AUTHENTICATION_SUCCESS:
            msg = f"Expected {SecurityEventType.AUTHENTICATION_SUCCESS}, got {event.event_type}"
            raise AssertionError(msg)
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
        if len(event_logger._event_history) != 1:
            msg = f"Expected {1}, got {len(event_logger._event_history)}"
            raise AssertionError(msg)
        event = event_logger._event_history[0]
        if event.event_type != SecurityEventType.AUTHENTICATION_FAILURE:
            msg = f"Expected {SecurityEventType.AUTHENTICATION_FAILURE}, got {event.event_type}"
            raise AssertionError(msg)
        assert event.severity == SecurityEventSeverity.MEDIUM

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

        if risk_score < 0:
            msg = f"Expected {risk_score} >= {0}"
            raise AssertionError(msg)
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
        if "PCI_DSS_8.2" not in flags:
            msg = f"Expected {'PCI_DSS_8.2'} in {flags}"
            raise AssertionError(msg)

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
        if "GDPR_ARTICLE_32" not in flags:
            msg = f"Expected {'GDPR_ARTICLE_32'} in {flags}"
            raise AssertionError(msg)

    def test_add_to_history_management(self, event_logger: SecurityEventLogger) -> None:
        """Test adding event to management history."""
        event = SecurityEvent(
            event_type=SecurityEventType.SEARCH_OPERATION,
            user_dn="cn=admin,dc=example,dc=com",
        )

        event_logger._add_to_history(event)

        if len(event_logger._event_history) != 1:
            msg = f"Expected {1}, got {len(event_logger._event_history)}"
            raise AssertionError(msg)
        logged_event = event_logger._event_history[0]
        if logged_event.event_type != event.event_type:
            msg = f"Expected {event.event_type}, got {logged_event.event_type}"
            raise AssertionError(msg)
        assert logged_event.severity == event.severity
        if logged_event.status != event.status:
            msg = f"Expected {event.status}, got {logged_event.status}"
            raise AssertionError(msg)

    def test_add_to_session_history(self, event_logger: SecurityEventLogger) -> None:
        """Test adding event to session history."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=test,dc=example,dc=com",
            session_id="session123",
        )

        event_logger._add_to_history(event)

        assert event_logger._session_events is not None
        if "session123" not in event_logger._session_events:
            msg = f"Expected {'session123'} in {event_logger._session_events}"
            raise AssertionError(msg)
        if len(event_logger._session_events["session123"]) != 1:
            msg = f"Expected {1}, got {len(event_logger._session_events['session123'])}"
            raise AssertionError(msg)
        assert event_logger._session_events["session123"][0] == event

    def test_add_to_user_history(self, event_logger: SecurityEventLogger) -> None:
        """Test adding event to user history."""
        event = SecurityEvent(
            event_type=SecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=test,dc=example,dc=com",
        )

        event_logger._add_to_history(event)

        assert event_logger._user_events is not None
        if "cn=test,dc=example,dc=com" not in event_logger._user_events:
            msg = (
                f"Expected {'cn=test,dc=example,dc=com'} in {event_logger._user_events}"
            )
            raise AssertionError(msg)
        if len(event_logger._user_events["cn=test,dc=example,dc=com"]) != 1:
            msg = f"Expected {1}, got {len(event_logger._user_events['cn=test,dc=example,dc=com'])}"
            raise AssertionError(msg)

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

        if metrics["total_events"] != EXPECTED_DATA_COUNT:
            msg = f"Expected {3}, got {metrics['total_events']}"
            raise AssertionError(msg)
        assert metrics["authentication_failures"] == 1
        if metrics["unique_users"] != EXPECTED_BULK_SIZE:
            msg = f"Expected {2}, got {metrics['unique_users']}"
            raise AssertionError(msg)
        assert metrics["unique_sessions"] == EXPECTED_BULK_SIZE
        if metrics["time_window_hours"] != 24:
            msg = f"Expected {24}, got {metrics['time_window_hours']}"
            raise AssertionError(msg)

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
        assert metrics is not None
        if metrics["total_events"] != 1:
            msg = f"Expected {1}, got {metrics['total_events']}"
            raise AssertionError(msg)
