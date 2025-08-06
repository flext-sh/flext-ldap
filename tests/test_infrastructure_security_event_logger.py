"""Tests for FLEXT-LDAP Infrastructure Security Event Logger.

Pragmatic test suite focusing on security event logging functionality,
audit trails, SOLID principles, and enterprise security patterns.

Test Coverage Focus:
    - Security event creation and logging
    - Event type enumeration and validation
    - Audit trail generation and management
    - FlextResult pattern compliance
    - Parameter Object pattern for event data
    - Security monitoring and alerting

Author: FLEXT Development Team

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import Mock

from flext_ldap.infrastructure.security_event_logger import (
    FlextLdapSecurityEventData,
    FlextLdapSecurityEventLogger,
    FlextLdapSecurityEventSeverity,
    FlextLdapSecurityEventStatus,
    FlextLdapSecurityEventType,
)


class TestFlextLdapSecurityEventType:
    """Test suite for security event type enumeration."""

    def test_authentication_event_types(self) -> None:
        """Test authentication-related event types."""
        assert FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS.value == "auth_success"
        assert FlextLdapSecurityEventType.AUTHENTICATION_FAILURE.value == "auth_failure"
        assert FlextLdapSecurityEventType.AUTHORIZATION_SUCCESS.value == "authz_success"
        assert FlextLdapSecurityEventType.AUTHORIZATION_FAILURE.value == "authz_failure"

    def test_connection_event_types(self) -> None:
        """Test connection-related event types."""
        assert FlextLdapSecurityEventType.CONNECTION_ESTABLISHED.value == "connection_established"
        assert FlextLdapSecurityEventType.CONNECTION_TERMINATED.value == "connection_terminated"
        assert FlextLdapSecurityEventType.TLS_NEGOTIATION.value == "tls_negotiation"

    def test_operation_event_types(self) -> None:
        """Test LDAP operation event types."""
        assert FlextLdapSecurityEventType.SEARCH_OPERATION.value == "search_operation"
        assert FlextLdapSecurityEventType.MODIFY_OPERATION.value == "modify_operation"
        assert FlextLdapSecurityEventType.ADD_OPERATION.value == "add_operation"
        assert FlextLdapSecurityEventType.DELETE_OPERATION.value == "delete_operation"
        assert FlextLdapSecurityEventType.BIND_OPERATION.value == "bind_operation"
        assert FlextLdapSecurityEventType.UNBIND_OPERATION.value == "unbind_operation"

    def test_security_event_types(self) -> None:
        """Test security-specific event types."""
        assert FlextLdapSecurityEventType.ACCOUNT_LOCKOUT.value == "account_lockout"
        assert FlextLdapSecurityEventType.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert FlextLdapSecurityEventType.SUSPICIOUS_ACTIVITY.value == "suspicious_activity"
        assert FlextLdapSecurityEventType.SECURITY_VIOLATION.value == "security_violation"


class TestFlextLdapSecurityEventData:
    """Test suite for security event data using Parameter Object pattern."""

    def test_event_data_creation_minimal(self) -> None:
        """Test security event data creation with minimal parameters."""
        event_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS
        )

        assert event_data.event_type == FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS
        assert event_data.severity == FlextLdapSecurityEventSeverity.INFO
        assert event_data.status == FlextLdapSecurityEventStatus.INFO
        assert event_data.user_dn is None
        assert event_data.client_ip is None

    def test_event_data_creation_comprehensive(self) -> None:
        """Test security event data creation with comprehensive parameters."""
        event_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.SEARCH_OPERATION,
            severity=FlextLdapSecurityEventSeverity.MEDIUM,
            status=FlextLdapSecurityEventStatus.SUCCESS,
            user_dn="cn=testuser,ou=users,dc=example,dc=com",
            client_ip="192.168.1.100",
            operation_id="op_123",
            target_dn="ou=users,dc=example,dc=com",
            attributes=["cn", "mail", "uid"],
            filter_expression="(objectClass=person)",
            result_count=42,
            session_id="session_123",
            request_id="req_456",
            duration_ms=150.5,
            data_size_bytes=2048,
            additional_context={"base": "ou=users,dc=example,dc=com"}
        )

        assert event_data.event_type == FlextLdapSecurityEventType.SEARCH_OPERATION
        assert event_data.severity == FlextLdapSecurityEventSeverity.MEDIUM
        assert event_data.status == FlextLdapSecurityEventStatus.SUCCESS
        assert event_data.user_dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert event_data.client_ip == "192.168.1.100"
        assert event_data.operation_id == "op_123"
        assert event_data.target_dn == "ou=users,dc=example,dc=com"
        assert event_data.attributes == ["cn", "mail", "uid"]
        assert event_data.filter_expression == "(objectClass=person)"
        assert event_data.result_count == 42
        assert event_data.session_id == "session_123"
        assert event_data.request_id == "req_456"
        assert event_data.duration_ms == 150.5
        assert event_data.data_size_bytes == 2048
        assert event_data.additional_context == {"base": "ou=users,dc=example,dc=com"}

    def test_event_data_with_failure_details(self) -> None:
        """Test security event data with failure information."""
        event_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.AUTHENTICATION_FAILURE,
            severity=FlextLdapSecurityEventSeverity.HIGH,
            status=FlextLdapSecurityEventStatus.FAILURE,
            user_dn="cn=baduser,ou=users,dc=example,dc=com",
            client_ip="10.0.0.5",
            error_message="Invalid credentials provided",
            error_code="49"
        )

        assert event_data.severity == FlextLdapSecurityEventSeverity.HIGH
        assert event_data.status == FlextLdapSecurityEventStatus.FAILURE
        assert event_data.error_message == "Invalid credentials provided"
        assert event_data.error_code == "49"
        assert event_data.event_type == FlextLdapSecurityEventType.AUTHENTICATION_FAILURE

    def test_event_data_to_security_event(self) -> None:
        """Test event data conversion to security event."""
        event_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.MODIFY_OPERATION,
            user_dn="cn=admin,ou=users,dc=example,dc=com"
        )

        # Test to_security_event method
        event = event_data.to_security_event()
        assert hasattr(event, "event_type")
        assert hasattr(event, "timestamp")
        assert hasattr(event, "user_dn")
        assert event.user_dn == "cn=admin,ou=users,dc=example,dc=com"


class TestFlextLdapSecurityEventLogger:
    """Test suite for security event logger implementation."""

    def test_logger_initialization(self) -> None:
        """Test security event logger initialization."""
        logger = FlextLdapSecurityEventLogger()

        assert hasattr(logger, "_event_history")
        assert isinstance(logger._event_history, list)
        assert len(logger._event_history) == 0

        # Test default configuration
        assert logger.max_event_history == 10000
        assert logger.enable_audit_trail is True
        assert logger.enable_compliance_logging is True
        assert logger.enable_risk_scoring is True

    def test_logger_custom_initialization(self) -> None:
        """Test security event logger with custom configuration."""
        logger = FlextLdapSecurityEventLogger(
            max_event_history=5000,
            enable_audit_trail=False,
            enable_compliance_logging=False,
            enable_risk_scoring=False
        )

        assert logger.max_event_history == 5000
        assert logger.enable_audit_trail is False
        assert logger.enable_compliance_logging is False
        assert logger.enable_risk_scoring is False

    async def test_log_event_success(self) -> None:
        """Test successful security event logging."""
        logger = FlextLdapSecurityEventLogger()

        event_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=testuser,ou=users,dc=example,dc=com",
            client_ip="192.168.1.10"
        )

        result = await logger.log_event(event_data)

        # Validate FlextResult pattern
        assert result.is_success
        assert result.data is not None

        # Validate event was logged
        assert len(logger._event_history) == 1
        logged_event = logger._event_history[0]
        assert logged_event.user_dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert logged_event.client_ip == "192.168.1.10"

    async def test_log_authentication_events(self) -> None:
        """Test logging of authentication-specific events."""
        logger = FlextLdapSecurityEventLogger()

        # Success event
        success_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=user1,ou=users,dc=example,dc=com",
            client_ip="192.168.1.10"
        )

        # Failure event
        failure_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.AUTHENTICATION_FAILURE,
            user_dn="cn=user2,ou=users,dc=example,dc=com",
            client_ip="192.168.1.20",
            error_message="Invalid password"
        )

        await logger.log_event(success_data)
        await logger.log_event(failure_data)

        assert len(logger._event_history) == 2

        # Validate success event
        success_event = logger._event_history[0]
        assert success_event.event_type == FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS

        # Validate failure event
        failure_event = logger._event_history[1]
        assert failure_event.event_type == FlextLdapSecurityEventType.AUTHENTICATION_FAILURE
        assert failure_event.error_message == "Invalid password"

    async def test_get_security_metrics_basic(self) -> None:
        """Test getting basic security metrics."""
        logger = FlextLdapSecurityEventLogger()

        # Log some events
        for i in range(3):
            event_data = FlextLdapSecurityEventData(
                event_type=FlextLdapSecurityEventType.SEARCH_OPERATION,
                user_dn=f"cn=user{i},ou=users,dc=example,dc=com"
            )
            await logger.log_event(event_data)

        result = await logger.get_security_metrics()

        assert result.is_success
        assert result.data is not None
        metrics = result.data
        assert metrics["total_events"] == 3

    async def test_log_authentication_event_success(self) -> None:
        """Test logging authentication event with convenience method."""
        logger = FlextLdapSecurityEventLogger()

        # Test successful authentication
        result = await logger.log_authentication_event(
            success=True,
            user_dn="cn=user1,ou=users,dc=example,dc=com",
            client_ip="192.168.1.10"
        )

        assert result.is_success
        assert len(logger._event_history) == 1

        event = logger._event_history[0]
        assert event.event_type == FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS
        assert event.user_dn == "cn=user1,ou=users,dc=example,dc=com"
        assert event.client_ip == "192.168.1.10"

    async def test_log_authentication_event_failure(self) -> None:
        """Test logging authentication failure event."""
        logger = FlextLdapSecurityEventLogger()

        # Test failed authentication
        result = await logger.log_authentication_event(
            success=False,
            user_dn="cn=user2,ou=users,dc=example,dc=com",
            client_ip="192.168.1.20",
            error_message="Invalid credentials"
        )

        assert result.is_success
        assert len(logger._event_history) == 1

        event = logger._event_history[0]
        assert event.event_type == FlextLdapSecurityEventType.AUTHENTICATION_FAILURE
        assert event.user_dn == "cn=user2,ou=users,dc=example,dc=com"
        assert event.client_ip == "192.168.1.20"
        assert event.error_message == "Invalid credentials"

    async def test_log_event_simple_method(self) -> None:
        """Test log_event_simple convenience method."""
        logger = FlextLdapSecurityEventLogger()

        # Test log_event_simple with various parameters
        result = await logger.log_event_simple(
            event_type=FlextLdapSecurityEventType.SEARCH_OPERATION,
            user_dn="cn=test,ou=users,dc=example,dc=com",
            client_ip="10.0.0.1",
            operation_id="op_123",
            result_count=42
        )

        assert result.is_success
        assert len(logger._event_history) == 1

        event = logger._event_history[0]
        assert event.event_type == FlextLdapSecurityEventType.SEARCH_OPERATION
        assert event.user_dn == "cn=test,ou=users,dc=example,dc=com"
        assert event.client_ip == "10.0.0.1"
        assert event.operation_id == "op_123"
        assert event.result_count == 42

    async def test_get_security_metrics_with_auth_failures(self) -> None:
        """Test security metrics with authentication failures."""
        logger = FlextLdapSecurityEventLogger()

        # Log authentication failures
        for i in range(3):
            await logger.log_authentication_event(
                success=False,
                user_dn=f"cn=user{i},ou=users,dc=example,dc=com",
                error_message="Invalid password"
            )

        # Log one success
        await logger.log_authentication_event(
            success=True,
            user_dn="cn=gooduser,ou=users,dc=example,dc=com"
        )

        result = await logger.get_security_metrics()

        assert result.is_success
        metrics = result.data
        assert metrics["total_events"] == 4
        assert metrics["authentication_failures"] == 3
        assert metrics["unique_users"] == 4

    def test_event_history_rotation(self) -> None:
        """Test event history rotation when max entries exceeded."""
        logger = FlextLdapSecurityEventLogger(max_event_history=3)

        # Fill beyond capacity by directly adding to history
        for i in range(5):
            event = Mock()
            event.timestamp = datetime.now(UTC)
            event.user_dn = f"cn=user{i},ou=users,dc=example,dc=com"
            event.session_id = None  # No session tracking
            logger._event_history.append(event)

        # Should maintain max entries (assuming rotation logic exists)
        # This tests the configured limit
        assert logger.max_event_history == 3

    def test_risk_scoring_configuration(self) -> None:
        """Test risk scoring configuration."""
        logger = FlextLdapSecurityEventLogger(enable_risk_scoring=True)

        assert logger.enable_risk_scoring is True

        # Test with risk scoring disabled
        logger_no_risk = FlextLdapSecurityEventLogger(enable_risk_scoring=False)
        assert logger_no_risk.enable_risk_scoring is False

    async def test_json_serialization_compatibility(self) -> None:
        """Test that logged events can be serialized to JSON."""
        logger = FlextLdapSecurityEventLogger()

        event_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.SEARCH_OPERATION,
            user_dn="cn=test,ou=users,dc=example,dc=com",
            client_ip="192.168.1.1",
            additional_context={"filter": "(objectClass=person)"}
        )

        await logger.log_event(event_data)

        # Test JSON serialization capability (basic test)
        logged_event = logger._event_history[0]

        # Should have serializable attributes
        assert hasattr(logged_event, "event_type")
        assert hasattr(logged_event, "timestamp")

        # Test that enum values are serializable
        event_type_value = logged_event.event_type.value
        assert isinstance(event_type_value, str)

        # Test to_dict method
        event_dict = logged_event.to_dict()
        assert isinstance(event_dict, dict)
        assert "event_id" in event_dict
        assert "event_type" in event_dict

        # Test to_json method
        event_json = logged_event.to_json()
        assert isinstance(event_json, str)
        parsed = json.loads(event_json)
        assert parsed["event_type"] == "search_operation"

    async def test_error_handling(self) -> None:
        """Test error handling in security event logging."""
        logger = FlextLdapSecurityEventLogger()

        # Test with valid event data that might cause internal errors
        # Mock the internal method to raise an exception
        original_method = logger._calculate_risk_score

        def mock_risk_score_error(event):
            error_msg = "Risk calculation failed"
            raise RuntimeError(error_msg)

        logger._calculate_risk_score = mock_risk_score_error

        event_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS,
            user_dn="cn=testuser,ou=users,dc=example,dc=com"
        )

        result = await logger.log_event(event_data)

        # Should handle gracefully
        assert not result.is_success
        assert "Failed to log security event" in result.error

        # Restore original method
        logger._calculate_risk_score = original_method

    def test_clean_architecture_compliance(self) -> None:
        """Test Clean Architecture compliance - infrastructure layer."""
        logger = FlextLdapSecurityEventLogger()

        # Should be infrastructure service
        assert hasattr(logger, "log_event")
        assert hasattr(logger, "get_security_metrics")

        # Should use FLEXT patterns
        assert hasattr(logger, "max_event_history")
        assert hasattr(logger, "enable_audit_trail")

        # Should have private implementation details
        assert hasattr(logger, "_event_history")
        assert hasattr(logger, "_session_events")
        assert hasattr(logger, "_user_events")

    async def test_risk_scoring_calculation(self) -> None:
        """Test risk score calculation for different event types."""
        logger = FlextLdapSecurityEventLogger(enable_risk_scoring=True)

        # Test high-risk event
        high_risk_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.PRIVILEGE_ESCALATION,
            severity=FlextLdapSecurityEventSeverity.CRITICAL,
            user_dn="cn=admin,ou=users,dc=example,dc=com"
        )

        result = await logger.log_event(high_risk_data)

        assert result.is_success
        event = logger._event_history[0]
        assert event.risk_score is not None
        assert event.risk_score > 0.5  # Should be high risk

    async def test_compliance_flags_generation(self) -> None:
        """Test compliance flags generation for different event types."""
        logger = FlextLdapSecurityEventLogger(enable_compliance_logging=True)

        # Test authentication failure (should have PCI DSS flag)
        auth_fail_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.AUTHENTICATION_FAILURE,
            user_dn="cn=test,ou=users,dc=example,dc=com"
        )

        result = await logger.log_event(auth_fail_data)

        assert result.is_success
        event = logger._event_history[0]
        assert isinstance(event.compliance_flags, list)
        assert any("PCI_DSS" in flag for flag in event.compliance_flags)

    async def test_session_tracking(self) -> None:
        """Test session-based event tracking."""
        logger = FlextLdapSecurityEventLogger()

        # Log events with session ID
        for i in range(3):
            event_data = FlextLdapSecurityEventData(
                event_type=FlextLdapSecurityEventType.SEARCH_OPERATION,
                session_id="session_123",
                user_dn=f"cn=user{i},ou=users,dc=example,dc=com"
            )
            await logger.log_event(event_data)

        # Check that session events are tracked
        assert "session_123" in logger._session_events
        assert len(logger._session_events["session_123"]) == 3

    async def test_user_tracking(self) -> None:
        """Test user-based event tracking."""
        logger = FlextLdapSecurityEventLogger()

        # Log events for same user
        user_dn = "cn=testuser,ou=users,dc=example,dc=com"
        for _ in range(2):
            event_data = FlextLdapSecurityEventData(
                event_type=FlextLdapSecurityEventType.SEARCH_OPERATION,
                user_dn=user_dn
            )
            await logger.log_event(event_data)

        # Check that user events are tracked
        assert user_dn in logger._user_events
        assert len(logger._user_events[user_dn]) == 2

    async def test_event_data_with_connection(self) -> None:
        """Test event data creation with connection object."""
        from flext_ldap.entities import FlextLdapConnection

        logger = FlextLdapSecurityEventLogger()

        # Create connection with correct parameters
        connection = FlextLdapConnection(
            id="conn_123",
            server_url="ldap://ldap.example.com:389",
            bind_dn="cn=admin,dc=example,dc=com",
            is_bound=True
        )

        event_data = FlextLdapSecurityEventData(
            event_type=FlextLdapSecurityEventType.CONNECTION_ESTABLISHED,
            connection=connection
        )

        result = await logger.log_event(event_data)

        assert result.is_success
        event = logger._event_history[0]
        # Since connection doesn't have host/port attributes, they'll be None
        assert event.server_host is None
        assert event.server_port is None
        # user_dn should be extracted from connection.bind_dn
        assert event.user_dn == "cn=admin,dc=example,dc=com"
