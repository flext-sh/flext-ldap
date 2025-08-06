"""Security Event Logging Infrastructure for LDAP Operations.

This module provides comprehensive security event logging for LDAP operations
with audit trails, event correlation, and security monitoring capabilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum

from flext_core import FlextGenerators, FlextResult, get_logger

from flext_ldap.entities import FlextLdapConnection

logger = get_logger(__name__)


class FlextLdapSecurityEventType(Enum):
    """Security event types for LDAP operations."""

    AUTHENTICATION_SUCCESS = "auth_success"
    AUTHENTICATION_FAILURE = "auth_failure"
    AUTHORIZATION_SUCCESS = "authz_success"
    AUTHORIZATION_FAILURE = "authz_failure"
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_TERMINATED = "connection_terminated"
    SEARCH_OPERATION = "search_operation"
    MODIFY_OPERATION = "modify_operation"
    ADD_OPERATION = "add_operation"
    DELETE_OPERATION = "delete_operation"
    BIND_OPERATION = "bind_operation"
    UNBIND_OPERATION = "unbind_operation"
    SCHEMA_ACCESS = "schema_access"
    CERTIFICATE_VALIDATION = "certificate_validation"
    TLS_NEGOTIATION = "tls_negotiation"
    PASSWORD_CHANGE = "password_change"  # noqa: S105  # nosec B105 - enum constant
    ACCOUNT_LOCKOUT = "account_lockout"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"
    DATA_EXPORT = "data_export"
    BULK_OPERATION = "bulk_operation"


class FlextLdapSecurityEventSeverity(Enum):
    """Security event severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FlextLdapSecurityEventStatus(Enum):
    """Security event status."""

    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"
    INFO = "info"


@dataclass
class FlextLdapSecurityEventData:
    """Data transfer object for security event creation.

    Eliminates the need for 18+ parameters in log_event method.
    Follows Parameter Object pattern for cleaner method signatures.
    """

    event_type: FlextLdapSecurityEventType
    severity: FlextLdapSecurityEventSeverity = FlextLdapSecurityEventSeverity.INFO
    status: FlextLdapSecurityEventStatus = FlextLdapSecurityEventStatus.INFO
    connection: FlextLdapConnection | None = None
    user_dn: str | None = None
    client_ip: str | None = None
    operation_id: str | None = None
    target_dn: str | None = None
    attributes: list[str] | None = field(default_factory=list)
    filter_expression: str | None = None
    result_count: int | None = None
    error_message: str | None = None
    error_code: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    duration_ms: float | None = None
    data_size_bytes: int | None = None
    additional_context: dict[str, object] | None = field(default_factory=dict)

    def to_security_event(self) -> FlextLdapSecurityEvent:
        """Convert to FlextLdapSecurityEvent instance using Parameter Object pattern."""
        return FlextLdapSecurityEvent(data=self)


class FlextLdapSecurityEvent:
    """Security event data structure using Parameter Object pattern."""

    def __init__(self, data: FlextLdapSecurityEventData) -> None:
        """Initialize security event using type-safe Parameter Object pattern.

        Args:
            data: FlextLdapSecurityEventData object (required)

        REFACTORED: Eliminated dual initialization anti-pattern.
        All event creation now uses type-safe FlextLdapSecurityEventData.

        """
        self._init_from_data_object(data)

    def _init_from_data_object(self, data: FlextLdapSecurityEventData) -> None:
        """Initialize from FlextLdapSecurityEventData using Parameter Object pattern."""
        # Extract connection details if available
        server_host = None
        server_port = None
        if data.connection:
            server_host = getattr(data.connection, "host", None)
            server_port = getattr(data.connection, "port", None)

        self.event_id = FlextGenerators.generate_uuid()
        self.event_type = data.event_type
        self.severity = data.severity
        self.status = data.status
        self.timestamp = datetime.now(UTC)
        self.user_dn = data.user_dn
        self.client_ip = data.client_ip
        self.server_host = server_host
        self.server_port = server_port
        self.operation_id = data.operation_id
        self.target_dn = data.target_dn
        self.attributes = data.attributes or []
        self.filter_expression = data.filter_expression
        self.result_count = data.result_count
        self.error_message = data.error_message
        self.error_code = data.error_code
        self.session_id = data.session_id
        self.request_id = data.request_id
        self.duration_ms = data.duration_ms
        self.data_size_bytes = data.data_size_bytes
        self.additional_context = data.additional_context or {}
        self.risk_score: float | None = None  # Not in data object, default
        self.compliance_flags: list[str] = []  # Not in data object, default

    def to_dict(self) -> dict[str, object]:
        """Convert security event to dictionary."""
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type.value if self.event_type else None,
            "severity": self.severity.value,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "user_dn": self.user_dn,
            "client_ip": self.client_ip,
            "server_host": self.server_host,
            "server_port": self.server_port,
            "operation_id": self.operation_id,
            "target_dn": self.target_dn,
            "attributes": self.attributes,
            "filter_expression": self.filter_expression,
            "result_count": self.result_count,
            "error_message": self.error_message,
            "error_code": self.error_code,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "duration_ms": self.duration_ms,
            "data_size_bytes": self.data_size_bytes,
            "additional_context": self.additional_context,
            "risk_score": self.risk_score,
            "compliance_flags": self.compliance_flags,
        }

    def to_json(self) -> str:
        """Convert security event to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class FlextLdapSecurityEventLogger:
    """Security event logger for LDAP operations."""

    def __init__(
        self,
        *,
        enable_audit_trail: bool = True,
        enable_compliance_logging: bool = True,
        enable_risk_scoring: bool = True,
        max_event_history: int = 10000,
    ) -> None:
        """Initialize security event logger.

        Args:
            enable_audit_trail: Enable audit trail logging
            enable_compliance_logging: Enable compliance logging
            enable_risk_scoring: Enable risk scoring
            max_event_history: Maximum events to keep in memory

        """
        self.enable_audit_trail = enable_audit_trail
        self.enable_compliance_logging = enable_compliance_logging
        self.enable_risk_scoring = enable_risk_scoring
        self.max_event_history = max_event_history

        self._event_history: list[FlextLdapSecurityEvent] = []
        self._session_events: dict[str, list[FlextLdapSecurityEvent]] = {}
        self._user_events: dict[str, list[FlextLdapSecurityEvent]] = {}
        self._risk_patterns: dict[str, float] = {}

        logger.info("Security event logger initialized")

    async def log_event(
        self,
        event_data: FlextLdapSecurityEventData,
    ) -> FlextResult[FlextLdapSecurityEvent]:
        """Log a security event using data transfer object.

        Args:
            event_data: Security event data containing all event information

        Returns:
            FlextResult containing the logged security event

        """
        try:
            # Enhance event data with connection details if needed
            if event_data.connection and not event_data.user_dn:
                event_data.user_dn = event_data.connection.bind_dn

            # Create security event using the data transfer object
            event = event_data.to_security_event()

            # Calculate risk score if enabled
            if self.enable_risk_scoring:
                event.risk_score = self._calculate_risk_score(event)

            # Add compliance flags if enabled
            if self.enable_compliance_logging:
                event.compliance_flags = self._get_compliance_flags(event)

            # Store event in history
            self._add_to_history(event)

            # Log event based on severity with proper logging
            event_dict = event.to_dict()
            event_msg: str = f"Security Event: {event_dict}"
            if event_data.severity == FlextLdapSecurityEventSeverity.CRITICAL:
                logger.critical(event_msg)
            elif event_data.severity == FlextLdapSecurityEventSeverity.HIGH:
                logger.error(event_msg)
            elif event_data.severity == FlextLdapSecurityEventSeverity.MEDIUM:
                logger.warning(event_msg)
            elif event_data.severity == FlextLdapSecurityEventSeverity.LOW:
                logger.info(event_msg)
            else:
                logger.debug(event_msg)

            return FlextResult.ok(event)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg: str = f"Failed to log security event: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    # Factory method using Parameter Object pattern for better maintainability
    def _create_event_data_from_params(
        self,
        event_type: FlextLdapSecurityEventType,
        **event_params: object,
    ) -> FlextLdapSecurityEventData:
        """Factory method to create type-safe FlextLdapSecurityEventData.

        Creates from parameters with proper type validation.

        REFACTORED: Eliminates redundant casts and type confusion.
        Uses proper type validation and safe conversion.

        Args:
            event_type: The type of security event (required)
            **event_params: All other event parameters as keyword arguments

        Returns:
            Type-safe FlextLdapSecurityEventData instance

        """

        # Safe type extraction with proper defaults
        def safe_extract_severity(key: str) -> FlextLdapSecurityEventSeverity:
            value = event_params.get(key, FlextLdapSecurityEventSeverity.INFO)
            return (
                value
                if isinstance(value, FlextLdapSecurityEventSeverity)
                else FlextLdapSecurityEventSeverity.INFO
            )

        def safe_extract_status(key: str) -> FlextLdapSecurityEventStatus:
            value = event_params.get(key, FlextLdapSecurityEventStatus.INFO)
            return (
                value
                if isinstance(value, FlextLdapSecurityEventStatus)
                else FlextLdapSecurityEventStatus.INFO
            )

        def safe_extract_string(key: str) -> str | None:
            value = event_params.get(key)
            return str(value) if value is not None else None

        def safe_extract_int(key: str) -> int | None:
            value = event_params.get(key)
            return (
                int(value)
                if isinstance(value, (int, float, str)) and str(value).isdigit()
                else None
            )

        def safe_extract_float(key: str) -> float | None:
            value = event_params.get(key)
            return float(value) if isinstance(value, (int, float, str)) else None

        # Extract connection safely
        connection_value = event_params.get("connection")
        connection = (
            connection_value
            if isinstance(connection_value, FlextLdapConnection)
            else None
        )

        # Extract attributes safely
        attributes_value = event_params.get("attributes")
        attributes = (
            list(attributes_value)
            if isinstance(attributes_value, (list, tuple))
            else None
        )

        # Extract additional context safely
        additional_context_value = event_params.get("additional_context")
        additional_context = (
            dict(additional_context_value)
            if isinstance(additional_context_value, dict)
            else None
        )

        return FlextLdapSecurityEventData(
            event_type=event_type,
            severity=safe_extract_severity("severity"),
            status=safe_extract_status("status"),
            connection=connection,
            user_dn=safe_extract_string("user_dn"),
            client_ip=safe_extract_string("client_ip"),
            operation_id=safe_extract_string("operation_id"),
            target_dn=safe_extract_string("target_dn"),
            attributes=attributes,
            filter_expression=safe_extract_string("filter_expression"),
            result_count=safe_extract_int("result_count"),
            error_message=safe_extract_string("error_message"),
            error_code=safe_extract_string("error_code"),
            session_id=safe_extract_string("session_id"),
            request_id=safe_extract_string("request_id"),
            duration_ms=safe_extract_float("duration_ms"),
            data_size_bytes=safe_extract_int("data_size_bytes"),
            additional_context=additional_context,
        )

    async def log_event_simple(
        self,
        event_type: FlextLdapSecurityEventType,
        **event_params: object,
    ) -> FlextResult[FlextLdapSecurityEvent]:
        """Convenience method for logging security events using flexible parameters.

        REFACTORED: Uses factory method for type-safe parameter conversion.
        Eliminates redundant casts and type confusion.

        Args:
            event_type: The type of security event (required)
            **event_params: All other event parameters as keyword arguments

        Returns:
            FlextResult containing the logged security event

        """
        event_data = self._create_event_data_from_params(event_type, **event_params)
        return await self.log_event(event_data)

    async def log_authentication_event(
        self,
        *,
        success: bool,  # Named-only to eliminate FBT001
        user_dn: str,
        **event_params: object,
    ) -> FlextResult[FlextLdapSecurityEvent]:
        """Log authentication event."""
        event_type = (
            FlextLdapSecurityEventType.AUTHENTICATION_SUCCESS
            if success
            else FlextLdapSecurityEventType.AUTHENTICATION_FAILURE
        )
        severity = (
            FlextLdapSecurityEventSeverity.INFO
            if success
            else FlextLdapSecurityEventSeverity.MEDIUM
        )
        status = (
            FlextLdapSecurityEventStatus.SUCCESS
            if success
            else FlextLdapSecurityEventStatus.FAILURE
        )

        # Use log_event_simple with Parameter Object pattern approach
        return await self.log_event_simple(
            event_type=event_type,
            severity=severity,
            status=status,
            user_dn=user_dn,
            **event_params,  # Pass all additional parameters through
        )

    def _calculate_risk_score(self, event: FlextLdapSecurityEvent) -> float:
        """Calculate risk score for a security event."""
        base_score = 0.0

        # Base score by event type
        event_type_scores = {
            FlextLdapSecurityEventType.AUTHENTICATION_FAILURE: 0.3,
            FlextLdapSecurityEventType.AUTHORIZATION_FAILURE: 0.4,
            FlextLdapSecurityEventType.SECURITY_VIOLATION: 0.8,
            FlextLdapSecurityEventType.SUSPICIOUS_ACTIVITY: 0.7,
            FlextLdapSecurityEventType.PRIVILEGE_ESCALATION: 0.9,
            FlextLdapSecurityEventType.ACCOUNT_LOCKOUT: 0.5,
            FlextLdapSecurityEventType.BULK_OPERATION: 0.3,
            FlextLdapSecurityEventType.DATA_EXPORT: 0.4,
        }

        if event.event_type:
            base_score = event_type_scores.get(event.event_type, 0.1)

        # Adjust based on severity
        severity_multipliers = {
            FlextLdapSecurityEventSeverity.CRITICAL: 1.0,
            FlextLdapSecurityEventSeverity.HIGH: 0.8,
            FlextLdapSecurityEventSeverity.MEDIUM: 0.6,
            FlextLdapSecurityEventSeverity.LOW: 0.4,
            FlextLdapSecurityEventSeverity.INFO: 0.2,
        }

        severity_multiplier = severity_multipliers.get(event.severity, 0.5)
        base_score *= severity_multiplier

        return min(base_score, 1.0)

    def _get_compliance_flags(self, event: FlextLdapSecurityEvent) -> list[str]:
        """Get compliance flags for a security event."""
        flags = []

        # PCI DSS flags
        if event.event_type in {
            FlextLdapSecurityEventType.AUTHENTICATION_FAILURE,
            FlextLdapSecurityEventType.AUTHORIZATION_FAILURE,
        }:
            flags.append("PCI_DSS_8.2")

        # GDPR flags
        if event.event_type == FlextLdapSecurityEventType.DATA_EXPORT:
            flags.append("GDPR_ARTICLE_32")

        return flags

    def _add_to_history(self, event: FlextLdapSecurityEvent) -> None:
        """Add event to history with size management."""
        # Add to general history
        self._event_history.append(event)
        if len(self._event_history) > self.max_event_history:
            self._event_history.pop(0)

        # Add to session history
        if event.session_id:
            if event.session_id not in self._session_events:
                self._session_events[event.session_id] = []
            self._session_events[event.session_id].append(event)

        # Add to user history
        if event.user_dn:
            if event.user_dn not in self._user_events:
                self._user_events[event.user_dn] = []
            self._user_events[event.user_dn].append(event)

    async def get_security_metrics(
        self,
        time_window_hours: int = 24,
    ) -> FlextResult[dict[str, object]]:
        """Get security metrics for the specified time window."""
        try:
            cutoff_time = datetime.now(UTC) - timedelta(hours=time_window_hours)
            recent_events = [
                e for e in self._event_history if e.timestamp >= cutoff_time
            ]

            # Calculate metrics
            total_events = len(recent_events)
            auth_failures = len(
                [
                    e
                    for e in recent_events
                    if e.event_type == FlextLdapSecurityEventType.AUTHENTICATION_FAILURE
                ],
            )

            # Calculate unique users and sessions
            unique_users = len({e.user_dn for e in recent_events if e.user_dn})
            unique_sessions = len({e.session_id for e in recent_events if e.session_id})

            metrics: dict[str, object] = {
                "time_window_hours": time_window_hours,
                "total_events": total_events,
                "authentication_failures": auth_failures,
                "unique_users": unique_users,
                "unique_sessions": unique_sessions,
            }

            return FlextResult.ok(metrics)

        except (RuntimeError, ValueError, TypeError) as e:
            error_msg: str = f"Failed to get security metrics: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)


# Backward compatibility aliases
SecurityEventType = FlextLdapSecurityEventType
SecurityEventSeverity = FlextLdapSecurityEventSeverity
SecurityEventStatus = FlextLdapSecurityEventStatus
SecurityEvent = FlextLdapSecurityEvent
SecurityEventLogger = FlextLdapSecurityEventLogger
