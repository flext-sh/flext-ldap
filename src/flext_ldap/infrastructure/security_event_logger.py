"""Security Event Logging Infrastructure for LDAP Operations.

This module provides comprehensive security event logging for LDAP operations
with audit trails, event correlation, and security monitoring capabilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import uuid4

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root imports
from flext_core import FlextResult, get_logger

if TYPE_CHECKING:
    from uuid import UUID

    from flext_ldap.domain.entities import FlextLdapConnection

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
    PASSWORD_CHANGE = "password_change"  # noqa: S105
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


class FlextLdapSecurityEvent:
    """Security event data structure."""

    def __init__(
        self,
        event_id: UUID | None = None,
        event_type: FlextLdapSecurityEventType | None = None,
        severity: FlextLdapSecurityEventSeverity = FlextLdapSecurityEventSeverity.INFO,
        status: FlextLdapSecurityEventStatus = FlextLdapSecurityEventStatus.INFO,
        timestamp: datetime | None = None,
        user_dn: str | None = None,
        client_ip: str | None = None,
        server_host: str | None = None,
        server_port: int | None = None,
        operation_id: str | None = None,
        target_dn: str | None = None,
        attributes: list[str] | None = None,
        filter_expression: str | None = None,
        result_count: int | None = None,
        error_message: str | None = None,
        error_code: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        duration_ms: float | None = None,
        data_size_bytes: int | None = None,
        additional_context: dict[str, Any] | None = None,
        risk_score: float | None = None,
        compliance_flags: list[str] | None = None,
    ) -> None:
        """Initialize security event."""
        self.event_id = event_id or uuid4()
        self.event_type = event_type
        self.severity = severity
        self.status = status
        self.timestamp = timestamp or datetime.now(UTC)
        self.user_dn = user_dn
        self.client_ip = client_ip
        self.server_host = server_host
        self.server_port = server_port
        self.operation_id = operation_id
        self.target_dn = target_dn
        self.attributes = attributes or []
        self.filter_expression = filter_expression
        self.result_count = result_count
        self.error_message = error_message
        self.error_code = error_code
        self.session_id = session_id
        self.request_id = request_id
        self.duration_ms = duration_ms
        self.data_size_bytes = data_size_bytes
        self.additional_context = additional_context or {}
        self.risk_score = risk_score
        self.compliance_flags = compliance_flags or []

    def to_dict(self) -> dict[str, Any]:
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
        event_type: FlextLdapSecurityEventType,
        severity: FlextLdapSecurityEventSeverity = FlextLdapSecurityEventSeverity.INFO,
        status: FlextLdapSecurityEventStatus = FlextLdapSecurityEventStatus.INFO,
        connection: FlextLdapConnection | None = None,
        user_dn: str | None = None,
        client_ip: str | None = None,
        operation_id: str | None = None,
        target_dn: str | None = None,
        attributes: list[str] | None = None,
        filter_expression: str | None = None,
        result_count: int | None = None,
        error_message: str | None = None,
        error_code: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        duration_ms: float | None = None,
        data_size_bytes: int | None = None,
        additional_context: dict[str, Any] | None = None,
    ) -> FlextResult[FlextLdapSecurityEvent]:
        """Log a security event.

        Args:
            event_type: Type of security event
            severity: Event severity level
            status: Event status
            connection: LDAP connection (optional)
            user_dn: User DN performing the operation
            client_ip: Client IP address
            operation_id: Operation identifier
            target_dn: Target DN for the operation
            attributes: Attributes involved in the operation
            filter_expression: Search filter used
            result_count: Number of results returned
            error_message: Error message if any
            error_code: Error code if any
            session_id: Session identifier
            request_id: Request identifier
            duration_ms: Operation duration in milliseconds
            data_size_bytes: Size of data processed
            additional_context: Additional context information

        Returns:
            FlextResult containing the logged security event

        """
        try:
            # Extract connection information if provided
            server_host = None
            server_port = None
            if connection:
                # Parse server_url to extract host and port
                server_url = connection.server_url
                if "://" in server_url:
                    # Extract host and port from URL like ldap://host:port
                    protocol_part, host_part = server_url.split("://", 1)
                    if ":" in host_part:
                        server_host, port_str = host_part.split(":", 1)
                        try:
                            server_port = int(port_str)
                        except ValueError:
                            server_port = 389  # Default LDAP port
                    else:
                        server_host = host_part
                        server_port = 636 if protocol_part == "ldaps" else 389
                else:
                    server_host = server_url
                    server_port = 389

                if not user_dn:
                    user_dn = connection.bind_dn

            # Create security event
            event = FlextLdapSecurityEvent(
                event_type=event_type,
                severity=severity,
                status=status,
                user_dn=user_dn,
                client_ip=client_ip,
                server_host=server_host,
                server_port=server_port,
                operation_id=operation_id,
                target_dn=target_dn,
                attributes=attributes,
                filter_expression=filter_expression,
                result_count=result_count,
                error_message=error_message,
                error_code=error_code,
                session_id=session_id,
                request_id=request_id,
                duration_ms=duration_ms,
                data_size_bytes=data_size_bytes,
                additional_context=additional_context,
            )

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
            event_msg = f"Security Event: {event_dict}"
            if severity == FlextLdapSecurityEventSeverity.CRITICAL:
                logger.critical(event_msg)
            elif severity == FlextLdapSecurityEventSeverity.HIGH:
                logger.error(event_msg)
            elif severity == FlextLdapSecurityEventSeverity.MEDIUM:
                logger.warning(event_msg)
            elif severity == FlextLdapSecurityEventSeverity.LOW:
                logger.info(event_msg)
            else:
                logger.debug(event_msg)

            return FlextResult.ok(event)

        except Exception as e:
            error_msg = f"Failed to log security event: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def log_authentication_event(
        self,
        *,
        success: bool,
        user_dn: str,
        client_ip: str | None = None,
        connection: FlextLdapConnection | None = None,
        error_message: str | None = None,
        session_id: str | None = None,
        additional_context: dict[str, Any] | None = None,
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

        return await self.log_event(
            event_type=event_type,
            severity=severity,
            status=status,
            connection=connection,
            user_dn=user_dn,
            client_ip=client_ip,
            error_message=error_message,
            session_id=session_id,
            additional_context=additional_context,
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
    ) -> FlextResult[dict[str, Any]]:
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

            metrics = {
                "time_window_hours": time_window_hours,
                "total_events": total_events,
                "authentication_failures": auth_failures,
                "unique_users": unique_users,
                "unique_sessions": unique_sessions,
            }

            return FlextResult.ok(metrics)

        except Exception as e:
            error_msg = f"Failed to get security metrics: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)


# Backward compatibility aliases
SecurityEventType = FlextLdapSecurityEventType
SecurityEventSeverity = FlextLdapSecurityEventSeverity
SecurityEventStatus = FlextLdapSecurityEventStatus
SecurityEvent = FlextLdapSecurityEvent
SecurityEventLogger = FlextLdapSecurityEventLogger
