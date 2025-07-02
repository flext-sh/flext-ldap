"""Base LDAP Protocol Classes.

This module provides base classes for LDAP protocol implementations with
enterprise-grade connection management, authentication frameworks, and
protocol abstraction patterns.

Base classes include:
    - LDAPProtocol: Abstract base for protocol implementations
    - ProtocolConnection: Base connection manager
    - ProtocolAuthentication: Authentication framework
    - ProtocolTransport: Transport layer abstraction

These base classes provide consistent interfaces for different LDAP protocols
while enabling protocol-specific optimizations and features.

Architecture:
    - LDAPProtocol: Core protocol interface and lifecycle management
    - ProtocolConnection: Connection state and operation coordination
    - ProtocolAuthentication: Authentication method abstraction
    - ProtocolTransport: Network/transport layer abstraction

Usage Example:
    >>> from ldap_core_shared.protocols.base import LDAPProtocol
    >>>
    >>> class CustomProtocol(LDAPProtocol):
    ...     protocol_name = "custom"
    ...
    ...     async def connect(self, url: str, **kwargs: ProtocolParams) -> None:
    ...         # Implement custom connection logic
    ...         pass

References:
    - perl-ldap: lib/Net/LDAP.pm (protocol abstraction)
    - RFC 4511: LDAP Protocol Specification
    - Enterprise protocol design patterns

"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ldap_core_shared.api.exceptions import LDAPConnectionError

# Type for protocol connection parameters
ProtocolParams = str, int, bool, float, list[str, None]

# Type for authentication methods and address info
AuthMethod = Callable[..., bool, str]

# Network protocol constants
MIN_PORT_NUMBER = 1  # Minimum valid TCP/UDP port number
MAX_PORT_NUMBER = 65535  # Maximum valid TCP/UDP port number
AddressInfo = str, tuple[str, int]

from pydantic import BaseModel, Field


class ProtocolState(Enum):
    """States for protocol connections."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    DISCONNECTING = "disconnecting"
    ERROR = "error"


class AuthenticationState(Enum):
    """States for authentication."""

    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    AUTHENTICATION_FAILED = "authentication_failed"
    EXPIRED = "expired"


class ProtocolCapability(Enum):
    """Protocol capabilities."""

    START_TLS = "start_tls"
    SASL_AUTHENTICATION = "sasl_authentication"
    CONTROLS = "controls"
    EXTENSIONS = "extensions"
    REFERRALS = "referrals"
    PAGING = "paging"
    PERSISTENT_SEARCH = "persistent_search"
    SYNC_REPLICATION = "sync_replication"


class ConnectionMetrics(BaseModel):
    """Metrics for protocol connections."""

    # Connection timing
    connection_established_at: datetime | None = Field(
        default=None,
        description="When connection was established",
    )

    last_activity_at: datetime | None = Field(
        default=None,
        description="Last activity timestamp",
    )

    total_connection_time: float | None = Field(
        default=None,
        description="Total connection time in seconds",
    )

    # Operation statistics
    operations_performed: int = Field(
        default=0,
        description="Total operations performed",
    )

    successful_operations: int = Field(
        default=0,
        description="Successful operations",
    )

    failed_operations: int = Field(
        default=0,
        description="Failed operations",
    )

    # Data transfer
    bytes_sent: int = Field(default=0, description="Bytes sent")
    bytes_received: int = Field(default=0, description="Bytes received")

    # Performance metrics
    average_response_time: float | None = Field(
        default=None,
        description="Average response time in seconds",
    )

    peak_memory_usage: int | None = Field(
        default=None,
        description="Peak memory usage in bytes",
    )

    def get_success_rate(self) -> float:
        """Get operation success rate as percentage."""
        if self.operations_performed == 0:
            return 100.0
        return (self.successful_operations / self.operations_performed) * 100.0

    def record_operation(
        self,
        success: bool,
        response_time: float | None = None,
    ) -> None:
        """Record operation metrics."""
        self.operations_performed += 1
        self.last_activity_at = datetime.now(UTC)

        if success:
            self.successful_operations += 1
        else:
            self.failed_operations += 1

        # Update average response time
        if response_time is not None:
            if self.average_response_time is None:
                self.average_response_time = response_time
            else:
                # Simple moving average
                self.average_response_time = (
                    self.average_response_time * (self.operations_performed - 1)
                    + response_time
                ) / self.operations_performed


class LDAPProtocol(ABC):
    """Abstract base class for LDAP protocol implementations."""

    protocol_name: str = "base"
    default_port: int | None = None

    def __init__(self) -> None:
        """Initialize LDAP protocol."""
        self._state = ProtocolState.DISCONNECTED
        self._auth_state = AuthenticationState.UNAUTHENTICATED
        self._capabilities: set[ProtocolCapability] = set()
        self._metrics = ConnectionMetrics()
        self._last_error: str | None = None

    @abstractmethod
    async def connect(self, url: str, **kwargs: ProtocolParams) -> None:
        """Connect to LDAP server.

        Args:
            url: Server URL
            **kwargs: Protocol-specific connection parameters

        """

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from LDAP server."""

    async def authenticate(self, method: str, **kwargs: ProtocolParams) -> None:
        """Authenticate with LDAP server.

        Args:
            method: Authentication method
            **kwargs: Authentication parameters

        Raises:
            NotImplementedError: Authentication not implemented in base class

        """
        # TODO: Implement base authentication framework
        # This would provide common authentication patterns
        msg = (
            "Base authentication framework not yet implemented. "
            "Implement common authentication patterns and method "
            "dispatch for protocol-specific authentication mechanisms."
        )
        raise NotImplementedError(msg)

    def set_state(self, state: ProtocolState) -> None:
        """Set protocol state."""
        self._state = state
        if state == ProtocolState.CONNECTED:
            self._metrics.connection_established_at = datetime.now(UTC)

    def set_auth_state(self, auth_state: AuthenticationState) -> None:
        """Set authentication state."""
        self._auth_state = auth_state

    def add_capability(self, capability: ProtocolCapability) -> None:
        """Add protocol capability."""
        self._capabilities.add(capability)

    def remove_capability(self, capability: ProtocolCapability) -> None:
        """Remove protocol capability."""
        self._capabilities.discard(capability)

    def has_capability(self, capability: ProtocolCapability) -> bool:
        """Check if protocol has capability."""
        return capability in self._capabilities

    def set_error(self, error: str) -> None:
        """Set last error."""
        self._last_error = error
        self._state = ProtocolState.ERROR

    def clear_error(self) -> None:
        """Clear last error."""
        self._last_error = None
        if self._state == ProtocolState.ERROR:
            self._state = ProtocolState.DISCONNECTED

    @property
    def state(self) -> ProtocolState:
        """Get current protocol state."""
        return self._state

    @property
    def auth_state(self) -> AuthenticationState:
        """Get current authentication state."""
        return self._auth_state

    @property
    def connected(self) -> bool:
        """Check if protocol is connected."""
        return self._state in {ProtocolState.CONNECTED, ProtocolState.AUTHENTICATED}

    @property
    def authenticated(self) -> bool:
        """Check if protocol is authenticated."""
        return self._auth_state == AuthenticationState.AUTHENTICATED

    @property
    def capabilities(self) -> set[ProtocolCapability]:
        """Get protocol capabilities."""
        return self._capabilities.copy()

    @property
    def metrics(self) -> ConnectionMetrics:
        """Get connection metrics."""
        return self._metrics

    @property
    def last_error(self) -> str | None:
        """Get last error."""
        return self._last_error


class ProtocolAuthentication(ABC):
    """Abstract base class for protocol authentication."""

    def __init__(self, protocol: LDAPProtocol) -> None:
        """Initialize protocol authentication.

        Args:
            protocol: Associated LDAP protocol

        """
        self._protocol = protocol
        self._auth_methods: dict[str, Any] = {}

    @abstractmethod
    async def authenticate(self, method: str, **kwargs: ProtocolParams) -> bool:
        """Perform authentication.

        Args:
            method: Authentication method
            **kwargs: Authentication parameters

        Returns:
            True if authentication successful

        """

    def register_auth_method(self, name: str, method: AuthMethod) -> None:
        """Register authentication method.

        Args:
            name: Method name
            method: Method implementation

        """
        self._auth_methods[name] = method

    def get_auth_methods(self) -> list[str]:
        """Get available authentication methods."""
        return list(self._auth_methods.keys())

    def has_auth_method(self, method: str) -> bool:
        """Check if authentication method is available."""
        return method in self._auth_methods


class ProtocolTransport(ABC):
    """Abstract base class for protocol transport."""

    def __init__(self) -> None:
        """Initialize protocol transport."""
        self._connected = False
        self._local_address: tuple[str, int] | None = None
        self._remote_address: tuple[str, int] | None = None

    @abstractmethod
    async def connect(self, address: AddressInfo, **kwargs: ProtocolParams) -> None:
        """Connect transport.

        Args:
            address: Target address
            **kwargs: Transport-specific parameters

        """

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect transport."""

    @abstractmethod
    async def send(self, data: bytes) -> int:
        """Send data.

        Args:
            data: Data to send

        Returns:
            Number of bytes sent

        """

    @abstractmethod
    async def receive(self, size: int) -> bytes:
        """Receive data.

        Args:
            size: Maximum number of bytes to receive

        Returns:
            Received data

        """

    @property
    def connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected

    @property
    def local_address(self) -> tuple[str, int] | None:
        """Get local address."""
        return self._local_address

    @property
    def remote_address(self) -> tuple[str, int] | None:
        """Get remote address."""
        return self._remote_address


class ProtocolConnection:
    """Base class for protocol connections."""

    def __init__(
        self,
        protocol: LDAPProtocol,
        timeout: float = 30.0,
        retry_attempts: int = 3,
        **kwargs: ProtocolParams,
    ) -> None:
        """Initialize protocol connection.

        Args:
            protocol: LDAP protocol implementation
            timeout: Connection timeout
            retry_attempts: Number of retry attempts
            **kwargs: Additional connection parameters

        """
        self._protocol = protocol
        self._timeout = timeout
        self._retry_attempts = retry_attempts
        self._connection_params = kwargs

        # Connection state
        self._url: str | None = None
        self._connected = False
        self._last_operation_time: datetime | None = None

    async def connect(self, url: str, **kwargs: ProtocolParams) -> None:
        """Connect to LDAP server.

        Args:
            url: Server URL
            **kwargs: Connection parameters

        """
        self._url = url
        connection_params = {**self._connection_params, **kwargs}

        # Attempt connection with retries
        last_error = None
        for attempt in range(self._retry_attempts):
            try:
                await asyncio.wait_for(
                    self._protocol.connect(url, **connection_params),
                    timeout=self._timeout,
                )
                self._connected = True
                return
            except Exception as e:
                last_error = e
                if attempt < self._retry_attempts - 1:
                    await asyncio.sleep(2**attempt)  # Exponential backoff

        msg = f"Failed to connect after {self._retry_attempts} attempts: {last_error}"
        raise LDAPConnectionError(msg)

    async def disconnect(self) -> None:
        """Disconnect from LDAP server."""
        if self._connected:
            await self._protocol.disconnect()
            self._connected = False

    async def authenticate(self, method: str, **kwargs: ProtocolParams) -> None:
        """Authenticate with LDAP server.

        Args:
            method: Authentication method
            **kwargs: Authentication parameters

        """
        if not self._connected:
            msg = "Not connected to LDAP server"
            raise LDAPConnectionError(msg)

        await self._protocol.authenticate(method, **kwargs)

    def record_operation(
        self,
        success: bool,
        response_time: float | None = None,
    ) -> None:
        """Record operation metrics.

        Args:
            success: Whether operation was successful
            response_time: Operation response time

        """
        self._last_operation_time = datetime.now(UTC)
        self._protocol.metrics.record_operation(success, response_time)

    def get_connection_info(self) -> dict[str, Any]:
        """Get connection information.

        Returns:
            Dictionary with connection details

        """
        return {
            "url": self._url,
            "protocol": self._protocol.protocol_name,
            "state": self._protocol.state.value,
            "auth_state": self._protocol.auth_state.value,
            "connected": self._connected,
            "authenticated": self._protocol.authenticated,
            "capabilities": [cap.value for cap in self._protocol.capabilities],
            "last_operation": self._last_operation_time.isoformat()
            if self._last_operation_time
            else None,
            "metrics": self._protocol.metrics.dict(),
        }

    @property
    def connected(self) -> bool:
        """Check if connection is active."""
        return self._connected and self._protocol.connected

    @property
    def authenticated(self) -> bool:
        """Check if connection is authenticated."""
        return self._protocol.authenticated

    @property
    def protocol(self) -> LDAPProtocol:
        """Get LDAP protocol."""
        return self._protocol

    @property
    def url(self) -> str | None:
        """Get connection URL."""
        return self._url


# Utility functions
def parse_ldap_url(url: str) -> dict[str, Any]:
    """Parse LDAP URL and extract components.

    Args:
        url: LDAP URL to parse

    Returns:
        Dictionary with URL components

    """
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(url)

    # Extract components
    result = {
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parse_qs(parsed.query),
        "fragment": parsed.fragment,
    }

    # Set default ports
    if result["port"] is None:
        if result["scheme"] == "ldap":
            result["port"] = 389
        elif result["scheme"] == "ldaps":
            result["port"] = 636

    return result


def validate_ldap_url(url: str) -> list[str]:
    """Validate LDAP URL format.

    Args:
        url: LDAP URL to validate

    Returns:
        List of validation errors

    """
    errors = []

    try:
        parsed = parse_ldap_url(url)

        # Check scheme
        if parsed["scheme"] not in {"ldap", "ldaps", "ldapi"}:
            errors.append(f"Invalid scheme: {parsed['scheme']}")

        # Check hostname for ldap/ldaps
        if parsed["scheme"] in {"ldap", "ldaps"} and not parsed["hostname"]:
            errors.append("Hostname required for ldap/ldaps URLs")

        # Check port range
        if parsed["port"] is not None and not (
            MIN_PORT_NUMBER <= parsed["port"] <= MAX_PORT_NUMBER
        ):
            errors.append(f"Invalid port: {parsed['port']}")

    except Exception as e:
        errors.append(f"URL parsing error: {e}")

    return errors


# TODO: Integration points for implementation:
#
# 1. Authentication Framework:
#    - Implement comprehensive authentication method framework
#    - SASL mechanism support and negotiation
#    - Credential management and security
#
# 2. Transport Layer Integration:
#    - Socket transport for TCP connections
#    - TLS transport for encrypted connections
#    - Unix socket transport for local connections
#
# 3. Protocol Message Handling:
#    - LDAP message encoding/decoding
#    - Request/response correlation
#    - Error handling and status codes
#
# 4. Connection Pool Management:
#    - Connection pooling and reuse
#    - Load balancing across multiple servers
#    - Health checking and failover
#
# 5. Security and Encryption:
#    - TLS/SSL support and configuration
#    - Certificate validation and management
#    - Security policy enforcement
#
# 6. Performance and Monitoring:
#    - Comprehensive metrics collection
#    - Performance monitoring and alerting
#    - Resource usage tracking
#
# 7. Testing Requirements:
#    - Unit tests for all base functionality
#    - Integration tests with actual servers
#    - Performance tests for connection handling
#    - Security tests for authentication and encryption
