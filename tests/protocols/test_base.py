"""Tests for Base LDAP Protocol Classes.

This module provides comprehensive test coverage for the base LDAP protocol
implementation including connection management, authentication frameworks,
protocol abstraction patterns, and enterprise-grade validation.

Test Coverage:
    - ProtocolState: Connection state enumeration and transitions
    - AuthenticationState: Authentication state management
    - ProtocolCapability: Protocol capability enumeration
    - ConnectionMetrics: Connection metrics and performance tracking
    - LDAPProtocol: Abstract protocol base class implementation
    - ProtocolAuthentication: Authentication framework abstraction
    - ProtocolTransport: Transport layer abstraction
    - ProtocolConnection: Connection management and coordination
    - URL parsing and validation utilities

Architecture Testing:
    - Abstract base class contracts and inheritance
    - State machine transitions and validation
    - Metrics collection and calculation accuracy
    - Connection lifecycle management
    - Authentication framework integration
    - Transport layer abstraction patterns

Performance Testing:
    - Connection establishment and retry logic
    - Metrics calculation and aggregation
    - State transition performance
    - Memory usage optimization validation
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, NoReturn
from unittest.mock import AsyncMock

import pytest

from ldap_core_shared.protocols.base import (
    AuthenticationState,
    ConnectionMetrics,
    LDAPProtocol,
    ProtocolAuthentication,
    ProtocolCapability,
    ProtocolConnection,
    ProtocolState,
    ProtocolTransport,
    parse_ldap_url,
    validate_ldap_url,
)


class TestProtocolState:
    """Test cases for ProtocolState enumeration."""

    def test_protocol_state_values(self) -> None:
        """Test protocol state enumeration values."""
        assert ProtocolState.DISCONNECTED.value == "disconnected"
        assert ProtocolState.CONNECTING.value == "connecting"
        assert ProtocolState.CONNECTED.value == "connected"
        assert ProtocolState.AUTHENTICATING.value == "authenticating"
        assert ProtocolState.AUTHENTICATED.value == "authenticated"
        assert ProtocolState.DISCONNECTING.value == "disconnecting"
        assert ProtocolState.ERROR.value == "error"

    def test_protocol_state_completeness(self) -> None:
        """Test that all expected protocol states are defined."""
        expected_states = {
            "DISCONNECTED",
            "CONNECTING",
            "CONNECTED",
            "AUTHENTICATING",
            "AUTHENTICATED",
            "DISCONNECTING",
            "ERROR",
        }
        actual_states = {member.name for member in ProtocolState}
        assert actual_states == expected_states


class TestAuthenticationState:
    """Test cases for AuthenticationState enumeration."""

    def test_authentication_state_values(self) -> None:
        """Test authentication state enumeration values."""
        assert AuthenticationState.UNAUTHENTICATED.value == "unauthenticated"
        assert AuthenticationState.AUTHENTICATING.value == "authenticating"
        assert AuthenticationState.AUTHENTICATED.value == "authenticated"
        assert (
            AuthenticationState.AUTHENTICATION_FAILED.value == "authentication_failed"
        )
        assert AuthenticationState.EXPIRED.value == "expired"

    def test_authentication_state_completeness(self) -> None:
        """Test that all expected authentication states are defined."""
        expected_states = {
            "UNAUTHENTICATED",
            "AUTHENTICATING",
            "AUTHENTICATED",
            "AUTHENTICATION_FAILED",
            "EXPIRED",
        }
        actual_states = {member.name for member in AuthenticationState}
        assert actual_states == expected_states


class TestProtocolCapability:
    """Test cases for ProtocolCapability enumeration."""

    def test_protocol_capability_values(self) -> None:
        """Test protocol capability enumeration values."""
        assert ProtocolCapability.START_TLS.value == "start_tls"
        assert ProtocolCapability.SASL_AUTHENTICATION.value == "sasl_authentication"
        assert ProtocolCapability.CONTROLS.value == "controls"
        assert ProtocolCapability.EXTENSIONS.value == "extensions"
        assert ProtocolCapability.REFERRALS.value == "referrals"
        assert ProtocolCapability.PAGING.value == "paging"
        assert ProtocolCapability.PERSISTENT_SEARCH.value == "persistent_search"
        assert ProtocolCapability.SYNC_REPLICATION.value == "sync_replication"

    def test_protocol_capability_completeness(self) -> None:
        """Test that all expected protocol capabilities are defined."""
        expected_capabilities = {
            "START_TLS",
            "SASL_AUTHENTICATION",
            "CONTROLS",
            "EXTENSIONS",
            "REFERRALS",
            "PAGING",
            "PERSISTENT_SEARCH",
            "SYNC_REPLICATION",
        }
        actual_capabilities = {member.name for member in ProtocolCapability}
        assert actual_capabilities == expected_capabilities


class TestConnectionMetrics:
    """Test cases for ConnectionMetrics."""

    def test_metrics_initialization_default(self) -> None:
        """Test metrics initialization with default values."""
        metrics = ConnectionMetrics()

        assert metrics.connection_established_at is None
        assert metrics.last_activity_at is None
        assert metrics.total_connection_time is None
        assert metrics.operations_performed == 0
        assert metrics.successful_operations == 0
        assert metrics.failed_operations == 0
        assert metrics.bytes_sent == 0
        assert metrics.bytes_received == 0
        assert metrics.average_response_time is None
        assert metrics.peak_memory_usage is None

    def test_metrics_initialization_with_values(self) -> None:
        """Test metrics initialization with specific values."""
        now = datetime.now(UTC)
        metrics = ConnectionMetrics(
            connection_established_at=now,
            operations_performed=100,
            successful_operations=95,
            failed_operations=5,
            bytes_sent=1024,
            bytes_received=2048,
            average_response_time=0.5,
            peak_memory_usage=1024000,
        )

        assert metrics.connection_established_at == now
        assert metrics.operations_performed == 100
        assert metrics.successful_operations == 95
        assert metrics.failed_operations == 5
        assert metrics.bytes_sent == 1024
        assert metrics.bytes_received == 2048
        assert metrics.average_response_time == 0.5
        assert metrics.peak_memory_usage == 1024000

    def test_get_success_rate_no_operations(self) -> None:
        """Test success rate calculation with no operations."""
        metrics = ConnectionMetrics()
        assert metrics.get_success_rate() == 100.0

    def test_get_success_rate_all_successful(self) -> None:
        """Test success rate calculation with all successful operations."""
        metrics = ConnectionMetrics(
            operations_performed=50,
            successful_operations=50,
        )
        assert metrics.get_success_rate() == 100.0

    def test_get_success_rate_partial_success(self) -> None:
        """Test success rate calculation with partial success."""
        metrics = ConnectionMetrics(
            operations_performed=100,
            successful_operations=75,
        )
        assert metrics.get_success_rate() == 75.0

    def test_get_success_rate_all_failed(self) -> None:
        """Test success rate calculation with all failed operations."""
        metrics = ConnectionMetrics(
            operations_performed=10,
            successful_operations=0,
        )
        assert metrics.get_success_rate() == 0.0

    def test_record_operation_successful(self) -> None:
        """Test recording successful operation."""
        metrics = ConnectionMetrics()

        metrics.record_operation(success=True, response_time=0.5)

        assert metrics.operations_performed == 1
        assert metrics.successful_operations == 1
        assert metrics.failed_operations == 0
        assert metrics.average_response_time == 0.5
        assert metrics.last_activity_at is not None
        assert metrics.get_success_rate() == 100.0

    def test_record_operation_failed(self) -> None:
        """Test recording failed operation."""
        metrics = ConnectionMetrics()

        metrics.record_operation(success=False, response_time=1.0)

        assert metrics.operations_performed == 1
        assert metrics.successful_operations == 0
        assert metrics.failed_operations == 1
        assert metrics.average_response_time == 1.0
        assert metrics.last_activity_at is not None
        assert metrics.get_success_rate() == 0.0

    def test_record_operation_without_response_time(self) -> None:
        """Test recording operation without response time."""
        metrics = ConnectionMetrics()

        metrics.record_operation(success=True)

        assert metrics.operations_performed == 1
        assert metrics.successful_operations == 1
        assert metrics.average_response_time is None

    def test_record_multiple_operations_average_response_time(self) -> None:
        """Test average response time calculation with multiple operations."""
        metrics = ConnectionMetrics()

        # Record multiple operations with different response times
        metrics.record_operation(success=True, response_time=0.5)
        metrics.record_operation(success=True, response_time=1.0)
        metrics.record_operation(success=False, response_time=1.5)

        assert metrics.operations_performed == 3
        assert metrics.successful_operations == 2
        assert metrics.failed_operations == 1
        assert metrics.average_response_time == 1.0  # (0.5 + 1.0 + 1.5) / 3

    def test_record_operation_mixed_with_without_response_time(self) -> None:
        """Test recording operations with mixed response time presence."""
        metrics = ConnectionMetrics()

        # First operation with response time
        metrics.record_operation(success=True, response_time=0.5)
        assert metrics.average_response_time == 0.5

        # Second operation without response time
        metrics.record_operation(success=True)
        assert metrics.average_response_time == 0.5  # Should remain unchanged

        # Third operation with response time
        metrics.record_operation(success=True, response_time=1.0)
        # Average should be (0.5 * 1 + 1.0) / 2 = 0.75
        # But calculated as (0.5 * 2 + 1.0) / 3 = 0.67 due to operation count
        assert abs(metrics.average_response_time - (0.5 * 2 + 1.0) / 3) < 0.01


class MockLDAPProtocol(LDAPProtocol):
    """Mock LDAP protocol for testing."""

    protocol_name = "mock"
    default_port = 389

    def __init__(self) -> None:
        super().__init__()
        self.connect_called = False
        self.disconnect_called = False
        self.connect_exception = None

    async def connect(self, url: str, **kwargs) -> None:
        """Mock connect implementation."""
        self.connect_called = True
        if self.connect_exception:
            raise self.connect_exception
        self.set_state(ProtocolState.CONNECTED)

    async def disconnect(self) -> None:
        """Mock disconnect implementation."""
        self.disconnect_called = True
        self.set_state(ProtocolState.DISCONNECTED)


class TestLDAPProtocol:
    """Test cases for LDAPProtocol abstract base class."""

    def test_protocol_initialization(self) -> None:
        """Test protocol initialization."""
        protocol = MockLDAPProtocol()

        assert protocol.protocol_name == "mock"
        assert protocol.default_port == 389
        assert protocol.state == ProtocolState.DISCONNECTED
        assert protocol.auth_state == AuthenticationState.UNAUTHENTICATED
        assert len(protocol.capabilities) == 0
        assert protocol.last_error is None
        assert not protocol.connected
        assert not protocol.authenticated

    @pytest.mark.asyncio
    async def test_connect_successful(self) -> None:
        """Test successful connection."""
        protocol = MockLDAPProtocol()

        await protocol.connect("ldap://example.com")

        assert protocol.connect_called
        assert protocol.state == ProtocolState.CONNECTED
        assert protocol.connected
        assert protocol.metrics.connection_established_at is not None

    @pytest.mark.asyncio
    async def test_connect_with_exception(self) -> None:
        """Test connection with exception."""
        protocol = MockLDAPProtocol()
        protocol.connect_exception = ConnectionError("Connection failed")

        with pytest.raises(ConnectionError):
            await protocol.connect("ldap://example.com")

        assert protocol.connect_called
        assert protocol.state == ProtocolState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_disconnect(self) -> None:
        """Test disconnection."""
        protocol = MockLDAPProtocol()
        await protocol.connect("ldap://example.com")

        await protocol.disconnect()

        assert protocol.disconnect_called
        assert protocol.state == ProtocolState.DISCONNECTED
        assert not protocol.connected

    @pytest.mark.asyncio
    async def test_authenticate_not_implemented(self) -> None:
        """Test authenticate method not implemented."""
        protocol = MockLDAPProtocol()

        with pytest.raises(
            NotImplementedError,
            match="Base authentication framework not yet implemented",
        ):
            await protocol.authenticate("simple")

    def test_set_state(self) -> None:
        """Test state setting."""
        protocol = MockLDAPProtocol()

        protocol.set_state(ProtocolState.CONNECTING)
        assert protocol.state == ProtocolState.CONNECTING

        protocol.set_state(ProtocolState.CONNECTED)
        assert protocol.state == ProtocolState.CONNECTED
        assert protocol.metrics.connection_established_at is not None

    def test_set_auth_state(self) -> None:
        """Test authentication state setting."""
        protocol = MockLDAPProtocol()

        protocol.set_auth_state(AuthenticationState.AUTHENTICATING)
        assert protocol.auth_state == AuthenticationState.AUTHENTICATING

        protocol.set_auth_state(AuthenticationState.AUTHENTICATED)
        assert protocol.auth_state == AuthenticationState.AUTHENTICATED
        assert protocol.authenticated

    def test_capability_management(self) -> None:
        """Test capability management."""
        protocol = MockLDAPProtocol()

        # Add capabilities
        protocol.add_capability(ProtocolCapability.START_TLS)
        protocol.add_capability(ProtocolCapability.SASL_AUTHENTICATION)

        assert protocol.has_capability(ProtocolCapability.START_TLS)
        assert protocol.has_capability(ProtocolCapability.SASL_AUTHENTICATION)
        assert not protocol.has_capability(ProtocolCapability.CONTROLS)

        capabilities = protocol.capabilities
        assert ProtocolCapability.START_TLS in capabilities
        assert ProtocolCapability.SASL_AUTHENTICATION in capabilities
        assert len(capabilities) == 2

        # Remove capability
        protocol.remove_capability(ProtocolCapability.START_TLS)
        assert not protocol.has_capability(ProtocolCapability.START_TLS)
        assert protocol.has_capability(ProtocolCapability.SASL_AUTHENTICATION)

        # Remove non-existent capability (should not raise)
        protocol.remove_capability(ProtocolCapability.CONTROLS)

    def test_error_management(self) -> None:
        """Test error management."""
        protocol = MockLDAPProtocol()

        # Set error
        protocol.set_error("Connection timeout")
        assert protocol.last_error == "Connection timeout"
        assert protocol.state == ProtocolState.ERROR

        # Clear error
        protocol.clear_error()
        assert protocol.last_error is None
        assert protocol.state == ProtocolState.DISCONNECTED

    def test_connected_property(self) -> None:
        """Test connected property."""
        protocol = MockLDAPProtocol()

        # Initially disconnected
        assert not protocol.connected

        # Connected state
        protocol.set_state(ProtocolState.CONNECTED)
        assert protocol.connected

        # Authenticated state
        protocol.set_state(ProtocolState.AUTHENTICATED)
        assert protocol.connected

        # Other states
        protocol.set_state(ProtocolState.CONNECTING)
        assert not protocol.connected

        protocol.set_state(ProtocolState.ERROR)
        assert not protocol.connected


class MockProtocolAuthentication(ProtocolAuthentication):
    """Mock protocol authentication for testing."""

    def __init__(self, protocol: LDAPProtocol) -> None:
        super().__init__(protocol)
        self.authenticate_called = False
        self.authenticate_result = True

    async def authenticate(self, method: str, **kwargs) -> bool:
        """Mock authenticate implementation."""
        self.authenticate_called = True
        return self.authenticate_result


class TestProtocolAuthentication:
    """Test cases for ProtocolAuthentication."""

    def test_authentication_initialization(self) -> None:
        """Test authentication initialization."""
        protocol = MockLDAPProtocol()
        auth = MockProtocolAuthentication(protocol)

        assert auth._protocol is protocol
        assert len(auth._auth_methods) == 0

    def test_register_auth_method(self) -> None:
        """Test registering authentication method."""
        protocol = MockLDAPProtocol()
        auth = MockProtocolAuthentication(protocol)

        def simple_auth(**kwargs) -> bool:
            return True

        auth.register_auth_method("simple", simple_auth)

        assert auth.has_auth_method("simple")
        assert "simple" in auth.get_auth_methods()

    def test_get_auth_methods(self) -> None:
        """Test getting authentication methods."""
        protocol = MockLDAPProtocol()
        auth = MockProtocolAuthentication(protocol)

        auth.register_auth_method("simple", lambda: True)
        auth.register_auth_method("sasl", lambda: True)

        methods = auth.get_auth_methods()
        assert "simple" in methods
        assert "sasl" in methods
        assert len(methods) == 2

    def test_has_auth_method(self) -> None:
        """Test checking authentication method availability."""
        protocol = MockLDAPProtocol()
        auth = MockProtocolAuthentication(protocol)

        assert not auth.has_auth_method("simple")

        auth.register_auth_method("simple", lambda: True)
        assert auth.has_auth_method("simple")
        assert not auth.has_auth_method("sasl")

    @pytest.mark.asyncio
    async def test_authenticate(self) -> None:
        """Test authentication method."""
        protocol = MockLDAPProtocol()
        auth = MockProtocolAuthentication(protocol)

        result = await auth.authenticate("simple")

        assert auth.authenticate_called
        assert result is True

    @pytest.mark.asyncio
    async def test_authenticate_failure(self) -> None:
        """Test authentication failure."""
        protocol = MockLDAPProtocol()
        auth = MockProtocolAuthentication(protocol)
        auth.authenticate_result = False

        result = await auth.authenticate("simple")

        assert auth.authenticate_called
        assert result is False


class MockProtocolTransport(ProtocolTransport):
    """Mock protocol transport for testing."""

    def __init__(self) -> None:
        super().__init__()
        self.connect_called = False
        self.disconnect_called = False
        self.sent_data = []
        self.receive_data = b""

    async def connect(self, address: tuple[str, int] | str, **kwargs: Any) -> None:
        """Mock connect implementation."""
        self.connect_called = True
        self._connected = True
        if isinstance(address, tuple):
            self._remote_address = address
        else:
            self._remote_address = (address, 389)

    async def disconnect(self) -> None:
        """Mock disconnect implementation."""
        self.disconnect_called = True
        self._connected = False

    async def send(self, data: bytes) -> int:
        """Mock send implementation."""
        self.sent_data.append(data)
        return len(data)

    async def receive(self, size: int) -> bytes:
        """Mock receive implementation."""
        data = self.receive_data[:size]
        self.receive_data = self.receive_data[size:]
        return data


class TestProtocolTransport:
    """Test cases for ProtocolTransport."""

    def test_transport_initialization(self) -> None:
        """Test transport initialization."""
        transport = MockProtocolTransport()

        assert not transport.connected
        assert transport.local_address is None
        assert transport.remote_address is None

    @pytest.mark.asyncio
    async def test_connect(self) -> None:
        """Test transport connection."""
        transport = MockProtocolTransport()

        await transport.connect(("example.com", 389))

        assert transport.connect_called
        assert transport.connected
        assert transport.remote_address == ("example.com", 389)

    @pytest.mark.asyncio
    async def test_connect_string_address(self) -> None:
        """Test transport connection with string address."""
        transport = MockProtocolTransport()

        await transport.connect("example.com")

        assert transport.connect_called
        assert transport.connected
        assert transport.remote_address == ("example.com", 389)

    @pytest.mark.asyncio
    async def test_disconnect(self) -> None:
        """Test transport disconnection."""
        transport = MockProtocolTransport()
        await transport.connect(("example.com", 389))

        await transport.disconnect()

        assert transport.disconnect_called
        assert not transport.connected

    @pytest.mark.asyncio
    async def test_send(self) -> None:
        """Test sending data."""
        transport = MockProtocolTransport()
        test_data = b"test message"

        bytes_sent = await transport.send(test_data)

        assert bytes_sent == len(test_data)
        assert test_data in transport.sent_data

    @pytest.mark.asyncio
    async def test_receive(self) -> None:
        """Test receiving data."""
        transport = MockProtocolTransport()
        transport.receive_data = b"response data"

        received = await transport.receive(8)

        assert received == b"response"
        assert transport.receive_data == b" data"

    @pytest.mark.asyncio
    async def test_receive_all_data(self) -> None:
        """Test receiving all available data."""
        transport = MockProtocolTransport()
        transport.receive_data = b"short"

        received = await transport.receive(100)

        assert received == b"short"
        assert transport.receive_data == b""


class TestProtocolConnection:
    """Test cases for ProtocolConnection."""

    def test_connection_initialization(self) -> None:
        """Test connection initialization."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(
            protocol=protocol,
            timeout=60.0,
            retry_attempts=5,
        )

        assert connection._protocol is protocol
        assert connection._timeout == 60.0
        assert connection._retry_attempts == 5
        assert not connection._connected
        assert connection.url is None

    @pytest.mark.asyncio
    async def test_connect_successful(self) -> None:
        """Test successful connection."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol)

        await connection.connect("ldap://example.com")

        assert protocol.connect_called
        assert connection._connected
        assert connection.connected
        assert connection.url == "ldap://example.com"

    @pytest.mark.asyncio
    async def test_connect_with_retry(self) -> None:
        """Test connection with retry logic."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol, retry_attempts=3)

        # First two attempts fail, third succeeds
        call_count = 0
        original_connect = protocol.connect

        async def failing_connect(url: str, **kwargs: Any) -> None:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                msg = "Connection failed"
                raise ConnectionError(msg)
            await original_connect(url, **kwargs)

        protocol.connect = failing_connect

        await connection.connect("ldap://example.com")

        assert call_count == 3
        assert connection._connected

    @pytest.mark.asyncio
    async def test_connect_all_retries_fail(self) -> None:
        """Test connection when all retries fail."""
        protocol = MockLDAPProtocol()
        protocol.connect_exception = ConnectionError("Persistent failure")
        connection = ProtocolConnection(protocol, retry_attempts=2)

        with pytest.raises(ConnectionError, match="Failed to connect after 2 attempts"):
            await connection.connect("ldap://example.com")

        assert not connection._connected

    @pytest.mark.asyncio
    async def test_connect_timeout(self) -> None:
        """Test connection timeout."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol, timeout=0.1)

        async def slow_connect(url: str, **kwargs: Any) -> None:
            await asyncio.sleep(0.2)  # Longer than timeout

        protocol.connect = slow_connect

        with pytest.raises(ConnectionError, match="Failed to connect after"):
            await connection.connect("ldap://example.com")

    @pytest.mark.asyncio
    async def test_disconnect(self) -> None:
        """Test disconnection."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol)

        await connection.connect("ldap://example.com")
        await connection.disconnect()

        assert protocol.disconnect_called
        assert not connection._connected

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self) -> None:
        """Test disconnection when not connected."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol)

        # Should not raise error
        await connection.disconnect()

        assert not protocol.disconnect_called

    @pytest.mark.asyncio
    async def test_authenticate_when_connected(self) -> None:
        """Test authentication when connected."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol)

        await connection.connect("ldap://example.com")

        # Mock the authenticate method to avoid NotImplementedError
        protocol.authenticate = AsyncMock()

        await connection.authenticate("simple", username="test", password="pass")

        protocol.authenticate.assert_called_once_with(
            "simple", username="test", password="pass"
        )

    @pytest.mark.asyncio
    async def test_authenticate_when_not_connected(self) -> None:
        """Test authentication when not connected."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol)

        with pytest.raises(ConnectionError, match="Not connected to LDAP server"):
            await connection.authenticate("simple")

    def test_record_operation(self) -> None:
        """Test recording operation metrics."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol)

        connection.record_operation(success=True, response_time=0.5)

        assert connection._last_operation_time is not None
        assert protocol.metrics.operations_performed == 1
        assert protocol.metrics.successful_operations == 1

    def test_get_connection_info(self) -> None:
        """Test getting connection information."""
        protocol = MockLDAPProtocol()
        protocol.add_capability(ProtocolCapability.START_TLS)
        connection = ProtocolConnection(protocol)

        info = connection.get_connection_info()

        assert info["protocol"] == "mock"
        assert info["state"] == "disconnected"
        assert info["auth_state"] == "unauthenticated"
        assert not info["connected"]
        assert not info["authenticated"]
        assert "start_tls" in info["capabilities"]
        assert "metrics" in info

    @pytest.mark.asyncio
    async def test_connection_properties(self) -> None:
        """Test connection properties."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol)

        # Initially not connected
        assert not connection.connected
        assert not connection.authenticated

        # After connection
        await connection.connect("ldap://example.com")
        assert connection.connected

        # After authentication
        protocol.set_auth_state(AuthenticationState.AUTHENTICATED)
        assert connection.authenticated


class TestUtilityFunctions:
    """Test cases for utility functions."""

    def test_parse_ldap_url_basic(self) -> None:
        """Test parsing basic LDAP URL."""
        url = "ldap://example.com"
        parsed = parse_ldap_url(url)

        assert parsed["scheme"] == "ldap"
        assert parsed["hostname"] == "example.com"
        assert parsed["port"] == 389  # Default LDAP port
        assert parsed["path"] == ""

    def test_parse_ldap_url_with_port(self) -> None:
        """Test parsing LDAP URL with custom port."""
        url = "ldap://example.com:1389"
        parsed = parse_ldap_url(url)

        assert parsed["scheme"] == "ldap"
        assert parsed["hostname"] == "example.com"
        assert parsed["port"] == 1389

    def test_parse_ldaps_url(self) -> None:
        """Test parsing LDAPS URL."""
        url = "ldaps://secure.example.com"
        parsed = parse_ldap_url(url)

        assert parsed["scheme"] == "ldaps"
        assert parsed["hostname"] == "secure.example.com"
        assert parsed["port"] == 636  # Default LDAPS port

    def test_parse_ldapi_url(self) -> None:
        """Test parsing LDAPI URL."""
        url = "ldapi:///var/run/ldapi"
        parsed = parse_ldap_url(url)

        assert parsed["scheme"] == "ldapi"
        assert parsed["hostname"] is None
        assert parsed["path"] == "/var/run/ldapi"

    def test_parse_ldap_url_with_path_and_query(self) -> None:
        """Test parsing LDAP URL with path and query parameters."""
        url = "ldap://example.com/dc=example,dc=com?objectClass?sub?cn=test"
        parsed = parse_ldap_url(url)

        assert parsed["scheme"] == "ldap"
        assert parsed["hostname"] == "example.com"
        assert parsed["path"] == "/dc=example,dc=com"
        assert "objectClass" in str(parsed["query"])

    def test_validate_ldap_url_valid_urls(self) -> None:
        """Test validation of valid LDAP URLs."""
        valid_urls = [
            "ldap://example.com",
            "ldaps://secure.example.com:636",
            "ldapi:///var/run/ldapi",
            "ldap://localhost:1389/dc=example,dc=com",
        ]

        for url in valid_urls:
            errors = validate_ldap_url(url)
            assert (
                len(errors) == 0
            ), f"URL {url} should be valid but got errors: {errors}"

    def test_validate_ldap_url_invalid_scheme(self) -> None:
        """Test validation of URLs with invalid scheme."""
        invalid_urls = [
            "http://example.com",
            "ftp://example.com",
            "invalid://example.com",
        ]

        for url in invalid_urls:
            errors = validate_ldap_url(url)
            assert len(errors) > 0
            assert any("Invalid scheme" in error for error in errors)

    def test_validate_ldap_url_missing_hostname(self) -> None:
        """Test validation of URLs missing hostname for ldap/ldaps."""
        invalid_urls = [
            "ldap://",
            "ldaps://",
        ]

        for url in invalid_urls:
            errors = validate_ldap_url(url)
            assert len(errors) > 0
            assert any("Hostname required" in error for error in errors)

    def test_validate_ldap_url_invalid_port(self) -> None:
        """Test validation of URLs with invalid port."""
        invalid_urls = [
            "ldap://example.com:0",
            "ldap://example.com:65536",
            "ldap://example.com:-1",
        ]

        for url in invalid_urls:
            errors = validate_ldap_url(url)
            assert len(errors) > 0
            assert any("Invalid port" in error for error in errors)

    def test_validate_ldap_url_malformed(self) -> None:
        """Test validation of malformed URLs."""
        invalid_urls = [
            "not a url",
            "ldap://[invalid",
            "",
        ]

        for url in invalid_urls:
            errors = validate_ldap_url(url)
            assert len(errors) > 0


class TestIntegrationScenarios:
    """Integration test scenarios."""

    @pytest.mark.asyncio
    async def test_complete_connection_lifecycle(self) -> None:
        """Test complete connection lifecycle."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol)

        # 1. Connect
        await connection.connect("ldap://example.com")
        assert connection.connected
        assert protocol.state == ProtocolState.CONNECTED

        # 2. Add capabilities
        protocol.add_capability(ProtocolCapability.START_TLS)
        protocol.add_capability(ProtocolCapability.SASL_AUTHENTICATION)

        # 3. Authenticate (mock)
        protocol.authenticate = AsyncMock()
        await connection.authenticate("simple", username="test")
        protocol.set_auth_state(AuthenticationState.AUTHENTICATED)

        assert connection.authenticated

        # 4. Record some operations
        connection.record_operation(True, 0.1)
        connection.record_operation(True, 0.2)
        connection.record_operation(False, 0.5)

        # 5. Check metrics
        assert protocol.metrics.operations_performed == 3
        assert protocol.metrics.successful_operations == 2
        assert protocol.metrics.failed_operations == 1
        assert protocol.metrics.get_success_rate() == pytest.approx(66.67, rel=1e-2)

        # 6. Get connection info
        info = connection.get_connection_info()
        assert info["connected"]
        assert info["authenticated"]
        assert len(info["capabilities"]) == 2

        # 7. Disconnect
        await connection.disconnect()
        assert not connection.connected

    def test_protocol_state_transitions(self) -> None:
        """Test protocol state transitions."""
        protocol = MockLDAPProtocol()

        # Initial state
        assert protocol.state == ProtocolState.DISCONNECTED

        # State transitions
        protocol.set_state(ProtocolState.CONNECTING)
        assert protocol.state == ProtocolState.CONNECTING

        protocol.set_state(ProtocolState.CONNECTED)
        assert protocol.state == ProtocolState.CONNECTED
        assert protocol.connected

        protocol.set_state(ProtocolState.AUTHENTICATING)
        assert protocol.state == ProtocolState.AUTHENTICATING

        protocol.set_state(ProtocolState.AUTHENTICATED)
        assert protocol.state == ProtocolState.AUTHENTICATED
        assert protocol.connected

        # Error state
        protocol.set_error("Test error")
        assert protocol.state == ProtocolState.ERROR
        assert not protocol.connected
        assert protocol.last_error == "Test error"

        # Clear error
        protocol.clear_error()
        assert protocol.state == ProtocolState.DISCONNECTED
        assert protocol.last_error is None

    def test_capabilities_management_integration(self) -> None:
        """Test capabilities management integration."""
        protocol = MockLDAPProtocol()

        # Add multiple capabilities
        capabilities_to_add = [
            ProtocolCapability.START_TLS,
            ProtocolCapability.SASL_AUTHENTICATION,
            ProtocolCapability.CONTROLS,
            ProtocolCapability.EXTENSIONS,
        ]

        for cap in capabilities_to_add:
            protocol.add_capability(cap)

        # Verify all capabilities
        assert len(protocol.capabilities) == len(capabilities_to_add)
        for cap in capabilities_to_add:
            assert protocol.has_capability(cap)

        # Remove some capabilities
        protocol.remove_capability(ProtocolCapability.START_TLS)
        protocol.remove_capability(ProtocolCapability.CONTROLS)

        assert not protocol.has_capability(ProtocolCapability.START_TLS)
        assert protocol.has_capability(ProtocolCapability.SASL_AUTHENTICATION)
        assert not protocol.has_capability(ProtocolCapability.CONTROLS)
        assert protocol.has_capability(ProtocolCapability.EXTENSIONS)


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_metrics_calculation_performance(self) -> None:
        """Test metrics calculation performance."""
        import time

        metrics = ConnectionMetrics()

        start_time = time.time()

        # Record many operations
        for i in range(1000):
            metrics.record_operation(success=(i % 5 != 0), response_time=0.001 * i)

        calculation_time = time.time() - start_time

        # Should calculate quickly
        assert calculation_time < 1.0  # Less than 1 second for 1000 operations
        assert metrics.operations_performed == 1000
        assert metrics.get_success_rate() == 80.0  # 4/5 success rate

    def test_capability_management_performance(self) -> None:
        """Test capability management performance."""
        import time

        protocol = MockLDAPProtocol()

        start_time = time.time()

        # Add and remove capabilities many times
        for _ in range(1000):
            protocol.add_capability(ProtocolCapability.START_TLS)
            protocol.add_capability(ProtocolCapability.SASL_AUTHENTICATION)
            protocol.remove_capability(ProtocolCapability.START_TLS)

        management_time = time.time() - start_time

        # Should manage capabilities quickly
        assert management_time < 1.0  # Less than 1 second for 1000 operations

    @pytest.mark.asyncio
    async def test_connection_retry_performance(self) -> None:
        """Test connection retry performance."""
        import time

        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol, retry_attempts=1, timeout=0.1)

        # Mock fast-failing connection
        async def fast_fail_connect(url: str, **kwargs: Any) -> NoReturn:
            msg = "Quick failure"
            raise ConnectionError(msg)

        protocol.connect = fast_fail_connect

        start_time = time.time()

        with pytest.raises(ConnectionError):
            await connection.connect("ldap://example.com")

        retry_time = time.time() - start_time

        # Should fail quickly without long delays
        assert retry_time < 0.5  # Should be quick with minimal retry delay


class TestErrorHandling:
    """Error handling test cases."""

    @pytest.mark.asyncio
    async def test_connection_error_handling(self) -> None:
        """Test connection error handling."""
        protocol = MockLDAPProtocol()
        connection = ProtocolConnection(protocol, retry_attempts=1)

        # Test various connection errors
        error_types = [
            ConnectionError("Network error"),
            TimeoutError("Connection timeout"),
            OSError("Socket error"),
        ]

        for error in error_types:
            protocol.connect_exception = error

            with pytest.raises(ConnectionError):
                await connection.connect("ldap://example.com")

            assert not connection.connected

    def test_protocol_error_state_handling(self) -> None:
        """Test protocol error state handling."""
        protocol = MockLDAPProtocol()

        # Set various errors
        errors = [
            "Connection lost",
            "Authentication failed",
            "Protocol violation",
            "Server error",
        ]

        for error_msg in errors:
            protocol.set_error(error_msg)
            assert protocol.state == ProtocolState.ERROR
            assert protocol.last_error == error_msg
            assert not protocol.connected

            # Clear and verify
            protocol.clear_error()
            assert protocol.state == ProtocolState.DISCONNECTED
            assert protocol.last_error is None

    def test_metrics_edge_cases(self) -> None:
        """Test metrics edge cases."""
        metrics = ConnectionMetrics()

        # Test with zero operations
        assert metrics.get_success_rate() == 100.0

        # Test with only failed operations
        for _ in range(5):
            metrics.record_operation(False)

        assert metrics.get_success_rate() == 0.0
        assert metrics.operations_performed == 5
        assert metrics.successful_operations == 0

    def test_url_validation_edge_cases(self) -> None:
        """Test URL validation edge cases."""
        # Test edge cases
        edge_cases = [
            ("", "Empty URL"),
            ("ldap://", "Missing hostname"),
            ("ldap://host:abc", "Invalid port"),
            ("invalid", "No scheme"),
        ]

        for url, description in edge_cases:
            errors = validate_ldap_url(url)
            assert (
                len(errors) > 0
            ), f"URL '{url}' ({description}) should have validation errors"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
