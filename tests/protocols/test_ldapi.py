"""Tests for LDAPI (LDAP over Unix Domain Sockets) Protocol Implementation.

This module provides comprehensive test coverage for the LDAPI protocol
implementation including Unix domain socket connections, peer credential
authentication, and local system integration with enterprise-grade validation.

Test Coverage:
    - LDAPIAuthMethod: Authentication method enumeration
    - LDAPISocketType: Unix socket type enumeration
    - LDAPIConfiguration: Configuration validation and security
    - LDAPICredentials: Unix credential management
    - LDAPITransport: Unix domain socket transport layer
    - LDAPIProtocol: Core LDAPI protocol implementation
    - LDAPIConnection: High-level connection management
    - URL parsing and validation utilities

Security Testing:
    - Socket path validation and security enforcement
    - Peer credential verification and authentication
    - Socket permission and ownership validation
    - EXTERNAL SASL mechanism integration
    - Unix domain socket security patterns

Integration Testing:
    - Connection establishment and lifecycle management
    - Authentication flow and credential passing
    - Transport layer abstraction and socket operations
    - Error handling and connection recovery
    - Performance optimization and resource management
"""

from __future__ import annotations

import socket
import stat
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from ldap_core_shared.protocols.ldapi import (
    LDAPIAuthMethod,
    LDAPIConfiguration,
    LDAPIConnection,
    LDAPICredentials,
    LDAPIProtocol,
    LDAPISocketType,
    LDAPITransport,
    create_ldapi_connection,
    parse_ldapi_url,
    test_ldapi_socket,
)


class TestLDAPIAuthMethod:
    """Test cases for LDAPIAuthMethod enumeration."""

    def test_auth_method_values(self) -> None:
        """Test authentication method enumeration values."""
        assert LDAPIAuthMethod.EXTERNAL.value == "external"
        assert LDAPIAuthMethod.SIMPLE.value == "simple"
        assert LDAPIAuthMethod.ANONYMOUS.value == "anonymous"
        assert LDAPIAuthMethod.PEER_CREDENTIALS.value == "peer_credentials"

    def test_auth_method_completeness(self) -> None:
        """Test that all expected authentication methods are defined."""
        expected_methods = {
            "EXTERNAL", "SIMPLE", "ANONYMOUS", "PEER_CREDENTIALS",
        }
        actual_methods = {member.name for member in LDAPIAuthMethod}
        assert actual_methods == expected_methods


class TestLDAPISocketType:
    """Test cases for LDAPISocketType enumeration."""

    def test_socket_type_values(self) -> None:
        """Test socket type enumeration values."""
        assert LDAPISocketType.STREAM.value == "stream"
        assert LDAPISocketType.DGRAM.value == "dgram"
        assert LDAPISocketType.SEQPACKET.value == "seqpacket"

    def test_socket_type_completeness(self) -> None:
        """Test that all expected socket types are defined."""
        expected_types = {"STREAM", "DGRAM", "SEQPACKET"}
        actual_types = {member.name for member in LDAPISocketType}
        assert actual_types == expected_types


class TestLDAPIConfiguration:
    """Test cases for LDAPIConfiguration."""

    def test_configuration_creation_minimal(self) -> None:
        """Test creating configuration with minimal required fields."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")

        assert config.socket_path == "/var/run/ldapi"
        assert config.socket_type == LDAPISocketType.STREAM
        assert config.auth_method == LDAPIAuthMethod.EXTERNAL
        assert config.use_peer_credentials is True
        assert config.verify_socket_owner is True
        assert config.require_secure_path is True

    def test_configuration_creation_complete(self) -> None:
        """Test creating configuration with all fields."""
        config = LDAPIConfiguration(
            socket_path="/tmp/ldapi.sock",
            socket_type=LDAPISocketType.DGRAM,
            auth_method=LDAPIAuthMethod.SIMPLE,
            use_peer_credentials=False,
            connect_timeout=60.0,
            socket_permissions=0o600,
            verify_socket_owner=False,
            allowed_socket_owners=[1000, 1001],
            require_secure_path=False,
            send_buffer_size=8192,
            recv_buffer_size=8192,
        )

        assert config.socket_path == "/tmp/ldapi.sock"
        assert config.socket_type == LDAPISocketType.DGRAM
        assert config.auth_method == LDAPIAuthMethod.SIMPLE
        assert config.use_peer_credentials is False
        assert config.connect_timeout == 60.0
        assert config.socket_permissions == 0o600
        assert config.verify_socket_owner is False
        assert config.allowed_socket_owners == [1000, 1001]
        assert config.require_secure_path is False
        assert config.send_buffer_size == 8192
        assert config.recv_buffer_size == 8192

    def test_socket_path_validation_empty(self) -> None:
        """Test socket path validation with empty path."""
        with pytest.raises(ValueError, match="Socket path cannot be empty"):
            LDAPIConfiguration(socket_path="")

    def test_socket_path_validation_whitespace(self) -> None:
        """Test socket path validation with whitespace."""
        with pytest.raises(ValueError, match="Socket path cannot be empty"):
            LDAPIConfiguration(socket_path="   ")

    def test_socket_path_validation_relative(self) -> None:
        """Test socket path validation with relative path."""
        with pytest.raises(ValueError, match="Socket path must be absolute"):
            LDAPIConfiguration(socket_path="relative/path")

    def test_socket_path_validation_url_encoded(self) -> None:
        """Test socket path validation with URL encoding."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi%2Fsocket")
        assert config.socket_path == "/var/run/ldapi/socket"

    def test_socket_path_validation_strips_whitespace(self) -> None:
        """Test socket path validation strips whitespace."""
        config = LDAPIConfiguration(socket_path="  /var/run/ldapi  ")
        assert config.socket_path == "/var/run/ldapi"

    def test_get_socket_family(self) -> None:
        """Test get_socket_family method."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        assert config.get_socket_family() == socket.AF_UNIX

    def test_get_socket_type_stream(self) -> None:
        """Test get_socket_type method for STREAM."""
        config = LDAPIConfiguration(
            socket_path="/var/run/ldapi",
            socket_type=LDAPISocketType.STREAM,
        )
        assert config.get_socket_type() == socket.SOCK_STREAM

    def test_get_socket_type_dgram(self) -> None:
        """Test get_socket_type method for DGRAM."""
        config = LDAPIConfiguration(
            socket_path="/var/run/ldapi",
            socket_type=LDAPISocketType.DGRAM,
        )
        assert config.get_socket_type() == socket.SOCK_DGRAM

    def test_get_socket_type_seqpacket(self) -> None:
        """Test get_socket_type method for SEQPACKET."""
        config = LDAPIConfiguration(
            socket_path="/var/run/ldapi",
            socket_type=LDAPISocketType.SEQPACKET,
        )
        assert config.get_socket_type() == socket.SOCK_SEQPACKET

    def test_validate_socket_security_nonexistent(self) -> None:
        """Test validate_socket_security with nonexistent socket."""
        config = LDAPIConfiguration(socket_path="/nonexistent/socket")
        errors = config.validate_socket_security()

        assert len(errors) == 1
        assert "Socket path does not exist" in errors[0]

    @patch("os.path.exists")
    @patch("os.stat")
    def test_validate_socket_security_not_socket(self, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test validate_socket_security with non-socket file."""
        mock_exists.return_value = True
        mock_stat.return_value = Mock(st_mode=0o100644)  # Regular file

        config = LDAPIConfiguration(socket_path="/tmp/not_socket")
        errors = config.validate_socket_security()

        assert len(errors) == 1
        assert "Path is not a socket" in errors[0]

    @patch("os.path.exists")
    @patch("os.stat")
    def test_validate_socket_security_insecure_permissions(self, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test validate_socket_security with insecure permissions."""
        mock_exists.return_value = True
        mock_stat.return_value = Mock(
            st_mode=stat.S_IFSOCK | 0o777,  # Socket with world-writable
            st_uid=1000,
        )

        config = LDAPIConfiguration(
            socket_path="/tmp/insecure_socket",
            require_secure_path=True,
        )
        errors = config.validate_socket_security()

        assert len(errors) == 1
        assert "Socket has insecure permissions" in errors[0]

    @patch("os.path.exists")
    @patch("os.stat")
    @patch("os.getuid")
    def test_validate_socket_security_wrong_owner(self, mock_getuid: Mock, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test validate_socket_security with wrong owner."""
        mock_exists.return_value = True
        mock_getuid.return_value = 1000
        mock_stat.return_value = Mock(
            st_mode=stat.S_IFSOCK | 0o600,  # Secure socket
            st_uid=2000,  # Different owner
        )

        config = LDAPIConfiguration(
            socket_path="/tmp/wrong_owner_socket",
            verify_socket_owner=True,
        )
        errors = config.validate_socket_security()

        assert len(errors) == 1
        assert "Socket owned by different user" in errors[0]

    @patch("os.path.exists")
    @patch("os.stat")
    def test_validate_socket_security_allowed_owner(self, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test validate_socket_security with allowed owner."""
        mock_exists.return_value = True
        mock_stat.return_value = Mock(
            st_mode=stat.S_IFSOCK | 0o600,  # Secure socket
            st_uid=2000,
        )

        config = LDAPIConfiguration(
            socket_path="/tmp/allowed_owner_socket",
            verify_socket_owner=True,
            allowed_socket_owners=[2000, 3000],
        )
        errors = config.validate_socket_security()

        assert len(errors) == 0

    @patch("os.path.exists")
    @patch("os.stat")
    def test_validate_socket_security_os_error(self, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test validate_socket_security with OS error."""
        mock_exists.return_value = True
        mock_stat.side_effect = OSError("Permission denied")

        config = LDAPIConfiguration(socket_path="/tmp/error_socket")
        errors = config.validate_socket_security()

        assert len(errors) == 1
        assert "Error checking socket" in errors[0]


class TestLDAPICredentials:
    """Test cases for LDAPICredentials."""

    def test_credentials_creation_minimal(self) -> None:
        """Test creating credentials with minimal fields."""
        creds = LDAPICredentials()

        assert creds.pid is None
        assert creds.uid is None
        assert creds.gid is None
        assert creds.username is None
        assert creds.groups == []
        assert creds.auth_id is None
        assert creds.authz_id is None
        assert isinstance(creds.obtained_at, datetime)

    def test_credentials_creation_complete(self) -> None:
        """Test creating credentials with all fields."""
        obtained_time = datetime.now(timezone.utc)
        creds = LDAPICredentials(
            pid=12345,
            uid=1000,
            gid=1000,
            username="testuser",
            groups=[1001, 1002],
            auth_id="testuser@example.com",
            authz_id="dn:uid=testuser,ou=people,dc=example,dc=com",
            obtained_at=obtained_time,
        )

        assert creds.pid == 12345
        assert creds.uid == 1000
        assert creds.gid == 1000
        assert creds.username == "testuser"
        assert creds.groups == [1001, 1002]
        assert creds.auth_id == "testuser@example.com"
        assert creds.authz_id == "dn:uid=testuser,ou=people,dc=example,dc=com"
        assert creds.obtained_at == obtained_time

    @patch("os.getuid")
    @patch("os.getgid")
    @patch("os.getpid")
    @patch("os.getgroups")
    @patch("pwd.getpwuid")
    def test_from_current_process_success(self, mock_getpwuid: Mock, mock_getgroups: Mock,
                                        mock_getpid: Mock, mock_getgid: Mock, mock_getuid: Mock) -> None:
        """Test from_current_process class method success."""
        mock_getuid.return_value = 1000
        mock_getgid.return_value = 1000
        mock_getpid.return_value = 12345
        mock_getgroups.return_value = [1001, 1002]
        mock_getpwuid.return_value = Mock(pw_name="testuser")

        creds = LDAPICredentials.from_current_process()

        assert creds.pid == 12345
        assert creds.uid == 1000
        assert creds.gid == 1000
        assert creds.username == "testuser"
        assert creds.groups == [1001, 1002]

    @patch("os.getuid")
    @patch("os.getgid")
    @patch("os.getpid")
    @patch("os.getgroups")
    @patch("pwd.getpwuid")
    def test_from_current_process_no_username(self, mock_getpwuid: Mock, mock_getgroups: Mock,
                                            mock_getpid: Mock, mock_getgid: Mock, mock_getuid: Mock) -> None:
        """Test from_current_process when username lookup fails."""
        mock_getuid.return_value = 1000
        mock_getgid.return_value = 1000
        mock_getpid.return_value = 12345
        mock_getgroups.return_value = [1001, 1002]
        mock_getpwuid.side_effect = KeyError("User not found")

        creds = LDAPICredentials.from_current_process()

        assert creds.pid == 12345
        assert creds.uid == 1000
        assert creds.gid == 1000
        assert creds.username is None
        assert creds.groups == [1001, 1002]

    def test_to_sasl_external_with_username(self) -> None:
        """Test to_sasl_external with username."""
        creds = LDAPICredentials(username="testuser")
        authz_id = creds.to_sasl_external()

        assert authz_id == "dn:uid=testuser,cn=external,cn=auth"

    def test_to_sasl_external_with_uid(self) -> None:
        """Test to_sasl_external with UID only."""
        creds = LDAPICredentials(uid=1000)
        authz_id = creds.to_sasl_external()

        assert authz_id == "dn:uid=1000,cn=external,cn=auth"

    def test_to_sasl_external_empty(self) -> None:
        """Test to_sasl_external with no identifier."""
        creds = LDAPICredentials()
        authz_id = creds.to_sasl_external()

        assert authz_id == ""

    def test_to_sasl_external_prefers_username(self) -> None:
        """Test to_sasl_external prefers username over UID."""
        creds = LDAPICredentials(username="testuser", uid=1000)
        authz_id = creds.to_sasl_external()

        assert authz_id == "dn:uid=testuser,cn=external,cn=auth"


class TestLDAPITransport:
    """Test cases for LDAPITransport."""

    def test_transport_initialization(self) -> None:
        """Test transport initialization."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        assert transport._config is config
        assert transport._socket is None
        assert transport._connected is False
        assert transport._peer_credentials is None

    def test_transport_properties_disconnected(self) -> None:
        """Test transport properties when disconnected."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        assert transport.connected is False
        assert transport.peer_credentials is None
        assert transport.socket is None

    @patch("socket.socket")
    async def test_connect_security_validation_failure(self, mock_socket: Mock) -> None:
        """Test connect with security validation failure."""
        config = LDAPIConfiguration(socket_path="/nonexistent/socket")
        transport = LDAPITransport(config)

        with pytest.raises(PermissionError, match="Socket security validation failed"):
            await transport.connect()

    @patch.object(LDAPIConfiguration, "validate_socket_security")
    @patch("socket.socket")
    async def test_connect_socket_creation_failure(self, mock_socket_class: Mock, mock_validate: Mock) -> None:
        """Test connect with socket creation failure."""
        mock_validate.return_value = []  # No security errors
        mock_socket_class.side_effect = OSError("Socket creation failed")

        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        with pytest.raises(ConnectionError, match="Failed to connect to Unix socket"):
            await transport.connect()

    @patch.object(LDAPIConfiguration, "validate_socket_security")
    @patch("socket.socket")
    async def test_connect_success_minimal(self, mock_socket_class: Mock, mock_validate: Mock) -> None:
        """Test successful connect with minimal configuration."""
        mock_validate.return_value = []  # No security errors
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        await transport.connect()

        # Verify socket configuration
        mock_socket_class.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        mock_socket.settimeout.assert_called_once_with(config.connect_timeout)
        mock_socket.connect.assert_called_once_with("/var/run/ldapi")

        assert transport.connected is True
        assert transport.socket is mock_socket

    @patch.object(LDAPIConfiguration, "validate_socket_security")
    @patch("socket.socket")
    async def test_connect_success_with_buffer_sizes(self, mock_socket_class: Mock, mock_validate: Mock) -> None:
        """Test successful connect with buffer size configuration."""
        mock_validate.return_value = []  # No security errors
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        config = LDAPIConfiguration(
            socket_path="/var/run/ldapi",
            send_buffer_size=8192,
            recv_buffer_size=4096,
        )
        transport = LDAPITransport(config)

        await transport.connect()

        # Verify socket options
        expected_calls = [
            ((socket.SOL_SOCKET, socket.SO_SNDBUF, 8192),),
            ((socket.SOL_SOCKET, socket.SO_RCVBUF, 4096),),
        ]
        mock_socket.setsockopt.assert_has_calls(expected_calls, any_order=True)

    @patch.object(LDAPIConfiguration, "validate_socket_security")
    @patch("socket.socket")
    @patch.object(LDAPITransport, "_get_peer_credentials")
    async def test_connect_with_peer_credentials(self, mock_get_creds: Mock, mock_socket_class: Mock, mock_validate: Mock) -> None:
        """Test connect with peer credentials enabled."""
        mock_validate.return_value = []  # No security errors
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_credentials = LDAPICredentials(pid=123, uid=1000, gid=1000)
        mock_get_creds.return_value = mock_credentials

        config = LDAPIConfiguration(
            socket_path="/var/run/ldapi",
            use_peer_credentials=True,
        )
        transport = LDAPITransport(config)

        await transport.connect()

        mock_get_creds.assert_called_once()
        assert transport.peer_credentials is mock_credentials

    @patch.object(LDAPIConfiguration, "validate_socket_security")
    @patch("socket.socket")
    async def test_connect_failure_cleanup(self, mock_socket_class: Mock, mock_validate: Mock) -> None:
        """Test connect failure performs proper cleanup."""
        mock_validate.return_value = []  # No security errors
        mock_socket = Mock()
        mock_socket.connect.side_effect = OSError("Connection failed")
        mock_socket_class.return_value = mock_socket

        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        with pytest.raises(ConnectionError):
            await transport.connect()

        # Verify cleanup
        mock_socket.close.assert_called_once()
        assert transport._socket is None

    async def test_disconnect_no_socket(self) -> None:
        """Test disconnect when no socket exists."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        # Should not raise exception
        await transport.disconnect()

        assert transport._connected is False

    async def test_disconnect_with_socket(self) -> None:
        """Test disconnect with active socket."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        # Simulate connected state
        mock_socket = Mock()
        transport._socket = mock_socket
        transport._connected = True
        transport._peer_credentials = LDAPICredentials()

        await transport.disconnect()

        mock_socket.close.assert_called_once()
        assert transport._socket is None
        assert transport._connected is False
        assert transport._peer_credentials is None

    async def test_disconnect_with_socket_error(self) -> None:
        """Test disconnect handles socket close error gracefully."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        # Simulate connected state with failing socket
        mock_socket = Mock()
        mock_socket.close.side_effect = OSError("Close failed")
        transport._socket = mock_socket
        transport._connected = True

        # Should not raise exception
        await transport.disconnect()

        assert transport._socket is None
        assert transport._connected is False

    @patch("socket.SO_PEERCRED", 1, create=True)
    def test_get_peer_credentials_linux(self) -> None:
        """Test _get_peer_credentials on Linux."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        # Mock socket with peer credentials
        mock_socket = Mock()
        # Pack pid=123, uid=1000, gid=1000 as 3 32-bit integers
        import struct
        creds_data = struct.pack("3i", 123, 1000, 1000)
        mock_socket.getsockopt.return_value = creds_data
        transport._socket = mock_socket

        credentials = transport._get_peer_credentials()

        assert credentials is not None
        assert credentials.pid == 123
        assert credentials.uid == 1000
        assert credentials.gid == 1000

    def test_get_peer_credentials_no_socket(self) -> None:
        """Test _get_peer_credentials with no socket."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        credentials = transport._get_peer_credentials()
        assert credentials is None

    def test_get_peer_credentials_not_supported(self) -> None:
        """Test _get_peer_credentials when not supported."""
        config = LDAPIConfiguration(socket_path="/var/run/ldapi")
        transport = LDAPITransport(config)

        mock_socket = Mock()
        mock_socket.getsockopt.side_effect = OSError("Not supported")
        transport._socket = mock_socket

        credentials = transport._get_peer_credentials()
        assert credentials is None


class TestLDAPIProtocol:
    """Test cases for LDAPIProtocol."""

    def test_protocol_initialization_default(self) -> None:
        """Test protocol initialization with default configuration."""
        protocol = LDAPIProtocol()

        assert protocol.protocol_name == "ldapi"
        assert protocol.default_port is None
        assert protocol._config.socket_path == "/var/run/ldapi"
        assert protocol._transport is None

    def test_protocol_initialization_with_config(self) -> None:
        """Test protocol initialization with custom configuration."""
        config = LDAPIConfiguration(socket_path="/tmp/custom.sock")
        protocol = LDAPIProtocol(config)

        assert protocol._config is config
        assert protocol._config.socket_path == "/tmp/custom.sock"

    async def test_connect_invalid_scheme(self) -> None:
        """Test connect with invalid URL scheme."""
        protocol = LDAPIProtocol()

        with pytest.raises(ValueError, match="Invalid LDAPI URL scheme"):
            await protocol.connect("http://example.com")

    async def test_connect_no_socket_path(self) -> None:
        """Test connect with URL missing socket path."""
        protocol = LDAPIProtocol()

        with pytest.raises(ValueError, match="Socket path not specified"):
            await protocol.connect("ldapi://")

    @patch.object(LDAPITransport, "connect")
    async def test_connect_success(self, mock_transport_connect: Mock) -> None:
        """Test successful connect."""
        mock_transport_connect.return_value = None

        protocol = LDAPIProtocol()
        await protocol.connect("ldapi:///var/run/custom.sock")

        assert protocol._config.socket_path == "/var/run/custom.sock"
        assert isinstance(protocol._transport, LDAPITransport)
        mock_transport_connect.assert_called_once()

    @patch.object(LDAPITransport, "connect")
    async def test_connect_url_encoded_path(self, mock_transport_connect: Mock) -> None:
        """Test connect with URL-encoded socket path."""
        mock_transport_connect.return_value = None

        protocol = LDAPIProtocol()
        await protocol.connect("ldapi:///var/run/ldapi%2Fsocket")

        assert protocol._config.socket_path == "/var/run/ldapi/socket"

    async def test_disconnect_no_transport(self) -> None:
        """Test disconnect when no transport exists."""
        protocol = LDAPIProtocol()

        # Should not raise exception
        await protocol.disconnect()

    @patch.object(LDAPITransport, "disconnect")
    async def test_disconnect_with_transport(self, mock_transport_disconnect: Mock) -> None:
        """Test disconnect with active transport."""
        mock_transport_disconnect.return_value = None

        protocol = LDAPIProtocol()
        protocol._transport = LDAPITransport(
            LDAPIConfiguration(socket_path="/var/run/ldapi"),
        )

        await protocol.disconnect()

        mock_transport_disconnect.assert_called_once()
        assert protocol._transport is None

    async def test_authenticate_external_not_implemented(self) -> None:
        """Test authenticate_external raises NotImplementedError."""
        protocol = LDAPIProtocol()

        with pytest.raises(NotImplementedError, match="LDAPI EXTERNAL authentication requires SASL"):
            await protocol.authenticate_external()

    def test_get_peer_credentials_no_transport(self) -> None:
        """Test get_peer_credentials with no transport."""
        protocol = LDAPIProtocol()

        credentials = protocol.get_peer_credentials()
        assert credentials is None

    def test_get_peer_credentials_with_transport(self) -> None:
        """Test get_peer_credentials with transport."""
        protocol = LDAPIProtocol()
        mock_transport = Mock()
        mock_credentials = LDAPICredentials(uid=1000)
        mock_transport.peer_credentials = mock_credentials
        protocol._transport = mock_transport

        credentials = protocol.get_peer_credentials()
        assert credentials is mock_credentials

    def test_connected_no_transport(self) -> None:
        """Test connected property with no transport."""
        protocol = LDAPIProtocol()

        assert protocol.connected is False

    def test_connected_with_transport(self) -> None:
        """Test connected property with transport."""
        protocol = LDAPIProtocol()
        mock_transport = Mock()
        mock_transport.connected = True
        protocol._transport = mock_transport

        assert protocol.connected is True

    def test_transport_property(self) -> None:
        """Test transport property."""
        protocol = LDAPIProtocol()
        mock_transport = Mock()
        protocol._transport = mock_transport

        assert protocol.transport is mock_transport

    def test_configuration_property(self) -> None:
        """Test configuration property."""
        config = LDAPIConfiguration(socket_path="/tmp/test.sock")
        protocol = LDAPIProtocol(config)

        assert protocol.configuration is config


class TestLDAPIConnection:
    """Test cases for LDAPIConnection."""

    def test_connection_initialization(self) -> None:
        """Test connection initialization."""
        connection = LDAPIConnection(
            socket_path="/var/run/ldapi",
            auth_method=LDAPIAuthMethod.SIMPLE,
            socket_type=LDAPISocketType.DGRAM,
        )

        assert connection._socket_path == "/var/run/ldapi"
        assert connection._auth_method == LDAPIAuthMethod.SIMPLE
        assert isinstance(connection._protocol, LDAPIProtocol)

    @patch.object(LDAPIProtocol, "connect")
    async def test_connect(self, mock_protocol_connect: Mock) -> None:
        """Test connection connect method."""
        mock_protocol_connect.return_value = None

        connection = LDAPIConnection("/var/run/ldapi")
        await connection.connect()

        expected_url = "ldapi:///var/run/ldapi"
        mock_protocol_connect.assert_called_once_with(expected_url)

    @patch.object(LDAPIProtocol, "connect")
    async def test_connect_url_encoding(self, mock_protocol_connect: Mock) -> None:
        """Test connection connect with URL encoding."""
        mock_protocol_connect.return_value = None

        connection = LDAPIConnection("/var/run/ldapi/socket")
        await connection.connect()

        expected_url = "ldapi:///var/run/ldapi%2Fsocket"
        mock_protocol_connect.assert_called_once_with(expected_url)

    async def test_bind_external_not_implemented(self) -> None:
        """Test bind_external raises NotImplementedError."""
        connection = LDAPIConnection("/var/run/ldapi")

        with pytest.raises(NotImplementedError, match="LDAPI EXTERNAL bind requires SASL"):
            await connection.bind_external()

    def test_get_connection_info(self) -> None:
        """Test get_connection_info method."""
        connection = LDAPIConnection(
            "/var/run/ldapi",
            auth_method=LDAPIAuthMethod.EXTERNAL,
        )

        # Mock protocol with credentials
        mock_credentials = LDAPICredentials(uid=1000, username="test")
        connection._protocol.get_peer_credentials = Mock(return_value=mock_credentials)

        info = connection.get_connection_info()

        assert info["protocol"] == "ldapi"
        assert info["socket_path"] == "/var/run/ldapi"
        assert info["auth_method"] == "external"
        assert info["peer_credentials"] == mock_credentials.dict()

    def test_get_connection_info_no_credentials(self) -> None:
        """Test get_connection_info with no peer credentials."""
        connection = LDAPIConnection("/var/run/ldapi")

        # Mock protocol without credentials
        connection._protocol.get_peer_credentials = Mock(return_value=None)

        info = connection.get_connection_info()

        assert info["peer_credentials"] is None

    def test_socket_path_property(self) -> None:
        """Test socket_path property."""
        connection = LDAPIConnection("/custom/path")

        assert connection.socket_path == "/custom/path"

    def test_auth_method_property(self) -> None:
        """Test auth_method property."""
        connection = LDAPIConnection(
            "/var/run/ldapi",
            auth_method=LDAPIAuthMethod.PEER_CREDENTIALS,
        )

        assert connection.auth_method == LDAPIAuthMethod.PEER_CREDENTIALS


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_create_ldapi_connection_default(self) -> None:
        """Test create_ldapi_connection with defaults."""
        connection = create_ldapi_connection()

        assert isinstance(connection, LDAPIConnection)
        assert connection.socket_path == "/var/run/ldapi"
        assert connection.auth_method == LDAPIAuthMethod.EXTERNAL

    def test_create_ldapi_connection_custom(self) -> None:
        """Test create_ldapi_connection with custom parameters."""
        connection = create_ldapi_connection(
            socket_path="/tmp/custom.sock",
            auth_method=LDAPIAuthMethod.SIMPLE,
        )

        assert connection.socket_path == "/tmp/custom.sock"
        assert connection.auth_method == LDAPIAuthMethod.SIMPLE

    def test_parse_ldapi_url_basic(self) -> None:
        """Test parse_ldapi_url with basic URL."""
        socket_path, params = parse_ldapi_url("ldapi:///var/run/ldapi")

        assert socket_path == "/var/run/ldapi"
        assert params == {}

    def test_parse_ldapi_url_encoded(self) -> None:
        """Test parse_ldapi_url with URL encoding."""
        socket_path, _params = parse_ldapi_url("ldapi:///var/run/ldapi%2Fsocket")

        assert socket_path == "/var/run/ldapi/socket"

    def test_parse_ldapi_url_with_query(self) -> None:
        """Test parse_ldapi_url with query parameters."""
        socket_path, params = parse_ldapi_url(
            "ldapi:///var/run/ldapi?auth=external&timeout=30",
        )

        assert socket_path == "/var/run/ldapi"
        assert params == {"auth": "external", "timeout": "30"}

    def test_parse_ldapi_url_multiple_values(self) -> None:
        """Test parse_ldapi_url with multiple parameter values."""
        socket_path, params = parse_ldapi_url(
            "ldapi:///var/run/ldapi?groups=1000&groups=1001",
        )

        assert socket_path == "/var/run/ldapi"
        assert params == {"groups": ["1000", "1001"]}

    def test_parse_ldapi_url_no_path(self) -> None:
        """Test parse_ldapi_url with no path."""
        socket_path, params = parse_ldapi_url("ldapi://")

        assert socket_path == "/var/run/ldapi"  # Default
        assert params == {}

    def test_parse_ldapi_url_invalid_scheme(self) -> None:
        """Test parse_ldapi_url with invalid scheme."""
        with pytest.raises(ValueError, match="Invalid LDAPI URL scheme"):
            parse_ldapi_url("http://example.com")


class TestSocketTesting:
    """Test cases for test_ldapi_socket function."""

    async def test_test_ldapi_socket_nonexistent(self) -> None:
        """Test test_ldapi_socket with nonexistent socket."""
        result = await test_ldapi_socket("/nonexistent/socket")

        assert result["socket_path"] == "/nonexistent/socket"
        assert result["exists"] is False
        assert result["is_socket"] is False
        assert result["accessible"] is False
        assert result["secure"] is True
        assert result["security_errors"] == []

    @patch("os.path.exists")
    @patch("os.stat")
    async def test_test_ldapi_socket_exists_not_socket(self, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test test_ldapi_socket with existing non-socket file."""
        mock_exists.return_value = True
        mock_stat.return_value = Mock(
            st_mode=0o100644,  # Regular file
            st_uid=1000,
        )

        result = await test_ldapi_socket("/tmp/not_socket")

        assert result["exists"] is True
        assert result["is_socket"] is False
        assert result["permissions"] == "0o644"
        assert result["owner"] == 1000

    @patch("os.path.exists")
    @patch("os.stat")
    @patch("socket.socket")
    async def test_test_ldapi_socket_accessible(self, mock_socket_class: Mock, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test test_ldapi_socket with accessible socket."""
        mock_exists.return_value = True
        mock_stat.return_value = Mock(
            st_mode=stat.S_IFSOCK | 0o600,  # Socket file
            st_uid=1000,
        )

        # Mock successful socket connection
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        result = await test_ldapi_socket("/var/run/ldapi")

        assert result["exists"] is True
        assert result["is_socket"] is True
        assert result["accessible"] is True
        assert result["permissions"] == "0o600"
        assert result["owner"] == 1000

        # Verify socket operations
        mock_socket_class.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        mock_socket.settimeout.assert_called_once_with(1.0)
        mock_socket.connect.assert_called_once_with("/var/run/ldapi")
        mock_socket.close.assert_called_once()

    @patch("os.path.exists")
    @patch("os.stat")
    @patch("socket.socket")
    async def test_test_ldapi_socket_not_accessible(self, mock_socket_class: Mock, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test test_ldapi_socket with inaccessible socket."""
        mock_exists.return_value = True
        mock_stat.return_value = Mock(
            st_mode=stat.S_IFSOCK | 0o600,  # Socket file
            st_uid=1000,
        )

        # Mock failed socket connection
        mock_socket = Mock()
        mock_socket.connect.side_effect = OSError("Connection refused")
        mock_socket_class.return_value = mock_socket

        result = await test_ldapi_socket("/var/run/ldapi")

        assert result["accessible"] is False

    @patch("os.path.exists")
    @patch("os.stat")
    async def test_test_ldapi_socket_stat_error(self, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test test_ldapi_socket with stat error."""
        mock_exists.return_value = True
        mock_stat.side_effect = OSError("Permission denied")

        result = await test_ldapi_socket("/var/run/ldapi")

        assert "error" in result
        assert "Permission denied" in result["error"]


class TestIntegrationScenarios:
    """Integration test scenarios."""

    async def test_full_connection_lifecycle(self) -> None:
        """Test complete connection lifecycle."""
        # This would be an integration test with actual socket
        # For unit testing, we mock the components

        with patch.object(LDAPIConfiguration, "validate_socket_security") as mock_validate, \
             patch("socket.socket") as mock_socket_class:

            mock_validate.return_value = []  # No security errors
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket

            # Create connection
            connection = LDAPIConnection("/var/run/ldapi")

            # Connect
            await connection.connect()

            # Verify connection state
            assert connection.connected  # This calls protocol.connected

            # Disconnect
            await connection.disconnect()

    def test_multiple_auth_methods(self) -> None:
        """Test different authentication methods."""
        auth_methods = [
            LDAPIAuthMethod.EXTERNAL,
            LDAPIAuthMethod.SIMPLE,
            LDAPIAuthMethod.ANONYMOUS,
            LDAPIAuthMethod.PEER_CREDENTIALS,
        ]

        for auth_method in auth_methods:
            connection = LDAPIConnection(
                "/var/run/ldapi",
                auth_method=auth_method,
            )
            assert connection.auth_method == auth_method

    def test_multiple_socket_types(self) -> None:
        """Test different socket types."""
        socket_types = [
            LDAPISocketType.STREAM,
            LDAPISocketType.DGRAM,
            LDAPISocketType.SEQPACKET,
        ]

        for socket_type in socket_types:
            config = LDAPIConfiguration(
                socket_path="/var/run/ldapi",
                socket_type=socket_type,
            )

            expected_constants = {
                LDAPISocketType.STREAM: socket.SOCK_STREAM,
                LDAPISocketType.DGRAM: socket.SOCK_DGRAM,
                LDAPISocketType.SEQPACKET: socket.SOCK_SEQPACKET,
            }

            assert config.get_socket_type() == expected_constants[socket_type]


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_socket_path_validation_security(self) -> None:
        """Test socket path validation for security."""
        # Test directory traversal protection
        valid_paths = [
            "/var/run/ldapi",
            "/tmp/ldapi.sock",
            "/usr/local/var/ldapi",
        ]

        for path in valid_paths:
            config = LDAPIConfiguration(socket_path=path)
            assert config.socket_path == path

        # Test invalid paths
        invalid_paths = [
            "",
            "   ",
            "relative/path",
            "../etc/passwd",
        ]

        for path in invalid_paths:
            with pytest.raises(ValueError):
                LDAPIConfiguration(socket_path=path)

    @patch("os.path.exists")
    @patch("os.stat")
    def test_comprehensive_security_validation(self, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test comprehensive security validation."""
        mock_exists.return_value = True

        # Test various security scenarios
        security_scenarios = [
            # (mode, uid, current_uid, allowed_owners, should_have_errors)
            (stat.S_IFSOCK | 0o600, 1000, 1000, [], False),  # Owner access
            (stat.S_IFSOCK | 0o777, 1000, 1000, [], True),   # World writable
            (stat.S_IFSOCK | 0o600, 0, 1000, [], False),     # Root owned
            (stat.S_IFSOCK | 0o600, 2000, 1000, [2000], False),  # Allowed owner
            (stat.S_IFSOCK | 0o600, 2000, 1000, [], True),   # Wrong owner
        ]

        for mode, uid, current_uid, allowed_owners, should_have_errors in security_scenarios:
            mock_stat.return_value = Mock(st_mode=mode, st_uid=uid)

            with patch("os.getuid", return_value=current_uid):
                config = LDAPIConfiguration(
                    socket_path="/var/run/ldapi",
                    allowed_socket_owners=allowed_owners,
                )
                errors = config.validate_socket_security()

                if should_have_errors:
                    assert len(errors) > 0
                else:
                    assert len(errors) == 0

    def test_credential_security(self) -> None:
        """Test credential handling security."""
        # Test credential creation with minimal exposure
        creds = LDAPICredentials(
            username="testuser",
            uid=1000,
            gid=1000,
        )

        # Test SASL external conversion
        authz_id = creds.to_sasl_external()
        assert "testuser" in authz_id
        assert "external" in authz_id

        # Test that credentials have timestamp
        assert isinstance(creds.obtained_at, datetime)
        assert creds.obtained_at.tzinfo is not None


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_configuration_creation_performance(self) -> None:
        """Test configuration creation performance."""
        import time

        start_time = time.time()

        # Create many configuration objects
        for i in range(1000):
            LDAPIConfiguration(
                socket_path=f"/var/run/ldapi_{i}",
                socket_type=LDAPISocketType.STREAM,
                auth_method=LDAPIAuthMethod.EXTERNAL,
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Less than 1 second for 1000 configs

    def test_credential_creation_performance(self) -> None:
        """Test credential creation performance."""
        import time

        start_time = time.time()

        # Create many credential objects
        for i in range(1000):
            LDAPICredentials(
                username=f"user{i}",
                uid=1000 + i,
                gid=1000,
                groups=[1001, 1002],
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Less than 1 second for 1000 credentials

    @patch("os.path.exists")
    @patch("os.stat")
    def test_security_validation_performance(self, mock_stat: Mock, mock_exists: Mock) -> None:
        """Test security validation performance."""
        import time

        mock_exists.return_value = True
        mock_stat.return_value = Mock(
            st_mode=stat.S_IFSOCK | 0o600,
            st_uid=1000,
        )

        config = LDAPIConfiguration(socket_path="/var/run/ldapi")

        start_time = time.time()

        # Perform many security validations
        for _ in range(1000):
            config.validate_socket_security()

        validation_time = time.time() - start_time

        # Should validate quickly
        assert validation_time < 1.0  # Less than 1 second for 1000 validations


class TestErrorHandling:
    """Error handling test cases."""

    def test_configuration_validation_errors(self) -> None:
        """Test configuration validation error handling."""
        # Test various validation error scenarios
        error_scenarios = [
            ("", "Socket path cannot be empty"),
            ("   ", "Socket path cannot be empty"),
            ("relative/path", "Socket path must be absolute"),
        ]

        for invalid_path, expected_error in error_scenarios:
            with pytest.raises(ValueError, match=expected_error):
                LDAPIConfiguration(socket_path=invalid_path)

    async def test_transport_error_handling(self) -> None:
        """Test transport error handling."""
        config = LDAPIConfiguration(socket_path="/nonexistent/socket")
        transport = LDAPITransport(config)

        # Test connection error handling
        with pytest.raises(PermissionError):
            await transport.connect()

        # Transport should remain in disconnected state
        assert transport.connected is False

    async def test_protocol_error_handling(self) -> None:
        """Test protocol error handling."""
        protocol = LDAPIProtocol()

        # Test invalid URL schemes
        invalid_urls = [
            "http://example.com",
            "ldap://example.com",
            "ftp://example.com",
        ]

        for url in invalid_urls:
            with pytest.raises(ValueError, match="Invalid LDAPI URL scheme"):
                await protocol.connect(url)

        # Test missing socket path
        with pytest.raises(ValueError, match="Socket path not specified"):
            await protocol.connect("ldapi://")

    def test_url_parsing_error_handling(self) -> None:
        """Test URL parsing error handling."""
        # Test invalid schemes
        with pytest.raises(ValueError, match="Invalid LDAPI URL scheme"):
            parse_ldapi_url("http://example.com")

        # Valid URLs should not raise errors
        valid_urls = [
            "ldapi:///var/run/ldapi",
            "ldapi:///tmp/ldapi.sock",
            "ldapi://",  # Uses default path
        ]

        for url in valid_urls:
            socket_path, params = parse_ldapi_url(url)
            assert isinstance(socket_path, str)
            assert isinstance(params, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
