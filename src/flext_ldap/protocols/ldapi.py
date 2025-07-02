from __future__ import annotations

from flext_ldap.utils.constants import DEFAULT_TIMEOUT_SECONDS

"""LDAP over Unix Domain Sockets (LDAPI) Protocol Implementation.

This module provides LDAPI (LDAP over IPC) protocol support following perl-ldap
patterns with enterprise-grade Unix domain socket connections, authentication,
and local system integration capabilities.

LDAPI enables high-performance local LDAP connections using Unix domain sockets,
providing secure authentication through Unix credentials and efficient
communication for same-host applications and administrative tools.

Architecture:
    - LDAPIProtocol: Core LDAPI protocol implementation
    - LDAPIConnection: Connection manager for Unix domain sockets
    - LDAPIAuthentication: Unix credential-based authentication
    - LDAPITransport: Unix socket transport layer

Usage Example:
    >>> from flext_ldapdapi import LDAPIConnection
    >>>
    >>> # Connect using Unix domain socket
    >>> connection = LDAPIConnection("/var/run/ldapi")
    >>> await connection.connect()
    >>>
    >>> # Authenticate using Unix credentials
    >>> await connection.bind_external()  # EXTERNAL SASL mechanism
    >>>
    >>> # Perform operations with high performance
    >>> results = await connection.search(
    ...     "dc=example,dc=com",
    ...     "(objectClass=*)"
    ... )

References:
    - perl-ldap: lib/Net/LDAP.pm (ldapi:// URL support)
    - RFC 4511: LDAP Protocol Specification
    - RFC 4513: LDAP Authentication Methods
    - Unix domain sockets and credential passing
"""


import os
import socket
import stat
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from urllib.parse import unquote, urlparse

from pydantic import BaseModel, Field, validator

from flext_ldap.exceptions.connection import LDAPConnectionError


class LDAPIAuthMethod(Enum):
    """Authentication methods for LDAPI connections."""

    EXTERNAL = "external"  # EXTERNAL SASL mechanism using Unix credentials
    SIMPLE = "simple"  # Simple bind with credentials
    ANONYMOUS = "anonymous"  # Anonymous bind
    PEER_CREDENTIALS = "peer_credentials"  # Unix peer credential authentication


class LDAPISocketType(Enum):
    """Types of Unix domain sockets."""

    STREAM = "stream"  # SOCK_STREAM (default for LDAPI)
    DGRAM = "dgram"  # SOCK_DGRAM (less common)
    SEQPACKET = "seqpacket"  # SOCK_SEQPACKET (reliable ordered)


class LDAPIConfiguration(BaseModel):
    """Configuration for LDAPI connections."""

    socket_path: str = Field(description="Path to Unix domain socket")

    socket_type: LDAPISocketType = Field(
        default=LDAPISocketType.STREAM,
        description="Type of Unix socket",
    )

    # Authentication settings
    auth_method: LDAPIAuthMethod = Field(
        default=LDAPIAuthMethod.EXTERNAL,
        description="Authentication method",
    )

    use_peer_credentials: bool = Field(
        default=True,
        description="Whether to use peer credential passing",
    )

    # Connection settings
    connect_timeout: float = Field(
        default=DEFAULT_TIMEOUT_SECONDS,
        description="Connection timeout in seconds",
    )

    socket_permissions: int | None = Field(
        default=None,
        description="Socket file permissions (octal)",
    )

    # Security settings
    verify_socket_owner: bool = Field(
        default=True,
        description="Whether to verify socket owner",
    )

    allowed_socket_owners: list[int] = Field(
        default_factory=list,
        description="List of allowed socket owner UIDs",
    )

    require_secure_path: bool = Field(
        default=True,
        description="Whether socket path must be secure",
    )

    # Performance settings
    send_buffer_size: int | None = Field(
        default=None,
        description="Socket send buffer size",
    )

    recv_buffer_size: int | None = Field(
        default=None,
        description="Socket receive buffer size",
    )

    @validator("socket_path")
    def validate_socket_path(self, v: str) -> str:
        """Validate Unix socket path."""
        if not v or not v.strip():
            msg = "Socket path cannot be empty"
            raise ValueError(msg)

        # Remove URL encoding if present
        if "%" in v:
            v = unquote(v)

        # Ensure absolute path
        if not os.path.isabs(v):
            msg = "Socket path must be absolute"
            raise ValueError(msg)

        return v.strip()

    def get_socket_family(self) -> int:
        """Get socket family constant."""
        return socket.AF_UNIX

    def get_socket_type(self) -> int:
        """Get socket type constant."""
        type_mapping = {
            LDAPISocketType.STREAM: socket.SOCK_STREAM,
            LDAPISocketType.DGRAM: socket.SOCK_DGRAM,
            LDAPISocketType.SEQPACKET: socket.SOCK_SEQPACKET,
        }
        return type_mapping[self.socket_type]

    def validate_socket_security(self) -> list[str]:
        """Validate socket security requirements.

        Returns:
            List of security validation errors
        """
        errors = []

        if not os.path.exists(self.socket_path):
            errors.append(f"Socket path does not exist: {self.socket_path}")
            return errors

        try:
            stat_info = os.stat(self.socket_path)

            # Check if it's a socket
            if not stat.S_ISSOCK(stat_info.st_mode):
                errors.append(f"Path is not a socket: {self.socket_path}")

            # Check socket permissions
            mode = stat_info.st_mode & 0o777
            if self.require_secure_path and mode & 0o077:  # World/group writable
                errors.append(f"Socket has insecure permissions: {oct(mode)}")

            # Check socket owner
            if self.verify_socket_owner:
                socket_uid = stat_info.st_uid
                current_uid = os.getuid()

                if self.allowed_socket_owners:
                    if socket_uid not in self.allowed_socket_owners:
                        errors.append(f"Socket owner {socket_uid} not in allowed list")
                elif socket_uid not in {current_uid, 0}:  # Not owned by user or root
                    errors.append(f"Socket owned by different user: {socket_uid}")

        except OSError as e:
            errors.append(f"Error checking socket: {e}")

        return errors


class LDAPICredentials(BaseModel):
    """Unix credentials for LDAPI authentication."""

    # Unix process credentials
    pid: int | None = Field(default=None, description="Process ID")
    uid: int | None = Field(default=None, description="User ID")
    gid: int | None = Field(default=None, description="Group ID")

    # Additional credentials
    username: str | None = Field(default=None, description="Unix username")
    groups: list[int] = Field(
        default_factory=list,
        description="Supplementary group IDs",
    )

    # Authentication data
    auth_id: str | None = Field(default=None, description="Authentication identity")
    authz_id: str | None = Field(default=None, description="Authorization identity")

    # Credential metadata
    obtained_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When credentials were obtained",
    )

    @classmethod
    def from_current_process(cls) -> LDAPICredentials:
        """Create credentials from current process.

        Returns:
            LDAPICredentials for current process
        """
        import pwd

        uid = os.getuid()
        gid = os.getgid()
        pid = os.getpid()

        try:
            user_info = pwd.getpwuid(uid)
            username = user_info.pw_name
        except KeyError:
            username = None

        return cls(
            pid=pid,
            uid=uid,
            gid=gid,
            username=username,
            groups=os.getgroups(),
        )

    def to_sasl_external(self) -> str:
        """Convert to SASL EXTERNAL authorization identity.

        Returns:
            SASL EXTERNAL authz-id string
        """
        if self.username:
            return f"dn:uid={self.username},cn=external,cn=auth"
        if self.uid is not None:
            return f"dn:uid={self.uid},cn=external,cn=auth"
        return ""


class LDAPITransport:
    """Unix domain socket transport for LDAPI."""

    def __init__(self, config: LDAPIConfiguration) -> None:
        """Initialize LDAPI transport.

        Args:
            config: LDAPI configuration
        """
        self._config = config
        self._socket: socket.socket | None = None
        self._connected = False
        self._peer_credentials: LDAPICredentials | None = None

    async def connect(self) -> None:
        """Connect to Unix domain socket.

        Raises:
            ConnectionError: If connection fails
            PermissionError: If socket access denied
        """
        # Validate socket security
        security_errors = self._config.validate_socket_security()
        if security_errors:
            msg = f"Socket security validation failed: {'; '.join(security_errors)}"
            raise PermissionError(
                msg,
            )

        try:
            # Create socket
            self._socket = socket.socket(
                self._config.get_socket_family(),
                self._config.get_socket_type(),
            )

            # Configure socket options
            if self._config.send_buffer_size:
                self._socket.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_SNDBUF,
                    self._config.send_buffer_size,
                )

            if self._config.recv_buffer_size:
                self._socket.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_RCVBUF,
                    self._config.recv_buffer_size,
                )

            # Set socket timeout
            self._socket.settimeout(self._config.connect_timeout)

            # Connect to Unix socket
            self._socket.connect(self._config.socket_path)
            self._connected = True

            # Get peer credentials if supported
            if self._config.use_peer_credentials:
                self._peer_credentials = self._get_peer_credentials()

        except Exception as e:
            if self._socket:
                self._socket.close()
                self._socket = None
            msg = f"Failed to connect to Unix socket {self._config.socket_path}: {e}"
            raise LDAPConnectionError(
                msg,
            )

    async def disconnect(self) -> None:
        """Disconnect from Unix domain socket."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            finally:
                self._socket = None
                self._connected = False
                self._peer_credentials = None

    def _get_peer_credentials(self) -> LDAPICredentials | None:
        """Get peer credentials from socket.

        Returns:
            Peer credentials or None if not available
        """
        if not self._socket:
            return None

        try:
            # Try to get peer credentials (Linux-specific)
            if hasattr(socket, "SO_PEERCRED"):
                creds = self._socket.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    12,
                )
                import struct

                pid, uid, gid = struct.unpack("3i", creds)

                return LDAPICredentials(pid=pid, uid=uid, gid=gid)
        except (OSError, AttributeError):
            pass

        return None

    @property
    def connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected and self._socket is not None

    @property
    def peer_credentials(self) -> LDAPICredentials | None:
        """Get peer credentials."""
        return self._peer_credentials

    @property
    def socket(self) -> socket.socket | None:
        """Get underlying socket."""
        return self._socket


class LDAPIProtocol(LDAPProtocol):
    """LDAPI protocol implementation."""

    protocol_name = "ldapi"
    default_port = None  # Unix sockets don't use ports

    def __init__(self, config: LDAPIConfiguration | None = None) -> None:
        """Initialize LDAPI protocol.

        Args:
            config: LDAPI configuration
        """
        self._config = config or LDAPIConfiguration(socket_path="/var/run/ldapi")
        self._transport: LDAPITransport | None = None
        super().__init__()

    async def connect(self, url: str, **kwargs: Any) -> None:
        """Connect using LDAPI protocol.

        Args:
            url: LDAPI URL (ldapi:///path/to/socket)
            **kwargs: Additional connection parameters
        """
        # Parse LDAPI URL
        parsed = urlparse(url)
        if parsed.scheme != "ldapi":
            msg = f"Invalid LDAPI URL scheme: {parsed.scheme}"
            raise ValueError(msg)

        # Extract socket path from URL
        socket_path = unquote(parsed.path) if parsed.path else self._config.socket_path
        if not socket_path:
            msg = "Socket path not specified in LDAPI URL"
            raise ValueError(msg)

        # Update configuration
        self._config.socket_path = socket_path

        # Create and connect transport
        self._transport = LDAPITransport(self._config)
        await self._transport.connect()

    async def disconnect(self) -> None:
        """Disconnect LDAPI protocol."""
        if self._transport:
            await self._transport.disconnect()
            self._transport = None

    async def authenticate_external(self) -> LDAPICredentials:
        """Authenticate using EXTERNAL SASL mechanism.

        Returns:
            Authentication credentials

        Raises:
            NotImplementedError: EXTERNAL authentication not yet implemented
        """
        # TODO: Implement EXTERNAL SASL authentication
        # This would use Unix credentials for authentication
        msg = (
            "LDAPI EXTERNAL authentication requires SASL integration. "
            "Implement EXTERNAL SASL mechanism using Unix peer credentials "
            "and proper credential passing for secure local authentication."
        )
        raise NotImplementedError(msg)

    def get_peer_credentials(self) -> LDAPICredentials | None:
        """Get peer credentials from connection.

        Returns:
            Peer credentials or None if not available
        """
        return self._transport.peer_credentials if self._transport else None

    @property
    def connected(self) -> bool:
        """Check if protocol is connected."""
        return self._transport.connected if self._transport else False

    @property
    def transport(self) -> LDAPITransport | None:
        """Get LDAPI transport."""
        return self._transport

    @property
    def configuration(self) -> LDAPIConfiguration:
        """Get LDAPI configuration."""
        return self._config


class LDAPIConnection(ProtocolConnection):
    """LDAP connection using Unix domain sockets."""

    def __init__(
        self,
        socket_path: str,
        auth_method: LDAPIAuthMethod = LDAPIAuthMethod.EXTERNAL,
        socket_type: LDAPISocketType = LDAPISocketType.STREAM,
        **kwargs: Any,
    ) -> None:
        """Initialize LDAPI connection.

        Args:
            socket_path: Path to Unix domain socket
            auth_method: Authentication method
            socket_type: Type of Unix socket
            **kwargs: Additional connection parameters
        """
        # Create LDAPI configuration
        config = LDAPIConfiguration(
            socket_path=socket_path,
            auth_method=auth_method,
            socket_type=socket_type,
        )

        # Initialize protocol
        protocol = LDAPIProtocol(config)

        # Initialize connection
        super().__init__(protocol, **kwargs)

        # Type annotation for mypy - clarify that _protocol is LDAPIProtocol
        self._protocol: LDAPIProtocol = protocol  # type: ignore[assignment]

        self._socket_path = socket_path
        self._auth_method = auth_method

    async def connect(self) -> None:
        """Connect to LDAP server via Unix domain socket."""
        ldapi_url = f"ldapi://{self._socket_path.replace('/', '%2F')}"
        await self._protocol.connect(ldapi_url)

    async def bind_external(self) -> None:
        """Bind using EXTERNAL SASL mechanism.

        Raises:
            NotImplementedError: EXTERNAL bind not yet implemented
        """
        # TODO: Implement EXTERNAL SASL bind
        # This would use Unix credentials for authentication
        msg = (
            "LDAPI EXTERNAL bind requires SASL and authentication integration. "
            "Implement EXTERNAL SASL bind using Unix peer credentials and "
            "proper LDAP bind operation with SASL mechanism support."
        )
        raise NotImplementedError(msg)

    def get_connection_info(self) -> dict[str, Any]:
        """Get connection information.

        Returns:
            Dictionary with connection details
        """
        info = super().get_connection_info()
        info.update(
            {
                "protocol": "ldapi",
                "socket_path": self._socket_path,
                "auth_method": self._auth_method.value,
                "peer_credentials": (
                    self._protocol.get_peer_credentials().dict()
                    if self._protocol.get_peer_credentials()
                    else None
                ),
            },
        )
        return info

    @property
    def socket_path(self) -> str:
        """Get Unix socket path."""
        return self._socket_path

    @property
    def auth_method(self) -> LDAPIAuthMethod:
        """Get authentication method."""
        return self._auth_method


# Convenience functions
def create_ldapi_connection(
    socket_path: str = "/var/run/ldapi",
    auth_method: LDAPIAuthMethod = LDAPIAuthMethod.EXTERNAL,
) -> LDAPIConnection:
    """Create LDAPI connection with default settings.

    Args:
        socket_path: Path to Unix domain socket
        auth_method: Authentication method

    Returns:
        Configured LDAPI connection
    """
    return LDAPIConnection(
        socket_path=socket_path,
        auth_method=auth_method,
    )


def parse_ldapi_url(url: str) -> tuple[str, dict[str, Any]]:
    """Parse LDAPI URL and extract connection parameters.

    Args:
        url: LDAPI URL (ldapi:///path/to/socket)

    Returns:
        Tuple of (socket_path, parameters)
    """
    parsed = urlparse(url)
    if parsed.scheme != "ldapi":
        msg = f"Invalid LDAPI URL scheme: {parsed.scheme}"
        raise ValueError(msg)

    # Decode socket path
    socket_path = unquote(parsed.path) if parsed.path else "/var/run/ldapi"

    # Extract query parameters
    import urllib.parse

    params = urllib.parse.parse_qs(parsed.query)

    # Convert single-item lists to values
    simplified_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    return socket_path, simplified_params


async def test_ldapi_socket(socket_path: str) -> dict[str, Any]:
    """Test LDAPI socket accessibility and security.

    Args:
        socket_path: Path to Unix domain socket

    Returns:
        Dictionary with test results
    """
    config = LDAPIConfiguration(socket_path=socket_path)

    results = {
        "socket_path": socket_path,
        "exists": os.path.exists(socket_path),
        "is_socket": False,
        "accessible": False,
        "secure": True,
        "security_errors": [],
        "permissions": None,
        "owner": None,
    }

    if results["exists"]:
        try:
            stat_info = os.stat(socket_path)
            results["is_socket"] = stat.S_ISSOCK(stat_info.st_mode)
            results["permissions"] = oct(stat_info.st_mode & 0o777)
            results["owner"] = stat_info.st_uid

            # Test security
            security_errors = config.validate_socket_security()
            results["security_errors"] = security_errors
            results["secure"] = len(security_errors) == 0

            # Test accessibility
            try:
                test_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                test_socket.settimeout(1.0)
                test_socket.connect(socket_path)
                test_socket.close()
                results["accessible"] = True
            except Exception:
                results["accessible"] = False

        except OSError as e:
            results["error"] = str(e)

    return results


# TODO: Integration points for implementation:
#
# 1. SASL Authentication Integration:
#    - Implement EXTERNAL SASL mechanism for Unix credential authentication
#    - Integration with SASL library for credential passing
#    - Proper bind operation support with SASL mechanisms
#
# 2. Socket Security and Validation:
#    - Comprehensive socket security validation
#    - Peer credential verification and authorization
#    - Socket permission and ownership enforcement
#
# 3. LDAP Protocol Integration:
#    - Integration with core LDAP protocol operations
#    - Proper message framing over Unix sockets
#    - Error handling and connection management
#
# 4. Connection Pool Integration:
#    - Unix socket connection pooling and reuse
#    - Efficient resource management for local connections
#    - Concurrent connection handling and limits
#
# 5. Performance Optimization:
#    - High-performance Unix socket communication
#    - Zero-copy operations where possible
#    - Efficient buffer management and reuse
#
# 6. Error Handling and Recovery:
#    - Comprehensive error handling for Unix socket operations
#    - Connection recovery and retry strategies
#    - Graceful handling of socket permission issues
#
# 7. Testing Requirements:
#    - Unit tests for all LDAPI functionality
#    - Integration tests with actual Unix sockets
#    - Security tests for credential passing
#    - Performance tests for local connection efficiency
