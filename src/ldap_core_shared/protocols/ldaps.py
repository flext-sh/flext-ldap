from __future__ import annotations

from ldap_core_shared.utils.constants import DEFAULT_TIMEOUT_SECONDS

"""LDAP over SSL/TLS (LDAPS) Protocol Implementation.

This module provides LDAPS protocol support following perl-ldap patterns with
enterprise-grade SSL/TLS encryption, certificate validation, and secure
communication capabilities.

LDAPS enables encrypted LDAP connections using SSL/TLS, providing confidentiality,
integrity, and authentication for directory communication in security-sensitive
environments and compliance scenarios.

Architecture:
    - LDAPSProtocol: Core LDAPS protocol implementation
    - LDAPSConnection: SSL/TLS connection manager
    - LDAPSConfiguration: SSL/TLS settings and certificate management
    - LDAPSTransport: Encrypted transport layer

Usage Example:
    >>> from ldap_core_shared.protocols.ldaps import LDAPSConnection
    >>>
    >>> # Connect using SSL/TLS encryption
    >>> connection = LDAPSConnection(
    ...     "ldaps://secure.example.com:636",
    ...     ca_cert_file="/etc/ssl/certs/ca-bundle.crt",
    ...     verify_ssl=True
    ... )
    >>> await connection.connect()
    >>>
    >>> # Authenticate over encrypted channel
    >>> await connection.bind(
    ...     "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    ...     "secure_password"
    ... )

References:
    - perl-ldap: lib/Net/LDAP.pm (ldaps:// URL support and SSL options)
    - RFC 4511: LDAP Protocol Specification
    - RFC 2830: LDAP Extension for Transport Layer Security
    - RFC 5280: Internet X.509 Public Key Infrastructure Certificate
"""


import asyncio
import ssl
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, validator

from ldap_core_shared.api.exceptions import LDAPConnectionError
from ldap_core_shared.protocols.base import (
    LDAPProtocol,
    ProtocolConnection,
    ProtocolState,
)


class SSLVersion(Enum):
    """SSL/TLS protocol versions."""

    TLS_1_0 = "TLSv1.0"
    TLS_1_1 = "TLSv1.1"
    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"
    SSL_3_0 = "SSLv3"  # Deprecated, for compatibility only


class CertificateVerification(Enum):
    """Certificate verification modes."""

    REQUIRED = "required"  # Strict certificate verification
    OPTIONAL = "optional"  # Verify if certificate present
    DISABLED = "disabled"  # No certificate verification (insecure)
    ALLOW_SELF_SIGNED = "allow_self_signed"  # Allow self-signed certificates


class CipherSuite(Enum):
    """SSL/TLS cipher suite categories."""

    HIGH_SECURITY = "high_security"  # High security ciphers only
    MEDIUM_SECURITY = "medium_security"  # Medium security ciphers
    COMPATIBILITY = "compatibility"  # Compatibility ciphers
    CUSTOM = "custom"  # Custom cipher string


class LDAPSConfiguration(BaseModel):
    """Configuration for LDAPS connections."""

    # SSL/TLS settings
    ssl_version: SSLVersion | None = Field(
        default=None,
        description="Minimum SSL/TLS version (None = system default)",
    )

    max_ssl_version: SSLVersion | None = Field(
        default=None,
        description="Maximum SSL/TLS version",
    )

    cipher_suite: CipherSuite = Field(
        default=CipherSuite.HIGH_SECURITY,
        description="Cipher suite selection",
    )

    custom_ciphers: str | None = Field(
        default=None,
        description="Custom cipher string",
    )

    # Certificate settings
    cert_verification: CertificateVerification = Field(
        default=CertificateVerification.REQUIRED,
        description="Certificate verification mode",
    )

    ca_cert_file: str | None = Field(
        default=None,
        description="CA certificate file path",
    )

    ca_cert_dir: str | None = Field(
        default=None,
        description="CA certificate directory path",
    )

    client_cert_file: str | None = Field(
        default=None,
        description="Client certificate file path",
    )

    client_key_file: str | None = Field(
        default=None,
        description="Client private key file path",
    )

    client_key_password: str | None = Field(
        default=None,
        description="Client private key password",
    )

    # Verification settings
    check_hostname: bool = Field(
        default=True,
        description="Whether to verify hostname against certificate",
    )

    verify_mode: str | None = Field(
        default=None,
        description="Certificate verification mode (CERT_REQUIRED, etc.)",
    )

    # Connection settings
    connect_timeout: float = Field(
        default=DEFAULT_TIMEOUT_SECONDS,
        description="SSL handshake timeout in seconds",
    )

    handshake_timeout: float = Field(
        default=10.0,
        description="SSL handshake timeout",
    )

    # Security options
    disable_compression: bool = Field(
        default=True,
        description="Whether to disable SSL compression",
    )

    disable_renegotiation: bool = Field(
        default=True,
        description="Whether to disable SSL renegotiation",
    )

    enable_sni: bool = Field(
        default=True,
        description="Whether to enable Server Name Indication",
    )

    # Advanced settings
    session_reuse: bool = Field(
        default=True,
        description="Whether to enable SSL session reuse",
    )

    ocsp_check: bool = Field(
        default=False,
        description="Whether to perform OCSP certificate checking",
    )

    crl_check: bool = Field(
        default=False,
        description="Whether to perform CRL certificate checking",
    )

    @validator("ca_cert_file")
    def validate_ca_cert_file(self, v: str | None) -> str | None:
        """Validate CA certificate file exists."""
        if v and not Path(v).exists():
            msg = f"CA certificate file not found: {v}"
            raise ValueError(msg)
        return v

    @validator("client_cert_file")
    def validate_client_cert_file(self, v: str | None) -> str | None:
        """Validate client certificate file exists."""
        if v and not Path(v).exists():
            msg = f"Client certificate file not found: {v}"
            raise ValueError(msg)
        return v

    @validator("client_key_file")
    def validate_client_key_file(self, v: str | None) -> str | None:
        """Validate client key file exists."""
        if v and not Path(v).exists():
            msg = f"Client key file not found: {v}"
            raise ValueError(msg)
        return v

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context from configuration.

        Returns:
            Configured SSL context

        """
        # Create SSL context with secure defaults
        context = ssl.create_default_context()

        # Set SSL/TLS version constraints
        if self.ssl_version:
            context.minimum_version = self._get_ssl_version_constant(self.ssl_version)

        if self.max_ssl_version:
            context.maximum_version = self._get_ssl_version_constant(
                self.max_ssl_version,
            )

        # Configure certificate verification
        if self.cert_verification == CertificateVerification.DISABLED:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif self.cert_verification == CertificateVerification.OPTIONAL:
            context.verify_mode = ssl.CERT_OPTIONAL
        elif self.cert_verification == CertificateVerification.ALLOW_SELF_SIGNED:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
        else:  # REQUIRED
            context.check_hostname = self.check_hostname
            context.verify_mode = ssl.CERT_REQUIRED

        # Load CA certificates
        if self.ca_cert_file:
            context.load_verify_locations(cafile=self.ca_cert_file)
        if self.ca_cert_dir:
            context.load_verify_locations(capath=self.ca_cert_dir)

        # Load client certificate and key
        if self.client_cert_file and self.client_key_file:
            context.load_cert_chain(
                self.client_cert_file,
                self.client_key_file,
                password=self.client_key_password,
            )

        # Configure cipher suites
        cipher_string = self._get_cipher_string()
        if cipher_string:
            context.set_ciphers(cipher_string)

        # Security options
        if self.disable_compression:
            context.options |= ssl.OP_NO_COMPRESSION

        if self.disable_renegotiation:
            context.options |= ssl.OP_NO_RENEGOTIATION

        return context

    def _get_ssl_version_constant(self, version: SSLVersion) -> ssl.TLSVersion:
        """Get SSL version constant."""
        version_mapping = {
            SSLVersion.TLS_1_0: ssl.TLSVersion.TLSv1,
            SSLVersion.TLS_1_1: ssl.TLSVersion.TLSv1_1,
            SSLVersion.TLS_1_2: ssl.TLSVersion.TLSv1_2,
            SSLVersion.TLS_1_3: ssl.TLSVersion.TLSv1_3,
        }
        return version_mapping.get(version, ssl.TLSVersion.TLSv1_2)

    def _get_cipher_string(self) -> str | None:
        """Get cipher string for configuration."""
        if self.cipher_suite == CipherSuite.CUSTOM:
            return self.custom_ciphers

        cipher_strings = {
            CipherSuite.HIGH_SECURITY: "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS",
            CipherSuite.MEDIUM_SECURITY: "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
            CipherSuite.COMPATIBILITY: "DEFAULT:!aNULL:!eNULL:!LOW:!EXPORT:!SSLv2",
        }

        return cipher_strings.get(self.cipher_suite)

    def validate_configuration(self) -> list[str]:
        """Validate LDAPS configuration.

        Returns:
            List of validation errors

        """
        errors = []

        # Check cipher configuration
        if self.cipher_suite == CipherSuite.CUSTOM and not self.custom_ciphers:
            errors.append(
                "Custom cipher string required when using CUSTOM cipher suite",
            )

        # Check client certificate configuration
        if self.client_cert_file and not self.client_key_file:
            errors.append(
                "Client key file required when client certificate is specified",
            )

        if self.client_key_file and not self.client_cert_file:
            errors.append(
                "Client certificate file required when client key is specified",
            )

        # Check timeout values
        if self.connect_timeout <= 0:
            errors.append("Connect timeout must be positive")

        if self.handshake_timeout <= 0:
            errors.append("Handshake timeout must be positive")

        return errors


class LDAPSTransport:
    """SSL/TLS transport for LDAPS connections."""

    def __init__(self, config: LDAPSConfiguration) -> None:
        """Initialize LDAPS transport.

        Args:
            config: LDAPS configuration

        """
        self._config = config
        self._ssl_context = config.create_ssl_context()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._ssl_object: ssl.SSLObject | None = None

    async def connect(self, hostname: str, port: int) -> None:
        """Connect with SSL/TLS encryption.

        Args:
            hostname: Server hostname
            port: Server port

        Raises:
            ConnectionError: If SSL connection fails

        """
        try:
            # Establish SSL connection
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    hostname,
                    port,
                    ssl=self._ssl_context,
                    server_hostname=hostname if self._config.enable_sni else None,
                ),
                timeout=self._config.connect_timeout,
            )

            self._connected = True

            # Get SSL object for inspection
            if self._writer:
                self._ssl_object = self._writer.transport.get_extra_info("ssl_object")

        except Exception as e:
            if self._writer:
                self._writer.close()
                await self._writer.wait_closed()
            msg = f"Failed to establish SSL connection to {hostname}:{port}: {e}"
            raise LDAPConnectionError(msg)

    async def disconnect(self) -> None:
        """Disconnect SSL/TLS transport."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            finally:
                self._reader = None
                self._writer = None
                self._ssl_object = None
                self._connected = False

    async def send(self, data: bytes) -> int:
        """Send data over SSL connection.

        Args:
            data: Data to send

        Returns:
            Number of bytes sent

        """
        if not self._writer:
            msg = "Not connected"
            raise LDAPConnectionError(msg)

        self._writer.write(data)
        await self._writer.drain()
        return len(data)

    async def receive(self, size: int) -> bytes:
        """Receive data from SSL connection.

        Args:
            size: Maximum bytes to receive

        Returns:
            Received data

        """
        if not self._reader:
            msg = "Not connected"
            raise LDAPConnectionError(msg)

        return await self._reader.read(size)

    def get_ssl_info(self) -> dict[str, Any]:
        """Get SSL connection information.

        Returns:
            Dictionary with SSL details

        """
        if not self._ssl_object:
            return {}

        try:
            cipher = self._ssl_object.cipher()
            peer_cert = self._ssl_object.getpeercert()

            return {
                "ssl_version": self._ssl_object.version(),
                "cipher_name": cipher[0] if cipher else None,
                "cipher_version": cipher[1] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "peer_certificate": peer_cert,
                "compression": self._ssl_object.compression(),
            }
        except Exception:
            return {}

    @property
    def connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected

    @property
    def ssl_context(self) -> ssl.SSLContext:
        """Get SSL context."""
        return self._ssl_context


class LDAPSProtocol(LDAPProtocol):
    """LDAPS protocol implementation."""

    protocol_name = "ldaps"
    default_port = 636

    def __init__(self, config: LDAPSConfiguration | None = None) -> None:
        """Initialize LDAPS protocol.

        Args:
            config: LDAPS configuration

        """
        self._config = config or LDAPSConfiguration()
        self._transport: LDAPSTransport | None = None
        self._hostname: str | None = None
        self._port: int | None = None
        super().__init__()

    async def connect(self, url: str, **kwargs: Any) -> None:
        """Connect using LDAPS protocol.

        Args:
            url: LDAPS URL (ldaps://hostname:port)
            **kwargs: Additional connection parameters

        """
        # Parse LDAPS URL
        parsed = urlparse(url)
        if parsed.scheme != "ldaps":
            msg = f"Invalid LDAPS URL scheme: {parsed.scheme}"
            raise ValueError(msg)

        if not parsed.hostname:
            msg = "Hostname required for LDAPS URL"
            raise ValueError(msg)

        self._hostname = parsed.hostname
        self._port = parsed.port or self.default_port

        # Validate configuration
        config_errors = self._config.validate_configuration()
        if config_errors:
            msg = f"Invalid LDAPS configuration: {'; '.join(config_errors)}"
            raise ValueError(msg)

        # Create and connect transport
        self._transport = LDAPSTransport(self._config)
        await self._transport.connect(self._hostname, self._port)

        self.set_state(ProtocolState.CONNECTED)

    async def disconnect(self) -> None:
        """Disconnect LDAPS protocol."""
        if self._transport:
            await self._transport.disconnect()
            self._transport = None

        self.set_state(ProtocolState.DISCONNECTED)

    def get_ssl_info(self) -> dict[str, Any]:
        """Get SSL connection information.

        Returns:
            Dictionary with SSL details

        """
        return self._transport.get_ssl_info() if self._transport else {}

    def verify_peer_certificate(self) -> dict[str, Any]:
        """Verify peer certificate against configuration.

        Returns:
            Dictionary with verification results

        """
        ssl_info = self.get_ssl_info()
        peer_cert = ssl_info.get("peer_certificate")

        verification_result: dict[str, Any] = {
            "verified": False,
            "certificate_present": peer_cert is not None,
            "hostname_match": False,
            "issuer_trusted": False,
            "errors": [],
        }

        if not peer_cert:
            verification_result["errors"].append("No peer certificate provided")
            return verification_result

        # Check hostname matching
        if self._config.check_hostname and self._hostname:
            try:
                ssl.match_hostname(peer_cert, self._hostname)
                verification_result["hostname_match"] = True
            except ssl.CertificateError as e:
                verification_result["errors"].append(
                    f"Hostname verification failed: {e}",
                )
        else:
            verification_result["hostname_match"] = True  # Skipped

        # Additional verification could be added here
        verification_result["verified"] = (
            verification_result["certificate_present"]
            and verification_result["hostname_match"]
            and not verification_result["errors"]
        )

        return verification_result

    @property
    def connected(self) -> bool:
        """Check if protocol is connected."""
        return self._transport.connected if self._transport else False

    @property
    def transport(self) -> LDAPSTransport | None:
        """Get LDAPS transport."""
        return self._transport

    @property
    def configuration(self) -> LDAPSConfiguration:
        """Get LDAPS configuration."""
        return self._config


class LDAPSConnection(ProtocolConnection):
    """LDAP connection using SSL/TLS encryption."""

    def __init__(
        self,
        url: str,
        ssl_context: ssl.SSLContext | None = None,
        ca_cert_file: str | None = None,
        client_cert_file: str | None = None,
        client_key_file: str | None = None,
        verify_ssl: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize LDAPS connection.

        Args:
            url: LDAPS server URL
            ssl_context: Pre-configured SSL context
            ca_cert_file: CA certificate file path
            client_cert_file: Client certificate file path
            client_key_file: Client key file path
            verify_ssl: Whether to verify SSL certificates
            **kwargs: Additional connection parameters

        """
        # Create LDAPS configuration
        config = LDAPSConfiguration(
            ca_cert_file=ca_cert_file,
            client_cert_file=client_cert_file,
            client_key_file=client_key_file,
            cert_verification=(
                CertificateVerification.REQUIRED
                if verify_ssl
                else CertificateVerification.DISABLED
            ),
        )

        # Use provided SSL context if available
        if ssl_context:
            # TODO: Integrate custom SSL context
            pass

        # Initialize protocol
        protocol = LDAPSProtocol(config)

        # Initialize connection
        super().__init__(protocol, **kwargs)

        self._url = url
        self._verify_ssl = verify_ssl

    async def connect(self) -> None:
        """Connect to LDAPS server."""
        await self._protocol.connect(self._url)

    async def start_tls(self) -> None:
        """Start TLS encryption (not applicable for LDAPS).

        Raises:
            RuntimeError: LDAPS connections are already encrypted

        """
        msg = "LDAPS connections are already encrypted - StartTLS not applicable"
        raise RuntimeError(msg)

    def get_ssl_info(self) -> dict[str, Any]:
        """Get SSL connection information.

        Returns:
            Dictionary with SSL details

        """
        if hasattr(self._protocol, "get_ssl_info"):
            return dict(self._protocol.get_ssl_info())
        return {}

    def verify_certificate(self) -> dict[str, Any]:
        """Verify peer certificate.

        Returns:
            Dictionary with verification results

        """
        if hasattr(self._protocol, "verify_peer_certificate"):
            return dict(self._protocol.verify_peer_certificate())
        return {"verified": False, "error": "Certificate verification not available"}

    def get_connection_info(self) -> dict[str, Any]:
        """Get connection information.

        Returns:
            Dictionary with connection details

        """
        info = super().get_connection_info()
        info.update(
            {
                "protocol": "ldaps",
                "encrypted": True,
                "ssl_info": self.get_ssl_info(),
                "certificate_verification": self.verify_certificate(),
            },
        )
        return info

    @property
    def encrypted(self) -> bool:
        """Check if connection is encrypted."""
        return True  # LDAPS is always encrypted

    @property
    def verify_ssl(self) -> bool:
        """Check if SSL verification is enabled."""
        return self._verify_ssl


# Convenience functions
def create_ldaps_connection(
    hostname: str,
    port: int = 636,
    ca_cert_file: str | None = None,
    verify_ssl: bool = True,
) -> LDAPSConnection:
    """Create LDAPS connection with basic settings.

    Args:
        hostname: Server hostname
        port: Server port (default 636)
        ca_cert_file: CA certificate file
        verify_ssl: Whether to verify SSL certificates

    Returns:
        Configured LDAPS connection

    """
    url = f"ldaps://{hostname}:{port}"

    return LDAPSConnection(
        url=url,
        ca_cert_file=ca_cert_file,
        verify_ssl=verify_ssl,
    )


def create_secure_ssl_context(
    ca_cert_file: str | None = None,
    client_cert_file: str | None = None,
    client_key_file: str | None = None,
) -> ssl.SSLContext:
    """Create secure SSL context for LDAPS.

    Args:
        ca_cert_file: CA certificate file
        client_cert_file: Client certificate file
        client_key_file: Client key file

    Returns:
        Configured SSL context

    """
    config = LDAPSConfiguration(
        ca_cert_file=ca_cert_file,
        client_cert_file=client_cert_file,
        client_key_file=client_key_file,
        cipher_suite=CipherSuite.HIGH_SECURITY,
        cert_verification=CertificateVerification.REQUIRED,
    )

    return config.create_ssl_context()


async def test_ldaps_connection(
    hostname: str,
    port: int | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Test LDAPS connection and SSL configuration.

    Args:
        hostname: Server hostname
        port: Server port (defaults to 636 if None)
        timeout: Connection timeout (defaults to 10.0 if None)

    Returns:
        Dictionary with test results

    """
    if port is None:
        port = 636
    if timeout is None:
        timeout = 10.0

    results: dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "reachable": False,
        "ssl_handshake": False,
        "certificate_valid": False,
        "ssl_info": {},
        "errors": [],
    }

    try:
        # Test basic connectivity
        connection = LDAPSConnection(f"ldaps://{hostname}:{port}")
        await asyncio.wait_for(connection.connect(), timeout=timeout)

        results["reachable"] = True
        results["ssl_handshake"] = True
        results["ssl_info"] = connection.get_ssl_info()

        # Test certificate verification
        cert_verification = connection.verify_certificate()
        results["certificate_valid"] = cert_verification["verified"]

        await connection.disconnect()

    except Exception as e:
        errors_list = results["errors"]
        assert isinstance(errors_list, list)
        errors_list.append(str(e))

    return results


# TODO: Integration points for implementation:
#
# 1. SSL/TLS Configuration Management:
#    - Comprehensive SSL context configuration
#    - Certificate chain validation and management
#    - Cipher suite selection and security policies
#
# 2. Certificate Management:
#    - X.509 certificate parsing and validation
#    - Certificate revocation checking (OCSP, CRL)
#    - Client certificate authentication
#
# 3. LDAP Protocol Integration:
#    - Integration with core LDAP protocol operations
#    - Message framing over encrypted connections
#    - Error handling for SSL/TLS issues
#
# 4. Security Policy Enforcement:
#    - SSL/TLS version policy enforcement
#    - Cipher suite restrictions and compliance
#    - Certificate validation policy management
#
# 5. Performance Optimization:
#    - SSL session reuse and caching
#    - Efficient encrypted data transfer
#    - Connection pooling for encrypted connections
#
# 6. Monitoring and Diagnostics:
#    - SSL/TLS connection monitoring
#    - Certificate expiration tracking
#    - Security event logging and alerting
#
# 7. Testing Requirements:
#    - Unit tests for all LDAPS functionality
#    - Integration tests with SSL-enabled servers
#    - Security tests for certificate validation
#    - Performance tests for encrypted connections
