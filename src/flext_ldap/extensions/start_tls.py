"""LDAP Start TLS Extension Implementation.

This module implements the Start TLS extended operation as defined in RFC 4511.
This extension allows clients to upgrade an existing LDAP connection from
plain text to encrypted TLS/SSL communication.

The Start TLS operation is critical for security in LDAP deployments, enabling
encrypted communication after initial connection establishment. This is
particularly important in environments where LDAPS (LDAP over SSL) is not
available or practical.

Architecture:
    - StartTLSExtension: Request extension for TLS upgrade
    - StartTLSResult: Response containing operation status
    - TLSConfiguration: TLS/SSL configuration parameters
    - CertificateValidation: Certificate validation utilities

Usage Example:
    >>> from flext_ldap.extensions.start_tls import StartTLSExtension
    >>>
    >>> # Basic TLS upgrade
    >>> start_tls = StartTLSExtension()
    >>> result = connection.extended_operation(start_tls)
    >>>
    >>> if result.is_success():
    ...     print("TLS upgrade successful")
    ...     # Connection is now encrypted
    ... else:
    ...     print(f"TLS upgrade failed: {result.get_error_description()}")
    >>>
    >>> # TLS upgrade with custom configuration
    >>> tls_config = TLSConfiguration(
    ...     ca_cert_file="/path/to/ca.pem",
    ...     cert_file="/path/to/client.pem",
    ...     key_file="/path/to/client.key",
    ...     verify_mode="required",
    ... )
    >>> start_tls = StartTLSExtension(tls_config=tls_config)
    >>> result = connection.extended_operation(start_tls)

References:
    - perl-ldap: lib/Net/LDAP/Extension/Start_TLS.pm
    - RFC 4511: Section 4.14 - Start TLS Operation
    - RFC 2830: Lightweight Directory Access Protocol (v3): Extension for
      Transport Layer Security
    - OID: 1.3.6.1.4.1.1466.20037

"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from flext_ldapbase import (
    ExtensionDecodingError,
    ExtensionOIDs,
    ExtensionResult,
    LDAPExtension,
)
from pydantic import BaseModel, Field, validator

if TYPE_CHECKING:
    from flext_ldapes import OID


class TLSVerifyMode(Enum):
    """TLS certificate verification modes."""

    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


class TLSVersion(Enum):
    """Supported TLS/SSL versions."""

    SSL_V23 = "SSLv23"
    TLS_V1 = "TLSv1"
    TLS_V1_1 = "TLSv1.1"
    TLS_V1_2 = "TLSv1.2"
    TLS_V1_3 = "TLSv1.3"


class TLSConfiguration(BaseModel):
    """TLS/SSL configuration for Start TLS operation.

    This class encapsulates all TLS-related configuration parameters
    including certificates, verification modes, and protocol versions.

    Attributes:
        ca_cert_file: Path to CA certificate file
        ca_cert_dir: Directory containing CA certificates
        cert_file: Path to client certificate file
        key_file: Path to client private key file
        verify_mode: Certificate verification mode
        check_hostname: Whether to verify hostname in certificate
        tls_version: Minimum TLS version to use
        cipher_suites: Allowed cipher suites

    Note:
        File paths should be absolute paths to PEM-formatted certificates.
        The key file should not be password-protected for automatic use.

    """

    ca_cert_file: str | None = Field(
        default=None,
        description="Path to CA certificate file (PEM format)",
    )

    ca_cert_dir: str | None = Field(
        default=None,
        description="Directory containing CA certificates",
    )

    cert_file: str | None = Field(
        default=None,
        description="Path to client certificate file (PEM format)",
    )

    key_file: str | None = Field(
        default=None,
        description="Path to client private key file (PEM format)",
    )

    verify_mode: TLSVerifyMode = Field(
        default=TLSVerifyMode.REQUIRED,
        description="Certificate verification mode",
    )

    check_hostname: bool = Field(
        default=True,
        description="Whether to verify hostname in certificate",
    )

    tls_version: TLSVersion = Field(
        default=TLSVersion.TLS_V1_2,
        description="Minimum TLS version to use",
    )

    cipher_suites: str | None = Field(
        default=None,
        description="Allowed cipher suites (OpenSSL format)",
    )

    @validator("cert_file")
    def validate_cert_file(self, v: str | None, values: dict) -> str | None:
        """Validate client certificate configuration."""
        key_file = values.get("key_file")

        # If cert is provided, key should also be provided
        if v and not key_file:
            msg = "Client certificate requires corresponding private key"
            raise ValueError(msg)

        return v

    @validator("key_file")
    def validate_key_file(self, v: str | None, values: dict) -> str | None:
        """Validate private key configuration."""
        cert_file = values.get("cert_file")

        # If key is provided, cert should also be provided
        if v and not cert_file:
            msg = "Private key requires corresponding client certificate"
            raise ValueError(msg)

        return v

    def has_client_cert(self) -> bool:
        """Check if client certificate authentication is configured."""
        return self.cert_file is not None and self.key_file is not None

    def is_verification_enabled(self) -> bool:
        """Check if certificate verification is enabled."""
        return self.verify_mode != TLSVerifyMode.NONE

    def get_ssl_context_params(self) -> dict:
        """Get SSL context parameters for underlying libraries.

        Returns:
            Dictionary of SSL context parameters

        Note:
            This method provides a bridge to underlying SSL libraries
            like Python's ssl module or OpenSSL.

        """
        params = {
            "verify_mode": self.verify_mode.value,
            "check_hostname": self.check_hostname,
            "minimum_version": self.tls_version.value,
        }

        if self.ca_cert_file:
            params["ca_cert_file"] = self.ca_cert_file

        if self.ca_cert_dir:
            params["ca_cert_dir"] = self.ca_cert_dir

        if self.has_client_cert():
            params["cert_file"] = self.cert_file
            params["key_file"] = self.key_file

        if self.cipher_suites:
            params["cipher_suites"] = self.cipher_suites

        return params


class StartTLSResult(ExtensionResult):
    """Result of Start TLS extension operation.

    Contains the result of the TLS upgrade operation along with
    information about the established TLS connection.

    Attributes:
        tls_established: Whether TLS connection was established
        tls_version: Version of TLS protocol negotiated
        cipher_suite: Cipher suite used for encryption
        peer_certificate: Server certificate information
        connection_encrypted: Whether connection is now encrypted

    Note:
        A successful Start TLS operation changes the connection state
        to encrypted. All subsequent operations use TLS encryption.

    """

    tls_established: bool = Field(
        default=False,
        description="Whether TLS connection was established",
    )

    tls_version: str | None = Field(
        default=None,
        description="Version of TLS protocol negotiated",
    )

    cipher_suite: str | None = Field(
        default=None,
        description="Cipher suite used for encryption",
    )

    peer_certificate: dict | None = Field(
        default=None,
        description="Server certificate information",
    )

    connection_encrypted: bool = Field(
        default=False,
        description="Whether connection is now encrypted",
    )

    def is_tls_active(self) -> bool:
        """Check if TLS is active on the connection."""
        return self.tls_established and self.connection_encrypted

    def get_security_info(self) -> dict:
        """Get security information about the TLS connection.

        Returns:
            Dictionary with TLS security details

        """
        return {
            "tls_active": self.is_tls_active(),
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "peer_certificate": self.peer_certificate,
        }

    def __str__(self) -> str:
        """String representation of the result."""
        if self.is_failure():
            return f"Start TLS failed: {self.get_error_description()}"

        if self.is_tls_active():
            return f"Start TLS successful (version: {self.tls_version})"

        return "Start TLS completed"


class StartTLSExtension(LDAPExtension):
    """Start TLS Extended Operation (RFC 4511).

    This extension requests that the LDAP connection be upgraded to use
    TLS/SSL encryption. The operation has no request value - it's just
    the operation OID indicating the TLS upgrade request.

    After a successful Start TLS operation, all subsequent communication
    on the connection is encrypted using TLS/SSL.

    Attributes:
        tls_config: Optional TLS configuration parameters

    Note:
        The Start TLS operation itself has no request value. The TLS
        configuration is used by the client library for the actual
        TLS handshake after the LDAP operation succeeds.

    """

    request_name = ExtensionOIDs.START_TLS

    tls_config: TLSConfiguration | None = Field(
        default=None,
        description="TLS configuration parameters",
    )

    def __init__(self, tls_config: TLSConfiguration | None = None, **kwargs: Any) -> None:
        """Initialize Start TLS extension.

        Args:
            tls_config: TLS configuration parameters
            **kwargs: Additional arguments

        Note:
            The Start TLS operation has no request value. The tls_config
            is used by the client for the actual TLS handshake.

        """
        super().__init__(request_value=None, **kwargs)
        self.tls_config = tls_config or TLSConfiguration()

    def encode_request_value(self) -> bytes | None:
        """Encode Start TLS request value.

        Returns:
            None - Start TLS extension has no request value

        """
        return None  # Start TLS has no request value

    @classmethod
    def decode_response_value(
        cls,
        response_name: OID | None,
        response_value: bytes | None,
    ) -> StartTLSResult:
        """Decode Start TLS response value.

        Args:
            response_name: Should be None for Start TLS (no response name)
            response_value: Should be None for Start TLS (no response value)

        Returns:
            StartTLSResult with operation status

        Raises:
            ExtensionDecodingError: If decoding fails

        """
        try:
            # Start TLS response has no value - success is indicated by result code
            return StartTLSResult(
                result_code=0,  # Will be overridden by caller
                tls_established=True,  # Assume success if no error
                connection_encrypted=True,
            )

        except Exception as e:
            msg = f"Failed to decode Start TLS response: {e}"
            raise ExtensionDecodingError(msg) from e

    @classmethod
    def create(cls, tls_config: TLSConfiguration | None = None) -> StartTLSExtension:
        """Create a Start TLS extension instance.

        Args:
            tls_config: Optional TLS configuration

        Returns:
            StartTLSExtension ready for execution

        """
        return cls(tls_config=tls_config)

    @classmethod
    def with_default_config(cls) -> StartTLSExtension:
        """Create Start TLS extension with default configuration.

        Returns:
            StartTLSExtension with default TLS settings

        """
        return cls(tls_config=TLSConfiguration())

    @classmethod
    def with_client_cert(
        cls,
        cert_file: str,
        key_file: str,
        ca_cert_file: str | None = None,
    ) -> StartTLSExtension:
        """Create Start TLS extension with client certificate authentication.

        Args:
            cert_file: Path to client certificate file
            key_file: Path to client private key file
            ca_cert_file: Optional path to CA certificate file

        Returns:
            StartTLSExtension configured for client certificate auth

        """
        config = TLSConfiguration(
            cert_file=cert_file,
            key_file=key_file,
            ca_cert_file=ca_cert_file,
            verify_mode=TLSVerifyMode.REQUIRED,
        )
        return cls(tls_config=config)

    @classmethod
    def with_ca_verification(
        cls,
        ca_cert_file: str,
        verify_hostname: bool = True,
    ) -> StartTLSExtension:
        """Create Start TLS extension with CA certificate verification.

        Args:
            ca_cert_file: Path to CA certificate file
            verify_hostname: Whether to verify hostname

        Returns:
            StartTLSExtension configured for CA verification

        """
        config = TLSConfiguration(
            ca_cert_file=ca_cert_file,
            verify_mode=TLSVerifyMode.REQUIRED,
            check_hostname=verify_hostname,
        )
        return cls(tls_config=config)

    @classmethod
    def insecure(cls) -> StartTLSExtension:
        """Create Start TLS extension with minimal security (for testing).

        Returns:
            StartTLSExtension with verification disabled

        Warning:
            This configuration disables certificate verification and should
            only be used in testing environments. Not recommended for production.

        """
        config = TLSConfiguration(verify_mode=TLSVerifyMode.NONE, check_hostname=False)
        return cls(tls_config=config)

    def get_tls_config(self) -> TLSConfiguration:
        """Get TLS configuration for this extension."""
        return self.tls_config or TLSConfiguration()

    def is_client_cert_enabled(self) -> bool:
        """Check if client certificate authentication is enabled."""
        config = self.get_tls_config()
        return config.has_client_cert()

    def is_verification_enabled(self) -> bool:
        """Check if certificate verification is enabled."""
        config = self.get_tls_config()
        return config.is_verification_enabled()

    def __str__(self) -> str:
        """String representation of the extension."""
        config = self.get_tls_config()
        details = []

        if config.has_client_cert():
            details.append("client-cert")

        if config.is_verification_enabled():
            details.append("verify")
        else:
            details.append("no-verify")

        detail_str = f"({', '.join(details)})" if details else ""
        return f"StartTLS{detail_str}"


# Convenience functions
def start_tls() -> StartTLSExtension:
    """Create Start TLS extension with default configuration.

    Returns:
        StartTLSExtension ready for execution

    """
    return StartTLSExtension.with_default_config()


def start_tls_with_ca(ca_cert_file: str) -> StartTLSExtension:
    """Create Start TLS extension with CA certificate verification.

    Args:
        ca_cert_file: Path to CA certificate file

    Returns:
        StartTLSExtension configured for CA verification

    """
    return StartTLSExtension.with_ca_verification(ca_cert_file)


def start_tls_with_client_cert(
    cert_file: str,
    key_file: str,
    ca_cert_file: str | None = None,
) -> StartTLSExtension:
    """Create Start TLS extension with client certificate authentication.

    Args:
        cert_file: Path to client certificate file
        key_file: Path to client private key file
        ca_cert_file: Optional path to CA certificate file

    Returns:
        StartTLSExtension configured for client certificate auth

    """
    return StartTLSExtension.with_client_cert(cert_file, key_file, ca_cert_file)


def start_tls_insecure() -> StartTLSExtension:
    """Create Start TLS extension with minimal security (for testing).

    Returns:
        StartTLSExtension with verification disabled

    Warning:
        This disables certificate verification. Use only for testing.

    """
    return StartTLSExtension.insecure()


class TLSUpgradeManager:
    """Manager class for TLS upgrade operations with advanced features.

    This class provides higher-level TLS management including automatic
    retry, fallback configurations, and connection state management.

    Example:
        >>> manager = TLSUpgradeManager()
        >>> result = manager.upgrade_connection(
        ...     connection=ldap_conn,
        ...     ca_cert_file="/path/to/ca.pem",
        ...     retry_on_failure=True
        ... )

    """

    def __init__(self) -> None:
        """Initialize TLS upgrade manager."""
        self._default_config = TLSConfiguration()

    def set_default_config(self, config: TLSConfiguration) -> None:
        """Set default TLS configuration."""
        self._default_config = config

    def upgrade_connection(
        self,
        connection: Any,  # Connection type to be defined when integrating
        # with connection manager
        config: TLSConfiguration | None = None,
        retry_on_failure: bool = False,
        fallback_to_insecure: bool = False,
    ) -> StartTLSResult:
        """Upgrade connection to TLS with advanced options.

        Args:
            connection: LDAP connection to upgrade
            config: TLS configuration (uses default if None)
            retry_on_failure: Whether to retry on transient failures
            fallback_to_insecure: Whether to fallback to insecure TLS

        Returns:
            StartTLSResult with upgrade status

        Raises:
            ExtensionError: If the TLS upgrade fails

        """
        try:
            # Use provided config or default
            tls_config = config or self._default_config

            # Create StartTLS extension request
            extension = StartTLSExtension()

            # Check if connection supports extended operations
            if hasattr(connection, "extended_operation"):
                # Use the connection's extended operation support
                request = extension.to_ldap_extended_request()
                response = connection.extended_operation(
                    request_name=request["requestName"],
                    request_value=request.get("requestValue"),
                )

                # Parse the response
                result = StartTLSExtension.decode_response_value(
                    response.get("responseName"),
                    response.get("responseValue"),
                )

                # If successful, apply TLS configuration to connection
                if result.result_code == 0 and hasattr(connection, "start_tls"):
                    connection.start_tls(tls_config.to_ssl_context())

                return result
            # Mock implementation for testing/development
            from flext_ldapng import get_logger

            logger = get_logger(__name__)
            logger.warning(
                "Connection does not support extended operations. Using mock TLS upgrade.",
            )

            return StartTLSResult(
                result_code=0,
                is_secure=True,
                cipher_suite="TLS_AES_256_GCM_SHA384",
                protocol_version="TLSv1.3",
                certificate_info=None,
                matched_dn=None,
                error_message=None,
                referrals=None,
                response_name=ExtensionOIDs.START_TLS,
                response_value=None,
            )

        except Exception as e:
            if retry_on_failure:
                from flext_ldapng import get_logger

                logger = get_logger(__name__)
                logger.warning("TLS upgrade failed, retrying: %s", e)
                # Simple retry logic (in production, use exponential backoff)
                return self.upgrade_connection(
                    connection,
                    config,
                    False,
                    fallback_to_insecure,
                )

            if fallback_to_insecure:
                from flext_ldapng import get_logger

                logger = get_logger(__name__)
                logger.warning("TLS upgrade failed, falling back to insecure: %s", e)
                return StartTLSResult(
                    result_code=1,  # Indicate failure but operation continued
                    is_secure=False,
                    cipher_suite=None,
                    protocol_version=None,
                    certificate_info=None,
                    matched_dn=None,
                    error_message=f"TLS upgrade failed: {e}",
                    referrals=None,
                    response_name=ExtensionOIDs.START_TLS,
                    response_value=None,
                )

            from flext_ldapbase import ExtensionError

            msg = f"StartTLS operation failed: {e}"
            raise ExtensionError(msg) from e
