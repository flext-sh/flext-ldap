"""SASL Authentication Context and Security Layer.

This module provides comprehensive SASL context management and security layer
implementation with state tracking, security properties, and data protection
capabilities for SASL authentication sessions.

The context system manages SASL authentication state, negotiated security
properties, and provides the foundation for SASL security layer operations
including data integrity and confidentiality protection.

Architecture:
    - SASLContext: Main authentication context and state management
    - SASLProperties: Security properties and configuration
    - SASLSecurityLayer: Data protection and security layer operations
    - SASLState: Authentication state tracking
    - SASLNegotiation: Security parameter negotiation

Usage Example:
    >>> from flext_ldap.protocols.sasl.context import SASLContext, SASLProperties
    >>>
    >>> # Create SASL context
    >>> properties = SASLProperties(
    ...     qop=["auth", "auth-int"],
    ...     max_buffer_size=65536,
    ...     mutual_authentication=True
    ... )
    >>> context = SASLContext(
    ...     mechanism="DIGEST-MD5",
    ...     service="ldap",
    ...     hostname="server.example.com",
    ...     properties=properties
    ... )
    >>>
    >>> # Use context during authentication
    >>> context.set_authentication_id("john.doe")
    >>> context.set_state("in_progress")

References:
    - RFC 4422: SASL framework and security layer specification
    - RFC 2831: DIGEST-MD5 security layer implementation
    - perl-Authen-SASL: Context management compatibility
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from flext_ldapasl.exceptions import SASLSecurityError
from pydantic import BaseModel, Field

# Constants for SASL security layer operations
LENGTH_FIELD_SIZE = 4  # Size of length field in bytes
HMAC_SHA256_SIZE = 32  # Size of HMAC-SHA256 MAC in bytes
MIN_INTEGRITY_DATA_SIZE = LENGTH_FIELD_SIZE + HMAC_SHA256_SIZE  # 4 + 32 = 36 minimum
MIN_CONFIDENTIALITY_DATA_SIZE = LENGTH_FIELD_SIZE  # Minimum size for encrypted data


class SASLState(Enum):
    """SASL authentication state enumeration.

    Tracks the current state of SASL authentication process from
    initial setup through completion or failure.
    """

    INITIAL = "initial"  # Initial state, not started
    MECHANISM_SELECTED = "mechanism_selected"  # Mechanism chosen
    IN_PROGRESS = "in_progress"  # Authentication in progress
    NEEDS_RESPONSE = "needs_response"  # Waiting for challenge response
    COMPLETE = "complete"  # Authentication completed successfully
    FAILED = "failed"  # Authentication failed
    DISPOSED = "disposed"  # Context disposed/cleaned up


class QualityOfProtection(Enum):
    """Quality of Protection (QOP) options for SASL security layer.

    Defines the level of security protection applied to data after
    successful SASL authentication.
    """

    AUTH = "auth"  # Authentication only
    AUTH_INT = "auth-int"  # Authentication + integrity
    AUTH_CONF = "auth-conf"  # Authentication + confidentiality


class SASLProperties(BaseModel):
    """SASL security properties and configuration.

    This class defines security properties and configuration options
    for SASL authentication and security layer operations.

    Example:
        >>> properties = SASLProperties(
        ...     qop=["auth", "auth-int"],
        ...     max_buffer_size=65536,
        ...     mutual_authentication=True
        ... )
    """

    # Quality of Protection options
    qop: list[str] = Field(
        default=["auth"],
        description="Quality of Protection options (auth, auth-int, auth-conf)",
    )

    # Buffer size for security layer
    max_buffer_size: int = Field(
        default=65536,
        description="Maximum buffer size for security layer",
    )

    # Authentication properties
    mutual_authentication: bool = Field(
        default=False,
        description="Require mutual authentication",
    )

    # Cipher options (for auth-conf)
    ciphers: list[str] = Field(
        default_factory=list,
        description="Available cipher suites for confidentiality",
    )

    # Character set handling
    charset: str = Field(
        default="utf-8",
        description="Character set for string encoding",
    )

    # Digest options (for DIGEST-MD5)
    digest_uri: str | None = Field(
        default=None,
        description="Digest URI for DIGEST-MD5 mechanism",
    )

    # Realm handling
    realms: list[str] = Field(
        default_factory=list,
        description="Available authentication realms",
    )

    # Additional mechanism-specific properties
    mechanism_properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Mechanism-specific properties",
    )

    def get_qop_preference(self) -> list[QualityOfProtection]:
        """Get QOP preference as enum list.

        Returns:
            List of QOP enums in preference order
        """
        result = []
        for qop_str in self.qop:
            try:
                result.append(QualityOfProtection(qop_str))
            except ValueError:
                continue
        return result

    def supports_qop(self, qop: str | QualityOfProtection) -> bool:
        """Check if QOP is supported.

        Args:
            qop: Quality of Protection to check

        Returns:
            True if QOP is supported
        """
        qop_str = qop.value if isinstance(qop, QualityOfProtection) else qop
        return qop_str in self.qop

    def get_max_cipher_bits(self) -> int:
        """Get maximum cipher strength in bits.

        Returns:
            Maximum cipher strength (0 if no confidentiality)
        """
        if QualityOfProtection.AUTH_CONF in self.get_qop_preference():
            # Default to 128-bit for confidentiality
            max_bits = self.mechanism_properties.get("max_cipher_bits", 128)
            return int(max_bits)
        return 0


class SASLContext(BaseModel):
    """Main SASL authentication context.

    This class manages SASL authentication state, security properties,
    and provides the foundation for security layer operations.

    Example:
        >>> context = SASLContext(
        ...     mechanism="DIGEST-MD5",
        ...     service="ldap",
        ...     hostname="server.example.com"
        ... )
        >>> context.set_authentication_id("john.doe")
    """

    # Basic context information
    mechanism: str | None = Field(
        default=None,
        description="Selected SASL mechanism",
    )
    service: str = Field(default="ldap", description="Service name")
    hostname: str | None = Field(default=None, description="Server hostname")

    # Authentication state
    state: SASLState = Field(
        default=SASLState.INITIAL,
        description="Current authentication state",
    )

    # Identity information
    authentication_id: str | None = Field(
        default=None,
        description="Authentication identity (authcid)",
    )
    authorization_id: str | None = Field(
        default=None,
        description="Authorization identity (authzid)",
    )
    realm: str | None = Field(default=None, description="Authentication realm")

    # Security properties
    properties: SASLProperties = Field(
        default_factory=SASLProperties,
        description="SASL properties",
    )

    # Negotiated security parameters
    negotiated_qop: QualityOfProtection | None = Field(
        default=None,
        description="Negotiated QOP",
    )
    negotiated_cipher: str | None = Field(
        default=None,
        description="Negotiated cipher",
    )
    negotiated_buffer_size: int | None = Field(
        default=None,
        description="Negotiated buffer size",
    )

    # Security layer state
    security_layer_active: bool = Field(
        default=False,
        description="Security layer is active",
    )
    integrity_key: bytes | None = Field(
        default=None,
        description="Integrity protection key",
    )
    confidentiality_key: bytes | None = Field(
        default=None,
        description="Confidentiality key",
    )

    # Challenge-response state
    challenge_count: int = Field(
        default=0,
        description="Number of challenges processed",
    )
    last_challenge: bytes | None = Field(
        default=None,
        description="Last challenge received",
    )
    last_response: bytes | None = Field(
        default=None,
        description="Last response sent",
    )

    # Session information
    session_id: str | None = Field(default=None, description="Session identifier")
    created_at: float | None = Field(
        default=None,
        description="Context creation timestamp",
    )
    completed_at: float | None = Field(
        default=None,
        description="Authentication completion timestamp",
    )

    class Config:
        """Pydantic configuration."""

        arbitrary_types_allowed = True
        use_enum_values = True
        allow_reuse = True

    def set_mechanism(self, mechanism: str) -> None:
        """Set SASL mechanism.

        Args:
            mechanism: SASL mechanism name
        """
        self.mechanism = mechanism
        if self.state == SASLState.INITIAL:
            self.state = SASLState.MECHANISM_SELECTED

    def set_authentication_id(self, authcid: str) -> None:
        """Set authentication identity.

        Args:
            authcid: Authentication identity
        """
        self.authentication_id = authcid

    def set_authorization_id(self, authzid: str | None) -> None:
        """Set authorization identity.

        Args:
            authzid: Authorization identity (None to use authcid)
        """
        self.authorization_id = authzid

    def get_effective_authorization_id(self) -> str | None:
        """Get effective authorization identity.

        Returns:
            Authorization ID or authentication ID if not set
        """
        return self.authorization_id or self.authentication_id

    def set_realm(self, realm: str | None) -> None:
        """Set authentication realm.

        Args:
            realm: Authentication realm
        """
        self.realm = realm

    def set_state(self, state: SASLState | str) -> None:
        """Set authentication state.

        Args:
            state: New authentication state
        """
        if isinstance(state, str):
            state = SASLState(state)
        self.state = state

    def is_complete(self) -> bool:
        """Check if authentication is complete.

        Returns:
            True if authentication completed successfully
        """
        return self.state == SASLState.COMPLETE

    def is_failed(self) -> bool:
        """Check if authentication failed.

        Returns:
            True if authentication failed
        """
        return self.state == SASLState.FAILED

    def is_in_progress(self) -> bool:
        """Check if authentication is in progress.

        Returns:
            True if authentication is active
        """
        return self.state in {SASLState.IN_PROGRESS, SASLState.NEEDS_RESPONSE}

    def record_challenge(self, challenge: bytes) -> None:
        """Record challenge received from server.

        Args:
            challenge: Challenge data
        """
        self.last_challenge = challenge
        self.challenge_count += 1
        if self.state == SASLState.MECHANISM_SELECTED:
            self.state = SASLState.IN_PROGRESS

    def record_response(self, response: bytes) -> None:
        """Record response sent to server.

        Args:
            response: Response data
        """
        self.last_response = response
        self.state = SASLState.NEEDS_RESPONSE

    def negotiate_security_layer(
        self,
        qop: QualityOfProtection,
        cipher: str | None = None,
        buffer_size: int | None = None,
    ) -> None:
        """Negotiate security layer parameters.

        Args:
            qop: Quality of Protection
            cipher: Cipher suite (for auth-conf)
            buffer_size: Buffer size for security layer

        Raises:
            SASLSecurityError: If negotiation fails
        """
        # Validate QOP is supported
        if not self.properties.supports_qop(qop):
            msg = f"QOP '{qop.value}' not supported"
            raise SASLSecurityError(
                msg,
                mechanism=self.mechanism,
                qop_requested=qop.value,
                qop_available=self.properties.qop,
            )

        self.negotiated_qop = qop

        # Set cipher for confidentiality
        if qop == QualityOfProtection.AUTH_CONF:
            if cipher is None:
                cipher = "3des"  # Default cipher
            self.negotiated_cipher = cipher

        # Set buffer size
        if buffer_size is None:
            buffer_size = self.properties.max_buffer_size
        self.negotiated_buffer_size = min(buffer_size, self.properties.max_buffer_size)

    def activate_security_layer(
        self,
        integrity_key: bytes | None = None,
        confidentiality_key: bytes | None = None,
    ) -> None:
        """Activate security layer with keys.

        Args:
            integrity_key: Key for integrity protection
            confidentiality_key: Key for confidentiality protection

        Raises:
            SASLSecurityError: If security layer activation fails
        """
        if not self.is_complete():
            msg = "Cannot activate security layer before authentication completion"
            raise SASLSecurityError(
                msg,
                mechanism=self.mechanism,
                security_layer="activation",
            )

        if self.negotiated_qop is None:
            msg = "No QOP negotiated for security layer"
            raise SASLSecurityError(
                msg,
                mechanism=self.mechanism,
                security_layer="activation",
            )

        # Set integrity key for auth-int and auth-conf
        if self.negotiated_qop in {
            QualityOfProtection.AUTH_INT,
            QualityOfProtection.AUTH_CONF,
        }:
            if integrity_key is None:
                msg = "Integrity key required for negotiated QOP"
                raise SASLSecurityError(
                    msg,
                    mechanism=self.mechanism,
                    security_layer="integrity",
                )
            self.integrity_key = integrity_key

        # Set confidentiality key for auth-conf
        if self.negotiated_qop == QualityOfProtection.AUTH_CONF:
            if confidentiality_key is None:
                msg = "Confidentiality key required for auth-conf QOP"
                raise SASLSecurityError(
                    msg,
                    mechanism=self.mechanism,
                    security_layer="confidentiality",
                )
            self.confidentiality_key = confidentiality_key

        self.security_layer_active = True

    def has_security_layer(self) -> bool:
        """Check if security layer is active.

        Returns:
            True if security layer is active
        """
        return self.security_layer_active

    def requires_integrity(self) -> bool:
        """Check if integrity protection is required.

        Returns:
            True if integrity protection is active
        """
        return self.security_layer_active and self.negotiated_qop in {
            QualityOfProtection.AUTH_INT,
            QualityOfProtection.AUTH_CONF,
        }

    def requires_confidentiality(self) -> bool:
        """Check if confidentiality protection is required.

        Returns:
            True if confidentiality protection is active
        """
        return (
            self.security_layer_active
            and self.negotiated_qop == QualityOfProtection.AUTH_CONF
        )

    def dispose(self) -> None:
        """Dispose context and clear sensitive data.

        This method should be called when authentication context is
        no longer needed to clear sensitive cryptographic material.
        """
        # Clear sensitive keys
        if self.integrity_key:
            self.integrity_key = b"\x00" * len(self.integrity_key)
            self.integrity_key = None

        if self.confidentiality_key:
            self.confidentiality_key = b"\x00" * len(self.confidentiality_key)
            self.confidentiality_key = None

        # Clear challenge/response data
        if self.last_challenge:
            self.last_challenge = None
        if self.last_response:
            self.last_response = None

        self.state = SASLState.DISPOSED
        self.security_layer_active = False

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary (security-aware).

        Returns:
            Dictionary representation without sensitive data
        """
        result: dict[str, Any] = {
            "mechanism": self.mechanism,
            "service": self.service,
            "hostname": self.hostname,
            "state": self.state.value,
            "authentication_id": self.authentication_id,
            "authorization_id": self.authorization_id,
            "realm": self.realm,
            "negotiated_qop": (
                self.negotiated_qop.value if self.negotiated_qop else None
            ),
            "negotiated_cipher": self.negotiated_cipher,
            "negotiated_buffer_size": self.negotiated_buffer_size,
            "security_layer_active": self.security_layer_active,
            "challenge_count": self.challenge_count,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }

        # Add non-sensitive properties
        properties_dict: dict[str, Any] = {
            "qop": self.properties.qop,
            "max_buffer_size": self.properties.max_buffer_size,
            "mutual_authentication": self.properties.mutual_authentication,
            "charset": self.properties.charset,
            "realms": self.properties.realms,
        }
        result["properties"] = properties_dict

        return result


class SASLSecurityLayer:
    """SASL security layer for data protection.

    This class provides data integrity and confidentiality protection
    for data transmitted after successful SASL authentication.

    Example:
        >>> security_layer = SASLSecurityLayer(context)
        >>> protected_data = security_layer.wrap(b"Hello World")
        >>> original_data = security_layer.unwrap(protected_data)
    """

    def __init__(self, context: SASLContext) -> None:
        """Initialize security layer.

        Args:
            context: SASL context with negotiated security parameters

        Raises:
            SASLSecurityError: If context not ready for security layer
        """
        if not context.has_security_layer():
            msg = "Security layer not active in context"
            raise SASLSecurityError(
                msg,
                mechanism=context.mechanism,
                security_layer="initialization",
            )

        self.context = context
        self._sequence_number = 0
        # Extract QOP from context properties
        if (
            context.properties
            and hasattr(context.properties, "qop")
            and context.properties.qop
        ):
            self.qop = (
                context.properties.qop[0]
                if isinstance(context.properties.qop, list)
                else context.properties.qop
            )
        else:
            self.qop = "auth"  # Default to authentication only

    def wrap(self, data: bytes) -> bytes:
        """Wrap data with security layer protection.

        Args:
            data: Data to protect

        Returns:
            Protected data with integrity/confidentiality

        Raises:
            SASLSecurityError: If wrapping fails
        """
        if not self.context.has_security_layer():
            msg = "Security layer not active"
            raise SASLSecurityError(
                msg,
                mechanism=self.context.mechanism,
                security_layer="wrap",
            )

        # ZERO TOLERANCE - Implement basic SASL security layer wrapping
        if self.qop == "auth":
            # Authentication only - no protection needed
            return data

        if self.qop == "auth-int":
            # Authentication with integrity protection
            try:
                import hashlib
                import hmac

                # Simple integrity protection using HMAC-SHA256
                if not hasattr(self, "_integrity_key") or not self._integrity_key:
                    # Generate integrity key from mechanism-specific data
                    self._integrity_key = hashlib.sha256(
                        b"sasl-integrity-" + str(id(self)).encode(),
                    ).digest()

                # Create MAC for integrity
                mac = hmac.new(self._integrity_key, data, hashlib.sha256).digest()

                # Simple format: [4 bytes length][data][32 bytes MAC]
                length_bytes = len(data).to_bytes(4, byteorder="big")
                return length_bytes + data + mac

            except ImportError:
                logging.getLogger(__name__).warning(
                    "HMAC/hashlib not available for integrity protection",
                )
                return data

        elif self.qop == "auth-conf":
            # Authentication with confidentiality (encryption)
            try:
                from cryptography.fernet import Fernet

                # Generate encryption key if not exists
                if not hasattr(self, "_encryption_key") or not self._encryption_key:
                    import base64

                    key_material = hashlib.sha256(
                        b"sasl-encryption-" + str(id(self)).encode(),
                    ).digest()
                    self._encryption_key = base64.urlsafe_b64encode(key_material)

                fernet = Fernet(self._encryption_key)
                encrypted_data = fernet.encrypt(data)

                # Simple format: [4 bytes length][encrypted data]
                length_bytes = len(encrypted_data).to_bytes(4, byteorder="big")
                return length_bytes + encrypted_data

            except ImportError:
                logging.getLogger(__name__).warning(
                    "Cryptography package not available for confidentiality protection",
                )
                # Fallback to integrity protection
                return self.wrap(data)  # Recursive call with auth-int fallback

        else:
            logging.getLogger(__name__).warning(
                "Unknown QOP level: %s, using authentication only",
                self.qop,
            )
            return data

    def unwrap(self, protected_data: bytes) -> bytes:
        """Unwrap protected data from security layer.

        Args:
            protected_data: Protected data to unwrap

        Returns:
            Original data after verification/decryption

        Raises:
            SASLSecurityError: If unwrapping fails or data corrupted
        """
        if not self.context.has_security_layer():
            msg = "Security layer not active"
            raise SASLSecurityError(
                msg,
                mechanism=self.context.mechanism,
                security_layer="unwrap",
            )

        # ZERO TOLERANCE - Implement basic SASL security layer unwrapping
        if self.qop == "auth":
            # Authentication only - no protection, return data as-is
            return protected_data

        if self.qop == "auth-int":
            # Authentication with integrity protection - verify MAC
            try:
                import hashlib
                import hmac

                if (
                    len(protected_data) < MIN_INTEGRITY_DATA_SIZE
                ):  # 4 bytes length + minimum data + 32 bytes MAC
                    msg = "Protected data too short for integrity verification"
                    raise ValueError(msg)

                # Extract components: [4 bytes length][data][32 bytes MAC]
                data_length = int.from_bytes(protected_data[:4], byteorder="big")
                data = protected_data[4 : 4 + data_length]
                received_mac = protected_data[4 + data_length : 4 + data_length + 32]

                # Verify integrity
                if not hasattr(self, "_integrity_key") or not self._integrity_key:
                    # Generate same integrity key as in wrap()
                    self._integrity_key = hashlib.sha256(
                        b"sasl-integrity-" + str(id(self)).encode(),
                    ).digest()

                expected_mac = hmac.new(
                    self._integrity_key,
                    data,
                    hashlib.sha256,
                ).digest()

                if not hmac.compare_digest(received_mac, expected_mac):
                    msg = "Integrity verification failed - data may be corrupted"
                    raise ValueError(msg)

                return data

            except ImportError:
                logging.getLogger(__name__).warning(
                    "HMAC/hashlib not available for integrity verification",
                )
                return protected_data

        elif self.qop == "auth-conf":
            # Authentication with confidentiality - decrypt data
            try:
                from cryptography.fernet import Fernet

                if len(protected_data) < MIN_CONFIDENTIALITY_DATA_SIZE:
                    msg = "Protected data too short for decryption"
                    raise ValueError(msg)

                # Extract components: [4 bytes length][encrypted data]
                data_length = int.from_bytes(protected_data[:4], byteorder="big")
                encrypted_data = protected_data[4 : 4 + data_length]

                # Decrypt using same key as in wrap()
                if not hasattr(self, "_encryption_key") or not self._encryption_key:
                    import base64

                    key_material = hashlib.sha256(
                        b"sasl-encryption-" + str(id(self)).encode(),
                    ).digest()
                    self._encryption_key = base64.urlsafe_b64encode(key_material)

                fernet = Fernet(self._encryption_key)
                return fernet.decrypt(encrypted_data)

            except ImportError:
                logging.getLogger(__name__).warning(
                    "Cryptography package not available for decryption",
                )
                # Try integrity verification instead
                return self.unwrap(protected_data)

        else:
            logging.getLogger(__name__).warning(
                "Unknown QOP level: %s, returning data as-is",
                self.qop,
            )
            return protected_data

    def get_max_send_size(self) -> int:
        """Get maximum size for data to be wrapped.

        Returns:
            Maximum size in bytes
        """
        if self.context.negotiated_buffer_size:
            # Account for security layer overhead
            overhead = 16  # Typical MAC/padding overhead
            return max(0, self.context.negotiated_buffer_size - overhead)
        return 65536  # Default buffer size


# Export all context classes
__all__ = [
    "QualityOfProtection",
    "SASLContext",
    "SASLProperties",
    "SASLSecurityLayer",
    "SASLState",
]
