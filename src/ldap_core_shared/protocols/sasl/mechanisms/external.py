"""SASL EXTERNAL Mechanism Implementation.

This module implements the SASL EXTERNAL mechanism for authentication
using external credentials such as TLS client certificates, Kerberos
tickets, or other out-of-band authentication methods.

The EXTERNAL mechanism allows authentication based on credentials
established outside the SASL exchange, typically through the underlying
transport layer (e.g., TLS client certificates) or operating system
authentication (e.g., Unix domain sockets).

Security Considerations:
    - Authentication relies on external security context
    - Secure transport establishment is critical
    - Identity mapping must be properly configured
    - Certificate validation and trust chains important

Usage Example:
    >>> from ldap_core_shared.protocols.sasl.mechanisms.external import ExternalMechanism
    >>> from ldap_core_shared.protocols.sasl.callback import SASLCallbackHandler
    >>>
    >>> # With authorization identity
    >>> callback = SASLCallbackHandler(authorization_id="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
    >>> mechanism = ExternalMechanism(callback)
    >>> response = mechanism.get_initial_response()
    >>>
    >>> # Without authorization identity (use certificate identity)
    >>> callback = SASLCallbackHandler()
    >>> mechanism = ExternalMechanism(callback)
    >>> response = mechanism.get_initial_response()  # Empty response

References:
    - RFC 4422: Simple Authentication and Security Layer (SASL)
    - RFC 4513: LDAP Authentication Methods and Security Mechanisms
    - RFC 5246: The Transport Layer Security (TLS) Protocol
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from ldap_core_shared.protocols.sasl.callback import (
    AuthorizeCallback,
    SASLCallbackHandler,
)
from ldap_core_shared.protocols.sasl.exceptions import (
    SASLAuthenticationError,
    SASLCallbackError,
)
from ldap_core_shared.protocols.sasl.mechanism import (
    SASLMechanism,
    SASLMechanismCapabilities,
    SASLMechanismType,
    SASLSecurityFlag,
)

if TYPE_CHECKING:
    from ldap_core_shared.protocols.sasl.context import SASLContext


class ExternalMechanism(SASLMechanism):
    """SASL EXTERNAL mechanism implementation.

    The EXTERNAL mechanism allows authentication using credentials
    established outside the SASL exchange. This is commonly used with:

    - TLS client certificates
    - Kerberos tickets (outside GSS-API)
    - Unix domain socket credentials
    - Operating system authentication
    - Hardware tokens or smart cards

    Message Format:
        The EXTERNAL mechanism uses a single message containing:
        - Empty message: Use identity from external credentials
        - Authorization identity: Specific identity to authorize as

    Example:
        >>> # Use certificate identity
        >>> mechanism = ExternalMechanism(callback_handler)
        >>> response = mechanism.get_initial_response()  # b''
        >>>
        >>> # Authorize as specific identity
        >>> callback.authorization_id = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        >>> response = mechanism.get_initial_response()  # b'cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com'
    """

    MECHANISM_NAME: ClassVar[str] = "EXTERNAL"
    MECHANISM_CAPABILITIES: ClassVar[SASLMechanismCapabilities] = (
        SASLMechanismCapabilities(
            mechanism_type=SASLMechanismType.CERTIFICATE,
            supports_initial_response=True,
            supports_server_challenges=False,  # EXTERNAL is single-message
            requires_server_name=False,
            requires_realm=False,
            security_flags=[
                SASLSecurityFlag.NO_ANONYMOUS,  # Provides authentication
                SASLSecurityFlag.NO_PLAIN_TEXT,  # No plaintext credentials
                SASLSecurityFlag.NO_ACTIVE,  # Depends on external security
            ],
            qop_supported=["auth"],  # Only authentication, security from transport
            max_security_strength=0,  # Security from external mechanism
            computational_cost=1,  # Very low computational cost
            network_round_trips=0,  # Initial response only
        )
    )

    def __init__(
        self,
        callback_handler: SASLCallbackHandler,
        context: SASLContext | None = None,
    ) -> None:
        """Initialize EXTERNAL mechanism.

        Args:
            callback_handler: Callback handler for authorization identity
            context: SASL context (created if not provided)
        """
        super().__init__(callback_handler, context)

        # EXTERNAL mechanism state
        self._authorization_id: str | None = None
        self._response_sent = False

    def evaluate_challenge(self, challenge: bytes) -> bytes | None:
        """Evaluate challenge and generate EXTERNAL response.

        For EXTERNAL mechanism:
        - Initial call (empty challenge): Generate EXTERNAL response
        - Subsequent calls: Should not occur (EXTERNAL is single-message)

        Args:
            challenge: Challenge from server (should be empty for EXTERNAL)

        Returns:
            EXTERNAL authentication response or None if complete

        Raises:
            SASLAuthenticationError: If authentication fails
        """
        self._record_challenge(challenge)

        # EXTERNAL mechanism should only process initial challenge
        if self._response_sent:
            if len(challenge) == 0:
                # Server accepted authentication
                self._set_complete()
                return None
            msg = "EXTERNAL mechanism received unexpected challenge"
            raise SASLAuthenticationError(
                msg,
                mechanism="EXTERNAL",
                challenge_step=self._challenge_count,
                error_code="unexpected-challenge",
            )

        # Initial challenge should be empty for EXTERNAL
        if len(challenge) > 0:
            msg = "EXTERNAL mechanism received non-empty initial challenge"
            raise SASLAuthenticationError(
                msg,
                mechanism="EXTERNAL",
                challenge_step=self._challenge_count,
                error_code="invalid-initial-challenge",
            )

        try:
            # Get authorization identity if provided
            self._obtain_authorization_id()

            # Generate EXTERNAL response
            response = self._generate_external_response()

            self._record_response(response)
            self._response_sent = True

            return response

        except SASLCallbackError as e:
            msg = f"Failed to obtain authorization identity: {e}"
            raise SASLAuthenticationError(
                msg,
                mechanism="EXTERNAL",
                challenge_step=self._challenge_count,
                error_code="callback-failed",
                original_error=e,
            ) from e
        except Exception as e:
            msg = f"EXTERNAL mechanism error: {e}"
            raise SASLAuthenticationError(
                msg,
                mechanism="EXTERNAL",
                challenge_step=self._challenge_count,
                error_code="mechanism-error",
                original_error=e,
            ) from e

    def _obtain_authorization_id(self) -> None:
        """Obtain authorization identity through callback system.

        The authorization identity is optional for EXTERNAL mechanism.
        If not provided, the server will use the identity from the
        external authentication mechanism (e.g., certificate subject).

        Raises:
            SASLCallbackError: If callback handling fails
        """
        # Authorization ID callback (optional for EXTERNAL)
        authz_callback = AuthorizeCallback(
            "Authorize as (empty for certificate identity): ",
        )

        try:
            # Handle callback - this may be a no-op if not interactive
            self.callback_handler.handle_callbacks([authz_callback])
            self._authorization_id = authz_callback.get_value()

            # Update context with authorization identity
            if self._authorization_id:
                self.context.set_authorization_id(self._authorization_id)

        except SASLCallbackError:
            # Authorization ID is optional for EXTERNAL - continue without it
            self._authorization_id = None

    def _generate_external_response(self) -> bytes:
        """Generate EXTERNAL mechanism response.

        EXTERNAL response format:
        - Empty: Use identity from external credentials
        - Authorization identity: Authorize as specific identity

        Returns:
            Encoded EXTERNAL response
        """
        if self._authorization_id:
            # Specific authorization identity requested
            return self._authorization_id.encode("utf-8")
        # Use identity from external credentials (empty response)
        return b""

    def get_external_identity_info(self) -> dict[str, str]:
        """Get information about external identity source.

        This method can be used to provide information about the
        external authentication mechanism being used.

        Returns:
            Dictionary with external identity information
        """
        info = {
            "mechanism": "EXTERNAL",
            "source": "unknown",  # Could be "tls", "unix", "kerberos", etc.
        }

        # Try to determine external authentication source
        if (
            hasattr(self.callback_handler, "hostname")
            and self.callback_handler.hostname
        ):
            info["source"] = "tls"  # Likely TLS client certificate

        if self._authorization_id:
            info["authorization_id"] = self._authorization_id

        return info

    def requires_external_authentication(self) -> bool:
        """Check if external authentication is required.

        Returns:
            True (EXTERNAL always requires external authentication)
        """
        return True

    def supports_authorization_identity(self) -> bool:
        """Check if mechanism supports authorization identity.

        Returns:
            True (EXTERNAL supports optional authorization identity)
        """
        return True

    def __str__(self) -> str:
        """String representation."""
        authz_info = (
            f", authz={self._authorization_id}" if self._authorization_id else ""
        )
        return f"ExternalMechanism(complete={self.is_complete()}{authz_info})"

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"ExternalMechanism("
            f"authorization_id={self._authorization_id!r}, "
            f"complete={self.is_complete()}, "
            f"challenge_count={self._challenge_count})"
        )


# TODO: Integration points for EXTERNAL mechanism enhancements:
#
# 1. TLS Integration:
#    - TLS client certificate validation
#    - Certificate chain verification
#    - Certificate revocation checking
#    - Certificate-to-identity mapping
#
# 2. Identity Mapping:
#    - Certificate subject DN mapping
#    - Alternative name processing
#    - Regular expression mapping rules
#    - LDAP identity lookup
#
# 3. Security Validation:
#    - External authentication verification
#    - Trust relationship validation
#    - Authorization policy enforcement
#    - Security context inspection
#
# 4. Unix Domain Socket Support:
#    - Peer credential retrieval
#    - UID/GID to identity mapping
#    - Process authentication
#    - Socket security validation
#
# 5. Kerberos Integration:
#    - Kerberos ticket validation
#    - Service principal mapping
#    - Delegation support
#    - Cross-realm authentication
#
# 6. LDAP Integration:
#    - LDAP external bind operations
#    - Certificate-based authentication
#    - Authorization identity resolution
#    - Account status validation
#
# 7. Error Handling:
#    - External authentication failures
#    - Identity mapping errors
#    - Authorization failures
#    - Certificate validation errors
#
# 8. Compliance and Standards:
#    - RFC 4422 compliance
#    - X.509 certificate standards
#    - LDAP authentication profiles
#    - Security best practices
