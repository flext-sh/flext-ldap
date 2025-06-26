"""SASL PLAIN Mechanism Implementation.

This module implements the SASL PLAIN mechanism (RFC 4616) for simple
username/password authentication. PLAIN transmits credentials in cleartext
and should only be used over secure connections (TLS/SSL).

The PLAIN mechanism provides a simple authentication method compatible
with basic username/password systems and is widely supported across
LDAP servers and other network services.

Security Considerations:
    - PLAIN transmits credentials in cleartext
    - MUST be used with TLS/SSL for security
    - Vulnerable to passive eavesdropping without encryption
    - Should not be used over insecure networks

Usage Example:
    >>> from ldap_core_shared.protocols.sasl.mechanisms.plain import PlainMechanism
    >>> from ldap_core_shared.protocols.sasl.callback import SASLCallbackHandler
    >>>
    >>> callback = SASLCallbackHandler(
    ...     username="john.doe",
    ...     password="secret123"
    ... )
    >>> mechanism = PlainMechanism(callback)
    >>> response = mechanism.get_initial_response()

References:
    - RFC 4616: The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
    - RFC 4422: Simple Authentication and Security Layer (SASL)
    - LDAP Protocol: SASL PLAIN usage in LDAP authentication
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Optional

from ldap_core_shared.protocols.sasl.callback import (
    AuthorizeCallback,
    NameCallback,
    PasswordCallback,
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
)

if TYPE_CHECKING:
    from ldap_core_shared.protocols.sasl.context import SASLContext


class PlainMechanism(SASLMechanism):
    r"""SASL PLAIN mechanism implementation.

    The PLAIN mechanism allows a client to authenticate using a username
    and password transmitted in cleartext. This mechanism provides no
    security features and should only be used over secure transports.

    Message Format:
        The PLAIN mechanism uses a single message containing:
        [authzid] NUL authcid NUL passwd

        Where:
        - authzid: authorization identity (optional)
        - authcid: authentication identity (username)
        - passwd: password
        - NUL: null character separator (\\x00)

    Example:
        >>> mechanism = PlainMechanism(callback_handler)
        >>> response = mechanism.get_initial_response()
        >>> # Response contains: b'\\x00username\\x00password'
    """

    MECHANISM_NAME: ClassVar[str] = "PLAIN"
    MECHANISM_CAPABILITIES: ClassVar[SASLMechanismCapabilities] = SASLMechanismCapabilities(
        mechanism_type=SASLMechanismType.SIMPLE,
        supports_initial_response=True,
        supports_server_challenges=False,  # PLAIN is single-message
        requires_server_name=False,
        requires_realm=False,
        security_flags=[],  # No security flags - plaintext mechanism
        qop_supported=["auth"],  # Only authentication, no integrity/confidentiality
        max_security_strength=0,  # No encryption
        computational_cost=1,  # Very low computational cost
        network_round_trips=0,  # Initial response only, no round trips
    )

    def __init__(
        self,
        callback_handler: SASLCallbackHandler,
        context: Optional[SASLContext] = None,
    ) -> None:
        """Initialize PLAIN mechanism.

        Args:
            callback_handler: Callback handler for credentials
            context: SASL context (created if not provided)
        """
        super().__init__(callback_handler, context)

        # PLAIN mechanism state
        self._username: Optional[str] = None
        self._password: Optional[str] = None
        self._authorization_id: Optional[str] = None
        self._response_sent = False

    def evaluate_challenge(self, challenge: bytes) -> Optional[bytes]:
        """Evaluate challenge and generate PLAIN response.

        For PLAIN mechanism:
        - Initial call (empty challenge): Generate PLAIN response
        - Subsequent calls: Should not occur (PLAIN is single-message)

        Args:
            challenge: Challenge from server (should be empty for PLAIN)

        Returns:
            PLAIN authentication response or None if complete

        Raises:
            SASLAuthenticationError: If authentication fails
        """
        self._record_challenge(challenge)

        # PLAIN mechanism should only process initial challenge
        if self._response_sent:
            if len(challenge) == 0:
                # Server accepted authentication
                self._set_complete()
                return None
            msg = "PLAIN mechanism received unexpected challenge"
            raise SASLAuthenticationError(
                msg,
                mechanism="PLAIN",
                challenge_step=self._challenge_count,
                error_code="unexpected-challenge",
            )

        # Initial challenge should be empty for PLAIN
        if len(challenge) > 0:
            msg = "PLAIN mechanism received non-empty initial challenge"
            raise SASLAuthenticationError(
                msg,
                mechanism="PLAIN",
                challenge_step=self._challenge_count,
                error_code="invalid-initial-challenge",
            )

        try:
            # Get credentials through callbacks
            self._obtain_credentials()

            # Generate PLAIN response
            response = self._generate_plain_response()

            self._record_response(response)
            self._response_sent = True

            return response

        except SASLCallbackError as e:
            msg = f"Failed to obtain credentials: {e}"
            raise SASLAuthenticationError(
                msg,
                mechanism="PLAIN",
                challenge_step=self._challenge_count,
                error_code="callback-failed",
                original_error=e,
            ) from e
        except Exception as e:
            msg = f"PLAIN mechanism error: {e}"
            raise SASLAuthenticationError(
                msg,
                mechanism="PLAIN",
                challenge_step=self._challenge_count,
                error_code="mechanism-error",
                original_error=e,
            ) from e

    def _obtain_credentials(self) -> None:
        """Obtain credentials through callback system.

        Raises:
            SASLCallbackError: If callbacks fail
        """
        # Create callbacks for required information
        callbacks = []

        # Username callback
        name_callback = NameCallback("Username: ")
        callbacks.append(name_callback)

        # Password callback
        password_callback = PasswordCallback("Password: ", echo_on=False)
        callbacks.append(password_callback)

        # Authorization ID callback (optional)
        authz_callback = AuthorizeCallback("Authorize as: ")
        callbacks.append(authz_callback)

        # Handle all callbacks
        self.callback_handler.handle_callbacks(callbacks)

        # Extract values
        self._username = name_callback.get_value()
        self._password = password_callback.get_value()
        self._authorization_id = authz_callback.get_value()

        # Validate required credentials
        if not self._username:
            msg = "Username required for PLAIN mechanism"
            raise SASLCallbackError(
                msg,
                callback_type="NameCallback",
            )

        if not self._password:
            msg = "Password required for PLAIN mechanism"
            raise SASLCallbackError(
                msg,
                callback_type="PasswordCallback",
            )

        # Update context with identity information
        self.context.set_authentication_id(self._username)
        if self._authorization_id:
            self.context.set_authorization_id(self._authorization_id)

    def _generate_plain_response(self) -> bytes:
        """Generate PLAIN mechanism response.

        PLAIN response format:
        [authzid] NUL authcid NUL passwd

        Returns:
            Encoded PLAIN response
        """
        # Authorization identity (optional)
        authzid = self._authorization_id or ""

        # Authentication identity (required)
        authcid = self._username or ""

        # Password (required)
        passwd = self._password or ""

        # Construct PLAIN response: authzid \0 authcid \0 passwd
        response_str = f"{authzid}\x00{authcid}\x00{passwd}"

        # Encode as UTF-8 bytes
        return response_str.encode("utf-8")

    def dispose(self) -> None:
        """Clear sensitive credential data.

        Override to clear PLAIN-specific sensitive data.
        """
        # Clear credentials
        if self._password:
            # Overwrite password memory
            self._password = "x" * len(self._password)
            self._password = None

        self._username = None
        self._authorization_id = None

        # Call parent dispose
        super().dispose()

    def __str__(self) -> str:
        """String representation (security-aware)."""
        return f"PlainMechanism(username={self._username}, complete={self.is_complete()})"

    def __repr__(self) -> str:
        """Detailed representation (security-aware)."""
        return (
            f"PlainMechanism("
            f"username={self._username!r}, "
            f"authorization_id={self._authorization_id!r}, "
            f"complete={self.is_complete()}, "
            f"challenge_count={self._challenge_count})"
        )


# TODO: Integration points for PLAIN mechanism enhancements:
#
# 1. Security Enhancements:
#    - TLS requirement enforcement
#    - Secure connection validation
#    - Credential validation
#    - Rate limiting support
#
# 2. LDAP Integration:
#    - LDAP bind operation integration
#    - Directory-specific username formats
#    - Realm-based authentication
#    - Account status checking
#
# 3. Error Handling:
#    - Invalid credential detection
#    - Account lockout handling
#    - Password expiration support
#    - Authentication policy enforcement
#
# 4. Performance Optimization:
#    - Credential caching (if appropriate)
#    - Connection pooling integration
#    - Batch authentication support
#    - Memory usage optimization
#
# 5. Compliance and Standards:
#    - RFC 4616 full compliance
#    - LDAP SASL profile compliance
#    - Security best practices
#    - Interoperability testing
