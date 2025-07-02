"""SASL DIGEST-MD5 Mechanism Implementation.

This module implements the SASL DIGEST-MD5 mechanism (RFC 2831) for
challenge-response authentication using MD5 digest. This mechanism
provides protection against passive eavesdropping and replay attacks.

DIGEST-MD5 is a challenge-response mechanism that avoids sending
passwords in cleartext while providing mutual authentication and
integrity protection capabilities.

Security Considerations:
    - Protects against passive eavesdropping
    - Provides mutual authentication
    - Supports integrity protection (auth-int)
    - MD5 is cryptographically weak (deprecated in RFC 6331)
    - Should migrate to SCRAM-SHA-1/SHA-256 for new deployments

Security Note:
    The MD5 usage in this implementation is REQUIRED by RFC 2831 (DIGEST-MD5).
    This is not a security vulnerability but a protocol specification requirement.
    The MD5 is used for digest computation as mandated by the standard.
    For new implementations, prefer SCRAM-SHA-256 or other modern mechanisms.

Usage Example:
    >>> from flext_ldap.protocols.sasl.mechanisms.digest_md5 import DigestMD5Mechanism
    >>> from flext_ldapasl.callback import SASLCallbackHandler
    >>>
    >>> callback = SASLCallbackHandler(
    ...     username="john.doe",
    ...     password="secret123",
    ...     realm="example.com"
    ... )
    >>> mechanism = DigestMD5Mechanism(callback)
    >>>
    >>> # Process server challenge
    >>> response = mechanism.evaluate_challenge(server_challenge)

References:
    - RFC 2831: Using Digest Authentication as a SASL Mechanism (Historic)
    - RFC 6331: Moving DIGEST-MD5 to Historic
    - RFC 2617: HTTP Authentication: Basic and Digest Access Authentication
    - RFC 4422: Simple Authentication and Security Layer (SASL)

"""

from __future__ import annotations

import hashlib
import secrets
from typing import ClassVar

from flext_ldapasl.callback import (
    NameCallback,
    PasswordCallback,
    RealmCallback,
    SASLCallbackHandler,
)
from flext_ldapasl.context import QualityOfProtection, SASLContext
from flext_ldapasl.exceptions import (
    SASLAuthenticationError,
    SASLCallbackError,
    SASLChallengeError,
)
from flext_ldapasl.mechanism import (
    SASLMechanism,
    SASLMechanismCapabilities,
    SASLMechanismType,
    SASLSecurityFlag,
)


class DigestMD5Mechanism(SASLMechanism):
    """SASL DIGEST-MD5 mechanism implementation.

    The DIGEST-MD5 mechanism provides challenge-response authentication
    using MD5 digest with mutual authentication and integrity protection
    capabilities.

    Authentication Flow:
        1. Server sends challenge with nonce and parameters
        2. Client computes response digest and sends credentials
        3. Server validates response and sends authentication result
        4. Optional: Security layer establishment for integrity

    Note: DIGEST-MD5 is deprecated (RFC 6331) due to MD5 weaknesses.
    New deployments should use SCRAM-SHA-1/SHA-256 instead.

    Example:
        >>> mechanism = DigestMD5Mechanism(callback_handler)
        >>> response1 = mechanism.evaluate_challenge(server_challenge1)
        >>> response2 = mechanism.evaluate_challenge(server_challenge2)

    """

    MECHANISM_NAME: ClassVar[str] = "DIGEST-MD5"
    MECHANISM_CAPABILITIES: ClassVar[SASLMechanismCapabilities] = (
        SASLMechanismCapabilities(
            mechanism_type=SASLMechanismType.CHALLENGE_RESPONSE,
            supports_initial_response=False,  # Server sends first challenge
            supports_server_challenges=True,
            requires_server_name=True,  # For digest-uri
            requires_realm=False,  # Realm can be discovered from challenge
            security_flags=[
                SASLSecurityFlag.NO_ANONYMOUS,  # Provides authentication
                SASLSecurityFlag.NO_PLAIN_TEXT,  # No plaintext passwords
                SASLSecurityFlag.MUTUAL_AUTH,  # Supports mutual authentication
            ],
            qop_supported=["auth", "auth-int"],  # Authentication and integrity
            max_security_strength=128,  # MD5 provides ~128-bit equivalent
            computational_cost=3,  # Moderate computational cost
            network_round_trips=2,  # Challenge-response-verify
        )
    )

    def __init__(
        self,
        callback_handler: SASLCallbackHandler,
        context: SASLContext | None = None,
    ) -> None:
        """Initialize DIGEST-MD5 mechanism.

        Args:
            callback_handler: Callback handler for credentials
            context: SASL context (created if not provided)

        """
        super().__init__(callback_handler, context)

        # DIGEST-MD5 state
        self._username: str | None = None
        self._password: str | None = None
        self._realm: str | None = None

        # Challenge/response state
        self._server_challenge: dict[str, str] | None = None
        self._client_nonce: str | None = None
        self._nonce_count = 0
        self._digest_uri: str | None = None
        self._qop: str | None = None

        # Authentication state
        self._expecting_challenge = True
        self._expecting_response_auth = False

    def evaluate_challenge(self, challenge: bytes) -> bytes | None:
        """Evaluate DIGEST-MD5 challenge and generate response.

        DIGEST-MD5 has multiple phases:
        1. Initial challenge from server (parameters and nonce)
        2. Client response with authentication digest
        3. Server response-auth verification (optional)

        Args:
            challenge: Challenge data from server

        Returns:
            Response data to send to server, or None if complete

        Raises:
            SASLAuthenticationError: If authentication fails
            SASLChallengeError: If challenge is malformed

        """
        self._record_challenge(challenge)

        try:
            if self._expecting_challenge:
                # Phase 1: Process initial server challenge
                return self._process_initial_challenge(challenge)
            if self._expecting_response_auth:
                # Phase 3: Process server response-auth
                return self._process_response_auth(challenge)
            msg = "Unexpected challenge in DIGEST-MD5"
            raise SASLChallengeError(
                msg,
                mechanism="DIGEST-MD5",
                challenge_step=self._challenge_count,
            )

        except SASLCallbackError as e:
            msg = f"Failed to obtain credentials: {e}"
            raise SASLAuthenticationError(
                msg,
                mechanism="DIGEST-MD5",
                challenge_step=self._challenge_count,
                error_code="callback-failed",
                original_error=e,
            ) from e
        except Exception as e:
            msg = f"DIGEST-MD5 mechanism error: {e}"
            raise SASLAuthenticationError(
                msg,
                mechanism="DIGEST-MD5",
                challenge_step=self._challenge_count,
                error_code="mechanism-error",
                original_error=e,
            ) from e

    def _process_initial_challenge(self, challenge: bytes) -> bytes:
        """Process initial server challenge.

        Args:
            challenge: Server challenge with parameters

        Returns:
            Client response with authentication digest

        """
        # Parse challenge parameters
        self._server_challenge = self._parse_challenge(challenge)

        # Validate required parameters
        if "nonce" not in self._server_challenge:
            msg = "Missing nonce in DIGEST-MD5 challenge"
            raise SASLChallengeError(
                msg,
                mechanism="DIGEST-MD5",
                challenge_malformed=True,
            )

        # Get credentials through callbacks
        self._obtain_credentials()

        # Select realm if multiple provided
        self._select_realm()

        # Build digest URI
        self._build_digest_uri()

        # Select QOP
        self._select_qop()

        # Generate client nonce
        self._client_nonce = self._generate_nonce()
        self._nonce_count = 1

        # Generate response
        response = self._generate_response()

        # Update state
        self._expecting_challenge = False
        self._expecting_response_auth = True

        self._record_response(response)
        return response

    def _process_response_auth(self, challenge: bytes) -> bytes | None:
        """Process server response-auth.

        Args:
            challenge: Server response-auth for verification

        Returns:
            None (authentication complete)

        """
        if len(challenge) == 0:
            # No response-auth, authentication complete
            self._set_complete()
            return None

        # Parse response-auth
        response_auth = self._parse_challenge(challenge)

        # Verify response-auth
        if not self._verify_response_auth(response_auth):
            msg = "Server response-auth verification failed"
            raise SASLAuthenticationError(
                msg,
                mechanism="DIGEST-MD5",
                error_code="response-auth-failed",
            )

        # Authentication successful
        self._set_complete()

        # Establish security layer if auth-int
        if self._qop == "auth-int":
            self._establish_security_layer()

        return None  # Empty response or None for completion

    def _parse_challenge(self, challenge: bytes) -> dict[str, str]:
        """Parse DIGEST-MD5 challenge parameters.

        Args:
            challenge: Raw challenge data

        Returns:
            Dictionary of challenge parameters

        """
        # TODO: Implement proper DIGEST-MD5 challenge parsing
        # This should parse the challenge string into key-value pairs
        # following RFC 2831 format

        challenge_str = challenge.decode("utf-8")
        params = {}

        # Simple parsing (should be more robust)
        for part in challenge_str.split(","):
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"')
                params[key] = value

        return params

    def _obtain_credentials(self) -> None:
        """Obtain credentials through callback system."""
        callbacks = []

        # Username callback
        name_callback = NameCallback("Username: ")
        callbacks.append(name_callback)

        # Password callback
        password_callback = PasswordCallback("Password: ", echo_on=False)
        callbacks.append(password_callback)

        # Realm callback (may use default from challenge)
        default_realm = (
            self._server_challenge.get("realm") if self._server_challenge else None
        )
        realm_callback = RealmCallback("Realm: ", default_realm)
        callbacks.append(realm_callback)

        # Handle callbacks
        self.callback_handler.handle_callbacks(callbacks)

        # Extract values
        self._username = name_callback.get_value()
        self._password = password_callback.get_value()
        self._realm = realm_callback.get_value()

        # Validate required credentials
        if not self._username:
            msg = "Username required"
            raise SASLCallbackError(msg, callback_type="NameCallback")
        if not self._password:
            msg = "Password required"
            raise SASLCallbackError(msg, callback_type="PasswordCallback")

        # Update context
        self.context.set_authentication_id(self._username)
        if self._realm:
            self.context.set_realm(self._realm)

    def _select_realm(self) -> None:
        """Select authentication realm."""
        if not self._realm:
            # Use first realm from challenge or empty
            realms = (
                self._server_challenge.get("realm", "")
                if self._server_challenge
                else ""
            ).split(",")
            self._realm = realms[0].strip() if realms and realms[0].strip() else ""

    def _build_digest_uri(self) -> None:
        """Build digest-uri for authentication."""
        service = self.callback_handler.service or "ldap"
        hostname = self.callback_handler.hostname or "localhost"
        self._digest_uri = f"{service}/{hostname}"

    def _select_qop(self) -> None:
        """Select Quality of Protection."""
        server_qop = (
            self._server_challenge.get("qop", "auth")
            if self._server_challenge
            else "auth"
        ).split(",")
        server_qop = [q.strip() for q in server_qop]

        # Prefer auth-int if available and supported
        if (
            "auth-int" in server_qop
            and "auth-int" in self.get_capabilities().qop_supported
        ):
            self._qop = "auth-int"
        else:
            self._qop = "auth"

    def _generate_nonce(self) -> str:
        """Generate client nonce."""
        return secrets.token_hex(16)

    def _generate_response(self) -> bytes:
        """Generate DIGEST-MD5 response."""
        # TODO: Implement proper DIGEST-MD5 response generation
        # This should compute the MD5 digest according to RFC 2831

        # Basic response structure (needs proper implementation)
        params = {
            "username": self._username,
            "realm": self._realm or "",
            "nonce": self._server_challenge["nonce"],
            "cnonce": self._client_nonce,
            "nc": f"{self._nonce_count:08x}",
            "qop": self._qop,
            "digest-uri": self._digest_uri,
            "response": self._compute_response_digest(),
        }

        # Format response
        response_parts = []
        for key, value in params.items():
            if value:
                response_parts.append(f'{key}="{value}"')

        response_str = ",".join(response_parts)
        return response_str.encode("utf-8")

    def _compute_response_digest(self) -> str:
        """Compute response digest."""
        # TODO: Implement proper MD5 digest computation
        # This is a placeholder implementation

        # H(A1) = MD5(username:realm:password)
        # NOTE: MD5 is required by RFC 2831 DIGEST-MD5 specification - not a security flaw
        a1 = f"{self._username}:{self._realm}:{self._password}"
        ha1 = hashlib.md5(a1.encode("utf-8")).hexdigest()  # noqa: S324

        # H(A2) = MD5(method:digest-uri)
        # NOTE: MD5 is required by RFC 2831 DIGEST-MD5 specification - not a security flaw
        a2 = f"AUTHENTICATE:{self._digest_uri}"
        ha2 = hashlib.md5(a2.encode("utf-8")).hexdigest()  # noqa: S324

        # Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        # NOTE: MD5 is required by RFC 2831 DIGEST-MD5 specification - not a security flaw
        response_str = f"{ha1}:{self._server_challenge['nonce']}:{self._nonce_count:08x}:{self._client_nonce}:{self._qop}:{ha2}"
        return hashlib.md5(response_str.encode("utf-8")).hexdigest()  # noqa: S324

    def _verify_response_auth(self, response_auth: dict[str, str]) -> bool:
        """Verify server response-auth."""
        # TODO: Implement proper response-auth verification
        # This should verify the server's authentication

        server_response = response_auth.get("rspauth")
        if not server_response:
            return True  # No response-auth to verify

        # Compute expected response-auth
        # H(A1) same as before
        # NOTE: MD5 is required by RFC 2831 DIGEST-MD5 specification - not a security flaw
        a1 = f"{self._username}:{self._realm}:{self._password}"
        ha1 = hashlib.md5(a1.encode("utf-8")).hexdigest()  # noqa: S324

        # H(A2) for response-auth = MD5(:digest-uri)
        # NOTE: MD5 is required by RFC 2831 DIGEST-MD5 specification - not a security flaw
        a2 = f":{self._digest_uri}"
        ha2 = hashlib.md5(a2.encode("utf-8")).hexdigest()  # noqa: S324

        # Expected response-auth
        # NOTE: MD5 is required by RFC 2831 DIGEST-MD5 specification - not a security flaw
        expected = f"{ha1}:{self._server_challenge['nonce']}:{self._nonce_count:08x}:{self._client_nonce}:{self._qop}:{ha2}"
        expected_hash = hashlib.md5(expected.encode("utf-8")).hexdigest()  # noqa: S324

        return server_response == expected_hash

    def _establish_security_layer(self) -> None:
        """Establish security layer for auth-int QOP."""
        # TODO: Implement security layer establishment
        # This should set up integrity protection keys

        if self._qop == "auth-int":
            self.context.negotiate_security_layer(
                QualityOfProtection.AUTH_INT,
                buffer_size=65536,
            )

            # Generate integrity key (simplified)
            # NOTE: MD5 is required by RFC 2831 DIGEST-MD5 specification - not a security flaw
            key_material = f"{self._username}:{self._realm}:{self._password}:integrity"
            integrity_key = hashlib.md5(key_material.encode("utf-8")).digest()  # noqa: S324

            self.context.activate_security_layer(integrity_key=integrity_key)

    def dispose(self) -> None:
        """Clear sensitive DIGEST-MD5 data."""
        # Clear credentials
        if self._password:
            self._password = "x" * len(self._password)
            self._password = None

        self._username = None
        self._realm = None
        self._server_challenge = None
        self._client_nonce = None

        super().dispose()

    def __str__(self) -> str:
        """String representation (security-aware)."""
        return f"DigestMD5Mechanism(username={self._username}, realm={self._realm}, complete={self.is_complete()})"


# TODO: Integration points for DIGEST-MD5 mechanism completion:
#
# 1. Complete RFC 2831 Implementation:
#    - Proper challenge parsing with quoted strings
#    - Correct MD5 digest computation
#    - Response-auth verification
#    - Character set handling (ISO-8859-1, UTF-8)
#
# 2. Security Layer Implementation:
#    - Integrity protection (auth-int)
#    - Message authentication codes
#    - Sequence number handling
#    - Buffer management
#
# 3. Parameter Validation:
#    - Nonce validation and replay protection
#    - QOP negotiation validation
#    - Cipher selection (for auth-conf)
#    - Realm validation
#
# 4. Error Handling:
#    - Malformed challenge handling
#    - Authentication failure scenarios
#    - Security layer negotiation failures
#    - Replay attack detection
#
# 5. LDAP Integration:
#    - LDAP-specific digest-uri format
#    - Directory service integration
#    - Account validation
#    - Policy enforcement
#
# 6. Security Considerations:
#    - MD5 weakness mitigation
#    - Migration path to SCRAM
#    - Timing attack prevention
#    - Memory protection
#
# 7. Performance Optimization:
#    - Efficient digest computation
#    - Memory management
#    - Connection reuse
#    - Caching strategies
