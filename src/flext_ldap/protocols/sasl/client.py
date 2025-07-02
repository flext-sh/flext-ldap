"""SASL Client Implementation.

This module provides comprehensive SASL client implementation with mechanism
selection, challenge-response processing, and security layer management
equivalent to perl-Authen-SASL client functionality.

The SASL client manages the client-side authentication flow, handling
mechanism negotiation, credential callbacks, and security layer establishment
for secure communication with SASL-enabled servers.

Architecture:
    - SASLClient: Main client implementation with perl-Authen-SASL compatibility
    - SASLClientFactory: Factory for creating configured clients
    - Client state management and error handling
    - Integration with all SASL mechanisms

Usage Example:
    >>> from flext_ldap.protocols.sasl.client import SASLClient
    >>> from flext_ldapasl.callback import SASLCallbackHandler
    >>>
    >>> callback = SASLCallbackHandler(username="user", password="<secure_password>")
    >>> client = SASLClient(mechanisms=["DIGEST-MD5", "PLAIN"], callback=callback)
    >>>
    >>> # perl-Authen-SASL compatible API
    >>> if client.client_start():
    ...     response = client.client_step(server_challenge)

References:
    - perl-Authen-SASL: Client interface compatibility
    - RFC 4422: SASL client implementation requirements
    - LDAP Protocol: SASL bind operation integration
"""

from __future__ import annotations

from typing import Any

from flext_ldapasl.callback import SASLCallbackHandler
from flext_ldapasl.context import SASLContext, SASLState
from flext_ldapasl.exceptions import (
    SASLAuthenticationError,
    SASLInvalidMechanismError,
    sasl_mechanism_not_available,
)
from flext_ldapasl.mechanism import (
    SASLMechanism,
    SASLMechanismRegistry,
)
from pydantic import BaseModel, Field


class SASLClient(BaseModel):
    """SASL client implementation with perl-Authen-SASL compatibility.

    This class provides the main SASL client functionality including
    mechanism selection, authentication flow management, and security
    layer establishment.

    Example:
        >>> # Create client with mechanism preferences
        >>> client = SASLClient(
        ...     mechanisms=["DIGEST-MD5", "PLAIN"],
        ...     callback=callback_handler,
        ...     service="ldap",
        ...     hostname="server.example.com"
        ... )
        >>>
        >>> # perl-Authen-SASL compatible usage
        >>> client.client_start()
        >>> response = client.client_step(challenge)
    """

    # Configuration
    mechanisms: list[str] = Field(
        default_factory=list,
        description="Preferred SASL mechanisms in order",
    )
    callback: SASLCallbackHandler | None = Field(
        default=None,
        description="Callback handler for credentials",
    )
    service: str = Field(
        default="ldap",
        description="Service name for SASL authentication",
    )
    hostname: str | None = Field(
        default=None,
        description="Server hostname",
    )
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional SASL properties",
    )

    # State
    _context: SASLContext
    _mechanism: SASLMechanism | None = None
    _selected_mechanism: str | None = None
    _started: bool = False

    class Config:
        """Pydantic configuration."""

        arbitrary_types_allowed = True

    def __init__(self, **data) -> None:
        """Initialize SASL client."""
        super().__init__(**data)

        # Create context
        self._context = SASLContext(
            service=self.service,
            hostname=self.hostname,
            properties=self.callback.properties if self.callback else {},
        )

    def client_start(self, mechanism: str | None = None) -> bool:
        """Start SASL authentication (perl-Authen-SASL compatible).

        This method initializes the SASL authentication process by
        selecting a mechanism and preparing for challenge-response.

        Args:
            mechanism: Specific mechanism to use (optional)

        Returns:
            True if authentication started successfully

        Raises:
            SASLInvalidMechanismError: If mechanism not available
        """
        if self._started:
            msg = "SASL client already started"
            raise SASLAuthenticationError(
                msg,
                error_code="already-started",
            )

        # Select mechanism
        selected = mechanism or self._select_best_mechanism()

        if not selected:
            available = SASLMechanismRegistry.get_available_mechanisms()
            msg = "none"
            raise sasl_mechanism_not_available(
                msg,
                available,
                error_code="no-suitable-mechanism",
            )

        # Create mechanism instance
        try:
            self._mechanism = SASLMechanismRegistry.create_mechanism(
                selected,
                self.callback or SASLCallbackHandler(),
                self._context,
            )
            self._selected_mechanism = selected
            self._context.set_mechanism(selected)

        except SASLInvalidMechanismError:
            raise
        except Exception as e:
            msg = f"Failed to initialize mechanism {selected}: {e}"
            raise SASLAuthenticationError(
                msg,
                mechanism=selected,
                error_code="mechanism-init-failed",
                original_error=e,
            ) from e

        self._started = True
        self._context.set_state(SASLState.IN_PROGRESS)

        return True

    def client_step(self, challenge: bytes | str | None = None) -> bytes | None:
        """Process challenge and generate response (perl-Authen-SASL compatible).

        This method processes a server challenge and generates the
        appropriate client response.

        Args:
            challenge: Server challenge data (bytes, string, or None for initial)

        Returns:
            Client response data or None if authentication complete

        Raises:
            SASLAuthenticationError: If authentication fails
        """
        if not self._started or not self._mechanism:
            msg = "SASL client not started"
            raise SASLAuthenticationError(
                msg,
                error_code="not-started",
            )

        # Convert challenge to bytes
        if challenge is None:
            challenge_bytes = b""
        elif isinstance(challenge, str):
            challenge_bytes = challenge.encode("utf-8")
        else:
            challenge_bytes = challenge

        try:
            # Process challenge through mechanism
            response = self._mechanism.evaluate_challenge(challenge_bytes)

            # Check if authentication completed
            if self._mechanism.is_complete():
                self._context.set_state(SASLState.COMPLETE)

            return response

        except Exception as e:
            self._context.set_state(SASLState.FAILED)
            if isinstance(e, SASLAuthenticationError):
                raise
            msg = f"Challenge processing failed: {e}"
            raise SASLAuthenticationError(
                msg,
                mechanism=self._selected_mechanism,
                error_code="challenge-failed",
                original_error=e,
            ) from e

    def get_initial_response(self) -> bytes | None:
        """Get initial response if mechanism supports it.

        Returns:
            Initial response data or None if not supported
        """
        if not self._mechanism:
            return None

        if self._mechanism.supports_initial_response():
            return self._mechanism.get_initial_response()

        return None

    def has_initial_response(self) -> bool:
        """Check if selected mechanism supports initial response.

        Returns:
            True if mechanism supports initial response
        """
        if not self._mechanism:
            return False

        return self._mechanism.supports_initial_response()

    def is_complete(self) -> bool:
        """Check if authentication is complete.

        Returns:
            True if authentication completed successfully
        """
        if not self._mechanism:
            return False

        return self._mechanism.is_complete()

    def get_mechanism(self) -> str | None:
        """Get selected mechanism name.

        Returns:
            Selected mechanism name or None if not started
        """
        return self._selected_mechanism

    def get_context(self) -> SASLContext | None:
        """Get SASL context.

        Returns:
            SASL authentication context
        """
        return self._context

    def get_property(self, property_name: str) -> Any:
        """Get negotiated security property (perl-Authen-SASL compatible).

        Args:
            property_name: Property name to retrieve

        Returns:
            Property value or None if not available
        """
        if not self._mechanism:
            return None

        return self._mechanism.get_negotiated_property(property_name)

    def error(self) -> str | None:
        """Get last error message (perl-Authen-SASL compatible).

        Returns:
            Error message or None if no error
        """
        if self._context and self._context.state == SASLState.FAILED:
            return "Authentication failed"
        return None

    def _select_best_mechanism(self) -> str | None:
        """Select best available mechanism from preferences.

        Returns:
            Selected mechanism name or None if none available
        """
        available = SASLMechanismRegistry.get_available_mechanisms()

        # Use provided mechanism list or default preference order
        preferences = self.mechanisms or [
            "GSSAPI",
            "DIGEST-MD5",
            "CRAM-MD5",
            "PLAIN",
            "EXTERNAL",
            "ANONYMOUS",
        ]

        # Find first available mechanism from preferences
        for mechanism in preferences:
            if mechanism.upper() in [m.upper() for m in available]:
                return mechanism.upper()

        # If no preference matches, use first available
        return available[0] if available else None

    def dispose(self) -> None:
        """Dispose client and clear sensitive data.

        This method should be called when the client is no longer needed
        to clear sensitive authentication material.
        """
        if self._mechanism:
            self._mechanism.dispose()
            self._mechanism = None

        if self._context:
            self._context.dispose()
            self._context = None

        self._started = False
        self._selected_mechanism = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit with cleanup."""
        self.dispose()

    def __str__(self) -> str:
        """String representation."""
        mechanism = self._selected_mechanism or "none"
        state = (
            "complete"
            if self.is_complete()
            else ("started" if self._started else "not-started")
        )
        return f"SASLClient(mechanism={mechanism}, state={state})"

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"SASLClient("
            f"mechanisms={self.mechanisms!r}, "
            f"service={self.service!r}, "
            f"hostname={self.hostname!r}, "
            f"selected={self._selected_mechanism!r}, "
            f"started={self._started}, "
            f"complete={self.is_complete()})"
        )


class SASLClientFactory:
    """Factory for creating configured SASL clients.

    This class provides convenient methods for creating SASL clients
    with common configurations and use cases.

    Example:
        >>> factory = SASLClientFactory()
        >>> client = factory.create_client(
        ...     mechanisms=["DIGEST-MD5"],
        ...     username="user",
        ...     password="<secure_password>"
        ... )
    """

    @staticmethod
    def create_client(
        mechanisms: list[str] | None = None,
        username: str | None = None,
        password: str | None = None,
        realm: str | None = None,
        service: str = "ldap",
        hostname: str | None = None,
        callback: SASLCallbackHandler | None = None,
        **properties: Any,
    ) -> SASLClient:
        """Create configured SASL client.

        Args:
            mechanisms: Preferred mechanism list
            username: Username for authentication
            password: Password for authentication
            realm: Authentication realm
            service: Service name
            hostname: Server hostname
            callback: Custom callback handler
            **properties: Additional SASL properties

        Returns:
            Configured SASLClient instance
        """
        # Create callback handler if not provided
        if callback is None:
            from flext_ldapasl.callback import create_simple_callback

            callback = create_simple_callback(
                username=username,
                password=password,
                realm=realm,
                service=service,
                hostname=hostname,
                **properties,
            )

        return SASLClient(
            mechanisms=mechanisms or [],
            callback=callback,
            service=service,
            hostname=hostname,
            properties=properties,
        )

    @staticmethod
    def create_plain_client(
        username: str,
        password: str,
        service: str = "ldap",
        hostname: str | None = None,
    ) -> SASLClient:
        """Create client for PLAIN authentication.

        Args:
            username: Username for authentication
            password: Password for authentication
            service: Service name
            hostname: Server hostname

        Returns:
            SASLClient configured for PLAIN mechanism
        """
        return SASLClientFactory.create_client(
            mechanisms=["PLAIN"],
            username=username,
            password=password,
            service=service,
            hostname=hostname,
        )

    @staticmethod
    def create_digest_md5_client(
        username: str,
        password: str,
        realm: str | None = None,
        service: str = "ldap",
        hostname: str | None = None,
    ) -> SASLClient:
        """Create client for DIGEST-MD5 authentication.

        Args:
            username: Username for authentication
            password: Password for authentication
            realm: Authentication realm
            service: Service name
            hostname: Server hostname

        Returns:
            SASLClient configured for DIGEST-MD5 mechanism
        """
        return SASLClientFactory.create_client(
            mechanisms=["DIGEST-MD5"],
            username=username,
            password=password,
            realm=realm,
            service=service,
            hostname=hostname,
        )

    @staticmethod
    def create_external_client(
        authorization_id: str | None = None,
        service: str = "ldap",
        hostname: str | None = None,
    ) -> SASLClient:
        """Create client for EXTERNAL authentication.

        Args:
            authorization_id: Authorization identity (optional)
            service: Service name
            hostname: Server hostname

        Returns:
            SASLClient configured for EXTERNAL mechanism
        """
        from flext_ldapasl.callback import SASLCallbackHandler

        callback = SASLCallbackHandler(
            authorization_id=authorization_id,
            service=service,
            hostname=hostname,
        )

        return SASLClient(
            mechanisms=["EXTERNAL"],
            callback=callback,
            service=service,
            hostname=hostname,
        )

    @staticmethod
    def create_anonymous_client(
        trace_info: str | None = None,
        service: str = "ldap",
        hostname: str | None = None,
    ) -> SASLClient:
        """Create client for ANONYMOUS authentication.

        Args:
            trace_info: Optional trace information
            service: Service name
            hostname: Server hostname

        Returns:
            SASLClient configured for ANONYMOUS mechanism
        """
        from flext_ldapasl.callback import SASLCallbackHandler

        callback = SASLCallbackHandler(
            service=service,
            hostname=hostname,
            properties={"trace_info": trace_info} if trace_info else {},
        )

        return SASLClient(
            mechanisms=["ANONYMOUS"],
            callback=callback,
            service=service,
            hostname=hostname,
        )


# Export client classes
__all__ = [
    "SASLClient",
    "SASLClientFactory",
]
