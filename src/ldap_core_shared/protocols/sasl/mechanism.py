"""SASL Mechanism Framework and Registry.

This module provides the base framework for SASL mechanism implementations
with a pluggable architecture, mechanism registry, and common functionality
for all SASL authentication mechanisms.

The mechanism framework provides a consistent interface for implementing
different SASL mechanisms while handling mechanism-specific requirements,
capability negotiation, and security property management.

Architecture:
    - SASLMechanism: Abstract base class for all mechanisms
    - SASLMechanismRegistry: Global mechanism registry and discovery
    - SASLMechanismCapabilities: Mechanism capability description
    - SASLMechanismFactory: Factory for creating mechanism instances

Usage Example:
    >>> from ldap_core_shared.protocols.sasl.mechanism import SASLMechanismRegistry
    >>>
    >>> # Get available mechanisms
    >>> mechanisms = SASLMechanismRegistry.get_available_mechanisms()
    >>>
    >>> # Create mechanism instance
    >>> mechanism = SASLMechanismRegistry.create_mechanism("DIGEST-MD5", callback)
    >>>
    >>> # Check mechanism capabilities
    >>> if mechanism.supports_initial_response():
    ...     initial = mechanism.get_initial_response()

References:
    - RFC 4422: SASL mechanism framework requirements
    - perl-Authen-SASL: Mechanism architecture compatibility
    - Java SASL: Mechanism interface design patterns

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel, Field

from ldap_core_shared.protocols.sasl.context import QualityOfProtection, SASLContext
from ldap_core_shared.protocols.sasl.exceptions import (
    SASLInvalidMechanismError,
    SASLMechanismError,
)

if TYPE_CHECKING:
    from ldap_core_shared.protocols.sasl.callback import SASLCallbackHandler


class SASLMechanismType(Enum):
    """SASL mechanism type classification."""

    SIMPLE = "simple"  # Simple username/password
    CHALLENGE_RESPONSE = "challenge_response"  # Challenge-response based
    TOKEN = "token"  # Token-based authentication
    CERTIFICATE = "certificate"  # Certificate-based authentication
    ANONYMOUS = "anonymous"  # Anonymous authentication


class SASLSecurityFlag(Enum):
    """SASL mechanism security flags."""

    NO_ANONYMOUS = "no_anonymous"  # Mechanism provides authentication
    NO_PLAIN_TEXT = "no_plain_text"  # No plaintext credentials
    NO_ACTIVE = "no_active"  # Immune to active attacks
    NO_DICTIONARY = "no_dictionary"  # Immune to dictionary attacks
    FORWARD_SECRECY = "forward_secrecy"  # Provides forward secrecy
    MUTUAL_AUTH = "mutual_auth"  # Supports mutual authentication
    PASS_CREDENTIALS = "pass_credentials"  # Supports credential delegation


class SASLMechanismCapabilities(BaseModel):
    """SASL mechanism capabilities and security properties.

    This class describes the capabilities and security properties
    of a SASL mechanism for capability negotiation and selection.

    Example:
        >>> capabilities = SASLMechanismCapabilities(
        ...     mechanism_type=SASLMechanismType.CHALLENGE_RESPONSE,
        ...     supports_initial_response=True,
        ...     security_flags=[SASLSecurityFlag.NO_PLAIN_TEXT],
        ...     qop_supported=["auth", "auth-int"]
        ... )

    """

    # Basic mechanism properties
    mechanism_type: SASLMechanismType = Field(
        description="Mechanism type classification",
    )

    # Protocol capabilities
    supports_initial_response: bool = Field(
        default=False,
        description="Mechanism can provide initial response",
    )

    supports_server_challenges: bool = Field(
        default=True,
        description="Mechanism supports server challenges",
    )

    requires_server_name: bool = Field(
        default=False,
        description="Mechanism requires server name",
    )

    requires_realm: bool = Field(
        default=False,
        description="Mechanism requires authentication realm",
    )

    # Security properties
    security_flags: list[SASLSecurityFlag] = Field(
        default_factory=list,
        description="Security flags for this mechanism",
    )

    qop_supported: list[str] = Field(
        default=["auth"],
        description="Supported Quality of Protection levels",
    )

    max_security_strength: int = Field(
        default=0,
        description="Maximum security strength in bits",
    )

    # Performance characteristics
    computational_cost: int = Field(
        default=1,
        description="Relative computational cost (1-10 scale)",
    )

    network_round_trips: int = Field(
        default=1,
        description="Typical number of network round trips",
    )

    def has_security_flag(self, flag: SASLSecurityFlag) -> bool:
        """Check if mechanism has security flag.

        Args:
            flag: Security flag to check

        Returns:
            True if mechanism has the flag

        """
        return flag in self.security_flags

    def supports_qop(self, qop: str) -> bool:
        """Check if mechanism supports QOP.

        Args:
            qop: Quality of Protection to check

        Returns:
            True if QOP is supported

        """
        return qop in self.qop_supported

    def is_secure_against_passive_attacks(self) -> bool:
        """Check if mechanism is secure against passive attacks.

        Returns:
            True if secure against passive eavesdropping

        """
        return self.has_security_flag(SASLSecurityFlag.NO_PLAIN_TEXT)

    def is_secure_against_active_attacks(self) -> bool:
        """Check if mechanism is secure against active attacks.

        Returns:
            True if secure against active attacks

        """
        return self.has_security_flag(SASLSecurityFlag.NO_ACTIVE)


class SASLMechanism(ABC):
    """Abstract base class for SASL mechanism implementations.

    This class provides the common interface and functionality for all
    SASL mechanisms, handling the authentication protocol flow and
    security layer negotiation.

    Example:
        >>> class CustomMechanism(SASLMechanism):
        ...     MECHANISM_NAME = "CUSTOM"
        ...
        ...     def evaluate_challenge(self, challenge):
        ...         # Custom challenge processing
        ...         return response

    """

    # Class-level mechanism information
    MECHANISM_NAME: ClassVar[str] = ""
    MECHANISM_CAPABILITIES: ClassVar[SASLMechanismCapabilities]

    def __init__(
        self,
        callback_handler: SASLCallbackHandler,
        context: SASLContext | None = None,
    ) -> None:
        """Initialize SASL mechanism.

        Args:
            callback_handler: Callback handler for credentials
            context: SASL context (created if not provided)

        """
        self.callback_handler = callback_handler
        self.context = context or SASLContext(
            mechanism=self.get_mechanism_name(),
            service=callback_handler.service,
            hostname=callback_handler.hostname,
        )

        # Authentication state
        self._complete = False
        self._challenge_count = 0
        self._last_challenge: bytes | None = None
        self._last_response: bytes | None = None

        # Mechanism-specific state
        self._mechanism_state: dict[str, Any] = {}

    @classmethod
    def get_mechanism_name(cls) -> str:
        """Get mechanism name.

        Returns:
            SASL mechanism name

        """
        return cls.MECHANISM_NAME

    @classmethod
    def get_capabilities(cls) -> SASLMechanismCapabilities:
        """Get mechanism capabilities.

        Returns:
            Mechanism capabilities

        """
        return cls.MECHANISM_CAPABILITIES

    def is_complete(self) -> bool:
        """Check if authentication is complete.

        Returns:
            True if authentication completed successfully

        """
        return self._complete

    def get_challenge_count(self) -> int:
        """Get number of challenges processed.

        Returns:
            Challenge count

        """
        return self._challenge_count

    def supports_initial_response(self) -> bool:
        """Check if mechanism supports initial response.

        Returns:
            True if mechanism can provide initial response

        """
        return self.get_capabilities().supports_initial_response

    def get_context(self) -> SASLContext:
        """Get SASL context.

        Returns:
            SASL authentication context

        """
        return self.context

    @abstractmethod
    def evaluate_challenge(self, challenge: bytes) -> bytes | None:
        """Evaluate server challenge and generate response.

        This is the main authentication method that processes server
        challenges and generates appropriate responses.

        Args:
            challenge: Challenge data from server (empty for initial)

        Returns:
            Response data to send to server, or None if no response

        Raises:
            SASLError: If challenge evaluation fails

        """

    def get_initial_response(self) -> bytes | None:
        """Get initial response for mechanisms that support it.

        Returns:
            Initial response data, or None if not supported

        Raises:
            SASLError: If initial response generation fails

        """
        if not self.supports_initial_response():
            return None

        return self.evaluate_challenge(b"")

    def dispose(self) -> None:
        """Dispose mechanism and clear sensitive data.

        This method should be called when mechanism is no longer needed
        to clear sensitive authentication material.
        """
        # Clear mechanism state
        self._mechanism_state.clear()
        self._last_challenge = None
        self._last_response = None

        # Dispose context
        self.context.dispose()

    def get_negotiated_property(self, property_name: str) -> Any:
        """Get negotiated security property value.

        Args:
            property_name: Property name

        Returns:
            Property value or None if not negotiated

        """
        if property_name == "qop":
            return (
                self.context.negotiated_qop.value
                if self.context.negotiated_qop
                else None
            )
        if property_name == "cipher":
            return self.context.negotiated_cipher
        if property_name == "maxbuf":
            return self.context.negotiated_buffer_size
        if property_name == "ssf":
            # Security Strength Factor
            if self.context.negotiated_qop == QualityOfProtection.AUTH_CONF:
                return self.get_capabilities().max_security_strength
            return 0
        return self.context.properties.mechanism_properties.get(property_name)

    def _record_challenge(self, challenge: bytes) -> None:
        """Record challenge for debugging and state tracking.

        Args:
            challenge: Challenge data

        """
        self._last_challenge = challenge
        self._challenge_count += 1
        self.context.record_challenge(challenge)

    def _record_response(self, response: bytes | None) -> None:
        """Record response for debugging and state tracking.

        Args:
            response: Response data

        """
        if response is not None:
            self._last_response = response
            self.context.record_response(response)

    def _set_complete(self) -> None:
        """Mark authentication as complete.

        This method should be called by mechanism implementations
        when authentication succeeds.
        """
        self._complete = True
        self.context.set_state("complete")

    def _mechanism_error(self, message: str, **kwargs) -> SASLMechanismError:
        """Create mechanism-specific error.

        Args:
            message: Error message
            **kwargs: Additional error context

        Returns:
            SASLMechanismError instance

        """
        return SASLMechanismError(
            message,
            mechanism=self.get_mechanism_name(),
            **kwargs,
        )


class SASLMechanismRegistry:
    """Global registry for SASL mechanism implementations.

    This class manages the registration and discovery of available
    SASL mechanisms, providing a factory interface for creating
    mechanism instances.

    Example:
        >>> # Register mechanism
        >>> SASLMechanismRegistry.register_mechanism(CustomMechanism)
        >>>
        >>> # Get available mechanisms
        >>> mechanisms = SASLMechanismRegistry.get_available_mechanisms()
        >>>
        >>> # Create mechanism instance
        >>> mechanism = SASLMechanismRegistry.create_mechanism("CUSTOM", callback)

    """

    _mechanisms: ClassVar[dict[str, type[SASLMechanism]]] = {}
    _initialized = False

    @classmethod
    def register_mechanism(cls, mechanism_class: type[SASLMechanism]) -> None:
        """Register SASL mechanism implementation.

        Args:
            mechanism_class: Mechanism class to register

        Raises:
            SASLInvalidMechanismError: If mechanism invalid

        """
        if not issubclass(mechanism_class, SASLMechanism):
            msg = f"Class {mechanism_class.__name__} is not a SASLMechanism subclass"
            raise SASLInvalidMechanismError(
                msg,
            )

        mechanism_name = mechanism_class.get_mechanism_name()
        if not mechanism_name:
            msg = f"Mechanism class {mechanism_class.__name__} has no MECHANISM_NAME"
            raise SASLInvalidMechanismError(
                msg,
            )

        cls._mechanisms[mechanism_name.upper()] = mechanism_class

    @classmethod
    def unregister_mechanism(cls, mechanism_name: str) -> None:
        """Unregister SASL mechanism.

        Args:
            mechanism_name: Name of mechanism to unregister

        """
        cls._mechanisms.pop(mechanism_name.upper(), None)

    @classmethod
    def get_available_mechanisms(cls) -> list[str]:
        """Get list of available mechanism names.

        Returns:
            List of registered mechanism names

        """
        cls._ensure_initialized()
        return list(cls._mechanisms.keys())

    @classmethod
    def is_mechanism_available(cls, mechanism_name: str) -> bool:
        """Check if mechanism is available.

        Args:
            mechanism_name: Mechanism name to check

        Returns:
            True if mechanism is registered

        """
        cls._ensure_initialized()
        return mechanism_name.upper() in cls._mechanisms

    @classmethod
    def get_mechanism_class(cls, mechanism_name: str) -> type[SASLMechanism]:
        """Get mechanism class by name.

        Args:
            mechanism_name: Mechanism name

        Returns:
            Mechanism class

        Raises:
            SASLInvalidMechanismError: If mechanism not found

        """
        cls._ensure_initialized()
        mechanism_class = cls._mechanisms.get(mechanism_name.upper())
        if mechanism_class is None:
            msg = f"SASL mechanism '{mechanism_name}' not available"
            raise SASLInvalidMechanismError(
                msg,
                requested_mechanism=mechanism_name,
                available_mechanisms=cls.get_available_mechanisms(),
            )
        return mechanism_class

    @classmethod
    def create_mechanism(
        cls,
        mechanism_name: str,
        callback_handler: SASLCallbackHandler,
        context: SASLContext | None = None,
    ) -> SASLMechanism:
        """Create mechanism instance.

        Args:
            mechanism_name: Mechanism name
            callback_handler: Callback handler for credentials
            context: SASL context (optional)

        Returns:
            Mechanism instance

        Raises:
            SASLInvalidMechanismError: If mechanism not available

        """
        mechanism_class = cls.get_mechanism_class(mechanism_name)
        return mechanism_class(callback_handler, context)

    @classmethod
    def get_mechanism_capabilities(
        cls,
        mechanism_name: str,
    ) -> SASLMechanismCapabilities:
        """Get mechanism capabilities.

        Args:
            mechanism_name: Mechanism name

        Returns:
            Mechanism capabilities

        Raises:
            SASLInvalidMechanismError: If mechanism not found

        """
        mechanism_class = cls.get_mechanism_class(mechanism_name)
        return mechanism_class.get_capabilities()

    @classmethod
    def select_mechanism(
        cls,
        available_mechanisms: list[str],
        security_requirements: dict[str, Any] | None = None,
    ) -> str | None:
        """Select best mechanism from available list.

        Args:
            available_mechanisms: List of available mechanism names
            security_requirements: Security requirements for selection

        Returns:
            Selected mechanism name or None if none suitable

        """
        cls._ensure_initialized()

        # Filter to registered mechanisms only
        candidates = [
            name for name in available_mechanisms if cls.is_mechanism_available(name)
        ]

        if not candidates:
            return None

        # Apply security requirements if provided
        if security_requirements:
            candidates = cls._filter_by_security_requirements(
                candidates,
                security_requirements,
            )

        # Select by preference order (could be customized)
        preference_order = [
            "GSSAPI",
            "DIGEST-MD5",
            "CRAM-MD5",
            "PLAIN",
            "ANONYMOUS",
        ]

        for preferred in preference_order:
            if preferred in candidates:
                return preferred

        # Return first candidate if no preference match
        return candidates[0] if candidates else None

    @classmethod
    def _filter_by_security_requirements(
        cls,
        mechanisms: list[str],
        requirements: dict[str, Any],
    ) -> list[str]:
        """Filter mechanisms by security requirements.

        Args:
            mechanisms: List of mechanism names
            requirements: Security requirements

        Returns:
            Filtered list of mechanism names

        """
        filtered = []

        for mechanism_name in mechanisms:
            try:
                capabilities = cls.get_mechanism_capabilities(mechanism_name)

                # Check minimum security strength
                min_strength = requirements.get("min_security_strength", 0)
                if capabilities.max_security_strength < min_strength:
                    continue

                # Check required security flags
                required_flags = requirements.get("required_security_flags", [])
                if not all(
                    capabilities.has_security_flag(flag) for flag in required_flags
                ):
                    continue

                # Check forbidden security flags
                forbidden_flags = requirements.get("forbidden_security_flags", [])
                if any(
                    capabilities.has_security_flag(flag) for flag in forbidden_flags
                ):
                    continue

                # Check QOP requirements
                required_qop = requirements.get("required_qop")
                if required_qop and not capabilities.supports_qop(required_qop):
                    continue

                filtered.append(mechanism_name)

            except SASLInvalidMechanismError:
                # Skip mechanisms that aren't available
                continue

        return filtered

    @classmethod
    def _ensure_initialized(cls) -> None:
        """Ensure registry is initialized with standard mechanisms."""
        if cls._initialized:
            return

        # Register standard mechanisms when they become available
        try:
            from ldap_core_shared.protocols.sasl.mechanisms.plain import PlainMechanism

            cls.register_mechanism(PlainMechanism)
        except ImportError:
            pass

        try:
            from ldap_core_shared.protocols.sasl.mechanisms.digest_md5 import (
                DigestMD5Mechanism,
            )

            cls.register_mechanism(DigestMD5Mechanism)
        except ImportError:
            pass

        try:
            from ldap_core_shared.protocols.sasl.mechanisms.external import (
                ExternalMechanism,
            )

            cls.register_mechanism(ExternalMechanism)
        except ImportError:
            pass

        try:
            from ldap_core_shared.protocols.sasl.mechanisms.anonymous import (
                AnonymousMechanism,
            )

            cls.register_mechanism(AnonymousMechanism)
        except ImportError:
            pass

        cls._initialized = True

    @classmethod
    def reset_registry(cls) -> None:
        """Reset registry (for testing)."""
        cls._mechanisms.clear()
        cls._initialized = False


# Export mechanism framework classes
__all__ = [
    "SASLMechanism",
    "SASLMechanismCapabilities",
    "SASLMechanismRegistry",
    "SASLMechanismType",
    "SASLSecurityFlag",
]
