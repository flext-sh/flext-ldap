"""SASL Authentication Exceptions.

This module provides comprehensive exception classes for SASL authentication
errors with detailed error information, debugging support, and proper
error hierarchy for all SASL-related failures.

Exception Hierarchy:
    - SASLError: Base exception for all SASL errors
    - SASLAuthenticationError: Authentication process failures
    - SASLInvalidMechanismError: Mechanism selection and capability errors
    - SASLSecurityError: Security layer and policy violations
    - SASLCallbackError: Callback handler failures
    - SASLChallengeError: Challenge-response processing errors

Architecture:
    - Structured error information with context
    - Mechanism-specific error details
    - Security-aware error reporting (no credential leaks)
    - Integration with LDAP authentication error hierarchy
    - Debugging and troubleshooting support

Usage Example:
    >>> from ldap_core_shared.protocols.sasl.exceptions import SASLAuthenticationError
    >>>
    >>> try:
    ...     client.evaluate_challenge(challenge)
    ... except SASLAuthenticationError as e:
    ...     print(f"Authentication failed: {e}")
    ...     print(f"Mechanism: {e.mechanism}")
    ...     print(f"Error code: {e.error_code}")

References:
    - RFC 4422: SASL error conditions and reporting
    - perl-Authen-SASL: Error handling compatibility
    - LDAP Protocol: SASL authentication error mapping

"""

from __future__ import annotations

from typing import Any, cast

# Type for SASL error context data
SASLErrorContext = str, int, bool, list[str, dict[str, Any], None]

from ldap_core_shared.exceptions.auth import AuthenticationError


class SASLError(AuthenticationError):
    """Base exception for all SASL authentication errors.

    This exception serves as the root of the SASL exception hierarchy,
    providing common functionality for all SASL-related errors including
    mechanism information, challenge context, and security-aware reporting.

    Example:
        >>> raise SASLError(
        ...     "SASL authentication failed",
        ...     mechanism="DIGEST-MD5",
        ...     error_code="invalid-response"
        ... )

    """

    def __init__(
        self,
        message: str,
        *,
        mechanism: str | None = None,
        challenge_step: int | None = None,
        server_message: str | None = None,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        original_error: Exception | None = None,
    ) -> None:
        """Initialize SASL error.

        Args:
            message: Error description
            mechanism: SASL mechanism name
            challenge_step: Step number in challenge-response sequence
            server_message: Server error message (if available)
            error_code: SASL error code
            context: Additional error context
            original_error: Underlying exception

        """
        sasl_context = context or {}

        if mechanism:
            sasl_context["mechanism"] = mechanism
        if challenge_step is not None:
            sasl_context["challenge_step"] = challenge_step
        if server_message:
            # Only include if it doesn't contain sensitive information
            if not self._contains_sensitive_info(server_message):
                sasl_context["server_message"] = server_message

        super().__init__(
            message=message,
            auth_method="SASL",
            error_code=error_code,
            context=sasl_context,
            original_error=original_error,
        )

        self.mechanism = mechanism
        self.challenge_step = challenge_step
        self.server_message = server_message

    @staticmethod
    def _contains_sensitive_info(message: str) -> bool:
        """Check if message contains sensitive information.

        Args:
            message: Message to check

        Returns:
            True if message might contain sensitive data

        """
        sensitive_keywords = [
            "password",
            "credential",
            "secret",
            "token",
            "key",
            "digest",
            "hash",
            "nonce",
            "response",
            "challenge",
        ]
        return any(keyword in message.lower() for keyword in sensitive_keywords)


class SASLAuthenticationError(SASLError):
    """Exception for SASL authentication process failures.

    Raised when SASL authentication fails due to invalid credentials,
    mechanism negotiation failures, or authentication policy violations.

    Example:
        >>> raise SASLAuthenticationError(
        ...     "Invalid credentials provided",
        ...     mechanism="PLAIN",
        ...     error_code="invalid-credentials"
        ... )

    """

    def __init__(
        self,
        message: str = "SASL authentication failed",
        *,
        auth_failure_reason: str | None = None,
        **kwargs: SASLErrorContext,
    ) -> None:
        """Initialize SASL authentication error.

        Args:
            message: Error description
            auth_failure_reason: Specific reason for authentication failure
            **kwargs: Additional arguments for SASLError

        """
        context_dict = kwargs.get("context")
        if not isinstance(context_dict, dict):
            context_dict = {}

        if auth_failure_reason:
            context_dict["auth_failure_reason"] = auth_failure_reason

        super().__init__(
            message,
            mechanism=cast("str | None", kwargs.get("mechanism")),
            challenge_step=cast("int | None", kwargs.get("challenge_step")),
            server_message=cast("str | None", kwargs.get("server_message")),
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context_dict,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )

        self.auth_failure_reason = auth_failure_reason


class SASLInvalidMechanismError(SASLError):
    """Exception for SASL mechanism selection and capability errors.

    Raised when requested SASL mechanism is not available, not supported,
    or incompatible with current configuration or security policy.

    Example:
        >>> raise SASLInvalidMechanismError(
        ...     "Mechanism not supported",
        ...     mechanism="GSSAPI",
        ...     available_mechanisms=["PLAIN", "DIGEST-MD5"]
        ... )

    """

    def __init__(
        self,
        message: str = "Invalid SASL mechanism",
        *,
        requested_mechanism: str | None = None,
        available_mechanisms: list[str] | None = None,
        **kwargs: SASLErrorContext,
    ) -> None:
        """Initialize SASL mechanism error.

        Args:
            message: Error description
            requested_mechanism: Mechanism that was requested
            available_mechanisms: List of available mechanisms
            **kwargs: Additional arguments for SASLError

        """
        context_dict = kwargs.get("context")
        if not isinstance(context_dict, dict):
            context_dict = {}

        if requested_mechanism:
            context_dict["requested_mechanism"] = requested_mechanism
        if available_mechanisms:
            context_dict["available_mechanisms"] = available_mechanisms

        super().__init__(
            message,
            mechanism=requested_mechanism,
            challenge_step=cast("int | None", kwargs.get("challenge_step")),
            server_message=cast("str | None", kwargs.get("server_message")),
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context_dict,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )

        self.requested_mechanism = requested_mechanism
        self.available_mechanisms = available_mechanisms


class SASLSecurityError(SASLError):
    """Exception for SASL security layer and policy violations.

    Raised when SASL security layer negotiation fails, security policies
    are violated, or data integrity/confidentiality requirements cannot be met.

    Example:
        >>> raise SASLSecurityError(
        ...     "Security layer negotiation failed",
        ...     mechanism="DIGEST-MD5",
        ...     security_layer="auth-conf",
        ...     error_code="qop-not-supported"
        ... )

    """

    def __init__(
        self,
        message: str = "SASL security error",
        *,
        security_layer: str | None = None,
        qop_requested: str | None = None,
        qop_available: list[str] | None = None,
        **kwargs: SASLErrorContext,
    ) -> None:
        """Initialize SASL security error.

        Args:
            message: Error description
            security_layer: Security layer being negotiated
            qop_requested: Quality of Protection requested
            qop_available: Available QOP options
            **kwargs: Additional arguments for SASLError

        """
        context_dict = kwargs.get("context")
        if not isinstance(context_dict, dict):
            context_dict = {}

        if security_layer:
            context_dict["security_layer"] = security_layer
        if qop_requested:
            context_dict["qop_requested"] = qop_requested
        if qop_available:
            context_dict["qop_available"] = qop_available

        super().__init__(
            message,
            mechanism=cast("str | None", kwargs.get("mechanism")),
            challenge_step=cast("int | None", kwargs.get("challenge_step")),
            server_message=cast("str | None", kwargs.get("server_message")),
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context_dict,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )

        self.security_layer = security_layer
        self.qop_requested = qop_requested
        self.qop_available = qop_available


class SASLCallbackError(SASLError):
    """Exception for SASL callback handler failures.

    Raised when callback handlers fail to provide required information,
    credentials are not available, or callback processing encounters errors.

    Example:
        >>> raise SASLCallbackError(
        ...     "Username callback failed",
        ...     callback_type="NameCallback",
        ...     error_code="callback-failed"
        ... )

    """

    def __init__(
        self,
        message: str = "SASL callback error",
        *,
        callback_type: str | None = None,
        callback_prompt: str | None = None,
        **kwargs: SASLErrorContext,
    ) -> None:
        """Initialize SASL callback error.

        Args:
            message: Error description
            callback_type: Type of callback that failed
            callback_prompt: Prompt text (if not sensitive)
            **kwargs: Additional arguments for SASLError

        """
        context_dict = kwargs.get("context")
        if not isinstance(context_dict, dict):
            context_dict = {}

        if callback_type:
            context_dict["callback_type"] = callback_type
        if callback_prompt and not self._contains_sensitive_info(callback_prompt):
            context_dict["callback_prompt"] = callback_prompt

        super().__init__(
            message,
            mechanism=cast("str | None", kwargs.get("mechanism")),
            challenge_step=cast("int | None", kwargs.get("challenge_step")),
            server_message=cast("str | None", kwargs.get("server_message")),
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context_dict,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )

        self.callback_type = callback_type
        self.callback_prompt = callback_prompt


class SASLChallengeError(SASLError):
    """Exception for SASL challenge-response processing errors.

    Raised when challenge-response processing fails due to malformed
    challenges, invalid responses, or protocol violations.

    Example:
        >>> raise SASLChallengeError(
        ...     "Invalid challenge format",
        ...     mechanism="DIGEST-MD5",
        ...     challenge_step=2,
        ...     error_code="malformed-challenge"
        ... )

    """

    def __init__(
        self,
        message: str = "SASL challenge processing error",
        *,
        challenge_malformed: bool = False,
        response_invalid: bool = False,
        **kwargs: SASLErrorContext,
    ) -> None:
        """Initialize SASL challenge error.

        Args:
            message: Error description
            challenge_malformed: Whether challenge was malformed
            response_invalid: Whether response was invalid
            **kwargs: Additional arguments for SASLError

        """
        context_dict = kwargs.get("context")
        if not isinstance(context_dict, dict):
            context_dict = {}

        if challenge_malformed:
            context_dict["challenge_malformed"] = True
        if response_invalid:
            context_dict["response_invalid"] = True

        super().__init__(
            message,
            mechanism=cast("str | None", kwargs.get("mechanism")),
            challenge_step=cast("int | None", kwargs.get("challenge_step")),
            server_message=cast("str | None", kwargs.get("server_message")),
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context_dict,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )

        self.challenge_malformed = challenge_malformed
        self.response_invalid = response_invalid


class SASLMechanismError(SASLError):
    """Exception for mechanism-specific SASL errors.

    Raised when specific SASL mechanisms encounter errors that are
    unique to their implementation or requirements.

    Example:
        >>> raise SASLMechanismError(
        ...     "GSSAPI ticket expired",
        ...     mechanism="GSSAPI",
        ...     mechanism_error="ticket-expired"
        ... )

    """

    def __init__(
        self,
        message: str = "SASL mechanism error",
        *,
        mechanism_error: str | None = None,
        mechanism_detail: dict[str, Any] | None = None,
        **kwargs: SASLErrorContext,
    ) -> None:
        """Initialize SASL mechanism error.

        Args:
            message: Error description
            mechanism_error: Mechanism-specific error code
            mechanism_detail: Mechanism-specific error details
            **kwargs: Additional arguments for SASLError

        """
        context_dict = kwargs.get("context")
        if not isinstance(context_dict, dict):
            context_dict = {}

        if mechanism_error:
            context_dict["mechanism_error"] = mechanism_error
        if mechanism_detail:
            context_dict["mechanism_detail"] = mechanism_detail

        super().__init__(
            message,
            mechanism=cast("str | None", kwargs.get("mechanism")),
            challenge_step=cast("int | None", kwargs.get("challenge_step")),
            server_message=cast("str | None", kwargs.get("server_message")),
            error_code=cast("str | None", kwargs.get("error_code")),
            context=context_dict,
            original_error=cast("Exception | None", kwargs.get("original_error")),
        )

        self.mechanism_error = mechanism_error
        self.mechanism_detail = mechanism_detail


# Convenience functions for common error scenarios


def sasl_authentication_failed(
    mechanism: str,
    reason: str = "Authentication failed",
    **kwargs: SASLErrorContext,
) -> SASLAuthenticationError:
    """Create authentication failed error.

    Args:
        mechanism: SASL mechanism name
        reason: Failure reason
        **kwargs: Additional error context

    Returns:
        SASLAuthenticationError instance

    """
    sasl_kwargs = dict(**kwargs)
    sasl_kwargs["mechanism"] = mechanism
    return SASLAuthenticationError(
        f"SASL {mechanism} authentication failed: {reason}",
        auth_failure_reason=reason,
        **sasl_kwargs,
    )


def sasl_mechanism_not_available(
    mechanism: str,
    available: list[str],
    **kwargs: SASLErrorContext,
) -> SASLInvalidMechanismError:
    """Create mechanism not available error.

    Args:
        mechanism: Requested mechanism name
        available: List of available mechanisms
        **kwargs: Additional error context

    Returns:
        SASLInvalidMechanismError instance

    """
    return SASLInvalidMechanismError(
        f"SASL mechanism '{mechanism}' not available",
        requested_mechanism=mechanism,
        available_mechanisms=available,
        **kwargs,
    )


def sasl_callback_failed(
    callback_type: str,
    reason: str = "Callback failed",
    **kwargs: SASLErrorContext,
) -> SASLCallbackError:
    """Create callback failed error.

    Args:
        callback_type: Type of callback that failed
        reason: Failure reason
        **kwargs: Additional error context

    Returns:
        SASLCallbackError instance

    """
    # Extract known kwargs for SASLCallbackError constructor
    mechanism = (
        cast("str | None", kwargs.get("mechanism"))
        if "mechanism" in kwargs and isinstance(kwargs["mechanism"], str)
        else None
    )
    challenge_step = (
        cast("int | None", kwargs.get("challenge_step"))
        if "challenge_step" in kwargs and isinstance(kwargs["challenge_step"], int)
        else None
    )
    server_message = (
        cast("str | None", kwargs.get("server_message"))
        if "server_message" in kwargs and isinstance(kwargs["server_message"], str)
        else None
    )
    error_code = (
        cast("str | None", kwargs.get("error_code"))
        if "error_code" in kwargs and isinstance(kwargs["error_code"], str)
        else None
    )
    context = (
        cast("dict[str, Any] | None", kwargs.get("context"))
        if "context" in kwargs and isinstance(kwargs["context"], dict)
        else None
    )
    original_error = (
        cast("Exception | None", kwargs.get("original_error"))
        if "original_error" in kwargs
        and isinstance(kwargs["original_error"], Exception)
        else None
    )

    return SASLCallbackError(
        f"SASL {callback_type} callback failed: {reason}",
        callback_type=callback_type,
        mechanism=mechanism,
        challenge_step=challenge_step,
        server_message=server_message,
        error_code=error_code,
        context=context,
        original_error=original_error,
    )


# Export all exception classes
__all__ = [
    "SASLAuthenticationError",
    "SASLCallbackError",
    "SASLChallengeError",
    "SASLError",
    "SASLInvalidMechanismError",
    "SASLMechanismError",
    "SASLSecurityError",
    "sasl_authentication_failed",
    "sasl_callback_failed",
    "sasl_mechanism_not_available",
]
