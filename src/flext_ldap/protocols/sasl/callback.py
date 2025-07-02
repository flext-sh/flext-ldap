"""SASL Callback System for Credential Handling.

This module provides comprehensive callback system for SASL authentication
credential handling with secure credential management, multiple callback types,
and interactive prompt support equivalent to perl-Authen-SASL callback framework.

The callback system provides a secure and flexible way to obtain authentication
credentials during SASL authentication without hardcoding sensitive information
in application code.

Architecture:
    - SASLCallback: Base callback interface
    - SASLCallbackHandler: Main callback handler implementation
    - NameCallback: Username/principal name callback
    - PasswordCallback: Password/secret callback
    - RealmCallback: Authentication realm callback
    - AuthorizeCallback: Authorization identity callback

Usage Example:
    >>> from flext_ldap.protocols.sasl.callback import SASLCallbackHandler
    >>>
    >>> # Create callback handler with credentials
    >>> callback = SASLCallbackHandler(
    ...     username="john.doe",
    ...     password="secret123",
    ...     realm="example.com"
    ... )
    >>>
    >>> # Create interactive callback handler
    >>> interactive = SASLCallbackHandler(interactive=True)
    >>>
    >>> # Use with SASL client
    >>> client = SASLClient(mechanisms=["DIGEST-MD5"], callback=callback)

References:
    - perl-Authen-SASL: Callback interface compatibility
    - RFC 4422: SASL callback framework requirements
    - Java SASL: Callback handler design patterns

"""

from __future__ import annotations

import getpass
from abc import ABC, abstractmethod
from typing import Any

from flext_ldapasl.exceptions import SASLCallbackError
from pydantic import BaseModel, Field, SecretStr


class SASLCallback(ABC):
    """Base class for SASL authentication callbacks.

    This abstract base class defines the interface for all SASL callbacks
    used to obtain authentication information during SASL authentication.

    Example:
        >>> class CustomCallback(SASLCallback):
        ...     def handle(self, callback_handler):
        ...         # Custom callback implementation
        ...         pass

    """

    def __init__(self, prompt: str | None = None) -> None:
        """Initialize callback.

        Args:
            prompt: Prompt text for interactive callbacks

        """
        self.prompt = prompt
        self._value: Any = None
        self._handled = False

    @abstractmethod
    def handle(self, callback_handler: SASLCallbackHandler) -> None:
        """Handle callback to obtain required information.

        Args:
            callback_handler: Handler that will provide the information

        Raises:
            SASLCallbackError: If callback handling fails

        """

    def get_value(self) -> Any:
        """Get callback value.

        Returns:
            Callback value after handling

        Raises:
            SASLCallbackError: If callback not handled yet

        """
        if not self._handled:
            msg = "Callback not handled yet"
            raise SASLCallbackError(
                msg,
                callback_type=self.__class__.__name__,
            )
        return self._value

    def set_value(self, value: Any) -> None:
        """Set callback value.

        Args:
            value: Value to set

        """
        self._value = value
        self._handled = True

    def is_handled(self) -> bool:
        """Check if callback has been handled.

        Returns:
            True if callback has been handled

        """
        return self._handled


class NameCallback(SASLCallback):
    """Callback for obtaining username/principal name.

    This callback is used to obtain the authentication name (username)
    during SASL authentication.

    Example:
        >>> callback = NameCallback("Username: ")
        >>> callback.handle(handler)
        >>> username = callback.get_value()

    """

    def __init__(
        self,
        prompt: str = "Username: ",
        default_name: str | None = None,
    ) -> None:
        """Initialize name callback.

        Args:
            prompt: Prompt text for interactive input
            default_name: Default username if available

        """
        super().__init__(prompt)
        self.default_name = default_name

    def handle(self, callback_handler: SASLCallbackHandler) -> None:
        """Handle name callback.

        Args:
            callback_handler: Handler to get username from

        """
        try:
            username = callback_handler.get_username(self.prompt, self.default_name)
            if username is None:
                msg = "Username not available"
                raise SASLCallbackError(
                    msg,
                    callback_type="NameCallback",
                    callback_prompt=self.prompt,
                )
            self.set_value(username)
        except Exception as e:
            msg = f"Name callback failed: {e}"
            raise SASLCallbackError(
                msg,
                callback_type="NameCallback",
            ) from e


class PasswordCallback(SASLCallback):
    """Callback for obtaining password/secret.

    This callback is used to obtain the authentication password or secret
    during SASL authentication with secure handling.

    Example:
        >>> callback = PasswordCallback("Password: ")
        >>> callback.handle(handler)
        >>> password = callback.get_value()

    """

    def __init__(self, prompt: str = "Password: ", echo_on: bool = False) -> None:
        """Initialize password callback.

        Args:
            prompt: Prompt text for interactive input
            echo_on: Whether to echo password input (security risk)

        """
        super().__init__(prompt)
        self.echo_on = echo_on

    def handle(self, callback_handler: SASLCallbackHandler) -> None:
        """Handle password callback.

        Args:
            callback_handler: Handler to get password from

        """
        try:
            password = callback_handler.get_password(self.prompt, self.echo_on)
            if password is None:
                msg = "Password not available"
                raise SASLCallbackError(
                    msg,
                    callback_type="PasswordCallback",
                )
            self.set_value(password)
        except Exception as e:
            msg = f"Password callback failed: {e}"
            raise SASLCallbackError(
                msg,
                callback_type="PasswordCallback",
            ) from e


class RealmCallback(SASLCallback):
    """Callback for obtaining authentication realm.

    This callback is used to obtain the authentication realm during
    SASL authentication when realm information is required.

    Example:
        >>> callback = RealmCallback("Realm: ", "example.com")
        >>> callback.handle(handler)
        >>> realm = callback.get_value()

    """

    def __init__(
        self,
        prompt: str = "Realm: ",
        default_realm: str | None = None,
    ) -> None:
        """Initialize realm callback.

        Args:
            prompt: Prompt text for interactive input
            default_realm: Default realm if available

        """
        super().__init__(prompt)
        self.default_realm = default_realm

    def handle(self, callback_handler: SASLCallbackHandler) -> None:
        """Handle realm callback.

        Args:
            callback_handler: Handler to get realm from

        """
        try:
            realm = callback_handler.get_realm(self.prompt, self.default_realm)
            # Realm can be None for some mechanisms
            self.set_value(realm)
        except Exception as e:
            msg = f"Realm callback failed: {e}"
            raise SASLCallbackError(
                msg,
                callback_type="RealmCallback",
            ) from e


class AuthorizeCallback(SASLCallback):
    """Callback for obtaining authorization identity.

    This callback is used to obtain the authorization identity (authzid)
    when different from the authentication identity (authcid).

    Example:
        >>> callback = AuthorizeCallback("Authorize as: ")
        >>> callback.handle(handler)
        >>> authzid = callback.get_value()

    """

    def __init__(
        self,
        prompt: str = "Authorize as: ",
        authentication_id: str | None = None,
        default_authorization_id: str | None = None,
    ) -> None:
        """Initialize authorize callback.

        Args:
            prompt: Prompt text for interactive input
            authentication_id: Authentication identity (for reference)
            default_authorization_id: Default authorization identity

        """
        super().__init__(prompt)
        self.authentication_id = authentication_id
        self.default_authorization_id = default_authorization_id

    def handle(self, callback_handler: SASLCallbackHandler) -> None:
        """Handle authorize callback.

        Args:
            callback_handler: Handler to get authorization ID from

        """
        try:
            authzid = callback_handler.get_authorization_id(
                self.prompt,
                self.authentication_id,
                self.default_authorization_id,
            )
            # Authorization ID can be None (use authentication ID)
            self.set_value(authzid)
        except Exception as e:
            msg = f"Authorize callback failed: {e}"
            raise SASLCallbackError(
                msg,
                callback_type="AuthorizeCallback",
            ) from e


class SASLCallbackHandler(BaseModel):
    """Main SASL callback handler implementation.

    This class provides credential handling for SASL authentication with
    support for stored credentials, interactive prompts, and secure
    credential management.

    Example:
        >>> # Handler with stored credentials
        >>> handler = SASLCallbackHandler(
        ...     username="john.doe",
        ...     password="secret123",
        ...     realm="example.com"
        ... )
        >>>
        >>> # Interactive handler
        >>> interactive = SASLCallbackHandler(interactive=True)

    """

    # Stored credentials (optional)
    username: str | None = Field(
        default=None,
        description="Username for authentication",
    )
    password: SecretStr | None = Field(
        default=None,
        description="Password for authentication",
    )
    realm: str | None = Field(default=None, description="Authentication realm")
    authorization_id: str | None = Field(
        default=None,
        description="Authorization identity",
    )

    # Configuration
    interactive: bool = Field(default=False, description="Allow interactive prompts")
    service: str = Field(default="ldap", description="Service name")
    hostname: str | None = Field(default=None, description="Server hostname")

    # Additional properties
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional SASL properties",
    )

    class Config:
        """Pydantic configuration."""

        arbitrary_types_allowed = True

    def handle_callbacks(self, callbacks: list[SASLCallback]) -> None:
        """Handle multiple callbacks.

        Args:
            callbacks: List of callbacks to handle

        Raises:
            SASLCallbackError: If any callback handling fails

        """
        for callback in callbacks:
            callback.handle(self)

    def get_username(
        self,
        prompt: str | None = None,
        default: str | None = None,
    ) -> str | None:
        """Get username for authentication.

        Args:
            prompt: Prompt text for interactive input
            default: Default username

        Returns:
            Username string or None

        """
        # Return stored username if available
        if self.username is not None:
            return self.username

        # Use default if provided
        if default is not None:
            return default

        # Interactive prompt if allowed
        if self.interactive:
            try:
                return input(prompt or "Username: ").strip() or None
            except (EOFError, KeyboardInterrupt):
                return None

        return None

    def get_password(
        self,
        prompt: str | None = None,
        echo_on: bool = False,
    ) -> str | None:
        """Get password for authentication.

        Args:
            prompt: Prompt text for interactive input
            echo_on: Whether to echo password (security risk)

        Returns:
            Password string or None

        """
        # Return stored password if available
        if self.password is not None:
            return self.password.get_secret_value()

        # Interactive prompt if allowed
        if self.interactive:
            try:
                if echo_on:
                    return input(prompt or "Password: ").strip() or None
                return getpass.getpass(prompt or "Password: ") or None
            except (EOFError, KeyboardInterrupt):
                return None

        return None

    def get_realm(
        self,
        prompt: str | None = None,
        default: str | None = None,
    ) -> str | None:
        """Get authentication realm.

        Args:
            prompt: Prompt text for interactive input
            default: Default realm

        Returns:
            Realm string or None

        """
        # Return stored realm if available
        if self.realm is not None:
            return self.realm

        # Use default if provided
        if default is not None:
            return default

        # Interactive prompt if allowed
        if self.interactive:
            try:
                result = input(prompt or "Realm: ").strip()
                return result or None
            except (EOFError, KeyboardInterrupt):
                return None

        return None

    def get_authorization_id(
        self,
        prompt: str | None = None,
        authentication_id: str | None = None,
        default: str | None = None,
    ) -> str | None:
        """Get authorization identity.

        Args:
            prompt: Prompt text for interactive input
            authentication_id: Authentication identity (for reference)
            default: Default authorization identity

        Returns:
            Authorization identity or None

        """
        # Return stored authorization ID if available
        if self.authorization_id is not None:
            return self.authorization_id

        # Use default if provided
        if default is not None:
            return default

        # Interactive prompt if allowed
        if self.interactive:
            try:
                full_prompt = prompt or "Authorize as: "
                if authentication_id:
                    full_prompt += f"(authenticated as {authentication_id}) "
                result = input(full_prompt).strip()
                return result or None
            except (EOFError, KeyboardInterrupt):
                return None

        return None

    def get_property(self, name: str, default: Any = None) -> Any:
        """Get SASL property value.

        Args:
            name: Property name
            default: Default value if property not found

        Returns:
            Property value or default

        """
        return self.properties.get(name, default)

    def set_property(self, name: str, value: Any) -> None:
        """Set SASL property value.

        Args:
            name: Property name
            value: Property value

        """
        self.properties[name] = value

    def clear_credentials(self) -> None:
        """Clear stored credentials for security.

        This method should be called after authentication to clear
        sensitive credential information from memory.
        """
        if self.password:
            # SecretStr handles secure cleanup
            pass
        self.username = None
        self.password = None
        self.authorization_id = None

    def __str__(self) -> str:
        """String representation (security-aware)."""
        return f"SASLCallbackHandler(username={self.username}, realm={self.realm}, interactive={self.interactive})"

    def __repr__(self) -> str:
        """Detailed representation (security-aware)."""
        return (
            f"SASLCallbackHandler("
            f"username={self.username!r}, "
            f"realm={self.realm!r}, "
            f"interactive={self.interactive}, "
            f"service={self.service!r}, "
            f"hostname={self.hostname!r})"
        )


# Convenience functions for common callback scenarios


def create_simple_callback(
    username: str | None = None,
    password: str | None = None,
    realm: str | None = None,
    **kwargs: Any,
) -> SASLCallbackHandler:
    """Create simple callback handler with credentials.

    Args:
        username: Username for authentication
        password: Password for authentication
        realm: Authentication realm
        **kwargs: Additional callback handler options

    Returns:
        SASLCallbackHandler instance

    """
    return SASLCallbackHandler(
        username=username,
        password=SecretStr(password) if password else None,
        realm=realm,
        **kwargs,
    )


def create_interactive_callback(**kwargs: Any) -> SASLCallbackHandler:
    """Create interactive callback handler.

    Args:
        **kwargs: Additional callback handler options

    Returns:
        SASLCallbackHandler instance with interactive=True

    """
    return SASLCallbackHandler(interactive=True, **kwargs)


# Export all callback classes and functions
__all__ = [
    "AuthorizeCallback",
    "NameCallback",
    "PasswordCallback",
    "RealmCallback",
    "SASLCallback",
    "SASLCallbackHandler",
    "create_interactive_callback",
    "create_simple_callback",
]
