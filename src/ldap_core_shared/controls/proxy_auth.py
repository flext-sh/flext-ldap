"""LDAP Proxy Authorization Control Implementation.

This module implements the Proxy Authorization Control as defined in RFC 4370.
This control enables a client to request that an operation be performed using
the authorization of another user (the proxied user).

The proxy authorization control is essential for applications that need to perform
operations on behalf of other users while maintaining proper audit trails and
access control enforcement.

Architecture:
    - ProxyAuthorizationControl: Client request control for proxy authorization
    - AuthorizationIdentity: Abstraction for authorization identities
    - ProxyAuthError: Specific exceptions for proxy authorization failures

Usage Example:
    >>> from ldap_core_shared.controls.proxy_auth import ProxyAuthorizationControl
    >>>
    >>> # Proxy as a specific user DN
    >>> proxy_control = ProxyAuthorizationControl.for_dn(
    ...     "uid=targetuser,ou=people,dc=example,dc=com"
    ... )
    >>>
    >>> # Proxy as a user with authorization ID
    >>> proxy_control = ProxyAuthorizationControl.for_auth_id("u:targetuser")
    >>>
    >>> # Perform operation as proxied user
    >>> result = connection.modify(
    ...     dn="cn=document,ou=files,dc=example,dc=com",
    ...     changes={"description": ["Modified by proxy"]},
    ...     controls=[proxy_control],
    ... )

References:
    - perl-ldap: lib/Net/LDAP/Control/ProxyAuth.pm
    - RFC 4370: Lightweight Directory Access Protocol (LDAP) Proxied Authorization Control
    - OID: 2.16.840.1.113730.3.4.18
"""

from __future__ import annotations

from typing import Optional, Union

from pydantic import Field, validator

from ldap_core_shared.controls.base import (
    ControlDecodingError,
    ControlEncodingError,
    ControlOIDs,
    LDAPControl,
)


class ProxyAuthError(Exception):
    """Exception raised for proxy authorization related errors."""


class AuthorizationIdentity:
    """Represents an authorization identity for proxy operations.

    Authorization identities can be in several forms:
    - DN form: dn:<distinguished-name>
    - User ID form: u:<userid>
    - DN string form: <distinguished-name> (without dn: prefix)

    This class normalizes and validates authorization identity formats.
    """

    def __init__(self, identity: str) -> None:
        """Initialize authorization identity.

        Args:
            identity: Authorization identity string

        Raises:
            ProxyAuthError: If identity format is invalid
        """
        self.identity = self._normalize_identity(identity)

    def _normalize_identity(self, identity: str) -> str:
        """Normalize authorization identity format.

        Args:
            identity: Raw identity string

        Returns:
            Normalized identity string

        Raises:
            ProxyAuthError: If identity format is invalid
        """
        if not identity:
            msg = "Authorization identity cannot be empty"
            raise ProxyAuthError(msg)

        identity = identity.strip()

        # Check for explicit DN format
        if identity.lower().startswith("dn:"):
            return identity

        # Check for user ID format
        if identity.startswith("u:"):
            return identity

        # Check if it looks like a DN (contains = and ,)
        if "=" in identity and "," in identity:
            return f"dn:{identity}"

        # Assume it's a user ID if no clear format
        if not identity.startswith(("dn:", "u:")):
            return f"u:{identity}"

        return identity

    def is_dn_form(self) -> bool:
        """Check if identity is in DN form."""
        return self.identity.lower().startswith("dn:")

    def is_user_id_form(self) -> bool:
        """Check if identity is in user ID form."""
        return self.identity.startswith("u:")

    def get_dn(self) -> Optional[str]:
        """Get DN if identity is in DN form.

        Returns:
            DN string or None if not DN form
        """
        if self.is_dn_form():
            return self.identity[3:]  # Remove "dn:" prefix
        return None

    def get_user_id(self) -> Optional[str]:
        """Get user ID if identity is in user ID form.

        Returns:
            User ID string or None if not user ID form
        """
        if self.is_user_id_form():
            return self.identity[2:]  # Remove "u:" prefix
        return None

    def __str__(self) -> str:
        """String representation of the identity."""
        return self.identity

    def __repr__(self) -> str:
        """Detailed representation of the identity."""
        return f"AuthorizationIdentity('{self.identity}')"


class ProxyAuthorizationControl(LDAPControl):
    """Proxy Authorization Control (RFC 4370).

    This control allows a client to request that an operation be processed
    under the authorization of a different user. The control value contains
    the authorization identity of the user to proxy as.

    The server will process the operation as if the proxied user had
    initiated it, subject to access control and proxy authorization policies.

    Attributes:
        authorization_identity: The identity to proxy as

    Note:
        The proxy authorization control is always critical - if the server
        doesn't support it or denies the proxy request, the operation fails.
    """

    control_type = ControlOIDs.PROXY_AUTHORIZATION

    authorization_identity: AuthorizationIdentity = Field(
        description="Authorization identity to proxy as"
    )

    def __init__(
        self,
        authorization_identity: Union[str, AuthorizationIdentity],
        criticality: bool = True,  # Typically critical
        **kwargs,
    ) -> None:
        """Initialize proxy authorization control.

        Args:
            authorization_identity: Identity to proxy as
            criticality: Whether control is critical (default True)
            **kwargs: Additional arguments
        """
        if isinstance(authorization_identity, str):
            authorization_identity = AuthorizationIdentity(authorization_identity)

        super().__init__(
            authorization_identity=authorization_identity,
            criticality=criticality,
            **kwargs,
        )

    @validator("authorization_identity", pre=True)
    def validate_authorization_identity(
        cls, v: Union[str, AuthorizationIdentity]
    ) -> AuthorizationIdentity:
        """Validate and convert authorization identity."""
        if isinstance(v, str):
            return AuthorizationIdentity(v)
        if isinstance(v, AuthorizationIdentity):
            return v
        msg = "authorization_identity must be string or AuthorizationIdentity"
        raise ValueError(msg)

    def encode_value(self) -> bytes:
        """Encode proxy authorization control value.

        The control value is simply the authorization identity string
        encoded as UTF-8 bytes (not ASN.1 encoded).

        Returns:
            UTF-8 encoded authorization identity

        Raises:
            ControlEncodingError: If encoding fails
        """
        try:
            return str(self.authorization_identity).encode("utf-8")
        except Exception as e:
            msg = f"Failed to encode proxy authorization control: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: Optional[bytes]) -> ProxyAuthorizationControl:
        """Decode proxy authorization control value.

        Args:
            control_value: UTF-8 encoded authorization identity

        Returns:
            ProxyAuthorizationControl instance

        Raises:
            ControlDecodingError: If decoding fails
        """
        if not control_value:
            msg = "Proxy authorization control requires a value"
            raise ControlDecodingError(msg)

        try:
            identity_str = control_value.decode("utf-8")
            return cls(authorization_identity=identity_str)
        except Exception as e:
            msg = f"Failed to decode proxy authorization control: {e}"
            raise ControlDecodingError(msg) from e

    @classmethod
    def for_dn(cls, dn: str, criticality: bool = True) -> ProxyAuthorizationControl:
        """Create proxy control for a specific DN.

        Args:
            dn: Distinguished name to proxy as
            criticality: Whether control is critical

        Returns:
            ProxyAuthorizationControl for the DN
        """
        return cls(authorization_identity=f"dn:{dn}", criticality=criticality)

    @classmethod
    def for_user_id(
        cls, user_id: str, criticality: bool = True
    ) -> ProxyAuthorizationControl:
        """Create proxy control for a user ID.

        Args:
            user_id: User identifier to proxy as
            criticality: Whether control is critical

        Returns:
            ProxyAuthorizationControl for the user ID
        """
        return cls(authorization_identity=f"u:{user_id}", criticality=criticality)

    @classmethod
    def for_auth_id(
        cls, auth_id: str, criticality: bool = True
    ) -> ProxyAuthorizationControl:
        """Create proxy control for an authorization ID.

        Args:
            auth_id: Authorization identity (will be normalized)
            criticality: Whether control is critical

        Returns:
            ProxyAuthorizationControl for the authorization ID
        """
        return cls(authorization_identity=auth_id, criticality=criticality)

    def get_proxy_dn(self) -> Optional[str]:
        """Get the DN being proxied, if available.

        Returns:
            DN string or None if not a DN-based proxy
        """
        return self.authorization_identity.get_dn()

    def get_proxy_user_id(self) -> Optional[str]:
        """Get the user ID being proxied, if available.

        Returns:
            User ID string or None if not a user ID-based proxy
        """
        return self.authorization_identity.get_user_id()

    def is_dn_proxy(self) -> bool:
        """Check if proxying as a DN."""
        return self.authorization_identity.is_dn_form()

    def is_user_id_proxy(self) -> bool:
        """Check if proxying as a user ID."""
        return self.authorization_identity.is_user_id_form()

    def __str__(self) -> str:
        """String representation of the control."""
        return (
            f"ProxyAuthorizationControl("
            f"proxy_as='{self.authorization_identity}', "
            f"critical={self.criticality})"
        )


class ProxyAuthorizationBuilder:
    """Builder class for creating proxy authorization controls with validation.

    This class provides a fluent interface for building proxy authorization
    controls with additional validation and convenience methods.

    Example:
        >>> builder = ProxyAuthorizationBuilder()
        >>> control = builder.proxy_as_user("jdoe").critical().build()
    """

    def __init__(self) -> None:
        """Initialize the builder."""
        self._authorization_identity: Optional[str] = None
        self._criticality: bool = True

    def proxy_as_dn(self, dn: str) -> ProxyAuthorizationBuilder:
        """Set proxy target as a DN.

        Args:
            dn: Distinguished name to proxy as

        Returns:
            Builder instance for chaining
        """
        self._authorization_identity = f"dn:{dn}"
        return self

    def proxy_as_user(self, user_id: str) -> ProxyAuthorizationBuilder:
        """Set proxy target as a user ID.

        Args:
            user_id: User identifier to proxy as

        Returns:
            Builder instance for chaining
        """
        self._authorization_identity = f"u:{user_id}"
        return self

    def proxy_as(self, identity: str) -> ProxyAuthorizationBuilder:
        """Set proxy target with automatic format detection.

        Args:
            identity: Authorization identity (auto-detected format)

        Returns:
            Builder instance for chaining
        """
        self._authorization_identity = identity
        return self

    def critical(self, is_critical: bool = True) -> ProxyAuthorizationBuilder:
        """Set control criticality.

        Args:
            is_critical: Whether the control is critical

        Returns:
            Builder instance for chaining
        """
        self._criticality = is_critical
        return self

    def non_critical(self) -> ProxyAuthorizationBuilder:
        """Set control as non-critical.

        Returns:
            Builder instance for chaining
        """
        return self.critical(False)

    def build(self) -> ProxyAuthorizationControl:
        """Build the proxy authorization control.

        Returns:
            Configured ProxyAuthorizationControl

        Raises:
            ProxyAuthError: If required fields are missing
        """
        if not self._authorization_identity:
            msg = "Authorization identity is required"
            raise ProxyAuthError(msg)

        return ProxyAuthorizationControl(
            authorization_identity=self._authorization_identity,
            criticality=self._criticality,
        )


# Convenience functions for common proxy scenarios
def proxy_as_dn(dn: str, critical: bool = True) -> ProxyAuthorizationControl:
    """Create proxy control for a DN.

    Args:
        dn: Distinguished name to proxy as
        critical: Whether control is critical

    Returns:
        ProxyAuthorizationControl for the DN
    """
    return ProxyAuthorizationControl.for_dn(dn, critical)


def proxy_as_user(user_id: str, critical: bool = True) -> ProxyAuthorizationControl:
    """Create proxy control for a user ID.

    Args:
        user_id: User identifier to proxy as
        critical: Whether control is critical

    Returns:
        ProxyAuthorizationControl for the user ID
    """
    return ProxyAuthorizationControl.for_user_id(user_id, critical)


def proxy_as_REDACTED_LDAP_BIND_PASSWORD() -> ProxyAuthorizationControl:
    """Create proxy control for REDACTED_LDAP_BIND_PASSWORD user.

    Returns:
        ProxyAuthorizationControl for REDACTED_LDAP_BIND_PASSWORD

    Note:
        This assumes an "REDACTED_LDAP_BIND_PASSWORD" user ID. Adjust based on your directory schema.
    """
    return ProxyAuthorizationControl.for_user_id("REDACTED_LDAP_BIND_PASSWORD", critical=True)


# TODO: Integration points for implementation:
#
# 1. Security Integration:
#    - Integrate with ldap_core_shared.core.security for proxy validation
#    - Implement proxy authorization policy checking
#    - Add audit logging for proxy operations
#
# 2. Connection Manager Integration:
#    - Add proxy support to all LDAP operations (search, modify, add, delete)
#    - Handle proxy authorization failures gracefully
#    - Provide proxy context information in operation results
#
# 3. Authentication Integration:
#    - Validate that the connecting user has proxy rights
#    - Check proxy authorization against directory ACLs
#    - Support nested proxy scenarios (if allowed by policy)
#
# 4. Monitoring and Auditing:
#    - Log all proxy operations for security auditing
#    - Track proxy usage patterns and statistics
#    - Alert on suspicious proxy activity
#
# 5. Configuration:
#    - Allow configuration of allowed proxy targets
#    - Support proxy authorization policy configuration
#    - Enable/disable proxy functionality per connection
#
# 6. Error Handling:
#    - Provide clear error messages for proxy failures
#    - Distinguish between authentication and authorization failures
#    - Handle proxy loops and circular references
#
# 7. Testing Requirements:
#    - Unit tests for all authorization identity formats
#    - Integration tests with real LDAP servers
#    - Security tests for proxy authorization bypass attempts
#    - Performance tests for proxy overhead
