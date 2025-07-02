"""LDAP Password Modify Extended Operation Implementation.

This module implements the Password Modify extended operation as defined in RFC 3062.
This extension provides a secure and standardized way to change user passwords in
LDAP directories, supporting both self-service and administrative password changes.

The password modify operation is critical for security and user management in LDAP
environments, providing proper validation, policy enforcement, and audit trails
for password changes.

Architecture:
    - ModifyPasswordExtension: Request extension for password modification
    - ModifyPasswordResult: Response containing operation status
    - PasswordChangeRequest: Structured password change parameters
    - PasswordPolicy: Integration with password policy controls

Usage Example:
    >>> from ldap_core_shared.extensions.modify_password import ModifyPasswordExtension
    >>>
    >>> # Self-service password change
    >>> modify_pwd = ModifyPasswordExtension(
    ...     old_password="current_secret", new_password="new_secure_password"
    ... )
    >>> result = connection.extended_operation(modify_pwd)
    >>>
    >>> # Administrative password reset
    >>> admin_reset = ModifyPasswordExtension(
    ...     user_identity="uid=jdoe,ou=people,dc=example,dc=com",
    ...     new_password="temp_password",
    ... )
    >>> result = connection.extended_operation(admin_reset)
    >>>
    >>> # Generate new password (server-generated)
    >>> generate_pwd = ModifyPasswordExtension(
    ...     user_identity="uid=jdoe,ou=people,dc=example,dc=com"
    ... )
    >>> result = connection.extended_operation(generate_pwd)
    >>> if result.is_success() and result.generated_password:
    ...     print(f"New password: {result.generated_password}")

References:
    - perl-ldap: lib/Net/LDAP/Extension/SetPassword.pm
    - RFC 3062: LDAP Password Modify Extended Operation
    - OID: 1.3.6.1.4.1.4203.1.11.1

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import Field, validator

from ldap_core_shared.extensions.base import (
    ExtensionDecodingError,
    ExtensionEncodingError,
    ExtensionOIDs,
    ExtensionResult,
    LDAPExtension,
)
from ldap_core_shared.utils.constants import BER_CONTEXT_TAG_0, BER_SEQUENCE_TAG

if TYPE_CHECKING:
    from ldap_core_shared.types.aliases import OID


class PasswordValidationError(Exception):
    """Exception raised for password validation failures."""


class ModifyPasswordResult(ExtensionResult):
    """Result of Password Modify extension operation.

    Contains the result of the password modification operation, including
    any server-generated password if applicable.

    Attributes:
        generated_password: Server-generated password (if requested)
        password_changed: Whether the password was successfully changed
        old_password_required: Whether old password was required but missing
        policy_violations: List of password policy violations

    Note:
        If new_password was not provided in the request, the server may
        generate a new password and return it in generated_password.

    """

    generated_password: str | None = Field(
        default=None,
        description="Server-generated password (if applicable)",
    )

    password_changed: bool = Field(
        default=False,
        description="Whether password was successfully changed",
    )

    old_password_required: bool = Field(
        default=False,
        description="Whether old password was required but missing",
    )

    policy_violations: list[str] = Field(
        default_factory=list,
        description="List of password policy violations",
    )

    def has_generated_password(self) -> bool:
        """Check if server generated a new password."""
        return self.generated_password is not None

    def is_policy_violation(self) -> bool:
        """Check if operation failed due to policy violations."""
        return bool(self.policy_violations)

    def get_policy_summary(self) -> str:
        """Get summary of policy violations."""
        if not self.policy_violations:
            return "No policy violations"

        return f"Policy violations: {', '.join(self.policy_violations)}"

    def __str__(self) -> str:
        """String representation of the result."""
        if self.is_failure():
            return f"Password modify failed: {self.get_error_description()}"

        if self.has_generated_password():
            return f"Password modified (generated: {self.generated_password[:3]}...)"

        return "Password modified successfully"


class ModifyPasswordExtension(LDAPExtension):
    """Password Modify Extended Operation (RFC 3062).

    This extension provides a standardized way to modify user passwords in
    LDAP directories. It supports self-service password changes, administrative
    password resets, and server-generated passwords.

    The operation can be used in several modes:
    1. Self-service: Current user changes their own password
    2. Administrative: Admin changes another user's password
    3. Password generation: Server generates a new password

    Attributes:
        user_identity: DN of user whose password to change (optional for self-service)
        old_password: Current password (required for self-service)
        new_password: New password (optional - server can generate)

    Note:
        If user_identity is None, the operation applies to the current user.
        If new_password is None, the server may generate a password.

    """

    request_name = ExtensionOIDs.MODIFY_PASSWORD

    user_identity: str | None = Field(
        default=None,
        description="DN of user whose password to change (None = current user)",
    )

    old_password: str | None = Field(
        default=None,
        description="Current password (required for self-service)",
    )

    new_password: str | None = Field(
        default=None,
        description="New password (None = server generates)",
    )

    @validator("user_identity")
    def validate_user_identity(self, v: str | None) -> str | None:
        """Validate user identity format."""
        if v is not None:
            v = v.strip()
            if not v:
                return None

            # Basic DN validation
            if "=" not in v:
                msg = "User identity must be a valid DN"
                raise PasswordValidationError(msg)

        return v

    @validator("old_password")
    def validate_old_password(self, v: str | None) -> str | None:
        """Validate old password."""
        if v is not None and not v:
            msg = "Old password cannot be empty string"
            raise PasswordValidationError(msg)
        return v

    @validator("new_password")
    def validate_new_password(self, v: str | None) -> str | None:
        """Validate new password."""
        if v is not None and not v:
            msg = "New password cannot be empty string"
            raise PasswordValidationError(msg)
        return v

    def encode_request_value(self) -> bytes:
        """Encode password modify request value as ASN.1.

        The request value is a SEQUENCE containing:
        PasswdModifyRequestValue ::= SEQUENCE {
            userIdentity    [0]  OCTET STRING OPTIONAL
            oldPasswd       [1]  OCTET STRING OPTIONAL
            newPasswd       [2]  OCTET STRING OPTIONAL }

        Returns:
            ASN.1 BER encoded request value

        Raises:
            ExtensionEncodingError: If encoding fails

        """
        try:
            content = b""

            # Encode user identity if provided
            if self.user_identity:
                identity_encoded = self._encode_octet_string(
                    self.user_identity.encode("utf-8"),
                )
                identity_tagged = self._encode_context_tag(0, identity_encoded)
                content += identity_tagged

            # Encode old password if provided
            if self.old_password:
                old_pwd_encoded = self._encode_octet_string(
                    self.old_password.encode("utf-8"),
                )
                old_pwd_tagged = self._encode_context_tag(1, old_pwd_encoded)
                content += old_pwd_tagged

            # Encode new password if provided
            if self.new_password:
                new_pwd_encoded = self._encode_octet_string(
                    self.new_password.encode("utf-8"),
                )
                new_pwd_tagged = self._encode_context_tag(2, new_pwd_encoded)
                content += new_pwd_tagged

            # Wrap in SEQUENCE
            return self._encode_sequence(content) if content else b""

        except Exception as e:
            msg = f"Failed to encode password modify request: {e}"
            raise ExtensionEncodingError(msg) from e

    @classmethod
    def decode_response_value(
        cls,
        response_name: OID | None,
        response_value: bytes | None,
    ) -> ModifyPasswordResult:
        """Decode password modify response value.

        Args:
            response_name: Should be None for password modify
            response_value: ASN.1 encoded response value (may be None)

        Returns:
            ModifyPasswordResult with operation status

        Raises:
            ExtensionDecodingError: If decoding fails

        """
        try:
            generated_password = None

            # Response value contains generated password if server created one
            if response_value:
                # Response is SEQUENCE { genPasswd [0] OCTET STRING OPTIONAL }
                content = cls._decode_sequence(response_value)

                if content and content[0] == BER_CONTEXT_TAG_0:  # Context tag [0]
                    _, pos = cls._decode_context_tag(content, 0)
                    password_bytes = content[2:pos]
                    generated_password = password_bytes.decode("utf-8")

            return ModifyPasswordResult(
                result_code=0,  # Will be overridden by caller
                generated_password=generated_password,
                password_changed=True,  # Assume success if no error
            )

        except Exception as e:
            msg = f"Failed to decode password modify response: {e}"
            raise ExtensionDecodingError(msg) from e

    @classmethod
    def self_service_change(
        cls,
        old_password: str,
        new_password: str,
    ) -> ModifyPasswordExtension:
        """Create extension for self-service password change.

        Args:
            old_password: Current password
            new_password: New password

        Returns:
            ModifyPasswordExtension for self-service change

        """
        return cls(
            user_identity=None,  # Current user
            old_password=old_password,
            new_password=new_password,
        )

    @classmethod
    def admin_reset(
        cls,
        user_identity: str,
        new_password: str,
    ) -> ModifyPasswordExtension:
        """Create extension for administrative password reset.

        Args:
            user_identity: DN of user whose password to reset
            new_password: New password

        Returns:
            ModifyPasswordExtension for admin reset

        """
        return cls(
            user_identity=user_identity,
            old_password=None,  # Admin doesn't need old password
            new_password=new_password,
        )

    @classmethod
    def generate_password(cls, user_identity: str) -> ModifyPasswordExtension:
        """Create extension for server-generated password.

        Args:
            user_identity: DN of user whose password to generate

        Returns:
            ModifyPasswordExtension for password generation

        """
        return cls(
            user_identity=user_identity,
            old_password=None,
            new_password=None,  # Server will generate
        )

    @classmethod
    def self_service_generate(cls) -> ModifyPasswordExtension:
        """Create extension for self-service password generation.

        Returns:
            ModifyPasswordExtension for self-service generation

        Note:
            This requests the server to generate a new password for
            the current user. Old password may still be required.

        """
        return cls(
            user_identity=None,  # Current user
            old_password=None,
            new_password=None,  # Server will generate
        )

    def is_self_service(self) -> bool:
        """Check if this is a self-service password operation."""
        return self.user_identity is None

    def is_admin_operation(self) -> bool:
        """Check if this is an administrative password operation."""
        return self.user_identity is not None

    def is_password_generation(self) -> bool:
        """Check if this requests password generation."""
        return self.new_password is None

    def requires_old_password(self) -> bool:
        """Check if operation likely requires old password."""
        return self.is_self_service() and not self.is_password_generation()

    def __str__(self) -> str:
        """String representation of the extension."""
        if self.is_self_service():
            if self.is_password_generation():
                return "ModifyPassword(self-service, generate)"
            return "ModifyPassword(self-service, change)"
        if self.is_password_generation():
            return f"ModifyPassword(admin, generate for {self.user_identity})"
        return f"ModifyPassword(admin, reset for {self.user_identity})"

    # Simple ASN.1 encoding helpers
    @staticmethod
    def _encode_octet_string(value: bytes) -> bytes:
        """Encode bytes as BER OCTET STRING."""
        length = len(value)
        return b"\x04" + length.to_bytes(1, "big") + value

    @staticmethod
    def _encode_sequence(content: bytes) -> bytes:
        """Encode content as BER SEQUENCE."""
        length = len(content)
        return b"\x30" + length.to_bytes(1, "big") + content

    @staticmethod
    def _encode_context_tag(tag_num: int, content: bytes) -> bytes:
        """Encode content with context-specific tag."""
        tag = 0x80 | tag_num  # Context-specific, primitive
        length = len(content)
        return bytes([tag]) + length.to_bytes(1, "big") + content

    @classmethod
    def _decode_sequence(cls, data: bytes) -> bytes:
        """Decode BER SEQUENCE and return content."""
        if not data or data[0] != BER_SEQUENCE_TAG:
            msg = "Not a SEQUENCE"
            raise ValueError(msg)
        length = data[1]
        return data[2 : 2 + length]

    @classmethod
    def _decode_context_tag(cls, data: bytes, pos: int) -> tuple[bytes, int]:
        """Decode context-specific tag and return content and new position."""
        data[pos]
        length = data[pos + 1]
        content = data[pos + 2 : pos + 2 + length]
        return content, pos + 2 + length


# Convenience functions
def change_password(old_password: str, new_password: str) -> ModifyPasswordExtension:
    """Create extension for self-service password change.

    Args:
        old_password: Current password
        new_password: New password

    Returns:
        ModifyPasswordExtension for password change

    """
    return ModifyPasswordExtension.self_service_change(old_password, new_password)


def reset_password(user_dn: str, new_password: str) -> ModifyPasswordExtension:
    """Create extension for administrative password reset.

    Args:
        user_dn: DN of user whose password to reset
        new_password: New password

    Returns:
        ModifyPasswordExtension for password reset

    """
    return ModifyPasswordExtension.admin_reset(user_dn, new_password)


def generate_password(user_dn: str) -> ModifyPasswordExtension:
    """Create extension for server-generated password.

    Args:
        user_dn: DN of user for password generation

    Returns:
        ModifyPasswordExtension for password generation

    """
    return ModifyPasswordExtension.generate_password(user_dn)


class PasswordChangeBuilder:
    """Builder class for creating password modify extensions with validation.

    This class provides a fluent interface for building password modification
    requests with proper validation and security checks.

    Example:
        >>> builder = PasswordChangeBuilder()
        >>> extension = (
        ...     builder.for_user("uid=jdoe,ou=people,dc=example,dc=com")
        ...     .with_old_password("current_secret")
        ...     .with_new_password("new_secure_password")
        ...     .build()
        ... )

    """

    def __init__(self) -> None:
        """Initialize the builder."""
        self._user_identity: str | None = None
        self._old_password: str | None = None
        self._new_password: str | None = None

    def for_user(self, user_dn: str) -> PasswordChangeBuilder:
        """Set target user for password change.

        Args:
            user_dn: Distinguished name of target user

        Returns:
            Builder instance for chaining

        """
        self._user_identity = user_dn
        return self

    def for_current_user(self) -> PasswordChangeBuilder:
        """Set operation for current user (self-service).

        Returns:
            Builder instance for chaining

        """
        self._user_identity = None
        return self

    def with_old_password(self, password: str) -> PasswordChangeBuilder:
        """Set current password.

        Args:
            password: Current password

        Returns:
            Builder instance for chaining

        """
        self._old_password = password
        return self

    def with_new_password(self, password: str) -> PasswordChangeBuilder:
        """Set new password.

        Args:
            password: New password

        Returns:
            Builder instance for chaining

        """
        self._new_password = password
        return self

    def generate_new_password(self) -> PasswordChangeBuilder:
        """Request server to generate new password.

        Returns:
            Builder instance for chaining

        """
        self._new_password = None
        return self

    def build(self) -> ModifyPasswordExtension:
        """Build the password modify extension.

        Returns:
            Configured ModifyPasswordExtension

        Raises:
            PasswordValidationError: If configuration is invalid

        """
        return ModifyPasswordExtension(
            user_identity=self._user_identity,
            old_password=self._old_password,
            new_password=self._new_password,
        )


# TODO: Integration points for implementation:
#
# 1. Security Integration:
#    - Integrate with password policy controls for validation
#    - Add password strength checking before submission
#    - Implement secure password generation utilities
#
# 2. Connection Manager Integration:
#    - Add password_modify method to LDAPConnectionManager
#    - Handle authentication state changes after password modification
#    - Provide automatic re-authentication with new password
#
# 3. User Experience Enhancements:
#    - Password strength meter integration
#    - Progressive disclosure of password requirements
#    - Real-time validation feedback
#
# 4. Audit and Logging:
#    - Log all password modification attempts for security auditing
#    - Track password change patterns and statistics
#    - Generate alerts for suspicious password activity
#
# 5. Policy Integration:
#    - Validate against organizational password policies
#    - Support custom password complexity requirements
#    - Integrate with password history and aging policies
#
# 6. Error Handling:
#    - Provide clear error messages for policy violations
#    - Handle password modification failures gracefully
#    - Support retry logic for transient failures
#
# 7. Testing Requirements:
#    - Unit tests for all password modification scenarios
#    - Integration tests with different LDAP servers
#    - Security tests for password policy enforcement
#    - Performance tests for high-volume password operations
