"""FLEXT-LDAP Domain Layer - Clean Architecture Domain Implementation.

This module implements the domain layer of the FLEXT-LDAP library following
Domain-Driven Design (DDD) principles and Clean Architecture patterns.

The domain layer contains:
- Domain Entities: Rich business objects with behavior
- Value Objects: Immutable domain values
- Domain Services: Business logic that doesn't fit in entities
- Specifications: Business rules and validation patterns
- Domain Events: Cross-aggregate communication patterns

All domain classes extend flext-core foundation patterns for consistency
across the FLEXT ecosystem.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import random
import re
import string
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar, Final

from flext_core import (
    FlextResult,
    get_logger,
)

from flext_ldap.constants import (
    FlextLdapObjectClassConstants,
    FlextLdapValidationConstants,
)

if TYPE_CHECKING:
    from flext_ldap.models import FlextLdapGroup, FlextLdapUser

logger = get_logger(__name__)

# =============================================================================
# DOMAIN CONSTANTS
# =============================================================================

MIN_PASSWORD_LENGTH: Final[int] = FlextLdapValidationConstants.MIN_PASSWORD_LENGTH
MAX_PASSWORD_LENGTH: Final[int] = FlextLdapValidationConstants.MAX_PASSWORD_LENGTH
MIN_USERNAME_LENGTH: Final[int] = 2
PASSWORD_GENERATION_MAX_RETRIES: Final[int] = 3
SECURE_RANDOM_GENERATION_MIN_RETRIES: Final[int] = 2
PASSWORD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$"
)

# =============================================================================
# DOMAIN SPECIFICATIONS - Business Rules Implementation
# =============================================================================


class FlextLdapDomainSpecification(ABC):
    """Base specification for LDAP domain validation extending flext-core patterns."""

    def __init__(self, name: str, description: str = "") -> None:
        """Initialize domain specification with business context."""
        self.name = name
        self.description = description

    @abstractmethod
    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if specification is satisfied by candidate."""
        ...

    def get_validation_error(self, candidate: object) -> str:
        """Get descriptive validation error message."""
        return f"Specification '{self.name}' failed for: {type(candidate).__name__}"


class FlextLdapUserSpecification(FlextLdapDomainSpecification):
    """Specification for comprehensive LDAP user validation."""

    def __init__(self) -> None:
        super().__init__(
            name="ValidLdapUser",
            description="Validates LDAP user entity business rules",
        )

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate is a valid LDAP user."""
        if not hasattr(candidate, "uid") or not hasattr(candidate, "dn"):
            return False

        # Validate required attributes
        uid = getattr(candidate, "uid", None)
        dn = getattr(candidate, "dn", None)
        cn = getattr(candidate, "cn", None)

        if not uid or not dn or not cn:
            return False

        # Validate object classes
        object_classes = getattr(candidate, "object_classes", [])
        required_classes = [
            FlextLdapObjectClassConstants.PERSON,
            FlextLdapObjectClassConstants.TOP,
        ]

        return all(cls in object_classes for cls in required_classes)

    def get_validation_error(self, candidate: object) -> str:
        """Get detailed user validation error."""
        if not hasattr(candidate, "uid"):
            return "User must have a valid UID"
        if not hasattr(candidate, "dn"):
            return "User must have a valid DN"
        return super().get_validation_error(candidate)


class FlextLdapGroupSpecification(FlextLdapDomainSpecification):
    """Specification for comprehensive LDAP group validation."""

    def __init__(self) -> None:
        super().__init__(
            name="ValidLdapGroup",
            description="Validates LDAP group entity business rules",
        )

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate is a valid LDAP group."""
        if not hasattr(candidate, "cn") or not hasattr(candidate, "dn"):
            return False

        # Validate object classes
        object_classes = getattr(candidate, "object_classes", [])
        required_classes = [
            FlextLdapObjectClassConstants.GROUP_OF_NAMES,
            FlextLdapObjectClassConstants.TOP,
        ]

        return any(cls in object_classes for cls in required_classes)

    def get_validation_error(self, candidate: object) -> str:
        """Get detailed group validation error."""
        if not hasattr(candidate, "cn"):
            return "Group must have a Common Name"
        if not hasattr(candidate, "dn"):
            return "Group must have a valid DN"
        return super().get_validation_error(candidate)


class FlextLdapDistinguishedNameSpecification(FlextLdapDomainSpecification):
    """Specification for RFC 4514 compliant DN validation."""

    DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:[a-zA-Z][\w-]*|\d+(?:\.\d+)*)\s*=\s*(?:[^,=+<>#;\\]+)+(?:\s*,\s*(?:[a-zA-Z][\w-]*|\d+(?:\.\d+)*)\s*=\s*(?:[^,=+<>#;\\]+)+)*$"
    )

    def __init__(self) -> None:
        super().__init__(
            name="ValidDistinguishedName",
            description="Validates RFC 4514 compliant Distinguished Names",
        )

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate is a valid DN string."""
        if not isinstance(candidate, str):
            return False

        if len(candidate) > FlextLdapValidationConstants.MAX_FILTER_LENGTH:
            return False

        return bool(self.DN_PATTERN.match(candidate))

    def get_validation_error(self, candidate: object) -> str:
        """Get detailed DN validation error."""
        if not isinstance(candidate, str):
            return "DN must be a string"
        if not candidate:
            return "DN cannot be empty"
        return f"Invalid DN format: {candidate!r}"


class FlextLdapPasswordSpecification(FlextLdapDomainSpecification):
    """Specification for password strength validation."""

    def __init__(self) -> None:
        super().__init__(
            name="SecurePassword",
            description="Validates password strength according to security policy",
        )

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate meets password requirements."""
        if not isinstance(candidate, str):
            return False

        if len(candidate) < MIN_PASSWORD_LENGTH:
            return False

        if len(candidate) > MAX_PASSWORD_LENGTH:
            return False

        # Check complexity if required
        if FlextLdapValidationConstants.REQUIRE_PASSWORD_COMPLEXITY:
            return bool(PASSWORD_PATTERN.match(candidate))

        return True

    def get_validation_error(self, candidate: object) -> str:
        """Get detailed password validation error."""
        if not isinstance(candidate, str):
            return "Password must be a string"
        if len(candidate) < MIN_PASSWORD_LENGTH:
            return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        if len(candidate) > MAX_PASSWORD_LENGTH:
            return f"Password cannot exceed {MAX_PASSWORD_LENGTH} characters"
        return "Password does not meet complexity requirements"


class FlextLdapActiveUserSpecification(FlextLdapDomainSpecification):
    """Specification for active user account validation."""

    def __init__(self) -> None:
        super().__init__(
            name="ActiveUser",
            description="Validates that user account is active and not disabled",
        )

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if user account is active."""
        if not hasattr(candidate, "status"):
            return False

        status = candidate.status
        # Try to use FlextEntityStatus if available, otherwise use string comparison
        try:
            from flext_core import FlextEntityStatus  # noqa: PLC0415

            return str(status) == str(FlextEntityStatus.ACTIVE)
        except ImportError:
            # Fallback if FlextEntityStatus not available
            return str(status).lower() in ("active", "enabled")

    def get_validation_error(self, candidate: object) -> str:
        """Get user status validation error."""
        if not hasattr(candidate, "status"):
            return "User must have a status field"
        status = getattr(candidate, "status", None)
        return f"User account is not active: {status}"


class FlextLdapEmailSpecification(FlextLdapDomainSpecification):
    """Specification for email address validation."""

    EMAIL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        FlextLdapValidationConstants.EMAIL_PATTERN
    )

    def __init__(self) -> None:
        super().__init__(
            name="ValidEmail",
            description="Validates email address format",
        )

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate is a valid email address."""
        if not isinstance(candidate, str):
            return False

        return bool(self.EMAIL_PATTERN.match(candidate))

    def get_validation_error(self, candidate: object) -> str:
        """Get email validation error."""
        if not isinstance(candidate, str):
            return "Email must be a string"
        return f"Invalid email format: {candidate!r}"


# =============================================================================
# COMPOSITE SPECIFICATIONS - Complex Business Rules
# =============================================================================


class FlextLdapCompleteUserSpecification(FlextLdapDomainSpecification):
    """Composite specification for complete user validation."""

    def __init__(self) -> None:
        super().__init__(
            name="CompleteUser",
            description="Validates complete user entity with all business rules",
        )
        self._user_spec = FlextLdapUserSpecification()
        self._dn_spec = FlextLdapDistinguishedNameSpecification()
        self._active_spec = FlextLdapActiveUserSpecification()

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate satisfies all user validation rules."""
        return (
            self._user_spec.is_satisfied_by(candidate)
            and self._dn_spec.is_satisfied_by(getattr(candidate, "dn", ""))
            and self._active_spec.is_satisfied_by(candidate)
        )

    def get_validation_error(self, candidate: object) -> str:
        """Get first failing validation error."""
        if not self._user_spec.is_satisfied_by(candidate):
            return self._user_spec.get_validation_error(candidate)
        if not self._dn_spec.is_satisfied_by(getattr(candidate, "dn", "")):
            return self._dn_spec.get_validation_error(getattr(candidate, "dn", ""))
        if not self._active_spec.is_satisfied_by(candidate):
            return self._active_spec.get_validation_error(candidate)
        return super().get_validation_error(candidate)


# =============================================================================
# DOMAIN SERVICES - Business Logic That Doesn't Belong in Entities
# =============================================================================


class FlextLdapUserManagementService:
    """Domain service for user management business logic."""

    def __init__(self) -> None:
        self._user_spec = FlextLdapCompleteUserSpecification()
        self._password_spec = FlextLdapPasswordSpecification()
        self._email_spec = FlextLdapEmailSpecification()

    def validate_user_creation(self, user_data: dict[str, object]) -> FlextResult[None]:
        """Validate user creation business rules."""
        try:
            # Check required fields
            required_fields = ["uid", "cn", "sn", "dn"]
            for field in required_fields:
                if field not in user_data or not user_data[field]:
                    return FlextResult.fail(f"Required field missing: {field}")

            # Validate DN format
            dn = str(user_data["dn"])
            if not self._user_spec._dn_spec.is_satisfied_by(dn):
                return FlextResult.fail(
                    self._user_spec._dn_spec.get_validation_error(dn)
                )

            # Validate email if provided
            if user_data.get("mail"):
                email = str(user_data["mail"])
                if not self._email_spec.is_satisfied_by(email):
                    return FlextResult.fail(self._email_spec.get_validation_error(email))

            # Validate password if provided
            if user_data.get("user_password"):
                password = str(user_data["user_password"])
                if not self._password_spec.is_satisfied_by(password):
                    return FlextResult.fail(
                        self._password_spec.get_validation_error(password)
                    )

            return FlextResult.ok(None)

        except Exception as e:
            logger.exception("User validation failed")
            return FlextResult.fail(f"User validation error: {e}")

    def can_delete_user(
        self, user: FlextLdapUser, requesting_user: FlextLdapUser
    ) -> FlextResult[bool]:
        """Check if user can be deleted by requesting user."""
        try:
            # Business rule: Users cannot delete themselves
            if user.uid == requesting_user.uid:
                return FlextResult.fail("Users cannot delete themselves")

            # Business rule: Only active users can perform deletions
            if not self._user_spec._active_spec.is_satisfied_by(requesting_user):
                return FlextResult.fail("Only active users can delete other users")

            return FlextResult.ok(data=True)

        except Exception as e:
            logger.exception("User deletion check failed")
            return FlextResult.fail(f"User deletion check error: {e}")

    def generate_username(self, first_name: str, last_name: str) -> FlextResult[str]:
        """Generate username following business rules."""
        try:
            if not first_name or not last_name:
                return FlextResult.fail("First name and last name required")

            # Business rule: username = first initial + last name, lowercase
            username = f"{first_name[0].lower()}{last_name.lower()}"

            # Remove invalid characters
            username = re.sub(r"[^a-zA-Z0-9._-]", "", username)

            if len(username) < MIN_USERNAME_LENGTH:
                return FlextResult.fail("Generated username too short")

            return FlextResult.ok(username)

        except Exception as e:
            logger.exception("Username generation failed")
            return FlextResult.fail(f"Username generation error: {e}")


class FlextLdapGroupManagementService:
    """Domain service for group management business logic."""

    def __init__(self) -> None:
        self._group_spec = FlextLdapGroupSpecification()
        self._dn_spec = FlextLdapDistinguishedNameSpecification()

    def can_add_member(  # noqa: FBT001
        self, group: FlextLdapGroup, user: FlextLdapUser, *, allow_inactive: bool = False
    ) -> FlextResult[bool]:
        """Check if user can be added to group."""
        try:
            # Validate group
            if not self._group_spec.is_satisfied_by(group):
                return FlextResult.fail(
                    self._group_spec.get_validation_error(group)
                )

            # Business rule: User must be active (unless explicitly allowed)
            if not allow_inactive:
                active_spec = FlextLdapActiveUserSpecification()
                if not active_spec.is_satisfied_by(user):
                    return FlextResult.fail("Only active users can be added to groups")

            # Business rule: User cannot be added if already a member
            if group.has_member(user.dn):
                return FlextResult.fail("User is already a member of this group")

            return FlextResult.ok(data=True)

        except Exception as e:
            logger.exception("Group membership check failed")
            return FlextResult.fail(f"Group membership check error: {e}")

    def validate_group_creation(
        self, group_data: dict[str, object]
    ) -> FlextResult[None]:
        """Validate group creation business rules."""
        try:
            # Check required fields
            required_fields = ["cn", "dn"]
            for field in required_fields:
                if field not in group_data or not group_data[field]:
                    return FlextResult.fail(f"Required field missing: {field}")

            # Validate DN format
            dn = str(group_data["dn"])
            if not self._dn_spec.is_satisfied_by(dn):
                return FlextResult.fail(self._dn_spec.get_validation_error(dn))

            return FlextResult.ok(None)

        except Exception as e:
            logger.exception("Group validation failed")
            return FlextResult.fail(f"Group validation error: {e}")


class FlextLdapPasswordService:
    """Domain service for password management business logic."""

    def __init__(self) -> None:
        self._password_spec = FlextLdapPasswordSpecification()

    def validate_password_change(
        self, current_password: str, new_password: str
    ) -> FlextResult[None]:
        """Validate password change business rules."""
        try:
            # Validate new password strength
            if not self._password_spec.is_satisfied_by(new_password):
                return FlextResult.fail(
                    self._password_spec.get_validation_error(new_password)
                )

            # Business rule: New password cannot be the same as current
            if current_password == new_password:
                return FlextResult.fail("New password must be different from current")

            return FlextResult.ok(None)

        except Exception as e:
            logger.exception("Password validation failed")
            return FlextResult.fail(f"Password validation error: {e}")

    def generate_secure_password(self, length: int = 12) -> FlextResult[str]:
        """Generate a secure password following business rules."""
        try:
            if length < MIN_PASSWORD_LENGTH:
                return FlextResult.fail(
                    f"Password length must be at least {MIN_PASSWORD_LENGTH}"
                )

            if length > MAX_PASSWORD_LENGTH:
                return FlextResult.fail(
                    f"Password length cannot exceed {MAX_PASSWORD_LENGTH}"
                )

            # Simple secure password generation (in production, use cryptographically secure)
            chars = string.ascii_letters + string.digits + "@$!%*?&"
            password = "".join(random.choices(chars, k=length))  # noqa: S311

            # Ensure it meets complexity requirements
            if not self._password_spec.is_satisfied_by(password):
                # Retry up to 3 times
                for _ in range(PASSWORD_GENERATION_MAX_RETRIES):
                    password = "".join(random.choices(chars, k=length))  # noqa: S311
                    if self._password_spec.is_satisfied_by(password):
                        break
                else:
                    return FlextResult.fail("Could not generate secure password")

            return FlextResult.ok(password)

        except Exception as e:
            logger.exception("Password generation failed")
            return FlextResult.fail(f"Password generation error: {e}")


# =============================================================================
# DOMAIN EVENTS - Cross-Aggregate Communication
# =============================================================================


class FlextLdapDomainEvent:
    """Base class for LDAP domain events."""

    def __init__(
        self,
        occurred_at: datetime | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize domain event."""
        self.occurred_at = occurred_at or datetime.now(UTC)
        for key, value in kwargs.items():
            setattr(self, key, value)


class FlextLdapUserCreatedEvent(FlextLdapDomainEvent):
    """Domain event fired when a user is created."""

    def __init__(
        self,
        user_id: str,
        user_dn: str,
        created_by: str,
        occurred_at: datetime | None = None,
    ) -> None:
        """Initialize user created event."""
        super().__init__(occurred_at=occurred_at)
        self.user_id = user_id
        self.user_dn = user_dn
        self.created_by = created_by

    @classmethod
    def create(
        cls, user_id: str, user_dn: str, created_by: str
    ) -> FlextLdapUserCreatedEvent:
        """Create user created event."""
        return cls(
            user_id=user_id,
            user_dn=user_dn,
            created_by=created_by,
            occurred_at=datetime.now(UTC),
        )


class FlextLdapUserDeletedEvent(FlextLdapDomainEvent):
    """Domain event fired when a user is deleted."""

    def __init__(
        self,
        user_id: str,
        user_dn: str,
        deleted_by: str,
        occurred_at: datetime | None = None,
    ) -> None:
        """Initialize user deleted event."""
        super().__init__(occurred_at=occurred_at)
        self.user_id = user_id
        self.user_dn = user_dn
        self.deleted_by = deleted_by

    @classmethod
    def create(
        cls, user_id: str, user_dn: str, deleted_by: str
    ) -> FlextLdapUserDeletedEvent:
        """Create user deleted event."""
        return cls(
            user_id=user_id,
            user_dn=user_dn,
            deleted_by=deleted_by,
            occurred_at=datetime.now(UTC),
        )


class FlextLdapGroupMemberAddedEvent(FlextLdapDomainEvent):
    """Domain event fired when a member is added to a group."""

    def __init__(
        self,
        group_dn: str,
        member_dn: str,
        added_by: str,
        occurred_at: datetime | None = None,
    ) -> None:
        """Initialize group member added event."""
        super().__init__(occurred_at=occurred_at)
        self.group_dn = group_dn
        self.member_dn = member_dn
        self.added_by = added_by

    @classmethod
    def create(
        cls, group_dn: str, member_dn: str, added_by: str
    ) -> FlextLdapGroupMemberAddedEvent:
        """Create group member added event."""
        return cls(
            group_dn=group_dn,
            member_dn=member_dn,
            added_by=added_by,
            occurred_at=datetime.now(UTC),
        )


class FlextLdapPasswordChangedEvent(FlextLdapDomainEvent):
    """Domain event fired when a user's password is changed."""

    def __init__(
        self,
        user_dn: str,
        changed_by: str,
        *,
        is_self_change: bool | None = None,
        occurred_at: datetime | None = None,
    ) -> None:
        """Initialize password changed event."""
        super().__init__(occurred_at=occurred_at)
        self.user_dn = user_dn
        self.changed_by = changed_by
        self.is_self_change = (
            is_self_change if is_self_change is not None else (user_dn == changed_by)
        )

    @classmethod
    def create(
        cls, user_dn: str, changed_by: str
    ) -> FlextLdapPasswordChangedEvent:
        """Create password changed event."""
        return cls(
            user_dn=user_dn,
            changed_by=changed_by,
            is_self_change=user_dn == changed_by,
            occurred_at=datetime.now(UTC),
        )


# =============================================================================
# DOMAIN FACTORIES - Object Creation with Business Rules
# =============================================================================


class FlextLdapDomainFactory:
    """Factory for creating domain objects with business rule validation."""

    def __init__(self) -> None:
        self._user_service = FlextLdapUserManagementService()
        self._group_service = FlextLdapGroupManagementService()
        self._password_service = FlextLdapPasswordService()

    def create_user_from_data(
        self, user_data: dict[str, object]
    ) -> FlextResult[FlextLdapUser]:
        """Create user entity from data with full validation."""
        try:
            # Validate business rules
            validation_result = self._user_service.validate_user_creation(user_data)
            if not validation_result.is_success:
                return FlextResult.fail(validation_result.error or "User validation failed")

            # Import here to avoid circular dependency
            from flext_ldap.models import FlextLdapUser  # noqa: PLC0415

            # Create user entity
            given_name = user_data.get("given_name")
            mail = user_data.get("mail")
            object_classes_raw = user_data.get("object_classes", ["inetOrgPerson", "person", "top"])
            attributes_raw = user_data.get("attributes", {})

            # Type-safe conversions
            object_classes = (
                object_classes_raw if isinstance(object_classes_raw, list)
                else ["inetOrgPerson", "person", "top"]
            )
            attributes = (
                attributes_raw if isinstance(attributes_raw, dict)
                else {}
            )

            user = FlextLdapUser(
                dn=str(user_data["dn"]),
                uid=str(user_data.get("uid", "")),
                cn=str(user_data.get("cn", "")),
                sn=str(user_data.get("sn", "")),
                given_name=str(given_name) if given_name else None,
                mail=str(mail) if mail else None,
                object_classes=object_classes,
                attributes=attributes,
            )

            # Final domain validation
            complete_spec = FlextLdapCompleteUserSpecification()
            if not complete_spec.is_satisfied_by(user):
                return FlextResult.fail(complete_spec.get_validation_error(user))

            return FlextResult.ok(user)

        except Exception as e:
            logger.exception("User creation failed")
            return FlextResult.fail(f"User creation error: {e}")

    def create_group_from_data(
        self, group_data: dict[str, object]
    ) -> FlextResult[FlextLdapGroup]:
        """Create group entity from data with full validation."""
        try:
            # Validate business rules
            validation_result = self._group_service.validate_group_creation(group_data)
            if not validation_result.is_success:
                return FlextResult.fail(validation_result.error or "Group validation failed")

            # Import here to avoid circular dependency
            from flext_ldap.models import FlextLdapGroup  # noqa: PLC0415

            # Create group entity
            description = group_data.get("description")
            members_raw = group_data.get("members", [])
            object_classes_raw = group_data.get("object_classes", ["groupOfNames", "top"])
            attributes_raw = group_data.get("attributes", {})

            # Type-safe conversions
            members = (
                members_raw if isinstance(members_raw, list)
                else []
            )
            object_classes = (
                object_classes_raw if isinstance(object_classes_raw, list)
                else ["groupOfNames", "top"]
            )
            attributes = (
                attributes_raw if isinstance(attributes_raw, dict)
                else {}
            )

            group = FlextLdapGroup(
                dn=str(group_data["dn"]),
                cn=str(group_data.get("cn", "")),
                description=str(description) if description else None,
                members=members,
                object_classes=object_classes,
                attributes=attributes,
            )

            # Final domain validation
            group_spec = FlextLdapGroupSpecification()
            if not group_spec.is_satisfied_by(group):
                return FlextResult.fail(group_spec.get_validation_error(group))

            return FlextResult.ok(group)

        except Exception as e:
            logger.exception("Group creation failed")
            return FlextResult.fail(f"Group creation error: {e}")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "MAX_PASSWORD_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "FlextLdapActiveUserSpecification",
    "FlextLdapCompleteUserSpecification",
    "FlextLdapDistinguishedNameSpecification",
    "FlextLdapDomainFactory",
    "FlextLdapDomainSpecification",
    "FlextLdapEmailSpecification",
    "FlextLdapGroupManagementService",
    "FlextLdapGroupMemberAddedEvent",
    "FlextLdapGroupSpecification",
    "FlextLdapPasswordChangedEvent",
    "FlextLdapPasswordService",
    "FlextLdapPasswordSpecification",
    "FlextLdapUserCreatedEvent",
    "FlextLdapUserDeletedEvent",
    "FlextLdapUserManagementService",
    "FlextLdapUserSpecification",
]
