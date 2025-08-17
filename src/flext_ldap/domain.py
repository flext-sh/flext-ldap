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

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import random
import re
import string
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import ClassVar, Final, TypeVar

from flext_core import FlextResult, get_logger

from flext_ldap.constants import (
    FlextLdapDefaultValues,
    FlextLdapObjectClassConstants,
    FlextLdapValidationConstants,
    FlextLdapValidationMessages,
)
from flext_ldap.models import FlextLdapGroup, FlextLdapUser

logger = get_logger(__name__)
T = TypeVar("T")
# =============================================================================
# DOMAIN CONSTANTS
# =============================================================================

MIN_PASSWORD_LENGTH: Final[int] = FlextLdapValidationConstants.MIN_PASSWORD_LENGTH
MAX_PASSWORD_LENGTH: Final[int] = FlextLdapValidationConstants.MAX_PASSWORD_LENGTH
MIN_USERNAME_LENGTH: Final[int] = 2
PASSWORD_GENERATION_MAX_RETRIES: Final[int] = 3
SECURE_RANDOM_GENERATION_MIN_RETRIES: Final[int] = 2
PASSWORD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$",
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
        return FlextLdapValidationMessages.SPECIFICATION_FAILED.format(
            name=self.name,
            type=type(candidate).__name__,
        )


class FlextLdapUserSpecification(FlextLdapDomainSpecification):
    """Specification for comprehensive LDAP user validation."""

    def __init__(self) -> None:
        super().__init__(
            name=FlextLdapDefaultValues.VALID_LDAP_USER_NAME,
            description=FlextLdapDefaultValues.VALID_LDAP_USER_DESCRIPTION,
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
        r"^(?:[a-zA-Z][\w-]*|\d+(?:\.\d+)*)\s*=\s*(?:[^,=+<>#;\\]+)+(?:\s*,\s*(?:[a-zA-Z][\w-]*|\d+(?:\.\d+)*)\s*=\s*(?:[^,=+<>#;\\]+)+)*$",
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
        # Use strict enum from flext_core
        from flext_core import FlextEntityStatus  # noqa: PLC0415

        return str(status) == str(FlextEntityStatus.ACTIVE)

    def get_validation_error(self, candidate: object) -> str:
        """Get user status validation error."""
        if not hasattr(candidate, "status"):
            return "User must have a status field"
        status = getattr(candidate, "status", None)
        return f"User account is not active: {status}"


class FlextLdapEmailSpecification(FlextLdapDomainSpecification):
    """Specification for email address validation."""

    EMAIL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        FlextLdapValidationConstants.EMAIL_PATTERN,
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
        """Validate user creation business rules - REFACTORED to reduce returns."""
        try:
            # Perform all validations in sequence
            return self._perform_all_user_validations(user_data)
        except Exception as e:
            logger.exception("User validation failed")
            return FlextResult.fail(f"User validation error: {e}")

    def _perform_all_user_validations(
        self,
        user_data: dict[str, object],
    ) -> FlextResult[None]:
        """Perform all user validations and return first failure or success."""
        # Chain all validations - stop at first failure
        validations = [
            self._validate_required_fields,
            self._validate_dn_field,
            self._validate_email_field,
            self._validate_password_field,
        ]

        for validation_func in validations:
            result = validation_func(user_data)
            if result.is_failure:
                return result

        return FlextResult.ok(None)

    def _validate_required_fields(
        self,
        user_data: dict[str, object],
    ) -> FlextResult[None]:
        """Validate required user fields."""
        required_fields = ["uid", "cn", "sn", "dn"]
        for field in required_fields:
            if field not in user_data or not user_data[field]:
                return FlextResult.fail(f"Required field missing: {field}")
        return FlextResult.ok(None)

    def _validate_dn_field(self, user_data: dict[str, object]) -> FlextResult[None]:
        """Validate DN field format."""
        dn = str(user_data["dn"])
        if not self._user_spec._dn_spec.is_satisfied_by(dn):
            return FlextResult.fail(
                self._user_spec._dn_spec.get_validation_error(dn),
            )
        return FlextResult.ok(None)

    def _validate_email_field(self, user_data: dict[str, object]) -> FlextResult[None]:
        """Validate email field if provided."""
        if user_data.get("mail"):
            email = str(user_data["mail"])
            if not self._email_spec.is_satisfied_by(email):
                return FlextResult.fail(
                    self._email_spec.get_validation_error(email),
                )
        return FlextResult.ok(None)

    def _validate_password_field(
        self,
        user_data: dict[str, object],
    ) -> FlextResult[None]:
        """Validate password field if provided."""
        if user_data.get("user_password"):
            password = str(user_data["user_password"])
            if not self._password_spec.is_satisfied_by(password):
                return FlextResult.fail(
                    self._password_spec.get_validation_error(password),
                )
        return FlextResult.ok(None)

    def can_delete_user(
        self,
        user: FlextLdapUser,
        requesting_user: FlextLdapUser,
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

    def can_add_member(
        self,
        group: FlextLdapGroup,
        user: FlextLdapUser,
        *,
        allow_inactive: bool = False,
    ) -> FlextResult[bool]:
        """Check if user can be added to group."""
        try:
            # Validate group
            if not self._group_spec.is_satisfied_by(group):
                return FlextResult.fail(
                    self._group_spec.get_validation_error(group),
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
        self,
        group_data: dict[str, object],
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
        self,
        current_password: str,
        new_password: str,
    ) -> FlextResult[None]:
        """Validate password change business rules."""
        try:
            # Validate new password strength
            if not self._password_spec.is_satisfied_by(new_password):
                return FlextResult.fail(
                    self._password_spec.get_validation_error(new_password),
                )

            # Business rule: New password cannot be the same as current
            if current_password == new_password:
                return FlextResult.fail("New password must be different from current")

            return FlextResult.ok(None)

        except Exception as e:
            logger.exception("Password validation failed")
            return FlextResult.fail(f"Password validation error: {e}")

    def generate_secure_password(self, length: int = 12) -> FlextResult[str]:
        """Generate a secure password following business rules - REFACTORED."""
        try:
            # Validate parameters in single check
            validation_error = self._validate_password_length(length)
            if validation_error:
                return FlextResult.fail(validation_error)

            # Generate password with retry logic
            return self._generate_password_with_retries(length)

        except Exception as e:
            logger.exception("Password generation failed")
            return FlextResult.fail(f"Password generation error: {e}")

    def _validate_password_length(self, length: int) -> str | None:
        """Validate password length parameters - EXTRACTED METHOD."""
        if length < MIN_PASSWORD_LENGTH:
            return f"Password length must be at least {MIN_PASSWORD_LENGTH}"
        if length > MAX_PASSWORD_LENGTH:
            return f"Password length cannot exceed {MAX_PASSWORD_LENGTH}"
        return None

    def _generate_password_with_retries(self, length: int) -> FlextResult[str]:
        """Generate password with retry logic - EXTRACTED METHOD."""
        chars = string.ascii_letters + string.digits + "@$!%*?&"

        # Initial attempt
        password = "".join(random.choices(chars, k=length))  # noqa: S311
        if self._password_spec.is_satisfied_by(password):
            return FlextResult.ok(password)

        # Retry attempts
        for _ in range(PASSWORD_GENERATION_MAX_RETRIES):
            password = "".join(random.choices(chars, k=length))  # noqa: S311
            if self._password_spec.is_satisfied_by(password):
                return FlextResult.ok(password)

        return FlextResult.fail("Could not generate secure password")


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


class FlextLdapBaseUserEvent(FlextLdapDomainEvent):
    """Base class for user-related domain events to eliminate duplication."""

    def __init__(
        self,
        user_id: str,
        user_dn: str,
        actor: str,
        occurred_at: datetime | None = None,
    ) -> None:
        """Initialize user event with common fields."""
        super().__init__(occurred_at=occurred_at)
        self.user_id = user_id
        self.user_dn = user_dn
        self.actor = actor

    @classmethod
    def create_with_timestamp(
        cls,
        user_id: str,
        user_dn: str,
        actor: str,
    ) -> FlextLdapDomainEvent:
        """Create event with current timestamp."""
        return cls(
            user_id=user_id,
            user_dn=user_dn,
            actor=actor,
            occurred_at=datetime.now(UTC),
        )


class FlextLdapUserCreatedEvent(FlextLdapBaseUserEvent):
    """Domain event fired when a user is created."""

    @classmethod
    def create(
        cls,
        user_id: str,
        user_dn: str,
        created_by: str,
    ) -> FlextLdapUserCreatedEvent:
        """Create user created event."""
        # Type cast to ensure correct return type
        return cls.create_with_timestamp(user_id, user_dn, created_by)  # type: ignore[return-value]


class FlextLdapUserDeletedEvent(FlextLdapBaseUserEvent):
    """Domain event fired when a user is deleted."""

    @classmethod
    def create(
        cls,
        user_id: str,
        user_dn: str,
        deleted_by: str,
    ) -> FlextLdapUserDeletedEvent:
        """Create user deleted event."""
        # Type cast to ensure correct return type
        return cls.create_with_timestamp(user_id, user_dn, deleted_by)  # type: ignore[return-value]


class FlextLdapBaseGroupEvent(FlextLdapDomainEvent):
    """Base class for group-related domain events to eliminate duplication."""

    def __init__(
        self,
        group_dn: str,
        actor: str,
        occurred_at: datetime | None = None,
    ) -> None:
        """Initialize group event with common fields."""
        super().__init__(occurred_at=occurred_at)
        self.group_dn = group_dn
        self.actor = actor

    @classmethod
    def create_with_timestamp(
        cls,
        group_dn: str,
        actor: str,
    ) -> FlextLdapDomainEvent:
        """Create event with current timestamp."""
        return cls(
            group_dn=group_dn,
            actor=actor,
            occurred_at=datetime.now(UTC),
        )


class FlextLdapGroupMemberAddedEvent(FlextLdapBaseGroupEvent):
    """Domain event fired when a member is added to a group."""

    def __init__(
        self,
        group_dn: str,
        member_dn: str,
        added_by: str,
        occurred_at: datetime | None = None,
    ) -> None:
        """Initialize group member added event."""
        super().__init__(group_dn=group_dn, actor=added_by, occurred_at=occurred_at)
        self.member_dn = member_dn
        self.added_by = added_by  # Maintain compatibility

    @classmethod
    def create(
        cls,
        group_dn: str,
        member_dn: str,
        added_by: str,
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
        cls,
        user_dn: str,
        changed_by: str,
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


class EntityParameterBuilder:
    """Helper class to build entity parameters with type safety - REDUCES COMPLEXITY."""

    @staticmethod
    def safe_str(value: object) -> str | None:
        """Safely convert value to string or None."""
        return str(value) if value else None

    @staticmethod
    def safe_list(value: object, default: list[str] | None = None) -> list[str]:
        """Safely convert value to list or use default."""
        if isinstance(value, list):
            return [str(item) for item in value]
        return default or []

    @staticmethod
    def safe_dict(value: object) -> dict[str, object]:
        """Safely convert value to dict or empty dict."""
        return dict(value) if isinstance(value, dict) else {}


class UserEntityBuilder:
    """Builder for FlextLdapUser entities - ELIMINATES DUPLICATION."""

    def __init__(self, params: dict[str, object]) -> None:
        self.params = params
        self.builder = EntityParameterBuilder()

    def build(self) -> object:
        """Build FlextLdapUser with reduced parameter complexity."""
        from flext_ldap.models import FlextLdapUser  # noqa: PLC0415

        return FlextLdapUser(
            dn=str(self.params["dn"]),
            uid=self.builder.safe_str(self.params["uid"]),
            cn=self.builder.safe_str(self.params["cn"]),
            sn=self.builder.safe_str(self.params["sn"]),
            given_name=self.builder.safe_str(self.params["given_name"]),
            mail=self.builder.safe_str(self.params["mail"]),
            object_classes=self.builder.safe_list(self.params["object_classes"]),
            attributes=self.builder.safe_dict(self.params["attributes"]),
        )


class GroupEntityBuilder:
    """Builder for FlextLdapGroup entities - ELIMINATES DUPLICATION."""

    def __init__(self, params: dict[str, object]) -> None:
        self.params = params
        self.builder = EntityParameterBuilder()

    def build(self) -> object:
        """Build FlextLdapGroup with reduced parameter complexity."""
        from flext_ldap.models import FlextLdapGroup  # noqa: PLC0415

        return FlextLdapGroup(
            dn=str(self.params["dn"]),
            cn=self.builder.safe_str(self.params["cn"]),
            description=self.builder.safe_str(self.params["description"]),
            members=self.builder.safe_list(self.params["members"]),
            object_classes=self.builder.safe_list(self.params["object_classes"]),
            attributes=self.builder.safe_dict(self.params["attributes"]),
        )


class FlextLdapDomainFactory:
    """Factory for creating domain objects with business rule validation."""

    def __init__(self) -> None:
        self._user_service = FlextLdapUserManagementService()
        self._group_service = FlextLdapGroupManagementService()
        self._password_service = FlextLdapPasswordService()

    def create_user_from_data(
        self,
        user_data: dict[str, object],
    ) -> FlextResult[FlextLdapUser]:
        """Create user entity from data with full validation."""
        operations: Mapping[str, Callable[[dict[str, object]], object]] = {
            "validate": self._user_service.validate_user_creation,
            "extract": self._extract_user_parameters,
            "create": self._create_user_entity,
            "final_validate": self._validate_created_user,
        }
        result = self._create_entity_from_data(user_data, "User", operations)
        # Narrow the type for the public API
        if result.is_failure:
            return FlextResult.fail(result.error or "User creation failed")
        created = result.unwrap()
        # Late import kept to avoid circular dependency; ruff allow
        from flext_ldap.models import (  # noqa: PLC0415
            FlextLdapUser as _User,
        )

        if isinstance(created, _User):
            return FlextResult.ok(created)
        return FlextResult.fail("User creation returned invalid type")

    def _extract_user_parameters(
        self,
        user_data: dict[str, object],
    ) -> dict[str, object]:
        """Extract and convert user parameters from raw data."""
        # Import here to avoid circular dependency

        given_name = user_data.get("given_name")
        mail = user_data.get("mail")
        object_classes_raw = user_data.get(
            "object_classes",
            ["inetOrgPerson", "person", "top"],
        )
        attributes_raw = user_data.get("attributes", {})

        # Type-safe conversions
        object_classes = (
            object_classes_raw
            if isinstance(object_classes_raw, list)
            else ["inetOrgPerson", "person", "top"]
        )
        attributes = attributes_raw if isinstance(attributes_raw, dict) else {}

        return {
            "dn": str(user_data["dn"]),
            "uid": str(user_data.get("uid", "")),
            "cn": str(user_data.get("cn", "")),
            "sn": str(user_data.get("sn", "")),
            "given_name": str(given_name) if given_name else None,
            "mail": str(mail) if mail else None,
            "object_classes": object_classes,
            "attributes": attributes,
        }

    def _create_user_entity(self, user_params: dict[str, object]) -> object:
        """Create FlextLdapUser entity from extracted parameters - REFACTORED."""
        builder = UserEntityBuilder(user_params)
        return builder.build()

    def _validate_created_user(self, user: object) -> FlextResult[object]:
        """Validate created user against domain specifications."""
        complete_spec = FlextLdapCompleteUserSpecification()
        if not complete_spec.is_satisfied_by(user):
            return FlextResult.fail(complete_spec.get_validation_error(user))
        return FlextResult.ok(user)

    def create_group_from_data(
        self,
        group_data: dict[str, object],
    ) -> FlextResult[FlextLdapGroup]:
        """Create group entity from data with full validation."""
        operations: Mapping[str, Callable[[dict[str, object]], object]] = {
            "validate": self._group_service.validate_group_creation,
            "extract": self._extract_group_parameters,
            "create": self._create_group_entity,
            "final_validate": self._validate_created_group,
        }
        result = self._create_entity_from_data(group_data, "Group", operations)
        if result.is_failure:
            return FlextResult.fail(result.error or "Group creation failed")
        created = result.unwrap()
        # Late import kept to avoid circular dependency; ruff allow
        from flext_ldap.models import (  # noqa: PLC0415
            FlextLdapGroup as _Group,
        )

        if isinstance(created, _Group):
            return FlextResult.ok(created)
        return FlextResult.fail("Group creation returned invalid type")

    def _extract_group_parameters(
        self,
        group_data: dict[str, object],
    ) -> dict[str, object]:
        """Extract and convert group parameters from raw data."""
        description = group_data.get("description")
        members_raw = group_data.get("members", [])
        object_classes_raw = group_data.get(
            "object_classes",
            ["groupOfNames", "top"],
        )
        attributes_raw = group_data.get("attributes", {})

        # Type-safe conversions
        members = members_raw if isinstance(members_raw, list) else []
        object_classes = (
            object_classes_raw
            if isinstance(object_classes_raw, list)
            else ["groupOfNames", "top"]
        )
        attributes = attributes_raw if isinstance(attributes_raw, dict) else {}

        return {
            "dn": str(group_data["dn"]),
            "cn": str(group_data.get("cn", "")),
            "description": str(description) if description else None,
            "members": members,
            "object_classes": object_classes,
            "attributes": attributes,
        }

    def _create_group_entity(self, group_params: dict[str, object]) -> object:
        """Create FlextLdapGroup entity from extracted parameters - REFACTORED."""
        builder = GroupEntityBuilder(group_params)
        return builder.build()

    def _validate_created_group(self, group: object) -> FlextResult[object]:
        """Validate created group against domain specifications."""
        group_spec = FlextLdapGroupSpecification()
        if not group_spec.is_satisfied_by(group):
            return FlextResult.fail(group_spec.get_validation_error(group))
        return FlextResult.ok(group)

    def _create_entity_from_data(
        self,
        data: dict[str, object],
        entity_type: str,
        operations: Mapping[str, Callable[[dict[str, object]], object]],
    ) -> FlextResult[object]:
        """Template method for entity creation - ELIMINATES CODE DUPLICATION.

        This method implements the common pattern shared by both user and group
        creation, eliminating the 25 lines of duplicated code identified by qlty.

        Args:
            data: Raw entity data to process
            entity_type: Type name for error messages ("User" or "Group")
            operations: Dict with keys: validate, extract, create, final_validate

        """
        try:
            # Execute entity creation pipeline
            return self._execute_entity_creation_pipeline(data, entity_type, operations)
        except Exception as e:
            logger.exception(f"{entity_type} creation failed")
            return FlextResult.fail(f"{entity_type} creation error: {e}")

    def _execute_entity_creation_pipeline(
        self,
        data: dict[str, object],
        entity_type: str,
        operations: Mapping[str, Callable[[dict[str, object]], object]],
    ) -> FlextResult[object]:
        """Execute the entity creation pipeline with validation at each step."""
        # Step 1: Validate business rules
        validation_result = self._execute_operation(
            operations.get("validate"),
            data,
            f"{entity_type} validation",
        )
        if validation_result.is_failure:
            return FlextResult.fail(
                validation_result.error or f"{entity_type} validation failed",
            )

        # Step 2: Extract parameters
        extract_result = self._execute_operation(
            operations.get("extract"),
            data,
            f"{entity_type} parameter extraction",
        )
        if extract_result.is_failure:
            return extract_result

        # Step 3: Create entity
        entity_params = extract_result.data
        create_result = self._execute_operation(
            operations.get("create"),
            entity_params,
            f"{entity_type} creation",
        )
        if create_result.is_failure:
            return create_result

        # Step 4: Final domain validation
        entity = create_result.data
        return self._execute_operation(
            operations.get("final_validate"),
            entity,
            f"{entity_type} final validation",
        )

    def _execute_operation(  # type: ignore[explicit-any]
        self,
        operation: Callable[..., object] | None,
        data: object,
        operation_name: str,
    ) -> FlextResult[object]:
        """Execute a single operation with error handling."""
        if not callable(operation):
            return FlextResult.fail(f"Invalid operation function for {operation_name}")

        try:
            result = operation(data)
            # Ensure result is FlextResult format
            if hasattr(result, "is_success"):
                return result  # type: ignore[return-value]
            # Wrap non-FlextResult returns
            return FlextResult.ok(result)
        except Exception as e:
            return FlextResult.fail(f"{operation_name} failed: {e}")


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
