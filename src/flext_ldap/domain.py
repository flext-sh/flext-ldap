"""LDAP domain module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import re
import secrets
import string
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import ClassVar, cast, override

from flext_core import (
    FlextCommands,
    FlextDomainService,
    FlextLogger,
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)

from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.typings import LdapAttributeDict

# Removed FlextLDAPUtilities - using Python standard library and flext-core
# directly

logger = FlextLogger(__name__)


class FlextLDAPDomain:
    """SINGLE CONSOLIDATED CLASS for all LDAP domain functionality.

    Following FLEXT architectural patterns - consolidates ALL LDAP domain functionality
    including specifications, domain services, domain events, and domain factories
    into one main class with specialized internal subclasses for organization.

    CONSOLIDATED CLASSES: All domain specifications + domain services + domain events + domain factories
    """

    # ==========================================================================
    # INTERNAL BASE CLASSES FOR DOMAIN PATTERNS
    # ==========================================================================

    class DomainSpecification:
        """Internal base domain specification using flext-core patterns - ELIMINATE LOCAL ABC."""

        def __init__(self, name: str, description: str = "") -> None:
            """Initialize domain specification with business context."""
            self.name = name
            self.description = description

        def is_satisfied_by(self, candidate: object) -> bool:
            """Check if specification is satisfied by candidate - implement in subclasses."""
            error_msg = "Subclasses must implement is_satisfied_by"
            raise NotImplementedError(error_msg)

        def get_validation_error(self, candidate: object) -> str:
            """Get descriptive validation error message."""
            return f"Specification '{self.name}' failed for {type(candidate).__name__}"

    # ==========================================================================
    # INTERNAL SPECIFICATION CLASSES FOR DIFFERENT DOMAIN RULES
    # ==========================================================================

    class UserSpecification(DomainSpecification):
        """Internal specification for comprehensive LDAP user validation."""

        def __init__(self) -> None:
            super().__init__(
                name=FlextLDAPConstants.DefaultValues.VALID_LDAP_USER_NAME,
                description=FlextLDAPConstants.DefaultValues.VALID_LDAP_USER_DESCRIPTION,
            )

        @override
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
                FlextLDAPConstants.ObjectClasses.PERSON,
                FlextLDAPConstants.ObjectClasses.TOP,
            ]

            return all(cls in object_classes for cls in required_classes)

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get detailed user validation error."""
            if not hasattr(candidate, "uid"):
                return "User must have a valid UID"
            if not hasattr(candidate, "dn"):
                return "User must have a valid DN"
            return super().get_validation_error(candidate)

    class GroupSpecification(DomainSpecification):
        """Internal specification for comprehensive LDAP group validation."""

        def __init__(self) -> None:
            super().__init__(
                name="ValidLdapGroup",
                description="Validates LDAP group entity business rules",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check if candidate is a valid LDAP group."""
            if not hasattr(candidate, "cn") or not hasattr(candidate, "dn"):
                return False

            # Validate object classes
            object_classes = getattr(candidate, "object_classes", [])
            required_classes = [
                FlextLDAPConstants.ObjectClasses.GROUP_OF_NAMES,
                FlextLDAPConstants.ObjectClasses.TOP,
            ]

            return all(cls in object_classes for cls in required_classes)

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get detailed group validation error."""
            if not hasattr(candidate, "cn"):
                return "Group must have a Common Name"
            if not hasattr(candidate, "dn"):
                return "Group must have a valid DN"
            return super().get_validation_error(candidate)

    class DistinguishedNameSpecification(DomainSpecification):
        """Internal specification for RFC 4514 compliant DN validation."""

        DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^(?:[a-zA-Z][\w-]*|\d+(?:\.\d+)*)\s*=\s*(?:[^,=+<>#;\\]+)+(?:\s*,\s*(?:[a-zA-Z][\w-]*|\d+(?:\.\d+)*)\s*=\s*(?:[^,=+<>#;\\]+)+)*$",
        )

        def __init__(self) -> None:
            super().__init__(
                name="ValidDistinguishedName",
                description="Validates RFC 4514 compliant Distinguished Names",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check if candidate is a valid DN string."""
            if not isinstance(candidate, str):
                return False

            if len(candidate) > FlextLDAPConstants.LdapValidation.MAX_FILTER_LENGTH:
                return False

            return bool(self.DN_PATTERN.match(candidate))

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get detailed DN validation error."""
            if not isinstance(candidate, str):
                return "DN must be a string"
            if not candidate:
                return "DN cannot be empty"
            return f"Invalid DN format: {candidate!r}"

    class PasswordSpecification(DomainSpecification):
        """Internal specification for password strength validation."""

        def __init__(self) -> None:
            super().__init__(
                name="SecurePassword",
                description="Validates password strength according to security policy",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check if candidate meets password requirements."""
            if not isinstance(candidate, str):
                return False

            if len(candidate) < FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH:
                return False

            if len(candidate) > FlextLDAPConstants.LdapValidation.MAX_PASSWORD_LENGTH:
                return False

            # Check complexity if required
            if FlextLDAPConstants.LdapValidation.REQUIRE_PASSWORD_COMPLEXITY:
                # Implement proper password complexity validation

                # Password must have: uppercase, lowercase, digit, special char
                has_upper = bool(re.search(r"[A-Z]", candidate))
                has_lower = bool(re.search(r"[a-z]", candidate))
                has_digit = bool(re.search(r"[0-9]", candidate))
                has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', candidate))

                return has_upper and has_lower and has_digit and has_special

            return True

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get detailed password validation error."""
            if not isinstance(candidate, str):
                return "Password must be a string"
            if len(candidate) < FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH:
                return f"Password must be at least {FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH} characters"
            if len(candidate) > FlextLDAPConstants.LdapValidation.MAX_PASSWORD_LENGTH:
                return f"Password cannot exceed {FlextLDAPConstants.LdapValidation.MAX_PASSWORD_LENGTH} characters"
            return "Password does not meet complexity requirements"

    class ActiveUserSpecification(DomainSpecification):
        """Internal specification for active user account validation."""

        def __init__(self) -> None:
            super().__init__(
                name="ActiveUser",
                description="Validates that user account is active and not disabled",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check if user account is active."""
            if not hasattr(candidate, "status"):
                return False

            status = getattr(candidate, "status", None)
            # Compare with enum value - EntityStatus.ACTIVE is "active" (lowercase)
            if status is None:
                return False
            if hasattr(status, "value"):
                return str(status.value) == "active"
            return str(status) == "active"

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get user status validation error."""
            if not hasattr(candidate, "status"):
                return "User must have a status field"
            status = getattr(candidate, "status", None)
            return f"User account is not active: {status}"

    class EmailSpecification(DomainSpecification):
        """Internal specification for email address validation."""

        EMAIL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            FlextLDAPConstants.LdapValidation.EMAIL_PATTERN,
        )

        def __init__(self) -> None:
            super().__init__(
                name="ValidEmail",
                description="Validates email address format",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check if candidate is a valid email address."""
            if not isinstance(candidate, str):
                return False

            return bool(self.EMAIL_PATTERN.match(candidate))

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get email validation error."""
            if not isinstance(candidate, str):
                return "Email must be a string"
            return f"Invalid email format: {candidate!r}"

    class CompleteUserSpecification(DomainSpecification):
        """Internal composite specification for complete user validation."""

        def __init__(self) -> None:
            super().__init__(
                name="CompleteUser",
                description="Validates complete user entity with all business rules",
            )
            self._user_spec = FlextLDAPDomain.UserSpecification()
            self._dn_spec = FlextLDAPDomain.DistinguishedNameSpecification()
            self._active_spec = FlextLDAPDomain.ActiveUserSpecification()

        @property
        def dn_spec(self) -> "FlextLDAPDomain.DistinguishedNameSpecification":
            """Access to DN specification for external validation."""
            return self._dn_spec

        @property
        def active_spec(self) -> "FlextLDAPDomain.ActiveUserSpecification":
            """Access to active user specification for external validation."""
            return self._active_spec

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check if candidate satisfies all user validation rules."""
            return (
                self._user_spec.is_satisfied_by(candidate)
                and self._dn_spec.is_satisfied_by(getattr(candidate, "dn", ""))
                and self._active_spec.is_satisfied_by(candidate)
            )

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get first failing validation error."""
            if not self._user_spec.is_satisfied_by(candidate):
                return self._user_spec.get_validation_error(candidate)
            if not self._dn_spec.is_satisfied_by(getattr(candidate, "dn", "")):
                return self._dn_spec.get_validation_error(getattr(candidate, "dn", ""))
            if not self._active_spec.is_satisfied_by(candidate):
                return self._active_spec.get_validation_error(candidate)
            return super().get_validation_error(candidate)

    # ==========================================================================
    # INTERNAL DOMAIN SERVICE CLASSES
    # ==========================================================================

    class UserManagementService(FlextDomainService[FlextLDAPEntities.User]):
        """Internal domain service for user management business logic."""

        def __init__(self) -> None:
            super().__init__()
            self._user_spec = FlextLDAPDomain.CompleteUserSpecification()
            self._password_spec = FlextLDAPDomain.PasswordSpecification()
            self._email_spec = FlextLDAPDomain.EmailSpecification()

        def execute(self) -> FlextResult[FlextLDAPEntities.User]:
            """Execute method required by FlextDomainService - CORRECTED signature."""
            return FlextResult.ok(
                FlextLDAPEntities.User(
                    id="default_user",
                    dn="cn=default,dc=example,dc=com",
                    uid="default",
                    cn="Default User",
                    sn="User",
                    given_name="Default",
                    mail="default@example.com",
                    user_password=None,
                    modified_at=None,
                ),
            )

        def validate_user_creation(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
            """Validate user creation business rules - REFACTORED to reduce returns."""
            try:
                # Perform all validations in sequence
                return self._perform_all_user_validations(user_data)
            except Exception as e:
                logger.exception("User validation failed")
                return FlextResult.fail(f"User validation error: {e}")

        def _perform_all_user_validations(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
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
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
            """Validate required user fields."""
            required_fields = ["uid", "cn", "sn", "dn"]
            for field in required_fields:
                if field not in user_data or not user_data[field]:
                    return FlextResult.fail(f"Required field missing: {field}")
            return FlextResult.ok(None)

        def _validate_dn_field(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
            """Validate DN field format."""
            dn = str(user_data["dn"])
            if not self._user_spec.dn_spec.is_satisfied_by(dn):
                return FlextResult.fail(
                    self._user_spec.dn_spec.get_validation_error(dn),
                )
            return FlextResult.ok(None)

        def _validate_email_field(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
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
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
            """Validate password field if provided."""
            # Support both common password field names
            password_value = user_data.get("password") or user_data.get("user_password")
            if password_value:
                password = str(password_value)
                if not self._password_spec.is_satisfied_by(password):
                    return FlextResult.fail(
                        self._password_spec.get_validation_error(password),
                    )
            return FlextResult.ok(None)

        def can_delete_user(
            self,
            user: FlextLDAPEntities.User,
            requesting_user: FlextLDAPEntities.User,
        ) -> FlextResult[bool]:
            """Check if user can be deleted by requesting user."""
            try:
                # Business rule: Users cannot delete themselves
                if user.uid == requesting_user.uid:
                    return FlextResult.fail("Users cannot delete themselves")

                # Business rule: Only active users can perform deletions
                if not self._user_spec.active_spec.is_satisfied_by(requesting_user):
                    return FlextResult.fail(
                        "Only active users can delete other users",
                    )

                success = True
                return FlextResult.ok(success)

            except Exception as e:
                logger.exception("User deletion check failed")
                return FlextResult.fail(f"User deletion check error: {e}")

        def generate_username(
            self,
            first_name: str,
            last_name: str,
        ) -> FlextResult[str]:
            """Generate username following business rules - USES FLEXT-CORE."""
            try:
                # Validate inputs using FlextUtilities
                if not FlextUtilities.TypeGuards.is_string_non_empty(
                    first_name,
                ) or not FlextUtilities.TypeGuards.is_string_non_empty(last_name):
                    return FlextResult.fail("First name and last name required")

                # Clean text using FlextUtilities
                clean_first = FlextUtilities.TextProcessor.clean_text(first_name)
                clean_last = FlextUtilities.TextProcessor.clean_text(last_name)

                if not clean_first or not clean_last:
                    return FlextResult.fail("Invalid names provided")

                # Business rule: username = first initial + last name, lowercase
                username = f"{clean_first[0].lower()}{clean_last.lower()}"

                # Slugify using FlextUtilities (removes invalid characters)
                username = FlextUtilities.TextProcessor.slugify(username)

                if (
                    len(username)
                    < FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH
                ):  # MIN_USERNAME_LENGTH não existe, usar MIN_PASSWORD_LENGTH ou criar constante
                    return FlextResult.fail("Generated username too short")

                return FlextResult.ok(username)

            except Exception as e:
                logger.exception("Username generation failed")
                return FlextResult.fail(f"Username generation error: {e}")

    class GroupManagementService(FlextDomainService[FlextLDAPEntities.Group]):
        """Internal domain service for group management business logic."""

        def __init__(self) -> None:
            super().__init__()
            self._group_spec = FlextLDAPDomain.GroupSpecification()
            self._dn_spec = FlextLDAPDomain.DistinguishedNameSpecification()

        def execute(self) -> FlextResult[FlextLDAPEntities.Group]:
            """Execute method required by FlextDomainService - CORRECTED signature."""
            return FlextResult.ok(
                FlextLDAPEntities.Group(
                    id="default_group",
                    dn="cn=default,dc=example,dc=com",
                    cn="Default Group",
                    description="Default group",
                    modified_at=None,
                ),
            )

        @property
        def dn_spec(self) -> "FlextLDAPDomain.DistinguishedNameSpecification":
            """Access to DN specification for external validation."""
            return self._dn_spec

        def can_add_member(
            self,
            group: FlextLDAPEntities.Group,
            user: FlextLDAPEntities.User,
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
                    active_spec = FlextLDAPDomain.ActiveUserSpecification()
                    if not active_spec.is_satisfied_by(user):
                        return FlextResult.fail(
                            "Only active users can be added to groups",
                        )

                # Business rule: User cannot be added if already a member
                if user.dn in group.members:
                    return FlextResult.fail(
                        "User is already a member of this group",
                    )

                success = True
                return FlextResult.ok(success)

            except Exception as e:
                logger.exception("Group membership check failed")
                return FlextResult.fail(f"Group membership check error: {e}")

        def validate_group_creation(
            self,
            group_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
            """Validate group creation business rules."""
            try:
                # Check required fields
                required_fields = ["cn", "dn"]
                for field in required_fields:
                    if field not in group_data or not group_data[field]:
                        return FlextResult.fail(
                            f"Required field missing: {field}",
                        )

                # Validate DN format
                dn = str(group_data["dn"])
                if not self._dn_spec.is_satisfied_by(dn):
                    return FlextResult.fail(
                        self._dn_spec.get_validation_error(dn),
                    )

                return FlextResult.ok(None)

            except Exception as e:
                logger.exception("Group validation failed")
                return FlextResult.fail(f"Group validation error: {e}")

    class PasswordService(FlextDomainService[str]):
        """Internal domain service for password management business logic."""

        def __init__(self) -> None:
            super().__init__()
            self._password_spec = FlextLDAPDomain.PasswordSpecification()

        def execute(self) -> FlextResult[str]:
            """Execute method required by FlextDomainService - CORRECTED signature."""
            return FlextResult.ok("Password service ready")

        def validate_password_change(
            self,
            current_password: str,
            new_password: str,
        ) -> FlextResult[object]:
            """Validate password change business rules."""
            try:
                # Validate new password strength
                if not self._password_spec.is_satisfied_by(new_password):
                    return FlextResult.fail(
                        self._password_spec.get_validation_error(new_password),
                    )

                # Business rule: New password cannot be the same as current
                if current_password == new_password:
                    return FlextResult.fail(
                        "New password must be different from current",
                    )

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
            if length < FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH:
                return f"Password length must be at least {FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH}"
            if length > FlextLDAPConstants.LdapValidation.MAX_PASSWORD_LENGTH:
                return f"Password length cannot exceed {FlextLDAPConstants.LdapValidation.MAX_PASSWORD_LENGTH}"
            return None

        def _generate_password_with_retries(self, length: int) -> FlextResult[str]:
            """Generate password with retry logic - EXTRACTED METHOD."""
            chars = (
                string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;'\",./<>?"
            )

            # Initial attempt
            password = "".join(secrets.choice(chars) for _ in range(length))
            if self._password_spec.is_satisfied_by(password):
                return FlextResult.ok(password)

            # Retry attempts
            for _ in range(
                3,
            ):  # PASSWORD_GENERATION_MAX_RETRIES não está centralizado, usar valor fixo ou criar constante
                password = "".join(secrets.choice(chars) for _ in range(length))
                if self._password_spec.is_satisfied_by(password):
                    return FlextResult.ok(password)

            return FlextResult.fail("Could not generate secure password")

    # ==========================================================================
    # DOMAIN EVENT FACTORY - ELIMINATES CODE DUPLICATION USING FACTORY PATTERN
    # ==========================================================================

    class _BaseDomainEvent(FlextModels.Value):
        """Base domain event class eliminating duplication using Template Method Pattern.

        Provides common validation and creation methods for all domain events,
        reducing code duplication from 35+ lines per event to single implementation.
        """

        actor: str
        occurred_at: datetime

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Template method for validating domain events using factory pattern."""
            # Get validation rules from subclass
            validation_rules = self._get_validation_rules()
            return FlextLDAPDomain._DomainEventFactory.create_base_validation_rules(
                validation_rules,
            )

        def _get_validation_rules(self) -> FlextTypes.Core.Headers:
            """Template method - subclasses provide their validation rules."""
            error_msg = "Subclasses must implement _get_validation_rules"
            raise NotImplementedError(error_msg)

        @classmethod
        def create_with_factory(cls, **kwargs: object) -> FlextModels.Value:
            """Template method for creating events using factory pattern."""
            return cast(
                "FlextModels.Value",
                FlextLDAPDomain._DomainEventFactory.create_event_base(cls, **kwargs),
            )

    class _DomainEventFactory:
        """Factory Pattern for creating domain events using flext-core patterns.

        Eliminates code duplication by centralizing common event creation logic
        following Factory Pattern and using FlextResult for error handling.
        """

        @staticmethod
        def create_base_validation_rules(
            required_fields: FlextTypes.Core.Headers,
        ) -> FlextResult[None]:
            """Centralized validation logic for all domain events using Railway Pattern."""
            for field_name, field_value in required_fields.items():
                if not field_value:
                    return FlextResult.fail(f"{field_name} cannot be empty")
            return FlextResult.ok(None)

        @staticmethod
        def create_event_base(event_class: type[object], **kwargs: object) -> object:
            """Create event instance with automatic timestamp using Factory Pattern."""
            # Add automatic timestamp if not provided
            if "occurred_at" not in kwargs:
                kwargs["occurred_at"] = datetime.now(UTC)
            return event_class(**kwargs)

        @staticmethod
        def create_typed_event(
            event_class: type[object], **event_kwargs: object
        ) -> object:
            """Template method for creating typed domain events - ELIMINATES ALL create duplication."""
            return FlextLDAPDomain._DomainEventFactory.create_event_base(
                event_class,
                **event_kwargs,
            )

    # ==========================================================================
    # INTERNAL DOMAIN EVENT CLASSES
    # ==========================================================================

    class UserCreatedEvent(_BaseDomainEvent):
        """Internal domain event fired when a user is created - eliminates duplication."""

        user_id: str
        user_dn: str

        def _get_validation_rules(self) -> FlextTypes.Core.Headers:
            """Provide validation rules for user created event."""
            return {
                "User ID": self.user_id,
                "User DN": self.user_dn,
                "Actor": self.actor,
            }

        @classmethod
        def create(
            cls,
            user_id: str,
            user_dn: str,
            created_by: str,
        ) -> "FlextLDAPDomain.UserCreatedEvent":
            """Create user created event using Template Method Pattern - ELIMINATES 13-line duplication."""
            return cast(
                "FlextLDAPDomain.UserCreatedEvent",
                FlextLDAPDomain._DomainEventFactory.create_typed_event(
                    cls,
                    user_id=user_id,
                    user_dn=user_dn,
                    actor=created_by,
                ),
            )

    class UserDeletedEvent(_BaseDomainEvent):
        """Internal domain event fired when a user is deleted - eliminates duplication."""

        user_id: str
        user_dn: str

        def _get_validation_rules(self) -> FlextTypes.Core.Headers:
            """Provide validation rules for user deleted event."""
            return {
                "User ID": self.user_id,
                "User DN": self.user_dn,
            }

        @classmethod
        def create(
            cls,
            user_id: str,
            user_dn: str,
            deleted_by: str,
        ) -> "FlextLDAPDomain.UserDeletedEvent":
            """Create user deleted event using Template Method Pattern - ELIMINATES 13-line duplication."""
            return cast(
                "FlextLDAPDomain.UserDeletedEvent",
                FlextLDAPDomain._DomainEventFactory.create_typed_event(
                    cls,
                    user_id=user_id,
                    user_dn=user_dn,
                    actor=deleted_by,
                ),
            )

    class GroupMemberAddedEvent(_BaseDomainEvent):
        """Internal domain event fired when a member is added to a group - eliminates duplication."""

        group_dn: str
        member_dn: str

        def _get_validation_rules(self) -> FlextTypes.Core.Headers:
            """Provide validation rules for group member added event."""
            return {
                "Group DN": self.group_dn,
                "Member DN": self.member_dn,
            }

        @classmethod
        def create(
            cls,
            group_dn: str,
            member_dn: str,
            added_by: str,
        ) -> "FlextLDAPDomain.GroupMemberAddedEvent":
            """Create group member added event using Template Method Pattern - ELIMINATES 13-line duplication."""
            return cast(
                "FlextLDAPDomain.GroupMemberAddedEvent",
                FlextLDAPDomain._DomainEventFactory.create_typed_event(
                    cls,
                    group_dn=group_dn,
                    member_dn=member_dn,
                    actor=added_by,
                ),
            )

    class PasswordChangedEvent(_BaseDomainEvent):
        """Internal domain event fired when a user's password is changed - eliminates duplication."""

        user_dn: str
        changed_by: str
        is_self_change: bool

        def _get_validation_rules(self) -> FlextTypes.Core.Headers:
            """Provide validation rules for password changed event."""
            return {
                "User DN": self.user_dn,
                "Changed by": self.changed_by,
            }

        @classmethod
        def create(
            cls,
            user_dn: str,
            changed_by: str,
        ) -> "FlextLDAPDomain.PasswordChangedEvent":
            """Create password changed event using Template Method Pattern - ELIMINATES 13-line duplication."""
            return cast(
                "FlextLDAPDomain.PasswordChangedEvent",
                FlextLDAPDomain._DomainEventFactory.create_typed_event(
                    cls,
                    user_dn=user_dn,
                    changed_by=changed_by,
                    actor=changed_by,
                    is_self_change=user_dn == changed_by,
                ),
            )

    # ==========================================================================
    # INTERNAL DOMAIN FACTORY CLASSES
    # ==========================================================================

    class EntityParameterBuilder:
        """Internal helper class to build entity parameters with type safety - REDUCES COMPLEXITY."""

        @staticmethod
        def safe_str(value: object) -> str | None:
            """Safely convert value to string or None - USES FLEXT-CORE."""
            # Cast to supported type for FlextUtilities
            safe_value = (
                value
                if isinstance(value, (str, int, float, bool, type(None)))
                else str(value)
            )
            result = FlextUtilities.TextProcessor.clean_text(str(safe_value))
            return result or None

        @staticmethod
        def safe_list(
            value: object, default: FlextTypes.Core.StringList | None = None
        ) -> FlextTypes.Core.StringList:
            """Safely convert value to list or use default - USES FLEXT-CORE."""
            if FlextUtilities.TypeGuards.is_list_non_empty(value):
                # Use Python standard conversion instead of custom wrapper
                return [str(item) for item in cast("FlextTypes.Core.List", value)]
            return default or []

        @staticmethod
        def safe_dict(value: object) -> FlextTypes.Core.Dict:
            """Safely convert value to dict or empty dict."""
            if isinstance(value, dict):
                typed_dict: FlextTypes.Core.Dict = cast("FlextTypes.Core.Dict", value)
                return dict(typed_dict)
            return {}

        @staticmethod
        def safe_ldap_attributes(value: object) -> LdapAttributeDict:
            """Safely convert value to LdapAttributeDict using Python standard conversion."""
            if not isinstance(value, dict):
                return {}
            # Use Python standard dict comprehension instead of custom converter
            return {
                k: [str(v)] if not isinstance(v, list) else [str(item) for item in v]
                for k, v in value.items()
                if v is not None
            }

    class _BaseEntityBuilder:
        """Base builder using Template Method Pattern - ELIMINATES DUPLICATION between User/Group builders."""

        def __init__(self, params: FlextTypes.Core.Dict, entity_type: str) -> None:
            self.params = params
            self.entity_type = entity_type
            self.builder = FlextLDAPDomain.EntityParameterBuilder()

        def build(self) -> object:
            """Template method for building entities - eliminates duplication."""
            # Step 1: Generate ID using template
            entity_id = self._generate_entity_id()

            # Step 2: Extract common parameters
            base_params = self._extract_base_parameters(entity_id)

            # Step 3: Extract specific parameters (implemented by subclasses)
            specific_params = self._extract_specific_parameters()

            # Step 4: Create entity with merged parameters
            return self._create_entity({**base_params, **specific_params})

        def _generate_entity_id(self) -> str:
            """Generate entity ID with timestamp."""
            return f"{self.entity_type}_{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"

        def _extract_base_parameters(self, entity_id: str) -> FlextTypes.Core.Dict:
            """Extract parameters common to all entities."""
            return {
                "id": entity_id,
                "dn": str(self.params["dn"]),
                "object_classes": self.builder.safe_list(self.params["object_classes"]),
                "attributes": self.builder.safe_ldap_attributes(
                    self.params["attributes"],
                ),
                "modified_at": None,
            }

        def _extract_specific_parameters(self) -> FlextTypes.Core.Dict:
            """Template method - subclasses implement entity-specific parameters."""
            error_msg = "Subclasses must implement _extract_specific_parameters"
            raise NotImplementedError(error_msg)

        def _create_entity(self, all_params: FlextTypes.Core.Dict) -> object:
            """Template method - subclasses implement entity creation."""
            error_msg = "Subclasses must implement _create_entity"
            raise NotImplementedError(error_msg)

    class UserEntityBuilder(_BaseEntityBuilder):
        """User entity builder using Template Method Pattern - ELIMINATES DUPLICATION."""

        def __init__(self, params: FlextTypes.Core.Dict) -> None:
            super().__init__(params, "user")

        def _extract_specific_parameters(self) -> FlextTypes.Core.Dict:
            """Extract user-specific parameters."""
            return {
                "uid": self.builder.safe_str(self.params["uid"]) or "",
                "cn": self.builder.safe_str(self.params["cn"]) or "",
                "sn": self.builder.safe_str(self.params["sn"]) or "",
                "given_name": self.builder.safe_str(self.params["given_name"]),
                "mail": self.builder.safe_str(self.params["mail"]),
                "user_password": self.builder.safe_str(
                    self.params.get("user_password"),
                ),
            }

        def _create_entity(self, all_params: FlextTypes.Core.Dict) -> object:
            """Create FlextLDAPEntities.User entity."""
            return FlextLDAPEntities.User(**all_params)

    class GroupEntityBuilder(_BaseEntityBuilder):
        """Group entity builder using Template Method Pattern - ELIMINATES DUPLICATION."""

        def __init__(self, params: FlextTypes.Core.Dict) -> None:
            super().__init__(params, "group")

        def _extract_specific_parameters(self) -> FlextTypes.Core.Dict:
            """Extract group-specific parameters."""
            return {
                "cn": self.builder.safe_str(self.params["cn"]) or "",
                "description": self.builder.safe_str(self.params["description"]),
                "members": self.builder.safe_list(self.params["members"]),
            }

        def _create_entity(self, all_params: FlextTypes.Core.Dict) -> object:
            """Create FlextLDAPEntities.Group entity."""
            return FlextLDAPEntities.Group(**all_params)

    # ==========================================================================
    # COMMAND PATTERNS - Using FlextCommands for complex operations
    # ==========================================================================

    class CreateUserCommand(FlextCommands.Models.Command):
        """Command for creating users using CQRS pattern."""

        user_data: FlextTypes.Core.Dict

        def validate_command(self) -> FlextResult[None]:
            """Validate user creation data."""
            if not self.user_data.get("uid"):
                return FlextResult.fail("uid is required")
            if not self.user_data.get("cn"):
                return FlextResult.fail("cn is required")
            return FlextResult.ok(None)

    class CreateUserCommandHandler(
        FlextCommands.Handlers.CommandHandler[object, object]
    ):
        """Handler for user creation commands using FlextCommands pattern."""

        def __init__(self) -> None:
            super().__init__()
            self._password_service = FlextLDAPDomain.PasswordService()

        def handle(
            self,
            command: object,
        ) -> FlextResult[object]:
            """Handle user creation command with full validation."""
            cmd = cast("FlextLDAPDomain.CreateUserCommand", command)
            validation_result = cmd.validate_command()
            if not validation_result.is_success:
                return FlextResult.fail(
                    validation_result.error or "Validation failed",
                )

            try:
                # Extract and validate user parameters
                user_params = self._extract_user_parameters(cmd.user_data)

                # Create user entity - use type ignore for dynamic parameter passing
                user = FlextLDAPEntities.User(**user_params)
                self.logger.info(f"User created successfully via command: {user.uid}")
                return FlextResult.ok(user)

            except Exception as e:
                error_msg = f"User creation command failed: {e!s}"
                self.logger.exception(error_msg)
                return FlextResult.fail(error_msg)

        def _extract_user_parameters(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextTypes.Core.Dict:
            """Extract and validate user parameters for entity creation."""
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]] = {
                "extract_uid": lambda data: str(data.get("uid", "")),
                "extract_cn": lambda data: str(data.get("cn", "")),
                "extract_sn": lambda data: str(
                    data.get(
                        "sn",
                        str(data.get("cn", "")).split()[-1] if data.get("cn") else "",
                    ),
                ),
                "extract_mail": lambda data: str(data.get("mail", "")),
                "extract_dn": lambda data: str(
                    data.get(
                        "dn",
                        f"uid={data.get('uid')},ou=users,{data.get('base_dn', 'dc=example,dc=com')}",
                    ),
                ),
                "extract_object_class": lambda data: data.get(
                    "objectClass",
                    ["inetOrgPerson", "organizationalPerson", "person", "top"],
                ),
            }

            return {key: operation(user_data) for key, operation in operations.items()}

    class DomainFactory:
        """Internal factory for creating domain objects with business rule validation.

        Refactored to use FlextCommands pattern for complex operations to reduce
        complexity and follow CQRS architectural patterns.
        """

        def __init__(self) -> None:
            self._user_service = FlextLDAPDomain.UserManagementService()
            self._group_service = FlextLDAPDomain.GroupManagementService()
            self._password_service = FlextLDAPDomain.PasswordService()
            self._create_user_handler = FlextLDAPDomain.CreateUserCommandHandler()

        def create_user_from_data(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLDAPEntities.User]:
            """Create user entity using FlextCommands pattern for reduced complexity."""
            # Use FlextCommands pattern to reduce complexity
            command = FlextLDAPDomain.CreateUserCommand(
                command_type="create_user", user_data=user_data
            )
            return cast(
                "FlextResult[FlextLDAPEntities.User]",
                self._create_user_handler.handle(command),
            )

        def _extract_user_parameters(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextTypes.Core.Dict:
            """Extract and convert user parameters from raw data."""
            given_name = user_data.get("given_name")
            mail = user_data.get("mail")
            object_classes_raw = user_data.get(
                "object_classes",
                ["inetOrgPerson", "person", "top"],
            )
            attributes_raw = user_data.get("attributes", {})

            # Type-safe conversions with explicit casts
            object_classes: FlextTypes.Core.StringList = (
                [str(item) for item in cast("FlextTypes.Core.List", object_classes_raw)]
                if isinstance(object_classes_raw, list)
                else ["inetOrgPerson", "person", "top"]
            )
            attributes: FlextTypes.Core.Dict = (
                cast("FlextTypes.Core.Dict", attributes_raw)
                if isinstance(attributes_raw, dict)
                else {}
            )

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

        def _create_user_entity(self, user_params: FlextTypes.Core.Dict) -> object:
            """Create FlextLDAPEntities.User entity from extracted parameters - REFACTORED."""
            builder = FlextLDAPDomain.UserEntityBuilder(user_params)
            return builder.build()

        def _validate_created_user(self, user: object) -> FlextResult[object]:
            """Validate created user against domain specifications."""
            complete_spec = FlextLDAPDomain.CompleteUserSpecification()
            if not complete_spec.is_satisfied_by(user):
                return FlextResult.fail(
                    complete_spec.get_validation_error(user),
                )
            return FlextResult.ok(user)

        def create_group_from_data(
            self,
            group_data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLDAPEntities.Group]:
            """Create group entity from data with full validation."""
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]] = {
                "validate": self._group_service.validate_group_creation,
                "extract": self._extract_group_parameters,
                "create": self._create_group_entity,
                "final_validate": self._validate_created_group,
            }
            result = self._create_entity_from_data(group_data, "Group", operations)
            if result.is_failure:
                return FlextResult.fail(
                    result.error or "Group creation failed",
                )
            # Use FlextResult.value for modern type-safe access (success verified above)
            created = result.value
            if created is None:
                return FlextResult.fail(
                    "Group creation returned None",
                )
            # Use imported FlextLDAPEntities from top of file
            group_class = FlextLDAPEntities.Group

            if isinstance(created, group_class):
                return FlextResult.ok(created)
            return FlextResult.fail(
                "Group creation returned invalid type",
            )

        def _extract_group_parameters(
            self,
            group_data: FlextTypes.Core.Dict,
        ) -> FlextTypes.Core.Dict:
            """Extract and convert group parameters from raw data."""
            description = group_data.get("description")
            members_raw = group_data.get("members", [])
            object_classes_raw = group_data.get(
                "object_classes",
                ["groupOfNames", "top"],
            )
            attributes_raw = group_data.get("attributes", {})

            # Type-safe conversions with explicit casts
            members: FlextTypes.Core.StringList = (
                [str(item) for item in cast("FlextTypes.Core.List", members_raw)]
                if isinstance(members_raw, list)
                else []
            )
            object_classes: FlextTypes.Core.StringList = (
                [str(item) for item in cast("FlextTypes.Core.List", object_classes_raw)]
                if isinstance(object_classes_raw, list)
                else ["groupOfNames", "top"]
            )
            attributes: FlextTypes.Core.Dict = (
                cast("FlextTypes.Core.Dict", attributes_raw)
                if isinstance(attributes_raw, dict)
                else {}
            )

            return {
                "dn": str(group_data["dn"]),
                "cn": str(group_data.get("cn", "")),
                "description": str(description) if description else None,
                "members": members,
                "object_classes": object_classes,
                "attributes": attributes,
            }

        def _create_group_entity(self, group_params: FlextTypes.Core.Dict) -> object:
            """Create FlextLDAPEntities.Group entity from extracted parameters - REFACTORED."""
            builder = FlextLDAPDomain.GroupEntityBuilder(group_params)
            return builder.build()

        def _validate_created_group(self, group: object) -> FlextResult[object]:
            """Validate created group against domain specifications."""
            group_spec = FlextLDAPDomain.GroupSpecification()
            if not group_spec.is_satisfied_by(group):
                return FlextResult.fail(group_spec.get_validation_error(group))
            return FlextResult.ok(group)

        def _create_entity_from_data(
            self,
            data: FlextTypes.Core.Dict,
            entity_type: str,
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]],
        ) -> FlextResult[object]:
            """Template method for entity creation - ELIMINATES CODE DUPLICATION."""
            try:
                # Execute entity creation pipeline
                return self._execute_entity_creation_pipeline(
                    data,
                    entity_type,
                    operations,
                )
            except Exception as e:
                logger.exception(f"{entity_type} creation failed")
                return FlextResult.fail(f"{entity_type} creation error: {e}")

        def _execute_entity_creation_pipeline(
            self,
            data: FlextTypes.Core.Dict,
            entity_type: str,
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]],
        ) -> FlextResult[object]:
            """Execute entity creation pipeline using Railway Oriented Programming - eliminates multiple returns."""
            # Railway chain: validate -> extract -> create -> final_validate
            return (
                FlextResult[FlextTypes.Core.Dict]
                .ok(data)
                .flat_map(
                    lambda d: self._validate_business_rules(d, operations, entity_type),
                )
                .flat_map(
                    lambda d: self._extract_parameters(d, operations, entity_type),
                )
                .flat_map(
                    lambda params: self._create_entity_from_params(
                        params,
                        operations,
                        entity_type,
                    ),
                )
                .flat_map(
                    lambda entity: self._final_validate_entity(
                        entity,
                        operations,
                        entity_type,
                    ),
                )
            )

        def _validate_business_rules(
            self,
            data: FlextTypes.Core.Dict,
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]],
            entity_type: str,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Step 1: Validate business rules."""
            result = self._execute_operation(
                operations.get("validate"),
                data,
                f"{entity_type} validation",
            )
            return result.flat_map(lambda _: FlextResult[FlextTypes.Core.Dict].ok(data))

        def _extract_parameters(
            self,
            data: FlextTypes.Core.Dict,
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]],
            entity_type: str,
        ) -> FlextResult[object]:
            """Step 2: Extract parameters."""
            return self._execute_operation(
                operations.get("extract"),
                data,
                f"{entity_type} parameter extraction",
            )

        def _create_entity_from_params(
            self,
            params: object,
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]],
            entity_type: str,
        ) -> FlextResult[object]:
            """Step 3: Create entity from parameters."""
            if params is None:
                return FlextResult.fail(
                    f"{entity_type} parameter extraction returned None",
                )
            return self._execute_operation(
                operations.get("create"),
                params,
                f"{entity_type} creation",
            )

        def _final_validate_entity(
            self,
            entity: object,
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]],
            entity_type: str,
        ) -> FlextResult[object]:
            """Step 4: Final domain validation."""
            if entity is None:
                return FlextResult.fail(f"{entity_type} creation returned None")
            return self._execute_operation(
                operations.get("final_validate"),
                entity,
                f"{entity_type} final validation",
            )

        def _execute_operation(
            self,
            operation: Callable[[FlextTypes.Core.Dict], object]
            | Callable[[object], object]
            | None,
            data: object,
            operation_name: str,
        ) -> FlextResult[object]:
            """Execute a single operation with error handling."""
            if operation is None:
                return FlextResult.fail(
                    f"Invalid operation function for {operation_name}",
                )

            try:
                # Handle both dict and general object data
                # Safely cast to expected dict type for operation
                if isinstance(data, dict):
                    result = operation(data)
                # Convert object to dict if possible
                elif hasattr(data, "__dict__"):
                    result = operation(vars(data))
                else:
                    return FlextResult.fail(
                        f"Cannot convert data to dict for operation {operation_name}",
                    )
                # Ensure result is FlextResult format
                if hasattr(result, "is_success") and hasattr(result, "value"):
                    return cast("FlextResult[object]", result)
                # Wrap non-FlextResult returns
                return FlextResult.ok(result)
            except Exception as e:
                return FlextResult.fail(f"{operation_name} failed: {e}")

    # ==========================================================================
    # MAIN CONSOLIDATED INTERFACE
    # ==========================================================================

    def __init__(self) -> None:
        """Initialize all domain handlers with consolidated pattern."""
        # Specifications
        self._user_spec = self.UserSpecification()
        self._group_spec = self.GroupSpecification()
        self._dn_spec = self.DistinguishedNameSpecification()
        self._password_spec = self.PasswordSpecification()
        self._email_spec = self.EmailSpecification()
        self._active_user_spec = self.ActiveUserSpecification()
        self._complete_user_spec = self.CompleteUserSpecification()

        # Services
        self._user_service = self.UserManagementService()
        self._group_service = self.GroupManagementService()
        self._password_service = self.PasswordService()

        # Factory
        self._factory = self.DomainFactory()

    @property
    def specifications(self) -> object:
        """Access domain specifications through consolidated interface."""
        return {
            "user": self._user_spec,
            "group": self._group_spec,
            "dn": self._dn_spec,
            "password": self._password_spec,
            "email": self._email_spec,
            "active_user": self._active_user_spec,
            "complete_user": self._complete_user_spec,
        }

    @property
    def services(self) -> object:
        """Access domain services through consolidated interface."""
        return {
            "user_management": self._user_service,
            "group_management": self._group_service,
            "password": self._password_service,
        }

    @property
    def factory(self) -> DomainFactory:
        """Access domain factory through consolidated interface."""
        return self._factory

    # High-level convenience methods
    def validate_user_creation(
        self,
        user_data: FlextTypes.Core.Dict,
    ) -> FlextResult[object]:
        """Validate user creation (convenience method)."""
        return self._user_service.validate_user_creation(user_data)

    def validate_group_creation(
        self,
        group_data: FlextTypes.Core.Dict,
    ) -> FlextResult[object]:
        """Validate group creation (convenience method)."""
        return self._group_service.validate_group_creation(group_data)

    def create_user_from_data(
        self,
        user_data: FlextTypes.Core.Dict,
    ) -> FlextResult[FlextLDAPEntities.User]:
        """Create user from data (convenience method)."""
        return self._factory.create_user_from_data(user_data)

    def create_group_from_data(
        self,
        group_data: FlextTypes.Core.Dict,
    ) -> FlextResult[FlextLDAPEntities.Group]:
        """Create group from data (convenience method)."""
        return self._factory.create_group_from_data(group_data)

    def generate_secure_password(self, length: int = 12) -> FlextResult[str]:
        """Generate secure password (convenience method)."""
        return self._password_service.generate_secure_password(length)


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Following FLEXT consolidation patterns
# =============================================================================

# Export aliases eliminated - use FlextLDAPDomain.* directly following flext-core pattern

__all__ = [
    "FlextLDAPDomain",
]
