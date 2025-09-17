"""LDAP domain module - Python 3.13 optimized with advanced DDD patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import re
import secrets
import string
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, cast, override

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from flext_core import (
    FlextDispatcher,
    FlextDomainService,
    FlextHandlers,
    FlextLogger,
    FlextMixins,
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes

# Advanced type definitions for domain
type DomainEntity = FlextLdapModels.User | FlextLdapModels.Group | FlextLdapModels.Entry
type ValidationResult = FlextResult[None]
type DomainEvent = dict[str, object]


class FlextLdapDomain(FlextMixins.Loggable):
    """LDAP domain functionality using FlextMixins.Loggable."""

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
            """Initialize LDAP user specification with default values."""
            super().__init__(
                name=FlextLdapConstants.DefaultValues.VALID_LDAP_USER_NAME,
                description=FlextLdapConstants.DefaultValues.VALID_LDAP_USER_DESCRIPTION,
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check using Python 3.13 structural pattern matching."""
            # Use pattern matching for attribute validation
            match candidate:
                case obj if (
                    hasattr(obj, "uid") and hasattr(obj, "dn") and hasattr(obj, "cn")
                ):
                    return self._validate_user_attributes(obj)
                case _:
                    return False

        def _validate_user_attributes(self, user: object) -> bool:
            """Validate user attributes using Python 3.13 patterns."""
            uid = getattr(user, "uid", None)
            dn = getattr(user, "dn", None)
            cn = getattr(user, "cn", None)
            object_classes = getattr(user, "object_classes", [])

            # Use pattern matching for validation logic
            match (uid, dn, cn):
                case (str() as u, str() as d, str() as c) if u and d and c:
                    return self._validate_object_classes(object_classes)
                case _:
                    return False

        def _validate_object_classes(self, object_classes: object) -> bool:
            """Validate object classes using pattern matching."""
            required_classes = [
                FlextLdapConstants.ObjectClasses.PERSON,
                FlextLdapConstants.ObjectClasses.TOP,
            ]

            match object_classes:
                case list() as classes:
                    return all(cls in classes for cls in required_classes)
                case _:
                    return False

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
            """Initialize LDAP group specification with default values."""
            super().__init__(
                name="ValidLdapGroup",
                description="Validates LDAP group entity business rules",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check using Python 3.13 structural pattern matching."""
            match candidate:
                case obj if hasattr(obj, "cn") and hasattr(obj, "dn"):
                    return self._validate_group_attributes(obj)
                case _:
                    return False

        def _validate_group_attributes(self, group: object) -> bool:
            """Validate group attributes using Python 3.13 patterns."""
            object_classes = getattr(group, "object_classes", [])
            required_classes = [
                FlextLdapConstants.ObjectClasses.GROUP_OF_NAMES,
                FlextLdapConstants.ObjectClasses.TOP,
            ]

            match object_classes:
                case list() as classes:
                    return all(cls in classes for cls in required_classes)
                case _:
                    return False

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
            """Initialize distinguished name specification with default values."""
            super().__init__(
                name="ValidDistinguishedName",
                description="Validates RFC 4514 compliant Distinguished Names",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check using Python 3.13 pattern matching and enhanced validation."""
            match candidate:
                case str() as dn_str:
                    return self._validate_dn_string(dn_str)
                case _:
                    return False

        def _validate_dn_string(self, dn_str: str) -> bool:
            """Validate DN string with length and pattern checks."""
            match len(dn_str):
                case length if (
                    length > FlextLdapConstants.LdapValidation.MAX_FILTER_LENGTH
                ):
                    return False
                case length if length == 0:
                    return False
                case _:
                    return bool(self.DN_PATTERN.match(dn_str))

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
            """Initialize password specification with default values."""
            super().__init__(
                name="SecurePassword",
                description="Validates password strength according to security policy",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check using Python 3.13 pattern matching for password validation."""
            match candidate:
                case str() as password:
                    return self._validate_password_requirements(password)
                case _:
                    return False

        def _validate_password_requirements(self, password: str) -> bool:
            """Validate password using pattern matching for length and complexity."""
            # Use pattern matching for length validation
            match len(password):
                case length if (
                    length < FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH
                ):
                    return False
                case length if (
                    length > FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH
                ):
                    return False
                case _:
                    return self._check_password_complexity(password)

        def _check_password_complexity(self, password: str) -> bool:
            """Check password complexity using enhanced patterns."""
            match FlextLdapConstants.LdapValidation.REQUIRE_PASSWORD_COMPLEXITY:
                case False:
                    return True
                case True:
                    return self._validate_complexity_rules(password)

        def _validate_complexity_rules(self, password: str) -> bool:
            """Validate complexity rules using compiled patterns."""
            # Use compiled patterns for better performance
            patterns = {
                "upper": re.compile(r"[A-Z]"),
                "lower": re.compile(r"[a-z]"),
                "digit": re.compile(r"[0-9]"),
                "special": re.compile(r'[!@#$%^&*(),.?":{}|<>]'),
            }

            return all(pattern.search(password) for pattern in patterns.values())

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get detailed password validation error."""
            if not isinstance(candidate, str):
                return "Password must be a string"
            if len(candidate) < FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH:
                return f"Password must be at least {FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH} characters"
            if len(candidate) > FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH:
                return f"Password cannot exceed {FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH} characters"
            return "Password does not meet complexity requirements"

    class ActiveUserSpecification(DomainSpecification):
        """Internal specification for active user account validation."""

        def __init__(self) -> None:
            """Initialize active user specification with default values."""
            super().__init__(
                name="ActiveUser",
                description="Validates that user account is active and not disabled",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check using Python 3.13 pattern matching for status validation."""
            match candidate:
                case obj if hasattr(obj, "status"):
                    return self._validate_user_status(obj)
                case _:
                    return False

        def _validate_user_status(self, user: object) -> bool:
            """Validate user status using pattern matching."""
            status = getattr(user, "status", None)

            match status:
                case None:
                    return False
                case obj if hasattr(obj, "value"):
                    return str(obj.value) == "active"
                case str() as status_str:
                    return status_str == "active"
                case _:
                    return str(status) == "active"

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get user status validation error."""
            if not hasattr(candidate, "status"):
                return "User must have a status field"
            status = getattr(candidate, "status", None)
            return f"User account is not active: {status}"

    class EmailSpecification(DomainSpecification):
        """Email validation specification using FlextModels.EmailAddress."""

        def __init__(self) -> None:
            """Initialize email specification using FlextModels validation."""
            super().__init__(
                name="ValidEmail",
                description="Validates email address format using FlextModels",
            )

        @override
        def is_satisfied_by(self, candidate: object) -> bool:
            """Check email validation using FlextModels.EmailAddress."""
            match candidate:
                case str() as email_str if email_str.strip():
                    email_result = FlextModels.EmailAddress.create(email_str.strip())
                    return email_result.is_success
                case _:
                    return False

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get email validation error using FlextModels."""
            if not isinstance(candidate, str):
                return "Email must be a string"

            email_result = FlextModels.EmailAddress.create(candidate)
            if email_result.is_failure:
                return f"Invalid email format: {email_result.error}"

            return f"Invalid email format: {candidate!r}"

    class CompleteUserSpecification(DomainSpecification):
        """Internal composite specification for complete user validation."""

        def __init__(self) -> None:
            """Initialize complete user specification with default values."""
            super().__init__(
                name="CompleteUser",
                description="Validates complete user entity with all business rules",
            )
            self._user_spec = FlextLdapDomain.UserSpecification()
            self._dn_spec = FlextLdapDomain.DistinguishedNameSpecification()
            self._active_spec = FlextLdapDomain.ActiveUserSpecification()

        @property
        def dn_spec(self) -> "FlextLdapDomain.DistinguishedNameSpecification":
            """Access to DN specification for external validation."""
            return self._dn_spec

        @property
        def active_spec(self) -> "FlextLdapDomain.ActiveUserSpecification":
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

    class UserManagementService(FlextDomainService[FlextLdapModels.User]):
        """Internal domain service for user management business logic."""

        def __init__(self) -> None:
            """Initialize user management service with specifications."""
            super().__init__()
            self._user_spec = FlextLdapDomain.CompleteUserSpecification()
            self._password_spec = FlextLdapDomain.PasswordSpecification()
            self._email_spec = FlextLdapDomain.EmailSpecification()

        def execute(self) -> FlextResult[FlextLdapModels.User]:
            """Execute method required by FlextDomainService - CORRECTED signature."""
            return FlextResult.ok(
                FlextLdapModels.User(
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
            """Validate user creation business rules - to reduce returns."""
            try:
                # Perform all validations in sequence
                return self._perform_all_user_validations(user_data)
            except Exception as e:
                self.log_error("User validation failed")
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
                    return FlextResult[object].fail(f"Required field missing: {field}")
            return FlextResult[object].ok(None)

        def _validate_dn_field(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
            """Validate DN field format."""
            dn = str(user_data["dn"])
            if not self._user_spec.dn_spec.is_satisfied_by(dn):
                return FlextResult[object].fail(
                    self._user_spec.dn_spec.get_validation_error(dn),
                )
            return FlextResult[object].ok(None)

        def _validate_email_field(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[object]:
            """Validate email field using FlextModels - SOURCE OF TRUTH."""
            if user_data.get("mail"):
                email = str(user_data["mail"])
                validation_result = FlextModels.create_validated_email(email)
                if not validation_result.is_success:
                    return FlextResult[object].fail(
                        validation_result.error or "Email validation failed",
                    )
            return FlextResult[object].ok(None)

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
                    return FlextResult[object].fail(
                        self._password_spec.get_validation_error(password),
                    )
            return FlextResult[object].ok(None)

        def can_delete_user(
            self,
            user: FlextLdapModels.User,
            requesting_user: FlextLdapModels.User,
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
                self.log_error("User deletion check failed")
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
                    < FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH
                ):  # MIN_USERNAME_LENGTH não existe, usar MIN_PASSWORD_LENGTH ou criar constante
                    return FlextResult.fail("Generated username too short")

                return FlextResult.ok(username)

            except Exception as e:
                self.log_error("Username generation failed")
                return FlextResult.fail(f"Username generation error: {e}")

    class GroupManagementService(FlextDomainService[FlextLdapModels.Group]):
        """Internal domain service for group management business logic."""

        def __init__(self) -> None:
            """Initialize group management service with specifications."""
            super().__init__()
            self._group_spec = FlextLdapDomain.GroupSpecification()
            self._dn_spec = FlextLdapDomain.DistinguishedNameSpecification()

        def execute(self) -> FlextResult[FlextLdapModels.Group]:
            """Execute method required by FlextDomainService - CORRECTED signature."""
            return FlextResult.ok(
                FlextLdapModels.Group(
                    id="default_group",
                    dn="cn=default,dc=example,dc=com",
                    cn="Default Group",
                    description="Default group",
                    modified_at=None,
                ),
            )

        @property
        def dn_spec(self) -> "FlextLdapDomain.DistinguishedNameSpecification":
            """Access to DN specification for external validation."""
            return self._dn_spec

        def can_add_member(
            self,
            group: FlextLdapModels.Group,
            user: FlextLdapModels.User,
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
                    active_spec = FlextLdapDomain.ActiveUserSpecification()
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
                self.log_error("Group membership check failed")
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
                        return FlextResult[object].fail(
                            f"Required field missing: {field}",
                        )

                # Validate DN format
                dn = str(group_data["dn"])
                if not self._dn_spec.is_satisfied_by(dn):
                    return FlextResult[object].fail(
                        self._dn_spec.get_validation_error(dn),
                    )

                return FlextResult[object].ok(None)

            except Exception as e:
                self.log_error("Group validation failed")
                return FlextResult[object].fail(f"Group validation error: {e}")

    class PasswordService(FlextDomainService[str]):
        """Internal domain service for password management business logic."""

        def __init__(self) -> None:
            """Initialize password management service with specifications."""
            super().__init__()
            self._password_spec = FlextLdapDomain.PasswordSpecification()

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
                    return FlextResult[object].fail(
                        self._password_spec.get_validation_error(new_password),
                    )

                # Business rule: New password cannot be the same as current
                if current_password == new_password:
                    return FlextResult[object].fail(
                        "New password must be different from current",
                    )

                return FlextResult[object].ok(None)

            except Exception as e:
                self.log_error("Password validation failed")
                return FlextResult[object].fail(f"Password validation error: {e}")

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
                self.log_error("Password generation failed")
                return FlextResult.fail(f"Password generation error: {e}")

        def _validate_password_length(self, length: int) -> str | None:
            """Validate password length parameters - EXTRACTED METHOD."""
            if length < FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH:
                return f"Password length must be at least {FlextLdapConstants.LdapValidation.MIN_PASSWORD_LENGTH}"
            if length > FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH:
                return f"Password length cannot exceed {FlextLdapConstants.LdapValidation.MAX_PASSWORD_LENGTH}"
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

    class _BaseDomainEvent(BaseModel):
        """Base domain event class using Pydantic v2 advanced patterns.

        Enhanced with Python 3.13 type safety and Pydantic v2 ConfigDict.
        """

        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            validate_assignment=True,
            str_strip_whitespace=True,
            use_enum_values=True,
        )

        actor: str = Field(
            ...,
            description="Actor who triggered this domain event",
            min_length=1,
            max_length=255,
        )
        occurred_at: datetime = Field(
            default_factory=datetime.now,
            description="When the domain event occurred using FlextUtilities SOURCE OF TRUTH",
        )

        @computed_field
        def event_id(self) -> str:
            """Generate unique event identifier using FlextUtilities SOURCE OF TRUTH - ELIMINATE timestamp duplication."""
            # Use FlextUtilities instead of local timestamp logic - SOLID compliance
            return FlextUtilities.Generators.generate_entity_id()

        @field_validator("actor")
        @classmethod
        def validate_actor_format(cls, v: str) -> str:
            """Validate actor follows proper format."""
            if not v.strip():
                msg = "Actor cannot be empty or whitespace"
                raise ValueError(msg)
            return v.strip()

    # Removed _DomainEventFactory - using FlextModels.Event directly from flext-core

    # ==========================================================================
    # INTERNAL DOMAIN EVENT CLASSES
    # ==========================================================================

    class UserCreatedEvent(_BaseDomainEvent):
        """Internal domain event fired when a user is created - uses flext-core patterns."""

        user_id: str
        user_dn: str

        @classmethod
        def create(
            cls,
            user_id: str,
            user_dn: str,
            created_by: str,
        ) -> "FlextLdapDomain.UserCreatedEvent":
            """Create user created event using FlextModels.Event patterns."""
            return cls(
                user_id=user_id,
                user_dn=user_dn,
                actor=created_by,
                occurred_at=datetime.now(UTC),
            )

    class UserDeletedEvent(_BaseDomainEvent):
        """Internal domain event fired when a user is deleted - uses flext-core patterns."""

        user_id: str
        user_dn: str

        @classmethod
        def create(
            cls,
            user_id: str,
            user_dn: str,
            deleted_by: str,
        ) -> "FlextLdapDomain.UserDeletedEvent":
            """Create user deleted event using FlextModels.Event patterns."""
            return cls(
                user_id=user_id,
                user_dn=user_dn,
                actor=deleted_by,
                occurred_at=datetime.now(UTC),
            )

    class GroupMemberAddedEvent(_BaseDomainEvent):
        """Internal domain event fired when a member is added to a group - uses flext-core patterns."""

        group_dn: str
        member_dn: str

        @classmethod
        def create(
            cls,
            group_dn: str,
            member_dn: str,
            added_by: str,
        ) -> "FlextLdapDomain.GroupMemberAddedEvent":
            """Create group member added event using FlextModels.Event patterns."""
            return cls(
                group_dn=group_dn,
                member_dn=member_dn,
                actor=added_by,
                occurred_at=datetime.now(UTC),
            )

    class PasswordChangedEvent(_BaseDomainEvent):
        """Internal domain event fired when a user's password is changed - uses flext-core patterns."""

        user_dn: str
        changed_by: str
        is_self_change: bool

        @classmethod
        def create(
            cls,
            user_dn: str,
            changed_by: str,
        ) -> "FlextLdapDomain.PasswordChangedEvent":
            """Create password changed event using FlextModels.Event patterns."""
            return cls(
                user_dn=user_dn,
                changed_by=changed_by,
                actor=changed_by,
                is_self_change=user_dn == changed_by,
                occurred_at=datetime.now(UTC),
            )

    # ==========================================================================
    # INTERNAL DOMAIN FACTORY CLASSES
    # ==========================================================================

    @dataclass(frozen=True, slots=True)
    class EntityParameterBuilder:
        """Internal helper class using Python 3.13 dataclass with slots for performance."""

        # Use type aliases for better readability
        _safe_types: ClassVar[tuple[type, ...]] = (str, int, float, bool, type(None))

        @staticmethod
        def safe_str(value: object) -> str | None:
            """Safely convert value using Python 3.13 structural pattern matching."""
            match value:
                case None:
                    return None
                case str() as text if text.strip():
                    result = FlextUtilities.TextProcessor.clean_text(text)
                    return result or None
                case int() | float() | bool() as primitive:
                    result = FlextUtilities.TextProcessor.clean_text(str(primitive))
                    return result or None
                case _:
                    result = FlextUtilities.TextProcessor.clean_text(str(value))
                    return result or None

        @staticmethod
        def safe_list(value: object, default: list[str] | None = None) -> list[str]:
            """Safely convert using Python 3.13 structural pattern matching."""
            match value:
                case list() as items if items:
                    # Validate all items are convertible to string
                    return [str(item) for item in items if item is not None]
                case tuple() as items if items:
                    return [str(item) for item in items if item is not None]
                case str() as single_item if single_item:
                    return [single_item]
                case _:
                    return default or []

        @staticmethod
        def safe_dict(value: object) -> FlextTypes.Core.Dict:
            """Safely convert using Python 3.13 pattern matching."""
            match value:
                case dict() as dict_value:
                    # Filter out None values and ensure string keys
                    return {str(k): v for k, v in dict_value.items() if v is not None}
                case _:
                    return {}

        @staticmethod
        def safe_ldap_attributes(value: object) -> FlextLdapTypes.Entry.AttributeDict:
            """Convert to LDAP attributes using Python 3.13 pattern matching."""
            match value:
                case dict() as attrs:
                    result: FlextLdapTypes.Entry.AttributeDict = {}
                    for k, v in attrs.items():
                        match v:
                            case None:
                                continue
                            case list() as list_val:
                                result[str(k)] = [
                                    str(item) for item in list_val if item is not None
                                ]
                            case str() | int() | float() | bool() as single_val:
                                result[str(k)] = [str(single_val)]
                            case _:
                                result[str(k)] = [str(v)]
                    return result
                case _:
                    return {}

    class _BaseEntityBuilder:
        """Base builder using Template Method Pattern - ELIMINATES DUPLICATION between User/Group builders."""

        def __init__(self, params: FlextTypes.Core.Dict, entity_type: str) -> None:
            """Initialize the instance."""
            self.params = params
            self.entity_type = entity_type
            self.builder = FlextLdapDomain.EntityParameterBuilder()

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
            """Generate entity ID using FlextUtilities SOURCE OF TRUTH - ELIMINATE local duplication."""
            return FlextUtilities.Generators.generate_entity_id()

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
            """Initialize user entity builder with parameters."""
            super().__init__(params, "user")

        def _extract_specific_parameters(self) -> FlextTypes.Core.Dict:
            """Extract user parameters using Python 3.13 pattern matching."""
            match self.params:
                case {"uid": uid, "cn": cn, "sn": sn, **optional}:
                    return {
                        "uid": self.builder.safe_str(uid) or "",
                        "cn": self.builder.safe_str(cn) or "",
                        "sn": self.builder.safe_str(sn) or "",
                        "given_name": self.builder.safe_str(optional.get("given_name")),
                        "mail": self.builder.safe_str(optional.get("mail")),
                        "user_password": self.builder.safe_str(
                            optional.get("user_password"),
                        ),
                    }
                case _:
                    # Fallback for partial data
                    return {
                        "uid": self.builder.safe_str(self.params.get("uid")) or "",
                        "cn": self.builder.safe_str(self.params.get("cn")) or "",
                        "sn": self.builder.safe_str(self.params.get("sn")) or "",
                        "given_name": self.builder.safe_str(
                            self.params.get("given_name"),
                        ),
                        "mail": self.builder.safe_str(self.params.get("mail")),
                        "user_password": self.builder.safe_str(
                            self.params.get("user_password"),
                        ),
                    }

        def _create_entity(
            self,
            all_params: FlextTypes.Core.Dict,
        ) -> FlextLdapModels.User:
            """Create FlextLdapModels.User entity."""
            return FlextLdapModels.User(
                id=str(all_params.get("id", all_params.get("dn", ""))),
                dn=str(all_params["dn"]),
                uid=str(all_params["uid"]),
                cn=str(all_params["cn"]) if all_params.get("cn") else None,
                sn=str(all_params["sn"]) if all_params.get("sn") else None,
                given_name=str(all_params["given_name"])
                if all_params.get("given_name")
                else None,
                mail=str(all_params["mail"]) if all_params.get("mail") else None,
                user_password=str(all_params["user_password"])
                if all_params.get("user_password")
                else None,
                object_classes=[
                    str(x)
                    for x in cast("list[object]", all_params.get("object_classes", []))
                ],
                attributes={
                    str(k): [str(item) for item in v]
                    if isinstance(v, list)
                    else [str(v)]
                    for k, v in cast(
                        "FlextLdapTypes.Entry.AttributeDict",
                        all_params.get("attributes", {}),
                    ).items()
                },
                status=str(all_params.get("status", "active")),
                modified_at=str(all_params.get("modified_at"))
                if all_params.get("modified_at")
                else None,
            )

    class GroupEntityBuilder(_BaseEntityBuilder):
        """Group entity builder using Template Method Pattern - ELIMINATES DUPLICATION."""

        def __init__(self, params: FlextTypes.Core.Dict) -> None:
            """Initialize group entity builder with parameters."""
            super().__init__(params, "group")

        def _extract_specific_parameters(self) -> FlextTypes.Core.Dict:
            """Extract group parameters using Python 3.13 pattern matching."""
            match self.params:
                case {"cn": cn, **optional}:
                    return {
                        "cn": self.builder.safe_str(cn) or "",
                        "description": self.builder.safe_str(
                            optional.get("description"),
                        ),
                        "members": self.builder.safe_list(optional.get("members", [])),
                    }
                case _:
                    # Fallback for partial data
                    return {
                        "cn": self.builder.safe_str(self.params.get("cn")) or "",
                        "description": self.builder.safe_str(
                            self.params.get("description"),
                        ),
                        "members": self.builder.safe_list(
                            self.params.get("members", []),
                        ),
                    }

        def _create_entity(
            self,
            all_params: FlextTypes.Core.Dict,
        ) -> FlextLdapModels.Group:
            """Create FlextLdapModels.Group entity."""
            return FlextLdapModels.Group(
                id=str(all_params.get("id", all_params.get("dn", ""))),
                dn=str(all_params["dn"]),
                cn=str(all_params["cn"]),
                description=str(all_params["description"])
                if all_params.get("description")
                else None,
                members=[
                    str(x) for x in cast("list[object]", all_params.get("members", []))
                ],
                object_classes=[
                    str(x)
                    for x in cast("list[object]", all_params.get("object_classes", []))
                ],
                attributes={
                    str(k): [str(item) for item in v]
                    if isinstance(v, list)
                    else [str(v)]
                    for k, v in cast(
                        "FlextLdapTypes.Entry.AttributeDict",
                        all_params.get("attributes", {}),
                    ).items()
                },
                status=str(all_params.get("status", "active")),
                modified_at=str(all_params.get("modified_at"))
                if all_params.get("modified_at")
                else None,
            )

    # ==========================================================================
    # COMMAND PATTERNS - Using Flext CQRS for complex operations
    # ==========================================================================

    class CreateUserCommand(FlextModels.Command):
        """Command for creating users using CQRS pattern."""

        user_data: FlextTypes.Core.Dict

        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            validate_assignment=True,
        )

        def validate_command(self) -> FlextResult[bool]:
            """Validate user creation data using Python 3.13 match expression."""
            # Use structural pattern matching for validation
            match self.user_data:
                case {"uid": str(uid), "cn": str(cn)} if uid.strip() and cn.strip():
                    return FlextResult[bool].ok(data=True)
                case data if not data.get("uid"):
                    return FlextResult[bool].fail("uid is required")
                case data if not data.get("cn"):
                    return FlextResult[bool].fail("cn is required")
                case data if (
                    isinstance(data.get("uid"), str) and not str(data["uid"]).strip()
                ):
                    return FlextResult[bool].fail("uid cannot be empty or whitespace")
                case data if (
                    isinstance(data.get("cn"), str) and not str(data["cn"]).strip()
                ):
                    return FlextResult[bool].fail("cn cannot be empty or whitespace")
                case _:
                    return FlextResult[bool].fail("Invalid user data structure")

    class UserCreationDomainService(FlextMixins.Loggable):
        """Domain service for user creation business logic - SOLID compliant.

        Follows Single Responsibility: Only user creation business rules
        Follows Dependency Inversion: No infrastructure dependencies
        """

        def __init__(self) -> None:
            """Initialize domain service."""
            super().__init__()
            self._password_service = FlextLdapDomain.PasswordService()

        def validate_user_creation_business_rules(
            self, command: "FlextLdapDomain.CreateUserCommand"
        ) -> FlextResult[None]:
            """Validate business rules for user creation - pure domain logic."""
            validation_result = command.validate_command()
            if validation_result.is_success:
                return FlextResult.ok(None)
            return FlextResult.fail(validation_result.error or "Validation failed")

        def extract_user_parameters(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Extract user parameters - domain business logic only."""
            try:
                # Use structural pattern matching for cleaner parameter extraction
                match user_data:
                    case {"uid": uid, "cn": cn, "dn": dn, **rest} if uid and cn and dn:
                        params = self._build_complete_user_params(
                            str(uid),
                            str(cn),
                            str(dn),
                            rest,
                        )
                    case {"uid": uid, "cn": cn, **rest} if uid and cn:
                        # Generate DN if missing - business rule
                        base_dn = rest.get("base_dn", "dc=example,dc=com")
                        dn = f"uid={uid},ou=users,{base_dn}"
                        params = self._build_complete_user_params(
                            str(uid),
                            str(cn),
                            dn,
                            rest,
                        )
                    case {"uid": uid, **rest} if uid:
                        # Generate minimal parameters - business rule
                        cn = rest.get("cn", uid)
                        base_dn = rest.get("base_dn", "dc=example,dc=com")
                        dn = f"uid={uid},ou=users,{base_dn}"
                        params = self._build_complete_user_params(
                            str(uid),
                            str(cn),
                            dn,
                            rest,
                        )
                    case _:
                        params = self._extract_with_defaults(user_data)

                return FlextResult.ok(params)
            except Exception as e:
                return FlextResult.fail(f"Parameter extraction failed: {e}")

        def create_user_entity(
            self, user_params: FlextTypes.Core.Dict
        ) -> FlextResult[FlextLdapModels.User]:
            """Create user entity - pure domain logic."""
            try:
                # Map extracted parameters to User model fields
                mapped_params = {
                    "id": user_params.get("extract_uid", user_params.get("uid", "")),
                    "dn": user_params.get("extract_dn", user_params.get("dn", "")),
                    "uid": user_params.get("extract_uid", user_params.get("uid")),
                    "cn": user_params.get("extract_cn", user_params.get("cn")),
                    "sn": user_params.get("extract_sn", user_params.get("sn")),
                    "mail": user_params.get("extract_mail", user_params.get("mail")),
                    "object_classes": user_params.get(
                        "extract_object_class", user_params.get("objectClass", [])
                    ),
                }
                # Remove None values
                mapped_params = {
                    k: v for k, v in mapped_params.items() if v is not None
                }

                user = FlextLdapModels.User.model_validate(mapped_params)
                return FlextResult.ok(user)
            except Exception as e:
                return FlextResult.fail(f"User entity creation failed: {e}")

        def _build_complete_user_params(
            self,
            uid: str,
            cn: str,
            dn: str,
            additional_data: FlextTypes.Core.Dict,
        ) -> FlextTypes.Core.Dict:
            """Build complete user parameters with business defaults."""
            sn = additional_data.get("sn", cn.rsplit(maxsplit=1)[-1] if cn else "User")
            return {
                "extract_uid": uid,
                "extract_cn": cn,
                "extract_sn": sn,
                "extract_mail": str(additional_data.get("mail", "")),
                "extract_dn": dn,
                "extract_object_class": additional_data.get(
                    "objectClass",
                    ["inetOrgPerson", "organizationalPerson", "person", "top"],
                ),
            }

        def _extract_with_defaults(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextTypes.Core.Dict:
            """Extract parameters with safe business defaults."""
            return {
                "extract_uid": str(user_data.get("uid", "")),
                "extract_cn": str(user_data.get("cn", "")),
                "extract_sn": str(user_data.get("sn", "")),
                "extract_mail": str(user_data.get("mail", "")),
                "extract_dn": str(user_data.get("dn", "")),
                "extract_object_class": user_data.get(
                    "objectClass",
                    ["inetOrgPerson", "organizationalPerson", "person", "top"],
                ),
            }

    class CreateUserCommandHandler(
        FlextHandlers["FlextLdapDomain.CreateUserCommand", FlextLdapModels.User]
    ):
        """Command handler for user creation using modern FlextHandlers pattern."""

        # Inherit DEFAULT_MODE from parent class

        def __init__(self) -> None:
            """Initialize command handler with FlextHandlers base."""
            super().__init__(handler_mode="command")
            self._user_creation_service = FlextLdapDomain.UserCreationDomainService()

        def handle(
            self,
            message: "FlextLdapDomain.CreateUserCommand",
        ) -> FlextResult[FlextLdapModels.User]:
            """Handle user creation command using domain service."""
            # Validate command business rules
            validation_result = (
                self._user_creation_service.validate_user_creation_business_rules(
                    message
                )
            )
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.User].fail(
                    validation_result.error or "Command validation failed"
                )

            # Extract user parameters from command
            params_result = self._user_creation_service.extract_user_parameters(
                message.user_data
            )
            if params_result.is_failure:
                return FlextResult[FlextLdapModels.User].fail(
                    params_result.error or "Parameter extraction failed"
                )

            # Create user entity from parameters
            creation_result = self._user_creation_service.create_user_entity(
                params_result.unwrap()
            )
            if creation_result.is_failure:
                return FlextResult[FlextLdapModels.User].fail(
                    creation_result.error or "User creation failed"
                )

            return FlextResult[FlextLdapModels.User].ok(creation_result.unwrap())

    class DomainFactory(FlextMixins.Loggable):
        """Internal factory for creating domain objects with business rule validation.

        Refactored to use Flext CQRS pattern for complex operations to reduce
        complexity and follow CQRS architectural patterns.
        """

        def __init__(self) -> None:
            """Initialize factory with domain services - SOLID compliant."""
            super().__init__()
            self._user_service = FlextLdapDomain.UserManagementService()
            self._group_service = FlextLdapDomain.GroupManagementService()
            self._password_service = FlextLdapDomain.PasswordService()
            # Use proper command handler with FlextHandlers
            self._create_user_handler = FlextLdapDomain.CreateUserCommandHandler()
            self._logger = FlextLogger(__name__)
            # Temporarily disable dispatcher due to command/handler matching issues
            # This will be re-enabled once the dispatcher integration is fixed
            self._dispatcher: FlextDispatcher | None = None
            self._logger.debug(
                "dispatcher_temporarily_disabled",
                factory=self.__class__.__name__,
                reason="command_handler_type_matching_issues",
            )

        def create_user_from_data(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLdapModels.User]:
            """Create user entity using FlextHandlers command pattern."""
            # Create command for CQRS pattern
            command = FlextLdapDomain.CreateUserCommand(
                command_type="create_user",
                user_data=user_data,
            )

            if self._dispatcher is not None:
                try:
                    dispatch_result = self._dispatcher.dispatch(command)
                    if dispatch_result.is_success:
                        handler_output = dispatch_result.unwrap()
                        if isinstance(handler_output, FlextResult):
                            return cast(
                                "FlextResult[FlextLdapModels.User]",
                                handler_output,
                            )
                        if isinstance(handler_output, FlextLdapModels.User):
                            return FlextResult[FlextLdapModels.User].ok(handler_output)
                        self._logger.error(
                            "dispatcher_unexpected_payload",
                            payload_type=handler_output.__class__.__name__,
                        )
                    else:
                        self._logger.error(
                            "dispatcher_command_failed",
                            error=dispatch_result.error,
                        )
                except Exception as exc:  # pragma: no cover - defensive logging
                    self._logger.exception(
                        "dispatcher_execution_failed",
                        error=str(exc),
                    )

            # Fallback to direct handler execution
            return self._create_user_handler.handle(command)

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

            object_classes: list[str] = (
                [str(item) for item in cast("list[str]", object_classes_raw)]
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
            """Create User entity using Python 3.13 pattern matching for validation."""
            # Validate required parameters using structural pattern matching
            match user_params:
                case {"dn": str() as dn, "uid": str() as uid} if dn and uid:
                    builder = FlextLdapDomain.UserEntityBuilder(user_params)
                    return builder.build()
                case _:
                    msg = "User parameters missing required fields (dn, uid)"
                    raise ValueError(msg)

        def _validate_created_user(self, user: object) -> FlextResult[object]:
            """Validate created user against domain specifications."""
            complete_spec = FlextLdapDomain.CompleteUserSpecification()
            if not complete_spec.is_satisfied_by(user):
                return FlextResult[object].fail(
                    complete_spec.get_validation_error(user),
                )
            return FlextResult[object].ok(user)

        def create_group_from_data(
            self,
            group_data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLdapModels.Group]:
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
            # Use imported FlextLdapModels from top of file
            group_class = FlextLdapModels.Group

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

            members: list[str] = (
                [str(item) for item in cast("list[str]", members_raw)]
                if isinstance(members_raw, list)
                else []
            )
            object_classes: list[str] = (
                [str(item) for item in cast("list[str]", object_classes_raw)]
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
            """Create Group entity using Python 3.13 pattern matching for validation."""
            # Validate required parameters using structural pattern matching
            match group_params:
                case {"dn": str() as dn, "cn": str() as cn} if dn and cn:
                    builder = FlextLdapDomain.GroupEntityBuilder(group_params)
                    return builder.build()
                case _:
                    msg = "Group parameters missing required fields (dn, cn)"
                    raise ValueError(msg)

        def _validate_created_group(self, group: object) -> FlextResult[object]:
            """Validate created group against domain specifications."""
            group_spec = FlextLdapDomain.GroupSpecification()
            if not group_spec.is_satisfied_by(group):
                return FlextResult[object].fail(group_spec.get_validation_error(group))
            return FlextResult[object].ok(group)

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
                self.log_error(f"{entity_type} creation failed")
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
            """Step 1: Validate business rules using Python 3.13 enhanced patterns."""
            # Use structural pattern matching for operation validation
            match operations.get("validate"):
                case None:
                    return FlextResult.fail(
                        f"No validation operation for {entity_type}",
                    )
                case validate_fn:
                    result = self._execute_operation(
                        validate_fn,
                        data,
                        f"{entity_type} validation",
                    )
                    # Use modern railway pattern chaining
                    return result.flat_map(
                        lambda _: FlextResult[FlextTypes.Core.Dict].ok(data),
                    )

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
            """Execute operation using Python 3.13 structural pattern matching."""
            match operation:
                case None:
                    return FlextResult.fail(
                        f"Invalid operation function for {operation_name}",
                    )
                case callable_op:
                    return self._execute_callable_operation(
                        callable_op,
                        data,
                        operation_name,
                    )

        def _execute_callable_operation(
            self,
            operation: Callable[[FlextTypes.Core.Dict], object]
            | Callable[[object], object],
            data: object,
            operation_name: str,
        ) -> FlextResult[object]:
            """Execute callable operation with enhanced error handling."""
            try:
                # Use pattern matching for data type handling
                match data:
                    case dict() as dict_data:
                        result = operation(dict_data)
                    case obj if hasattr(obj, "__dict__"):
                        result = operation(vars(obj))
                    case _:
                        return FlextResult.fail(
                            f"Cannot convert data to dict for operation {operation_name}",
                        )

                # Pattern match result type for proper wrapping
                match result:
                    case obj if hasattr(obj, "is_success") and hasattr(obj, "value"):
                        return cast("FlextResult[object]", result)
                    case _:
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

    # High-level convenience methods

    def generate_secure_password(self, length: int = 12) -> FlextResult[str]:
        """Generate secure password (convenience method)."""
        return self._password_service.generate_secure_password(length)


__all__ = [
    "FlextLdapDomain",
]
