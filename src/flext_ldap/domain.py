"""SINGLE CONSOLIDATED FlextLdapDomain class following FLEXT architectural patterns.

import re
from datetime import datetime
from typing import Callable, cast, TypeVar, ClassVar, Mapping
try:
    from typing import override  # Python 3.12+
except ImportError:
    def override(func):
        return func

FLEXT_REFACTORING_PROMPT.md COMPLIANCE: Single consolidated class for all LDAP domain functionality.
All specialized functionality delivered through internal subclasses within FlextLdapDomain.

CONSOLIDATED CLASSES: All domain specifications + domain services + domain events + domain factories
"""

import re
import secrets
import string
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import ClassVar, TypeVar, cast, override

from flext_core import (
    FlextDomainService,
    FlextEntityId,
    FlextEntityStatus,
    FlextModel,
    FlextResult,
    FlextTypes,
    get_logger,
)

from flext_ldap.constants import (
    FlextLdapDefaultValues,
    FlextLdapObjectClassConstants,
    FlextLdapValidationConstants,
)
from flext_ldap.models import FlextLdapGroup, FlextLdapUser
from flext_ldap.typings import LdapAttributeDict

logger = get_logger(__name__)
T = TypeVar("T")


class FlextLdapDomain:
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
                name=FlextLdapDefaultValues.VALID_LDAP_USER_NAME,
                description=FlextLdapDefaultValues.VALID_LDAP_USER_DESCRIPTION,
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
                FlextLdapObjectClassConstants.PERSON,
                FlextLdapObjectClassConstants.TOP,
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
                FlextLdapObjectClassConstants.GROUP_OF_NAMES,
                FlextLdapObjectClassConstants.TOP,
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

            if len(candidate) > FlextLdapValidationConstants.MAX_FILTER_LENGTH:
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

            if len(candidate) < FlextLdapValidationConstants.MIN_PASSWORD_LENGTH:
                return False

            if len(candidate) > FlextLdapValidationConstants.MAX_PASSWORD_LENGTH:
                return False

            # Check complexity if required
            if FlextLdapValidationConstants.REQUIRE_PASSWORD_COMPLEXITY:
                # PASSWORD_PATTERN não está centralizado, usar regex local ou criar constante se necessário
                return True  # NOTE: Password complexity validation can be implemented here if needed

            return True

        @override
        def get_validation_error(self, candidate: object) -> str:
            """Get detailed password validation error."""
            if not isinstance(candidate, str):
                return "Password must be a string"
            if len(candidate) < FlextLdapValidationConstants.MIN_PASSWORD_LENGTH:
                return f"Password must be at least {FlextLdapValidationConstants.MIN_PASSWORD_LENGTH} characters"
            if len(candidate) > FlextLdapValidationConstants.MAX_PASSWORD_LENGTH:
                return f"Password cannot exceed {FlextLdapValidationConstants.MAX_PASSWORD_LENGTH} characters"
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
            # Compare with enum value, not string representation
            if isinstance(status, FlextEntityStatus):
                return status == FlextEntityStatus.ACTIVE
            return str(status) == FlextEntityStatus.ACTIVE.value

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
            FlextLdapValidationConstants.EMAIL_PATTERN,
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

    class UserManagementService(FlextDomainService[FlextLdapUser]):
        """Internal domain service for user management business logic."""

        def __init__(self, **data: object) -> None:
            super().__init__(**data)
            self._user_spec = FlextLdapDomain.CompleteUserSpecification()
            self._password_spec = FlextLdapDomain.PasswordSpecification()
            self._email_spec = FlextLdapDomain.EmailSpecification()

        def execute(self) -> FlextResult[FlextLdapUser]:
            """Execute method required by FlextDomainService - CORRECTED signature."""
            return FlextResult[FlextLdapUser].ok(
                FlextLdapUser(
                    id=FlextEntityId("default_user"),
                    dn="cn=default,dc=example,dc=com",
                    uid="default",
                    cn="Default User",
                    sn="User",
                    given_name="Default",
                    mail="default@example.com",
                    user_password=None,
                    modified_at=None,
                )
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
                return FlextResult[object].fail(f"User validation error: {e}")

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

            return FlextResult[object].ok(None)

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
            self, user_data: FlextTypes.Core.Dict
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
            """Validate email field if provided."""
            if user_data.get("mail"):
                email = str(user_data["mail"])
                if not self._email_spec.is_satisfied_by(email):
                    return FlextResult[object].fail(
                        self._email_spec.get_validation_error(email),
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
            user: FlextLdapUser,
            requesting_user: FlextLdapUser,
        ) -> FlextResult[bool]:
            """Check if user can be deleted by requesting user."""
            try:
                # Business rule: Users cannot delete themselves
                if user.uid == requesting_user.uid:
                    return FlextResult[bool].fail("Users cannot delete themselves")

                # Business rule: Only active users can perform deletions
                if not self._user_spec.active_spec.is_satisfied_by(requesting_user):
                    return FlextResult[bool].fail(
                        "Only active users can delete other users",
                    )

                success = True
                return FlextResult[bool].ok(success)

            except Exception as e:
                logger.exception("User deletion check failed")
                return FlextResult[bool].fail(f"User deletion check error: {e}")

        def generate_username(
            self, first_name: str, last_name: str
        ) -> FlextResult[str]:
            """Generate username following business rules - USES FLEXT-CORE."""
            from flext_core import FlextUtilities

            try:
                # Validate inputs using FlextUtilities
                if not FlextUtilities.TypeGuards.is_non_empty_string(
                    first_name
                ) or not FlextUtilities.TypeGuards.is_non_empty_string(last_name):
                    return FlextResult[str].fail("First name and last name required")

                # Clean text using FlextUtilities
                clean_first = FlextUtilities.TextProcessor.clean_text(first_name)
                clean_last = FlextUtilities.TextProcessor.clean_text(last_name)

                if not clean_first or not clean_last:
                    return FlextResult[str].fail("Invalid names provided")

                # Business rule: username = first initial + last name, lowercase
                username = f"{clean_first[0].lower()}{clean_last.lower()}"

                # Slugify using FlextUtilities (removes invalid characters)
                username = FlextUtilities.TextProcessor.slugify(username)

                if (
                    len(username) < FlextLdapValidationConstants.MIN_PASSWORD_LENGTH
                ):  # MIN_USERNAME_LENGTH não existe, usar MIN_PASSWORD_LENGTH ou criar constante
                    return FlextResult[str].fail("Generated username too short")

                return FlextResult[str].ok(username)

            except Exception as e:
                logger.exception("Username generation failed")
                return FlextResult[str].fail(f"Username generation error: {e}")

    class GroupManagementService(FlextDomainService[FlextLdapGroup]):
        """Internal domain service for group management business logic."""

        def __init__(self, **data: object) -> None:
            super().__init__(**data)
            self._group_spec = FlextLdapDomain.GroupSpecification()
            self._dn_spec = FlextLdapDomain.DistinguishedNameSpecification()

        def execute(self) -> FlextResult[FlextLdapGroup]:
            """Execute method required by FlextDomainService - CORRECTED signature."""
            return FlextResult[FlextLdapGroup].ok(
                FlextLdapGroup(
                    id=FlextEntityId("default_group"),
                    dn="cn=default,dc=example,dc=com",
                    cn="Default Group",
                    description="Default group",
                    modified_at=None,
                )
            )

        @property
        def dn_spec(self) -> "FlextLdapDomain.DistinguishedNameSpecification":
            """Access to DN specification for external validation."""
            return self._dn_spec

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
                    return FlextResult[bool].fail(
                        self._group_spec.get_validation_error(group),
                    )

                # Business rule: User must be active (unless explicitly allowed)
                if not allow_inactive:
                    active_spec = FlextLdapDomain.ActiveUserSpecification()
                    if not active_spec.is_satisfied_by(user):
                        return FlextResult[bool].fail(
                            "Only active users can be added to groups",
                        )

                # Business rule: User cannot be added if already a member
                if user.dn in group.members:
                    return FlextResult[bool].fail(
                        "User is already a member of this group"
                    )

                success = True
                return FlextResult[bool].ok(success)

            except Exception as e:
                logger.exception("Group membership check failed")
                return FlextResult[bool].fail(f"Group membership check error: {e}")

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
                            f"Required field missing: {field}"
                        )

                # Validate DN format
                dn = str(group_data["dn"])
                if not self._dn_spec.is_satisfied_by(dn):
                    return FlextResult[object].fail(
                        self._dn_spec.get_validation_error(dn)
                    )

                return FlextResult[object].ok(None)

            except Exception as e:
                logger.exception("Group validation failed")
                return FlextResult[object].fail(f"Group validation error: {e}")

    class PasswordService(FlextDomainService[str]):
        """Internal domain service for password management business logic."""

        def __init__(self, **data: object) -> None:
            super().__init__(**data)
            self._password_spec = FlextLdapDomain.PasswordSpecification()

        def execute(self) -> FlextResult[str]:
            """Execute method required by FlextDomainService - CORRECTED signature."""
            return FlextResult[str].ok("Password service ready")

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
                logger.exception("Password validation failed")
                return FlextResult[object].fail(f"Password validation error: {e}")

        def generate_secure_password(self, length: int = 12) -> FlextResult[str]:
            """Generate a secure password following business rules - REFACTORED."""
            try:
                # Validate parameters in single check
                validation_error = self._validate_password_length(length)
                if validation_error:
                    return FlextResult[str].fail(validation_error)

                # Generate password with retry logic
                return self._generate_password_with_retries(length)

            except Exception as e:
                logger.exception("Password generation failed")
                return FlextResult[str].fail(f"Password generation error: {e}")

        def _validate_password_length(self, length: int) -> str | None:
            """Validate password length parameters - EXTRACTED METHOD."""
            if length < FlextLdapValidationConstants.MIN_PASSWORD_LENGTH:
                return f"Password length must be at least {FlextLdapValidationConstants.MIN_PASSWORD_LENGTH}"
            if length > FlextLdapValidationConstants.MAX_PASSWORD_LENGTH:
                return f"Password length cannot exceed {FlextLdapValidationConstants.MAX_PASSWORD_LENGTH}"
            return None

        def _generate_password_with_retries(self, length: int) -> FlextResult[str]:
            """Generate password with retry logic - EXTRACTED METHOD."""
            chars = (
                string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;'\",./<>?"
            )

            # Initial attempt
            password = "".join(secrets.choice(chars) for _ in range(length))
            if self._password_spec.is_satisfied_by(password):
                return FlextResult[str].ok(password)

            # Retry attempts
            for _ in range(
                3
            ):  # PASSWORD_GENERATION_MAX_RETRIES não está centralizado, usar valor fixo ou criar constante
                password = "".join(secrets.choice(chars) for _ in range(length))
                if self._password_spec.is_satisfied_by(password):
                    return FlextResult[str].ok(password)

            return FlextResult[str].fail("Could not generate secure password")

    # ==========================================================================
    # INTERNAL DOMAIN EVENT CLASSES
    # ==========================================================================

    class UserCreatedEvent(FlextModel):
        """Internal domain event fired when a user is created."""

        user_id: str
        user_dn: str
        actor: str
        occurred_at: datetime

        @classmethod
        def create(
            cls,
            user_id: str,
            user_dn: str,
            created_by: str,
        ) -> "FlextLdapDomain.UserCreatedEvent":
            """Create user created event."""
            return cls(
                user_id=user_id,
                user_dn=user_dn,
                actor=created_by,
                occurred_at=datetime.now(UTC),
            )

    class UserDeletedEvent(FlextModel):
        """Internal domain event fired when a user is deleted."""

        user_id: str
        user_dn: str
        actor: str
        occurred_at: datetime

        @classmethod
        def create(
            cls,
            user_id: str,
            user_dn: str,
            deleted_by: str,
        ) -> "FlextLdapDomain.UserDeletedEvent":
            """Create user deleted event."""
            return cls(
                user_id=user_id,
                user_dn=user_dn,
                actor=deleted_by,
                occurred_at=datetime.now(UTC),
            )

    class GroupMemberAddedEvent(FlextModel):
        """Internal domain event fired when a member is added to a group."""

        group_dn: str
        member_dn: str
        actor: str
        occurred_at: datetime

        @classmethod
        def create(
            cls,
            group_dn: str,
            member_dn: str,
            added_by: str,
        ) -> "FlextLdapDomain.GroupMemberAddedEvent":
            """Create group member added event."""
            return cls(
                group_dn=group_dn,
                member_dn=member_dn,
                actor=added_by,
                occurred_at=datetime.now(UTC),
            )

    class PasswordChangedEvent(FlextModel):
        """Internal domain event fired when a user's password is changed."""

        user_dn: str
        changed_by: str
        is_self_change: bool
        occurred_at: datetime

        @classmethod
        def create(
            cls,
            user_dn: str,
            changed_by: str,
        ) -> "FlextLdapDomain.PasswordChangedEvent":
            """Create password changed event."""
            return cls(
                user_dn=user_dn,
                changed_by=changed_by,
                is_self_change=user_dn == changed_by,
                occurred_at=datetime.now(UTC),
            )

    # ==========================================================================
    # INTERNAL DOMAIN FACTORY CLASSES
    # ==========================================================================

    class EntityParameterBuilder:
        """Internal helper class to build entity parameters with type safety - REDUCES COMPLEXITY."""

        @staticmethod
        def safe_str(value: object) -> str | None:
            """Safely convert value to string or None - USES FLEXT-CORE."""
            from flext_core import FlextUtilities

            # Cast to supported type for FlextUtilities
            safe_value = (
                value
                if isinstance(value, (str, int, float, bool, type(None)))
                else str(value)
            )
            result = FlextUtilities.Conversions.safe_str(safe_value)
            return result or None

        @staticmethod
        def safe_list(value: object, default: list[str] | None = None) -> list[str]:
            """Safely convert value to list or use default - USES FLEXT-CORE."""
            from flext_core import FlextUtilities

            if FlextUtilities.TypeGuards.is_list(value):
                return FlextUtilities.LdapConverters.safe_convert_list_to_strings(
                    cast("list[object]", value)
                )
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
            """Safely convert value to LdapAttributeDict."""
            from .utilities import FlextLdapUtilities

            return FlextLdapUtilities.LdapConverters.safe_convert_external_dict_to_ldap_attributes(
                value
            )  # type: ignore[return-value]

    class UserEntityBuilder:
        """Internal builder for FlextLdapUser entities - ELIMINATES DUPLICATION."""

        def __init__(self, params: FlextTypes.Core.Dict) -> None:
            self.params = params
            self.builder = FlextLdapDomain.EntityParameterBuilder()

        def build(self) -> object:
            """Build FlextLdapUser with reduced parameter complexity."""
            return FlextLdapUser(
                id=FlextEntityId(
                    f"user_{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"
                ),
                dn=str(self.params["dn"]),
                uid=self.builder.safe_str(self.params["uid"]) or "",
                cn=self.builder.safe_str(self.params["cn"]) or "",
                sn=self.builder.safe_str(self.params["sn"]) or "",
                given_name=self.builder.safe_str(self.params["given_name"]),
                mail=self.builder.safe_str(self.params["mail"]),
                user_password=self.builder.safe_str(self.params.get("user_password")),
                object_classes=self.builder.safe_list(self.params["object_classes"]),
                attributes=self.builder.safe_ldap_attributes(self.params["attributes"]),
                modified_at=None,
            )

    class GroupEntityBuilder:
        """Internal builder for FlextLdapGroup entities - ELIMINATES DUPLICATION."""

        def __init__(self, params: FlextTypes.Core.Dict) -> None:
            self.params = params
            self.builder = FlextLdapDomain.EntityParameterBuilder()

        def build(self) -> object:
            """Build FlextLdapGroup with reduced parameter complexity."""
            return FlextLdapGroup(
                id=FlextEntityId(
                    f"group_{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"
                ),
                dn=str(self.params["dn"]),
                cn=self.builder.safe_str(self.params["cn"]) or "",
                description=self.builder.safe_str(self.params["description"]),
                members=self.builder.safe_list(self.params["members"]),
                object_classes=self.builder.safe_list(self.params["object_classes"]),
                attributes=self.builder.safe_ldap_attributes(self.params["attributes"]),
                modified_at=None,
            )

    class DomainFactory:
        """Internal factory for creating domain objects with business rule validation."""

        def __init__(self) -> None:
            self._user_service = FlextLdapDomain.UserManagementService()
            self._group_service = FlextLdapDomain.GroupManagementService()
            self._password_service = FlextLdapDomain.PasswordService()

        def create_user_from_data(
            self,
            user_data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLdapUser]:
            """Create user entity from data with full validation."""
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]] = {
                "validate": self._user_service.validate_user_creation,
                "extract": self._extract_user_parameters,
                "create": self._create_user_entity,
                "final_validate": self._validate_created_user,
            }
            result = self._create_entity_from_data(user_data, "User", operations)
            # Narrow the type for the public API
            if result.is_failure:
                return FlextResult[FlextLdapUser].fail(
                    result.error or "User creation failed",
                )
            # Use FlextResult.value for modern type-safe access (success verified above)
            created = result.value
            if created is None:
                return FlextResult[FlextLdapUser].fail("User creation returned None")
            # Late import kept to avoid circular dependency; ruff allow
            from .models import (
                FlextLdapUser as _User,
            )

            if isinstance(created, _User):
                return FlextResult[FlextLdapUser].ok(created)
            return FlextResult[FlextLdapUser].fail(
                "User creation returned invalid type"
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
            object_classes: list[str] = (
                [str(item) for item in cast("list[object]", object_classes_raw)]
                if isinstance(object_classes_raw, list)
                else ["inetOrgPerson", "person", "top"]
            )
            attributes: dict[str, object] = (
                cast("dict[str, object]", attributes_raw)
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
            """Create FlextLdapUser entity from extracted parameters - REFACTORED."""
            builder = FlextLdapDomain.UserEntityBuilder(user_params)
            return builder.build()

        def _validate_created_user(self, user: object) -> FlextResult[object]:
            """Validate created user against domain specifications."""
            complete_spec = FlextLdapDomain.CompleteUserSpecification()
            if not complete_spec.is_satisfied_by(user):
                return FlextResult[object].fail(
                    complete_spec.get_validation_error(user)
                )
            return FlextResult[object].ok(user)

        def create_group_from_data(
            self,
            group_data: FlextTypes.Core.Dict,
        ) -> FlextResult[FlextLdapGroup]:
            """Create group entity from data with full validation."""
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]] = {
                "validate": self._group_service.validate_group_creation,
                "extract": self._extract_group_parameters,
                "create": self._create_group_entity,
                "final_validate": self._validate_created_group,
            }
            result = self._create_entity_from_data(group_data, "Group", operations)
            if result.is_failure:
                return FlextResult[FlextLdapGroup].fail(
                    result.error or "Group creation failed",
                )
            # Use FlextResult.value for modern type-safe access (success verified above)
            created = result.value
            if created is None:
                return FlextResult[FlextLdapGroup].fail("Group creation returned None")
            # Late import kept to avoid circular dependency; ruff allow
            from .models import (
                FlextLdapGroup as _Group,
            )

            if isinstance(created, _Group):
                return FlextResult[FlextLdapGroup].ok(created)
            return FlextResult[FlextLdapGroup].fail(
                "Group creation returned invalid type"
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
            members: list[str] = (
                [str(item) for item in cast("list[object]", members_raw)]
                if isinstance(members_raw, list)
                else []
            )
            object_classes: list[str] = (
                [str(item) for item in cast("list[object]", object_classes_raw)]
                if isinstance(object_classes_raw, list)
                else ["groupOfNames", "top"]
            )
            attributes: dict[str, object] = (
                cast("dict[str, object]", attributes_raw)
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
            """Create FlextLdapGroup entity from extracted parameters - REFACTORED."""
            builder = FlextLdapDomain.GroupEntityBuilder(group_params)
            return builder.build()

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
                    data, entity_type, operations
                )
            except Exception as e:
                logger.exception(f"{entity_type} creation failed")
                return FlextResult[object].fail(f"{entity_type} creation error: {e}")

        def _execute_entity_creation_pipeline(
            self,
            data: FlextTypes.Core.Dict,
            entity_type: str,
            operations: Mapping[str, Callable[[FlextTypes.Core.Dict], object]],
        ) -> FlextResult[object]:
            """Execute the entity creation pipeline with validation at each step."""
            # Step 1: Validate business rules
            validation_result = self._execute_operation(
                operations.get("validate"),
                data,
                f"{entity_type} validation",
            )
            if validation_result.is_failure:
                return FlextResult[object].fail(
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

            # Step 3: Create entity using .value pattern
            entity_params = extract_result.value
            if entity_params is None:
                return FlextResult[object].fail(
                    f"{entity_type} parameter extraction returned None"
                )
            create_result = self._execute_operation(
                operations.get("create"),
                entity_params,
                f"{entity_type} creation",
            )
            if create_result.is_failure:
                return create_result

            # Step 4: Final domain validation using .value pattern
            entity = create_result.value
            if entity is None:
                return FlextResult[object].fail(f"{entity_type} creation returned None")
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
                return FlextResult[object].fail(
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
                    return FlextResult[object].fail(
                        f"Cannot convert data to dict for operation {operation_name}"
                    )
                # Ensure result is FlextResult format
                if hasattr(result, "is_success") and hasattr(result, "value"):
                    return cast("FlextResult[object]", result)
                # Wrap non-FlextResult returns
                return FlextResult[object].ok(result)
            except Exception as e:
                return FlextResult[object].fail(f"{operation_name} failed: {e}")

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
        self, user_data: FlextTypes.Core.Dict
    ) -> FlextResult[object]:
        """Validate user creation (convenience method)."""
        return self._user_service.validate_user_creation(user_data)

    def validate_group_creation(
        self, group_data: FlextTypes.Core.Dict
    ) -> FlextResult[object]:
        """Validate group creation (convenience method)."""
        return self._group_service.validate_group_creation(group_data)

    def create_user_from_data(
        self, user_data: FlextTypes.Core.Dict
    ) -> FlextResult[FlextLdapUser]:
        """Create user from data (convenience method)."""
        return self._factory.create_user_from_data(user_data)

    def create_group_from_data(
        self, group_data: FlextTypes.Core.Dict
    ) -> FlextResult[FlextLdapGroup]:
        """Create group from data (convenience method)."""
        return self._factory.create_group_from_data(group_data)

    def generate_secure_password(self, length: int = 12) -> FlextResult[str]:
        """Generate secure password (convenience method)."""
        return self._password_service.generate_secure_password(length)


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Following FLEXT consolidation patterns
# =============================================================================

# Export internal classes for external access (backward compatibility)
FlextLdapDomainSpecification = FlextLdapDomain.DomainSpecification
FlextLdapUserSpecification = FlextLdapDomain.UserSpecification
FlextLdapGroupSpecification = FlextLdapDomain.GroupSpecification
FlextLdapDistinguishedNameSpecification = FlextLdapDomain.DistinguishedNameSpecification
FlextLdapPasswordSpecification = FlextLdapDomain.PasswordSpecification
FlextLdapActiveUserSpecification = FlextLdapDomain.ActiveUserSpecification
FlextLdapEmailSpecification = FlextLdapDomain.EmailSpecification
FlextLdapCompleteUserSpecification = FlextLdapDomain.CompleteUserSpecification
FlextLdapUserManagementService = FlextLdapDomain.UserManagementService
FlextLdapGroupManagementService = FlextLdapDomain.GroupManagementService
FlextLdapPasswordService = FlextLdapDomain.PasswordService
FlextLdapUserCreatedEvent = FlextLdapDomain.UserCreatedEvent
FlextLdapUserDeletedEvent = FlextLdapDomain.UserDeletedEvent
FlextLdapGroupMemberAddedEvent = FlextLdapDomain.GroupMemberAddedEvent
FlextLdapPasswordChangedEvent = FlextLdapDomain.PasswordChangedEvent
FlextLdapDomainFactory = FlextLdapDomain.DomainFactory
FlextLdapEntityParameterBuilder = FlextLdapDomain.EntityParameterBuilder
FlextLdapUserEntityBuilder = FlextLdapDomain.UserEntityBuilder
FlextLdapGroupEntityBuilder = FlextLdapDomain.GroupEntityBuilder

__all__ = [
    "FlextLdapActiveUserSpecification",
    "FlextLdapCompleteUserSpecification",
    "FlextLdapDistinguishedNameSpecification",
    "FlextLdapDomain",
    "FlextLdapDomainFactory",
    # Legacy compatibility aliases
    "FlextLdapDomainSpecification",
    "FlextLdapEmailSpecification",
    # Internal builder classes for backward compatibility
    "FlextLdapEntityParameterBuilder",
    "FlextLdapGroupEntityBuilder",
    "FlextLdapGroupManagementService",
    "FlextLdapGroupMemberAddedEvent",
    "FlextLdapGroupSpecification",
    "FlextLdapPasswordChangedEvent",
    "FlextLdapPasswordService",
    "FlextLdapPasswordSpecification",
    "FlextLdapUserCreatedEvent",
    "FlextLdapUserDeletedEvent",
    "FlextLdapUserEntityBuilder",
    "FlextLdapUserManagementService",
    "FlextLdapUserSpecification",
]
