"""FLEXT-LDAP Unified Models Module.

This module provides unified Pydantic models for FLEXT-LDAP, following the FLEXT standards
of having a single unified class per module that inherits from FlextModels.

Contains only the actively used models from the FLEXT-LDAP project.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, final

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from flext_core import (
    FlextDomainService,
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.validations import FlextLdapValidations

if TYPE_CHECKING:
    from collections.abc import Sequence

    from flext_ldap.typings import FlextLdapTypes


class FlextLdapModels(FlextModels):
    """Unified LDAP Models class inheriting from FlextModels.

    This class provides only the actively used LDAP-specific Pydantic models as nested classes,
    following the FLEXT standard architecture pattern.
    """

    class SearchRequest(BaseModel):
        """LDAP Search Request Model - actively used in API."""

        base_dn: str = Field(description="Base DN for search")
        filter_str: str = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
            description="LDAP search filter",
        )
        scope: str = Field(
            default=FlextLdapConstants.Scopes.SUBTREE,
            description="Search scope",
        )
        attributes: list[str] | None = Field(
            default=None,
            description="Attributes to retrieve",
        )
        size_limit: int = Field(
            default=FlextLdapConstants.Connection.MAX_SIZE_LIMIT,
            description="Maximum number of entries to return",
            gt=0,
        )
        time_limit: int = Field(
            default=FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
            description="Search timeout in seconds",
            gt=0,
        )

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, value: str) -> str:
            """Validate base DN using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(
                value.strip(),
                "Base DN",
            )
            if validation_result.is_failure:
                raise ValueError(validation_result.error)

            return value.strip()

        @field_validator("scope")
        @classmethod
        def validate_scope(cls, value: str) -> str:
            """Validate search scope."""
            if value not in FlextLdapConstants.Scopes.VALID_SCOPES:
                valid_scopes = ", ".join(sorted(FlextLdapConstants.Scopes.VALID_SCOPES))
                msg = f"Invalid scope. Must be one of: {valid_scopes}"
                raise ValueError(msg)
            return value

        @classmethod
        def create_user_search(
            cls,
            base_dn: str,
            uid: str | None = None,
        ) -> FlextLdapModels.SearchRequest:
            """Create search request for common user patterns."""
            filter_str = (
                f"(&(objectClass=person)(uid={uid}))" if uid else "(objectClass=person)"
            )
            return cls(
                base_dn=base_dn,
                filter_str=filter_str,
                scope="subtree",
                attributes=["uid", "cn", "sn", "mail"],
                size_limit=100,
                time_limit=30,
            )

    class Entry(BaseModel):
        """LDAP Entry Model - actively used in API."""

        id: str = Field(description="Entry identifier")
        dn: str = Field(description="Distinguished Name")
        object_classes: list[str] = Field(
            default_factory=list,
            description="Object classes",
        )
        attributes: FlextLdapTypes.Entry.AttributeDict = Field(
            default_factory=dict,
            description="Entry attributes",
        )
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, value: str) -> str:
            """Validate DN format using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value.strip()

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate entry business rules."""
            # Basic entry validations
            if not self.dn:
                return FlextResult[None].fail("Entry must have a DN")

            # LDAP entries must have at least one object class
            if not self.object_classes:
                return FlextResult[None].fail(
                    "Entry must have at least one object class",
                )

            return FlextResult[None].ok(None)

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values from entry attributes.

            Args:
                name: Attribute name to retrieve

            Returns:
                List of attribute values, None if attribute not found

            """
            if name not in self.attributes:
                return None

            attribute_value = self.attributes[name]

            # Ensure return type is always a list of strings
            # AttributeDict values can only be: list[str] | list[bytes] | str | bytes
            if isinstance(attribute_value, str):
                return [attribute_value]
            if isinstance(attribute_value, bytes):
                return [attribute_value.decode("utf-8")]
            if isinstance(attribute_value, list):
                # Convert all items to strings
                return [
                    item.decode("utf-8") if isinstance(item, bytes) else str(item)
                    for item in attribute_value
                ]

            # This should never be reached due to AttributeDict type constraints
            # but keeping as fallback for type safety
            return [str(attribute_value)]  # type: ignore[unreachable]

    class User(BaseModel):
        """LDAP User Model - actively used in API."""

        id: str = Field(description="User identifier")
        dn: str = Field(description="Distinguished Name")
        uid: str | None = Field(default=None, description="User ID")
        cn: str | None = Field(default=None, description="Common Name")
        sn: str | None = Field(default=None, description="Surname")
        given_name: str | None = Field(default=None, description="Given Name")
        mail: str | None = Field(default=None, description="Email Address")
        display_name: str | None = Field(default=None, description="Display Name")
        user_password: str | None = Field(default=None, description="User password")
        status: str | None = Field(default=None, description="User status")
        created_at: str | None = Field(default=None, description="Creation timestamp")
        object_classes: list[str] = Field(
            default_factory=list,
            description="Object classes",
        )
        attributes: FlextLdapTypes.Entry.AttributeDict = Field(
            default_factory=dict,
            description="User attributes",
        )
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, value: str) -> str:
            """Validate DN format using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value.strip()

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            validation_result = FlextLdapValidations.validate_email(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)

            return value

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate user business rules."""
            # User-specific validations
            if "person" not in self.object_classes:
                return FlextResult[None].fail("User must have 'person' object class")

            if not self.cn:
                return FlextResult[None].fail("User must have a Common Name")

            return FlextResult[None].ok(None)

    class Group(BaseModel):
        """LDAP Group Model - actively used in API."""

        id: str = Field(description="Group identifier")
        dn: str = Field(description="Distinguished Name")
        cn: str | None = Field(default=None, description="Common Name")
        description: str | None = Field(default=None, description="Group Description")
        status: str | None = Field(default=None, description="Group status")
        members: list[str] = Field(
            default_factory=list,
            description="Group members (DNs)",
        )
        object_classes: list[str] = Field(
            default_factory=list,
            description="Object classes",
        )
        attributes: FlextLdapTypes.Entry.AttributeDict = Field(
            default_factory=dict,
            description="Group attributes",
        )
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, value: str) -> str:
            """Validate DN format using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value.strip()

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate group business rules."""
            # Group-specific validations
            if "groupOfNames" not in self.object_classes:
                return FlextResult[None].fail(
                    "Group must have 'groupOfNames' object class",
                )

            return FlextResult[None].ok(None)

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group."""
            return member_dn in self.members

        def add_member(self, member_dn: str) -> FlextResult[None]:
            """Add member to group."""
            if member_dn not in self.members:
                self.members.append(member_dn)
                return FlextResult[None].ok(None)
            return FlextResult[None].ok(None)  # Already a member, no-op

        def remove_member(self, member_dn: str) -> FlextResult[None]:
            """Remove member from group."""
            if member_dn in self.members:
                self.members.remove(member_dn)
                return FlextResult[None].ok(None)
            return FlextResult[None].fail(f"Member {member_dn} not found in group")

    class CreateUserRequest(BaseModel):
        """Create User Request Model - actively used in API."""

        dn: str = Field(description="User DN")
        uid: str = Field(description="User ID")
        cn: str = Field(description="Common Name")
        sn: str = Field(description="Surname")
        given_name: str | None = Field(default=None, description="Given Name")
        mail: str | None = Field(default=None, description="Email Address")
        description: str | None = Field(default=None, description="User description")
        telephone_number: str | None = Field(default=None, description="Phone number")
        user_password: str | None = Field(default=None, description="User Password")
        object_classes: list[str] = Field(
            default_factory=lambda: [
                FlextLdapConstants.ObjectClasses.TOP,
                FlextLdapConstants.ObjectClasses.PERSON,
                FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
            ],
            description="Object classes for user",
        )
        additional_attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Additional user attributes",
        )

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            validation_result = FlextLdapValidations.validate_email(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)

            return value

        @field_validator("user_password")
        @classmethod
        def validate_password(cls, value: str | None) -> str | None:
            """Validate password requirements using centralized validation."""
            validation_result = FlextLdapValidations.validate_password(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)

            return value

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate create user request business rules."""
            if not self.dn:
                return FlextResult[None].fail("DN cannot be empty")
            if not self.uid:
                return FlextResult[None].fail("UID cannot be empty")
            if not self.cn:
                return FlextResult[None].fail("Common Name cannot be empty")
            return FlextResult[None].ok(None)

        def to_user_entity(self) -> FlextLdapModels.User:
            """Convert request to user entity."""
            return FlextLdapModels.User(
                id=f"user_{self.uid}",
                dn=self.dn,
                uid=self.uid,
                cn=self.cn,
                sn=self.sn,
                given_name=self.given_name,
                mail=self.mail,
                user_password=self.user_password,
                object_classes=self.object_classes.copy(),
                attributes={},
                modified_at=None,
            )

    class CreateGroupRequest(BaseModel):
        """Create Group Request Model - actively used in API."""

        dn: str = Field(description="Group DN")
        cn: str = Field(description="Common Name")
        description: str | None = Field(default=None, description="Group Description")
        member_dns: list[str] = Field(
            default_factory=list,
            description="Initial group members (DNs)",
        )
        object_classes: list[str] = Field(
            default_factory=lambda: [
                FlextLdapConstants.ObjectClasses.TOP,
                FlextLdapConstants.ObjectClasses.GROUP_OF_NAMES,
            ],
            description="Object classes for group",
        )
        additional_attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Additional group attributes",
        )

    class UpdateGroupRequest(BaseModel):
        """Update Group Request Model - used in protocols."""

        dn: str = Field(description="Distinguished Name of group to update")
        cn: str | None = Field(default=None, description="New Common Name")
        description: str | None = Field(
            default=None,
            description="New group description",
        )
        member_dns: list[str] | None = Field(
            default=None,
            description="New list of member DNs (replaces existing)",
        )

    class SearchResponse(BaseModel):
        """Search Response Model - used in protocols."""

        entries: list[FlextTypes.Core.Dict] = Field(
            default_factory=list,
            description="Search result entries",
        )
        total_count: int = Field(default=0, description="Total number of entries found")
        has_more: bool = Field(
            default=False,
            description="Whether more entries are available",
        )
        search_time_ms: float = Field(
            default=0.0,
            description="Search execution time in ms",
        )

    class ConnectionRequest(BaseModel):
        """LDAP Connection Request Model - used for operational requests."""

        server_uri: str = Field(description="LDAP server URI")
        bind_dn: str | None = Field(
            default=None,
            description="Bind DN for authentication",
        )
        bind_password: str | None = Field(default=None, description="Bind password")
        operation_type: str = Field(
            description="Operation type: test, connect, bind, terminate",
        )
        timeout: int = Field(
            default=30,
            description="Connection timeout in seconds",
            gt=0,
            le=300,
        )

    # Utility methods for type conversion
    @staticmethod
    def _convert_to_str(value: str | bytes | int | None) -> str | None:
        """Convert LDAP attribute value to string."""
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        if isinstance(value, int):
            return str(value)
        return str(value)

    @staticmethod
    def _convert_to_str_list(
        value: list[str] | list[bytes] | str | bytes | None,
    ) -> list[str]:
        """Convert LDAP member list to list of strings."""
        if value is None:
            return []
        if isinstance(value, (str, bytes)):
            # Single value, convert to list
            converted = FlextLdapModels._convert_to_str(value)
            return [converted] if converted is not None else []
        # Must be a list due to type constraints
        result = []
        for item in value:
            converted = FlextLdapModels._convert_to_str(item)
            if converted is not None:
                result.append(converted)
        return result

    # Factory methods for creating models
    @classmethod
    def create_search_request(
        cls,
        base_dn: str,
        *,
        filter_str: str = FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
        scope: str = FlextLdapConstants.Scopes.SUBTREE,
        attributes: list[str] | None = None,
        size_limit: int = FlextLdapConstants.Connection.MAX_SIZE_LIMIT,
        time_limit: int = FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
    ) -> SearchRequest:
        """Create search request."""
        return cls.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
            size_limit=size_limit,
            time_limit=time_limit,
        )

    @classmethod
    def create_user_from_entry(cls, entry: Entry) -> User:
        """Create User model from LDAP entry."""
        return cls.User(
            id=entry.id,
            dn=entry.dn,
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            modified_at=entry.modified_at,
            uid=cls._convert_to_str(
                entry.attributes.get(FlextLdapConstants.Attributes.USER_ID, [None])[0],
            ),
            cn=cls._convert_to_str(
                entry.attributes.get(FlextLdapConstants.Attributes.COMMON_NAME, [None])[
                    0
                ],
            ),
            sn=cls._convert_to_str(
                entry.attributes.get(FlextLdapConstants.Attributes.SURNAME, [None])[0],
            ),
            given_name=cls._convert_to_str(
                entry.attributes.get(
                    FlextLdapConstants.Attributes.GIVEN_NAME,
                    [None],
                )[0],
            ),
            mail=cls._convert_to_str(
                entry.attributes.get(FlextLdapConstants.Attributes.MAIL, [None])[0],
            ),
            display_name=cls._convert_to_str(
                entry.attributes.get(
                    FlextLdapConstants.Attributes.DISPLAY_NAME,
                    [None],
                )[0],
            ),
        )

    @classmethod
    def create_group_from_entry(cls, entry: Entry) -> Group:
        """Create Group model from LDAP entry."""
        return cls.Group(
            id=entry.id,
            dn=entry.dn,
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            modified_at=entry.modified_at,
            cn=cls._convert_to_str(
                entry.attributes.get(FlextLdapConstants.Attributes.COMMON_NAME, [None])[
                    0
                ],
            ),
            description=cls._convert_to_str(
                entry.attributes.get(
                    FlextLdapConstants.Attributes.DESCRIPTION,
                    [None],
                )[0],
            ),
            members=cls._convert_to_str_list(
                entry.attributes.get(FlextLdapConstants.Attributes.MEMBER, []),
            ),
        )

    class ValueObjects(FlextDomainService[object]):
        """Single FlextLdapModels.ValueObjects class with all LDAP value objects.

        Consolidates ALL LDAP value objects into a single class following FLEXT patterns.
        Everything from DN validation to filter creation is available as internal classes
        with NO legacy compatibility and domain-driven design principles.
        """

        def execute(self) -> FlextResult[object]:
            """Execute domain operation - required by FlextDomainService."""
            return FlextResult[object].ok({"status": "value_objects_available"})

        # =========================================================================
        # DISTINGUISHED NAME - DN value object with RFC 2253 compliance
        # =========================================================================

        @final
        class DistinguishedName(FlextModels.Value):
            """LDAP Distinguished Name value object with RFC 2253 compliance."""

            model_config = ConfigDict(
                extra="forbid",
                validate_assignment=True,
                str_strip_whitespace=True,
                frozen=True,
            )

            value: str = Field(
                ...,
                description="RFC 2253 compliant Distinguished Name",
                min_length=FlextLdapConstants.Validation.MIN_DN_LENGTH,
                max_length=FlextLdapConstants.Validation.MAX_DN_LENGTH,
            )

            # DN validation pattern from SOURCE OF TRUTH
            DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
                FlextLdapConstants.Validation.DN_PATTERN,
            )

            @field_validator("value")
            @classmethod
            def validate_dn_format(cls, value: str) -> str:
                """Validate DN using direct validation - ELIMINATE local duplication."""
                # Use direct validation instead of FlextValidations
                if not value or not value.strip():
                    error_msg = "Distinguished Name cannot be empty"
                    raise ValueError(error_msg)

                # Direct pattern validation for DN format
                if not re.match(r"^[a-zA-Z]+=.+", value):
                    error_msg = f"Invalid DN format: {value}"
                    raise ValueError(error_msg)

                return value.strip()

            def validate_business_rules(self) -> FlextResult[None]:
                """Validate business rules for DN."""
                # DN is validated in field_validator, no additional business rules
                return FlextResult.ok(None)

            @property
            def rdn(self) -> str:
                """Get the Relative Distinguished Name (first component)."""
                return self.value.split(",", 1)[0].strip()

            def is_descendant_of(
                self,
                parent_dn: str | FlextLdapModels.ValueObjects.DistinguishedName,
            ) -> bool:
                """Check if this DN is a descendant of the given parent DN."""
                parent_str = (
                    parent_dn if isinstance(parent_dn, str) else parent_dn.value
                )
                return self.value.lower().endswith(parent_str.lower())

            @classmethod
            def create(
                cls,
                *args: object,
                **kwargs: object,
            ) -> FlextResult[FlextLdapModels.ValueObjects.DistinguishedName]:
                """Create DN from string with validation."""
                if len(args) != 1 or not isinstance(args[0], str):
                    return FlextResult.fail("DistinguishedName.create requires exactly one string argument")
                
                value = args[0]
                try:
                    dn = cls(value=value)
                    return FlextResult.ok(dn)
                except ValueError as e:
                    return FlextResult.fail(str(e))
                except TypeError as e:
                    return FlextResult.fail(f"Invalid input type: {e}")

        # =========================================================================
        # SCOPE - LDAP search scope value object
        # =========================================================================

        @final
        class Scope(FlextModels.Value):
            """LDAP search scope value object."""

            scope: str = Field(..., description="LDAP search scope")

            # Valid LDAP scopes from SOURCE OF TRUTH
            VALID_SCOPES: ClassVar[set[str]] = FlextLdapConstants.Scopes.VALID_SCOPES

            @field_validator("scope")
            @classmethod
            def validate_scope(cls, value: str) -> str:
                """Validate LDAP scope value."""
                normalized = value.lower()
                if normalized not in cls.VALID_SCOPES:
                    msg = f"Invalid LDAP scope: {value}. Must be one of {cls.VALID_SCOPES}"
                    raise ValueError(msg)
                return normalized

            def validate_business_rules(self) -> FlextResult[None]:
                """Validate business rules."""
                # Scope is validated in field_validator, no additional business rules
                return FlextResult.ok(None)

            @classmethod
            def create(
                cls,
                *args: object,
                **kwargs: object,
            ) -> FlextResult[FlextLdapModels.ValueObjects.Scope]:
                """Create scope value object with validation."""
                if len(args) != 1 or not isinstance(args[0], str):
                    return FlextResult.fail("Scope.create requires exactly one string argument")
                
                scope = args[0]
                try:
                    scope_obj = cls(scope=scope)
                    return FlextResult.ok(scope_obj)
                except ValueError as e:
                    return FlextResult.fail(str(e))

            @classmethod
            def base(cls) -> FlextLdapModels.ValueObjects.Scope:
                """Create base scope (search only the entry itself)."""
                return cls(scope=FlextLdapConstants.Scopes.BASE)

            @classmethod
            def one(cls) -> FlextLdapModels.ValueObjects.Scope:
                """Create one-level scope (search direct children only)."""
                return cls(scope=FlextLdapConstants.Scopes.ONELEVEL)

            @classmethod
            def sub(cls) -> FlextLdapModels.ValueObjects.Scope:
                """Create subtree scope (search entry and all descendants)."""
                return cls(scope=FlextLdapConstants.Scopes.SUBTREE)

            # NO aliases - use sub() and one() methods directly

        # =========================================================================
        # FILTER - LDAP filter value object with RFC 4515 compliance
        # =========================================================================

        @final
        class Filter(FlextModels.Value):
            """LDAP filter value object with RFC 4515 compliance."""

            model_config = ConfigDict(
                extra="forbid",
                validate_assignment=True,
                str_strip_whitespace=True,
                frozen=True,
            )

            value: str = Field(
                ...,
                description="RFC 4515 compliant LDAP filter",
                min_length=FlextLdapConstants.Validation.MIN_FILTER_LENGTH,
                max_length=FlextLdapConstants.Validation.MAX_FILTER_LENGTH,
            )

            # LDAP filter validation pattern from SOURCE OF TRUTH
            FILTER_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
                FlextLdapConstants.Validation.FILTER_PATTERN,
            )

            @field_validator("value")
            @classmethod
            def validate_filter_format(cls, value: str) -> str:
                """Validate LDAP filter using centralized validation - ELIMINATE local duplication."""
                # Use centralized validation from validations module
                validation_result = FlextLdapValidations.validate_filter(value)
                if validation_result.is_failure:
                    raise ValueError(validation_result.error)

                # Clean text using FlextUtilities (keep this as it's domain-specific)
                clean_result = FlextUtilities.TextProcessor.clean_text(value)
                if clean_result.is_failure:
                    error_msg = "LDAP filter cannot be empty after cleaning"
                    raise ValueError(error_msg)

                clean_value = clean_result.value
                if not clean_value:
                    error_msg = "LDAP filter cannot be empty after cleaning"
                    raise ValueError(error_msg)

                # Must start and end with parentheses
                if not (clean_value.startswith("(") and clean_value.endswith(")")):
                    msg = f"LDAP filter must be enclosed in parentheses: {clean_value}"
                    raise ValueError(msg)

                return clean_value

            def validate_business_rules(self) -> FlextResult[None]:
                """Validate business rules for filter."""
                # Filter is validated in field_validator, no additional business rules
                return FlextResult.ok(None)

            @classmethod
            def create(
                cls,
                value: str,
            ) -> FlextResult[FlextLdapModels.ValueObjects.Filter]:
                """Create filter from string with validation."""
                try:
                    filter_obj = cls(value=value)
                    return FlextResult.ok(filter_obj)
                except ValueError as e:
                    return FlextResult.fail(str(e))
                except TypeError as e:
                    return FlextResult.fail(f"Invalid input type: {e}")

            @classmethod
            def equals(
                cls,
                attribute: str,
                value: str,
            ) -> FlextLdapModels.ValueObjects.Filter:
                """Create equality filter."""
                return cls(value=f"({attribute}={value})")

            @classmethod
            def starts_with(
                cls,
                attribute: str,
                value: str,
            ) -> FlextLdapModels.ValueObjects.Filter:
                """Create starts-with filter."""
                return cls(value=f"({attribute}={value}*)")

            @classmethod
            def object_class(
                cls,
                object_class: str,
            ) -> FlextLdapModels.ValueObjects.Filter:
                """Create object class filter."""
                return cls(value=f"(objectClass={object_class})")

            @classmethod
            def all_objects(cls) -> FlextLdapModels.ValueObjects.Filter:
                """Create filter that matches all objects."""
                return cls(value="(objectClass=*)")

    class UserConversionParams(BaseModel):
        """User conversion parameters."""

        model_config = ConfigDict(
            frozen=True,  # Immutable for safety
            extra="forbid",  # Strict validation
            validate_assignment=True,
            str_strip_whitespace=True,
        )

        entries: Sequence[FlextLdapTypes.Search.ResultEntry] = Field(
            description="LDAP entries to convert",
            min_length=0,
        )
        include_disabled: bool = Field(
            default=False,
            description="Include disabled user accounts",
        )
        include_system: bool = Field(
            default=False,
            description="Include system accounts",
        )
        attribute_filter: list[str] | None = Field(
            default=None,
            description="Filter specific attributes",
            min_length=0,  # Allow empty lists
        )

        @field_validator("entries")
        @classmethod
        def validate_entries(
            cls,
            v: Sequence[FlextLdapTypes.Search.ResultEntry],
        ) -> Sequence[FlextLdapTypes.Search.ResultEntry]:
            """Validate entries structure."""
            return v

        @computed_field
        def entry_count(self) -> int:
            """Return count of entries."""
            return len(self.entries)

        @computed_field
        def has_filters(self) -> bool:
            """Check if object filters are applied."""
            return (
                self.include_disabled
                or self.include_system
                or bool(self.attribute_filter)
            )

    class ConnectionConfig(BaseModel):
        """LDAP Connection Configuration Model - consolidated from scattered definitions."""

        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            validate_assignment=True,
            str_strip_whitespace=True,
        )

        server: str = Field(description="LDAP server URI")
        port: int = Field(
            default=389,
            description="LDAP server port",
            gt=0,
            le=65535,
        )
        bind_dn: str | None = Field(
            default=None,
            description="Bind DN for authentication",
        )
        bind_password: str | None = Field(default=None, description="Bind password")
        timeout: int = Field(
            default=30,
            description="Connection timeout in seconds",
            gt=0,
            le=300,
        )
        use_ssl: bool = Field(default=False, description="Use SSL/TLS encryption")

        @field_validator("server")
        @classmethod
        def validate_server(cls, value: str) -> str:
            """Validate server URI format."""
            if not value or not value.strip():
                msg = "Server URI cannot be empty"
                raise ValueError(msg)

            value = value.strip()
            if not (value.startswith(("ldap://", "ldaps://"))):
                msg = "Server must be a valid LDAP URI (ldap:// or ldaps://)"
                raise ValueError(msg)

            return value

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate connection config business rules."""
            if not self.server:
                return FlextResult[None].fail("Server cannot be empty")
            if self.timeout <= 0:
                return FlextResult[None].fail("Timeout must be positive")
            return FlextResult[None].ok(None)


__all__ = ["FlextLdapModels"]
