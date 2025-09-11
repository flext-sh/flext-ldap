"""LDAP Entities - Python 3.13 optimized with advanced Pydantic v2 patterns.

Single class with all LDAP domain entities implementing rich business objects
organized as internal classes with Python 3.13 structural pattern matching,
type aliases, and Pydantic v2 computed fields for maximum performance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self, override

from flext_core import (
    FlextMixins,
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
    FlextValidations,
)
from pydantic import (
    ConfigDict,
    Field,
    computed_field,
    field_validator,
)

from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.typings import LdapAttributeDict, LdapAttributeValue
from flext_ldap.value_objects import FlextLDAPValueObjects

# Advanced type aliases using Python 3.13
type EntityId = str
type DistinguishedName = str
type LdapFilter = str
type SearchScope = Literal["base", "onelevel", "subtree"]
type AttributeName = str
type AttributeValueList = list[str]
type EntityResult[T] = FlextResult[T]
type EntityStatus = Literal["active", "inactive", "disabled", "pending"]
type ObjectClassList = list[str]


class FlextLDAPEntities(FlextMixins.Loggable):
    """Single FlextLDAPEntities class with all LDAP domain entities using FlextMixins.Loggable.

    Consolidates ALL LDAP entities into a single class following FLEXT patterns.
    Everything from search requests to domain entities is available as internal classes
    with full backward compatibility and rich business logic.

    """

    # =========================================================================
    # ERROR MESSAGES - Constants for exception messages
    # =========================================================================

    class ErrorMessages:
        """Error message constants following TRY003 and EM101/EM102 rules."""

        DN_CANNOT_BE_EMPTY = "DN cannot be empty"
        INVALID_DN_FORMAT = "Invalid DN format: {error}"

    # =========================================================================
    # SEARCH MODELS - Request and response models for search operations
    # =========================================================================

    class SearchRequest(FlextModels.Value):
        """Request model for LDAP search operations with Python 3.13 + Pydantic v2 patterns."""

        # Pydantic v2 advanced configuration
        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            validate_assignment=True,
            str_strip_whitespace=True,
        )

        # Advanced type annotations with Annotated and constraints
        base_dn: Annotated[str, Field(min_length=3, description="Base DN for search")]
        scope: Annotated[
            str,
            Field(
                default="subtree",
                pattern="^(base|one|onelevel|subtree)$",
                description="Search scope",
            ),
        ]
        filter_str: Annotated[
            str,
            Field(
                default="(objectClass=*)",
                pattern=r"^\(.+\)$",
                description="LDAP search filter (must be enclosed in parentheses)",
            ),
        ]
        attributes: Annotated[
            FlextTypes.Core.StringList | None,
            Field(
                default=None,
                description="Attributes to retrieve (None for all)",
            ),
        ]
        size_limit: Annotated[
            int,
            Field(
                default=1000,
                gt=0,
                le=10000,
                description="Maximum number of entries to return",
            ),
        ]
        time_limit: Annotated[
            int,
            Field(
                default=30,
                gt=0,
                le=300,
                description="Search time limit in seconds",
            ),
        ]

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate search request business rules."""
            if not self.base_dn:
                return FlextResult.fail("Base DN cannot be empty")
            if not self.filter_str:
                return FlextResult.fail("Filter cannot be empty")
            return FlextResult.ok(None)

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN format."""
            try:
                FlextLDAPValueObjects.DistinguishedName(value=v)
                return v
            except ValueError as e:
                msg = f"Invalid base DN format: {e}"
                raise ValueError(msg) from e

        @field_validator("filter_str")
        @classmethod
        def validate_filter(cls, v: str) -> str:
            """Validate filter format using FlextValidations - NO DUPLICATION."""
            # Use FlextValidations pattern matching for LDAP filter validation
            pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
                v, r"^\(.+\)$", "LDAP filter must be enclosed in parentheses"
            )
            if pattern_result.is_failure:
                error_msg = f"Filter validation failed: {pattern_result.error}"
                raise ValueError(error_msg)
            return v

        @classmethod
        def create_user_search(cls, base_dn: str, uid: str | None = None) -> Self:
            """Factory method for common user search patterns."""
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

    # =========================================================================
    # DISCRIMINATED UNIONS - Advanced Python 3.13 + Pydantic Type Safety
    # =========================================================================

    class UserSearchResult(FlextModels.Value):
        """Type-safe user search result with discriminated union."""

        entry_type: Literal["user"] = "user"
        dn: str = Field(..., description="Distinguished Name")
        uid: str = Field(..., description="User ID")
        cn: str | None = Field(None, description="Common Name")
        sn: str | None = Field(None, description="Surname")
        given_name: str | None = Field(None, description="Given Name")
        mail: str | None = Field(None, description="Email address")

        @computed_field
        def display_name(self) -> str:
            """Computed display name for user."""
            if self.cn:
                return self.cn
            if self.given_name and self.sn:
                return f"{self.given_name} {self.sn}"
            return self.uid

    class GroupSearchResult(FlextModels.Value):
        """Type-safe group search result with discriminated union."""

        entry_type: Literal["group"] = "group"
        dn: str = Field(..., description="Distinguished Name")
        cn: str = Field(..., description="Group Common Name")
        description: str | None = Field(None, description="Group description")
        members: FlextTypes.Core.StringList = Field(
            default_factory=list, description="Group member DNs"
        )

        @computed_field
        def member_count(self) -> int:
            """Computed member count."""
            return len(self.members)

    class GenericSearchResult(FlextModels.Value):
        """Type-safe generic search result with discriminated union."""

        entry_type: Literal["generic"] = "generic"
        dn: str = Field(..., description="Distinguished Name")
        object_classes: FlextTypes.Core.StringList = Field(
            default_factory=list,
            description="LDAP object classes",
        )
        attributes: LdapAttributeDict = Field(
            default_factory=dict,
            description="All LDAP attributes",
        )

        @computed_field
        def primary_object_class(self) -> str:
            """Primary object class for this entry."""
            return self.object_classes[0] if self.object_classes else "unknown"

    class SearchResponse(FlextModels.Value, FlextMixins.Loggable):
        """Advanced search response with discriminated unions for type safety."""

        entries: list[FlextTypes.Core.Dict] = Field(
            default_factory=list,
            description="Type-safe search result entries with discriminated unions",
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

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate search response business rules."""
            if self.total_count < 0:
                return FlextResult.fail("Total count cannot be negative")
            if self.search_time_ms < 0:
                return FlextResult.fail("Search time cannot be negative")

            # Validate reasonable results (domain rule)
            if self.total_count > FlextLDAPConstants.Connection.MAX_SIZE_LIMIT:
                self.log_operation(
                    operation="Large search result", count=self.total_count
                )

            return FlextResult.ok(None)

    class SearchParams(FlextModels.Config, FlextMixins.Loggable):
        """Unified parameter object for search operations across all components.

        Consolidates all SearchParams classes from operations.py, repositories.py,
        and exceptions.py to eliminate duplication and provide consistent interface.
        """

        model_config = ConfigDict(frozen=True, extra="forbid")

        # Core search parameters (from operations.py)
        connection_id: str = Field(
            ...,
            min_length=1,
            description="LDAP connection identifier",
        )
        base_dn: str = Field(..., min_length=1, description="Base DN for search")
        search_filter: str = Field(
            default="(objectClass=*)",
            min_length=1,
            description="LDAP search filter",
        )
        scope: str = Field(
            default="subtree",
            pattern=r"^(base|one|subtree|onelevel)$",
            description="Search scope",
        )
        attributes: FlextTypes.Core.StringList | None = Field(
            default=None,
            description="Attributes to retrieve",
        )
        size_limit: int = Field(
            default=1000,
            gt=0,
            le=10000,
            description="Maximum entries to return",
        )
        time_limit: int = Field(
            default=30,
            gt=0,
            le=300,
            description="Search timeout in seconds",
        )

        # Repository-specific parameters (from repositories.py)
        identifier: str | None = Field(
            default=None,
            min_length=1,
            description="Specific identifier to search for",
        )
        search_scope: str | None = Field(
            default=None,
            description="Repository search scope",
        )

        # Exception handling parameters (from exceptions.py)
        timeout: int | None = Field(
            default=None,
            ge=1,
            le=300,
            description="Operation timeout",
        )
        retry_count: int | None = Field(
            default=None,
            ge=0,
            le=10,
            description="Retry attempts",
        )

        @classmethod
        def create_basic_search(
            cls,
            connection_id: str,
            base_dn: str,
            search_filter: str = "(objectClass=*)",
        ) -> FlextLDAPEntities.SearchParams:
            """Factory method for basic search operations."""
            return cls(
                connection_id=connection_id,
                base_dn=base_dn,
                search_filter=search_filter,
            )

        @classmethod
        def create_user_search(
            cls,
            connection_id: str,
            base_dn: str,
            uid: str | None = None,
            size_limit: int = 1,
            time_limit: int = 30,
        ) -> FlextLDAPEntities.SearchParams:
            """Factory method for user-specific searches."""
            filter_str = (
                f"(&(objectClass=person)(uid={uid}))"
                if uid
                else "(&(objectClass=person))"
            )
            return cls(
                connection_id=connection_id,
                base_dn=base_dn,
                search_filter=filter_str,
                attributes=["uid", "cn", "sn", "givenName", "mail"],
                size_limit=size_limit,
                time_limit=time_limit,
            )

        @classmethod
        def create_group_search(
            cls,
            connection_id: str,
            base_dn: str,
            cn: str | None = None,
            size_limit: int = 1,
            time_limit: int = 30,
        ) -> FlextLDAPEntities.SearchParams:
            """Factory method for group-specific searches."""
            filter_str = (
                f"(&(objectClass=groupOfNames)(cn={cn}))"
                if cn
                else "(&(objectClass=groupOfNames))"
            )
            return cls(
                connection_id=connection_id,
                base_dn=base_dn,
                search_filter=filter_str,
                attributes=["cn", "member", "description"],
                size_limit=size_limit,
                time_limit=time_limit,
            )

        @classmethod
        def create_repository_search(
            cls,
            identifier: str,
            base_dn: str = "dc=example,dc=com",
        ) -> FlextLDAPEntities.SearchParams:
            """Factory method for repository searches."""
            return cls(
                connection_id="repository_connection",
                base_dn=base_dn,
                identifier=identifier,
                search_filter=f"(uid={identifier})",
            )

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate search parameters business rules."""
            if self.size_limit <= 0:
                return FlextResult.fail("Size limit must be positive")
            if self.time_limit <= 0:
                return FlextResult.fail("Time limit must be positive")

            # Validate reasonable limits (domain rule)
            if self.size_limit > FlextLDAPConstants.Connection.MAX_SIZE_LIMIT:
                self.log_operation(
                    operation="Large search limit",
                    size_limit=self.size_limit,
                )

            return FlextResult.ok(None)

    # =========================================================================
    # DOMAIN ENTITIES - Rich LDAP domain objects
    # =========================================================================

    class Entry(FlextModels.Entity):
        """Base LDAP directory entry implementing rich domain model patterns."""

        # Override id field with validator to convert EntityId to str
        id: str = Field(..., description="Entity identifier")

        @field_validator("id", mode="before")
        @classmethod
        def convert_entity_id(cls, v: str | FlextModels.EntityId) -> str:
            """Convert EntityId to string if needed."""
            # Handle FlextModels.EntityId objects
            if isinstance(v, FlextModels.EntityId):
                return str(v)
            # Handle string and other types
            return str(v)

        dn: str = Field(..., description="Distinguished Name")
        object_classes: FlextTypes.Core.StringList = Field(
            default_factory=list,
            description="LDAP object classes",
        )
        attributes: LdapAttributeDict = Field(
            default_factory=dict,
            description="LDAP attributes dictionary",
        )
        status: str = Field(
            default="active",
            description="Entity status from FlextConstants.Status",
        )

        # Entity metadata
        created_at: datetime = Field(
            default_factory=FlextUtilities.TimeUtils.get_timestamp_utc,
            description="Creation timestamp using FlextUtilities SOURCE OF TRUTH",
        )
        modified_at: datetime | None = Field(
            None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format using FlextValidations SOURCE OF TRUTH."""
            result = FlextValidations.Rules.StringRules.validate_non_empty(v)
            if result.is_failure:
                error_msg = FlextLDAPEntities.ErrorMessages.DN_CANNOT_BE_EMPTY
                raise ValueError(error_msg)

            pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
                v, r"^[a-zA-Z]+=.+", "DN format"
            )
            if pattern_result.is_failure:
                error_msg = FlextLDAPEntities.ErrorMessages.INVALID_DN_FORMAT.format(
                    error=pattern_result.error
                )
                raise ValueError(error_msg)

            return v

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules."""
            if not self.object_classes:
                return FlextResult.fail(
                    "Entry must have at least one object class",
                )
            return FlextResult.ok(None)

        def get_rdn(self) -> str:
            """Get the Relative Distinguished Name."""
            return self.dn.split(",", 1)[0].strip()

        def get_parent_dn(self) -> str | None:
            """Get parent DN."""
            parts = self.dn.split(",", 1)
            return parts[1].strip() if len(parts) > 1 else None

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            return object_class.lower() in [oc.lower() for oc in self.object_classes]

        def get_attribute(self, name: str) -> LdapAttributeValue | None:
            """Get attribute value."""
            return self.attributes.get(name)

        def set_attribute(self, name: str, value: LdapAttributeValue) -> None:
            """Set attribute value."""
            self.attributes[name] = value
            # Use model field assignment through __setattr__
            object.__setattr__(
                self, "modified_at", FlextUtilities.TimeUtils.get_timestamp_utc()
            )

    class User(Entry):
        """LDAP user entity with user-specific validation."""

        uid: str = Field(..., description="User ID")
        cn: str | None = Field(None, description="Common Name")
        sn: str | None = Field(None, description="Surname")
        given_name: str | None = Field(None, description="Given Name")
        mail: str | None = Field(None, description="Email address")
        user_password: str | None = Field(None, description="User password")

        def model_post_init(self, __context: object, /) -> None:
            """Populate LDAP attributes from entity fields."""
            super().model_post_init(__context)
            # Convert entity fields to LDAP attributes
            if self.uid:
                self.attributes["uid"] = self.uid
            if self.cn:
                self.attributes["cn"] = self.cn
            if self.sn:
                self.attributes["sn"] = self.sn
            if self.given_name:
                self.attributes["givenName"] = self.given_name
            if self.mail:
                self.attributes["mail"] = self.mail
            if self.user_password:
                self.attributes["userPassword"] = self.user_password

        @field_validator("mail")
        @classmethod
        def validate_email(cls, v: str | None) -> str | None:
            """Validate email format - USES FLEXT-CORE."""
            # FlextValidations already imported at top

            if v:
                result = FlextValidations.Rules.StringRules.validate_email(v)
                if not result.is_success:
                    msg = "Invalid email format"
                    raise ValueError(msg)
            return v

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate user business rules."""
            # Call parent validation first
            parent_result = super().validate_business_rules()
            if not parent_result.is_success:
                return parent_result

            # User-specific validations
            if not self.has_object_class("person"):
                return FlextResult.fail("User must have 'person' object class")

            if not self.cn and not self.get_attribute("cn"):
                return FlextResult.fail("User must have a Common Name")

            return FlextResult.ok(None)

        def get_full_name(self) -> str:
            """Get user's full name."""
            if self.cn:
                return self.cn
            if self.given_name and self.sn:
                return f"{self.given_name} {self.sn}"
            return self.uid

    class Group(Entry):
        """LDAP group entity with group-specific validation."""

        cn: str = Field(..., description="Common Name")
        description: str | None = Field(None, description="Group description")
        members: FlextTypes.Core.StringList = Field(
            default_factory=list,
            description="Group member DNs",
        )

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate group business rules."""
            # Call parent validation first
            parent_result = super().validate_business_rules()
            if not parent_result.is_success:
                return parent_result

            # Group-specific validations
            if not self.has_object_class("groupOfNames"):
                return FlextResult.fail(
                    "Group must have 'groupOfNames' object class",
                )

            return FlextResult.ok(None)

        def add_member(self, member_dn: str) -> FlextResult[None]:
            """Add member to group."""
            if member_dn not in self.members:
                self.members.append(member_dn)
                self.modified_at = FlextUtilities.TimeUtils.get_timestamp_utc()
                return FlextResult.ok(None)
            return FlextResult.ok(None)  # Already a member, no-op

        def remove_member(self, member_dn: str) -> FlextResult[None]:
            """Remove member from group."""
            if member_dn in self.members:
                self.members.remove(member_dn)
                self.modified_at = FlextUtilities.TimeUtils.get_timestamp_utc()
                return FlextResult.ok(None)
            return FlextResult.fail(f"Member {member_dn} not found in group")

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group."""
            return member_dn in self.members

    # =========================================================================
    # REQUEST MODELS - Operation request models
    # =========================================================================

    class CreateUserRequest(FlextModels.Value):
        """Request model for creating LDAP users."""

        dn: str = Field(..., description="Distinguished Name for new user")
        uid: str = Field(..., description="User ID", min_length=1)
        cn: str = Field(..., description="Common Name", min_length=1)
        sn: str | None = Field(None, description="Surname")
        given_name: str | None = Field(None, description="Given Name")
        mail: str | None = Field(None, description="Email address")
        description: str | None = Field(None, description="User description")
        telephone_number: str | None = Field(None, description="Telephone number")
        user_password: str | None = Field(None, description="User password")
        object_classes: FlextTypes.Core.StringList = Field(
            default_factory=lambda: [
                "top",
                "person",
                "organizationalPerson",
                "inetOrgPerson",
            ],
            description="LDAP object classes",
        )

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate create user request business rules."""
            if not self.dn:
                return FlextResult.fail("DN cannot be empty")
            if not self.uid:
                return FlextResult.fail("UID cannot be empty")
            if not self.cn:
                return FlextResult.fail("Common Name cannot be empty")
            return FlextResult.ok(None)

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format using FlextValidations SOURCE OF TRUTH."""
            result = FlextValidations.Rules.StringRules.validate_non_empty(v)
            if result.is_failure:
                error_msg = FlextLDAPEntities.ErrorMessages.DN_CANNOT_BE_EMPTY
                raise ValueError(error_msg)

            pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
                v, r"^[a-zA-Z]+=.+", "DN format"
            )
            if pattern_result.is_failure:
                error_msg = FlextLDAPEntities.ErrorMessages.INVALID_DN_FORMAT.format(
                    error=pattern_result.error
                )
                raise ValueError(error_msg)

            return v

        @field_validator("mail")
        @classmethod
        def validate_email(cls, v: str | None) -> str | None:
            """Validate email format - USES FLEXT-CORE."""
            # FlextValidations already imported at top

            if v:
                result = FlextValidations.Rules.StringRules.validate_email(v)
                if not result.is_success:
                    msg = "Invalid email format"
                    raise ValueError(msg)
            return v

        def to_user_entity(self) -> FlextLDAPEntities.User:
            """Convert request to user entity."""
            return FlextLDAPEntities.User(
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

    class CreateGroupRequest(FlextModels.Value):
        """Request model for creating LDAP groups."""

        dn: str = Field(..., description="Distinguished Name for new group")
        cn: str = Field(..., description="Common Name", min_length=1)
        description: str | None = Field(None, description="Group description")
        member_dns: FlextTypes.Core.StringList = Field(
            default_factory=list,
            description="List of member DNs",
        )
        object_classes: FlextTypes.Core.StringList = Field(
            default_factory=lambda: [
                "top",
                "groupOfNames",
            ],
            description="LDAP object classes",
        )

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate create group request business rules."""
            if not self.dn:
                return FlextResult.fail("DN cannot be empty")
            if not self.cn:
                return FlextResult.fail("Common Name cannot be empty")
            return FlextResult.ok(None)

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format using FlextValidations SOURCE OF TRUTH."""
            result = FlextValidations.Rules.StringRules.validate_non_empty(v)
            if result.is_failure:
                error_msg = FlextLDAPEntities.ErrorMessages.DN_CANNOT_BE_EMPTY
                raise ValueError(error_msg)

            pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
                v, r"^[a-zA-Z]+=.+", "DN format"
            )
            if pattern_result.is_failure:
                error_msg = FlextLDAPEntities.ErrorMessages.INVALID_DN_FORMAT.format(
                    error=pattern_result.error
                )
                raise ValueError(error_msg)

            return v

        def to_group_entity(self) -> FlextLDAPEntities.Group:
            """Convert request to group entity."""
            return FlextLDAPEntities.Group(
                id=f"group_{self.cn}",
                dn=self.dn,
                cn=self.cn,
                description=self.description,
                members=self.member_dns.copy(),
                object_classes=self.object_classes.copy(),
                attributes={},
                modified_at=None,
            )

    class UpdateGroupRequest(FlextModels.Value):
        """Request model for updating LDAP groups."""

        dn: str = Field(..., description="Distinguished Name of group to update")
        cn: str | None = Field(None, description="New Common Name")
        description: str | None = Field(None, description="New group description")
        member_dns: FlextTypes.Core.StringList | None = Field(
            None,
            description="New list of member DNs (replaces existing)",
        )

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate update group request business rules."""
            if not self.dn:
                return FlextResult.fail("DN cannot be empty")

            has_updates = any(
                [
                    self.cn is not None,
                    self.description is not None,
                    self.member_dns is not None,
                ]
            )

            if not has_updates:
                return FlextResult.fail(
                    "At least one field must be provided for update"
                )

            return FlextResult.ok(None)

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format using FlextValidations SOURCE OF TRUTH."""
            result = FlextValidations.Rules.StringRules.validate_non_empty(v)
            if result.is_failure:
                error_msg = FlextLDAPEntities.ErrorMessages.DN_CANNOT_BE_EMPTY
                raise ValueError(error_msg)

            pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
                v, r"^[a-zA-Z]+=.+", "DN format"
            )
            if pattern_result.is_failure:
                error_msg = FlextLDAPEntities.ErrorMessages.INVALID_DN_FORMAT.format(
                    error=pattern_result.error
                )
                raise ValueError(error_msg)

            return v


# LdapAttributeDict already imported in TYPE_CHECKING block above

# Rebuild models after all definitions are complete
FlextLDAPEntities.User.model_rebuild()
FlextLDAPEntities.Group.model_rebuild()
FlextLDAPEntities.Entry.model_rebuild()
FlextLDAPEntities.SearchRequest.model_rebuild()
FlextLDAPEntities.SearchResponse.model_rebuild()
FlextLDAPEntities.CreateUserRequest.model_rebuild()
FlextLDAPEntities.CreateGroupRequest.model_rebuild()
FlextLDAPEntities.UpdateGroupRequest.model_rebuild()


__all__ = [
    # Primary consolidated class
    "FlextLDAPEntities",
]

# Export module-level aliases eliminated - use FlextLDAPEntities.* directly following flext-core pattern
