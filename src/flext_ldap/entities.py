"""LDAP Domain Entities - Mutable domain entities with business logic.

This module consolidates ALL LDAP domain entities into a single
FlextLdapEntities class following FLEXT one-class-per-module standards.

Domain entities represent mutable business objects with identity and
behavior, such as Users, Groups, and Entries.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

# ruff: noqa: F821
# Nested class forward references are valid with __future__.annotations but ruff doesn't recognize them

from __future__ import annotations

from datetime import datetime

from pydantic import (
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)

from flext_core import FlextModels, FlextResult, FlextTypes
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapEntities(FlextModels):
    """Unified LDAP entities class consolidating ALL domain entities.

    This class consolidates:
    - LdapUser: User entity with enterprise attributes
    - Group: Group entity with membership management
    - Entry: Generic LDAP entry entity
    - SearchRequest: Search operation request
    - SearchResponse: Search operation response
    - CreateUserRequest: User creation request
    - CreateGroupRequest: Group creation request

    Into a single unified class following FLEXT patterns. ALL LDAP entities
    are now available as nested classes within FlextLdapEntities.
    """

    # Enhanced base configuration for all LDAP entities
    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        validate_return=True,
        ser_json_timedelta="iso8601",
        ser_json_bytes="base64",
        serialize_by_alias=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_default=True,
        # LDAP-specific configurations
        frozen=False,  # Allow mutable LDAP entities for updates
        extra="forbid",  # Strict LDAP attribute validation
        # LDAP serialization features
        json_encoders={
            datetime: lambda v: v.isoformat() if v else None,
        },
    )

    # =========================================================================
    # BASE CLASSES - Common functionality for entities
    # =========================================================================

    class FlextLdapBaseModel(FlextModels.ArbitraryTypesModel):
        """Base model for all LDAP models with common configuration."""

        # Timestamps
        created_at: datetime = Field(
            default_factory=datetime.now,
            description="Creation timestamp",
        )
        modified_at: datetime = Field(
            default_factory=datetime.now,
            description="Last modification timestamp",
        )

        @field_serializer("created_at", "modified_at")
        def serialize_datetime(self, value: datetime) -> str:
            """Serialize datetime to ISO format."""
            return value.isoformat()

    class FlextLdapValidationMixin:
        """Validation mixin for LDAP models."""

        @model_validator(mode="after")
        def validate_ldap_entity(self) -> FlextLdapValidationMixin:
            """Validate LDAP entity after construction."""
            # Add any cross-field validation here
            return self

    class FlextLdapEntityBase(FlextLdapBaseModel, FlextLdapValidationMixin):
        """Base class for LDAP entities with common fields and validation.

        Provides common fields and validation methods that are shared
        across multiple LDAP entity types.
        """

        # Common additional attributes field
        additional_attributes: dict[
            str, FlextLdapTypes.LdapEntries.EntryAttributeValue
        ] = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )

    # =========================================================================
    # CORE LDAP ENTITIES - Primary Domain Objects
    # =========================================================================

    class LdapUser(FlextLdapEntityBase):
        """LDAP User entity with enterprise attributes and advanced Pydantic 2.11 features.

        **CENTRALIZED APPROACH**: All user operations follow centralized patterns:
        - FlextLdapEntities.LdapUser.* for user-specific operations
        - Centralized validation through FlextLdapValidations
        - No wrappers, aliases, or fallbacks
        - Direct use of flext-core centralized models

        **PYTHON 3.13+ COMPATIBILITY**: Uses modern union syntax and latest type features.
        """

        # Core identification
        dn: str = Field(..., description="Distinguished Name (unique identifier)")
        cn: str = Field(..., description="Common Name")
        uid: str = Field(..., description="User ID")
        sn: str = Field(..., description="Surname")
        given_name: str | None = Field(default=None, description="Given Name")

        # Contact information
        mail: str | None = Field(default=None, description="Primary email address")
        telephone_number: str | None = Field(
            default=None, description="Primary phone number"
        )
        mobile: str | None = Field(default=None, description="Mobile phone number")

        # Organizational
        department: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_DEPARTMENT,
            description="Department",
        )
        title: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_TITLE, description="Job title"
        )
        organization: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_ORGANIZATION,
            description="Organization",
        )
        organizational_unit: str | None = Field(
            default=None, description="Organizational Unit"
        )

        # Authentication
        user_password: str | SecretStr | None = Field(
            default=None, description="User password"
        )

        # LDAP metadata
        object_classes: FlextTypes.StringList = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
        )

        # Core enterprise fields
        status: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_STATUS,
            description="User status",
        )
        created_at: datetime | None = Field(
            default=None, description="Creation timestamp"
        )
        display_name: str | None = Field(default=None, description="Display Name")
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )
        created_timestamp: datetime | None = Field(
            default=None, description="Creation timestamp"
        )
        modified_timestamp: datetime | None = Field(
            default=None, description="Modification timestamp"
        )

        @field_validator("department", "title", "organization", "status", mode="before")
        @classmethod
        def set_defaults_from_constants(
            cls, v: str | None, info: ValidationInfo
        ) -> str:
            """Set defaults from constants if None is provided."""
            if v is None:
                field_name = info.field_name
                if field_name == "department":
                    return FlextLdapConstants.Defaults.DEFAULT_DEPARTMENT
                elif field_name == "title":
                    return FlextLdapConstants.Defaults.DEFAULT_TITLE
                elif field_name == "organization":
                    return FlextLdapConstants.Defaults.DEFAULT_ORGANIZATION
                elif field_name == "status":
                    return FlextLdapConstants.Defaults.DEFAULT_STATUS
            return v or ""

        @field_validator("mail")
        @classmethod
        def validate_email(cls, v: str | None) -> str | None:
            """Validate email format."""
            if v and not FlextLdapValidations.validate_email(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid email format: {v}")
            return v

        @field_validator("uid")
        @classmethod
        def validate_uid(cls, v: str) -> str:
            """Validate user ID format."""
            if not FlextLdapValidations.validate_uid(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid UID format: {v}")
            return v

        @field_validator("dn")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format."""
            if not FlextLdapValidations.validate_dn(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid DN format: {v}")
            return v

        @model_validator(mode="after")
        def validate_user_consistency(self) -> LdapUser:
            """Validate user entity consistency."""
            # Ensure UID is in DN
            if f"uid={self.uid}" not in self.dn:
                raise FlextLdapExceptions.ValidationError(
                    "User DN must contain the specified UID"
                )

            # Validate password policy if password is set
            if self.user_password and isinstance(self.user_password, str):
                # Note: Password policy validation would be implemented here
                pass

            return self

        @computed_field
        def full_name(self) -> str:
            """Compute full name from given name and surname."""
            if self.given_name and self.sn:
                return f"{self.given_name} {self.sn}"
            elif self.given_name:
                return self.given_name
            elif self.sn:
                return self.sn
            else:
                return self.cn

        @computed_field
        def is_active(self) -> bool:
            """Determine if user is active based on status."""
            return self.status != "inactive" if self.status else True

        def update_password(self, new_password: str) -> FlextResult[None]:
            """Update user password with validation."""
            # Validate new password
            if not new_password or len(new_password) < 8:
                return FlextResult[None].fail("Password must be at least 8 characters")

            # In a real implementation, this would hash the password
            self.user_password = new_password
            self.modified_at = datetime.now()
            return FlextResult[None].ok(None)

        def update_contact_info(
            self,
            mail: str | None = None,
            telephone_number: str | None = None,
            mobile: str | None = None,
        ) -> FlextResult[None]:
            """Update contact information."""
            if mail is not None:
                if not FlextLdapValidations.validate_email(mail):
                    return FlextResult[None].fail(f"Invalid email format: {mail}")
                self.mail = mail

            self.telephone_number = telephone_number
            self.mobile = mobile
            self.modified_at = datetime.now()
            return FlextResult[None].ok(None)

        def deactivate(self) -> FlextResult[None]:
            """Deactivate the user."""
            self.status = "inactive"
            self.modified_at = datetime.now()
            return FlextResult[None].ok(None)

        def activate(self) -> FlextResult[None]:
            """Activate the user."""
            self.status = "active"
            self.modified_at = datetime.now()
            return FlextResult[None].ok(None)

    class Group(FlextLdapEntityBase):
        """LDAP Group entity with membership management and advanced features.

        **CENTRALIZED APPROACH**: All group operations follow centralized patterns:
        - FlextLdapEntities.Group.* for group-specific operations
        - Centralized validation through FlextLdapValidations
        - No wrappers, aliases, or fallbacks
        - Direct use of flext-core centralized models
        """

        # Core identification
        dn: str = Field(..., description="Distinguished Name (unique identifier)")
        cn: str = Field(..., description="Common Name")
        gid_number: int | None = Field(default=None, description="Group ID number")

        # Description and metadata
        description: str | None = Field(default=None, description="Group description")
        display_name: str | None = Field(default=None, description="Display Name")

        # Membership
        member: FlextTypes.StringList = Field(
            default_factory=list, description="Group members (DNs)"
        )
        unique_member: FlextTypes.StringList = Field(
            default_factory=list, description="Unique group members (DNs)"
        )
        member_of: FlextTypes.StringList = Field(
            default_factory=list, description="Groups this group is a member of"
        )
        owner: str | None = Field(default=None, description="Group owner DN")

        # LDAP metadata
        object_classes: FlextTypes.StringList = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format."""
            if not FlextLdapValidations.validate_dn(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid DN format: {v}")
            return v

        @field_validator("cn")
        @classmethod
        def validate_cn(cls, v: str) -> str:
            """Validate common name."""
            if not v or not v.strip():
                raise FlextLdapExceptions.ValidationError("Common name cannot be empty")
            return v.strip()

        @field_validator("member", "unique_member", "member_of")
        @classmethod
        def validate_member_dns(cls, v: FlextTypes.StringList) -> FlextTypes.StringList:
            """Validate member DNs."""
            for dn in v:
                if dn and not FlextLdapValidations.validate_dn(dn):
                    raise FlextLdapExceptions.ValidationError(
                        f"Invalid member DN: {dn}"
                    )
            return v

        @field_validator("owner")
        @classmethod
        def validate_owner_dn(cls, v: str | None) -> str | None:
            """Validate owner DN."""
            if v and not FlextLdapValidations.validate_dn(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid owner DN: {v}")
            return v

        @computed_field
        def member_count(self) -> int:
            """Get total number of members."""
            return len(set(self.member + self.unique_member))

        @computed_field
        def is_empty(self) -> bool:
            """Check if group has no members."""
            return self.member_count == 0

        def add_member(self, member_dn: str) -> FlextResult[None]:
            """Add a member to the group."""
            if not FlextLdapValidations.validate_dn(member_dn):
                return FlextResult[None].fail(f"Invalid member DN: {member_dn}")

            if member_dn not in self.member:
                self.member.append(member_dn)
                self.modified_at = datetime.now()
            return FlextResult[None].ok(None)

        def remove_member(self, member_dn: str) -> FlextResult[None]:
            """Remove a member from the group."""
            if member_dn in self.member:
                self.member.remove(member_dn)
                self.modified_at = datetime.now()
            elif member_dn in self.unique_member:
                self.unique_member.remove(member_dn)
                self.modified_at = datetime.now()
            else:
                return FlextResult[None].fail(f"Member not found: {member_dn}")
            return FlextResult[None].ok(None)

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group."""
            return member_dn in self.member or member_dn in self.unique_member

        def set_owner(self, owner_dn: str) -> FlextResult[None]:
            """Set the group owner."""
            if not FlextLdapValidations.validate_dn(owner_dn):
                return FlextResult[None].fail(f"Invalid owner DN: {owner_dn}")

            self.owner = owner_dn
            self.modified_at = datetime.now()
            return FlextResult[None].ok(None)

    class Entry(FlextLdapEntityBase):
        """Generic LDAP Entry entity representing any LDAP object.

        **CENTRALIZED APPROACH**: All entry operations follow centralized patterns:
        - FlextLdapEntities.Entry.* for entry-specific operations
        - Centralized validation through FlextLdapValidations
        - No wrappers, aliases, or fallbacks
        - Direct use of flext-core centralized models
        """

        # Core identification
        dn: str = Field(..., description="Distinguished Name (unique identifier)")

        # Entry data
        attributes: dict[str, FlextLdapTypes.LdapEntries.EntryAttributeValue] = Field(
            default_factory=dict, description="LDAP attributes"
        )
        object_classes: FlextTypes.StringList = Field(
            default_factory=list, description="LDAP object classes"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format."""
            if not FlextLdapValidations.validate_dn(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid DN format: {v}")
            return v

        @computed_field
        def rdn(self) -> str:
            """Get the Relative Distinguished Name."""
            return self.dn.split(",")[0]

        @computed_field
        def parent_dn(self) -> str | None:
            """Get the parent DN."""
            parts = self.dn.split(",", 1)
            return parts[1] if len(parts) > 1 else None

        def get_attribute(
            self, name: str
        ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue | None:
            """Get attribute value by name."""
            return self.attributes.get(name)

        def set_attribute(
            self, name: str, value: FlextLdapTypes.LdapEntries.EntryAttributeValue
        ) -> None:
            """Set attribute value."""
            self.attributes[name] = value
            self.modified_at = datetime.now()

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            return object_class in self.object_classes

        def add_object_class(self, object_class: str) -> None:
            """Add object class to entry."""
            if object_class not in self.object_classes:
                self.object_classes.append(object_class)
                self.modified_at = datetime.now()

    # =========================================================================
    # REQUEST/RESPONSE OBJECTS - Operation payloads
    # =========================================================================

    class SearchRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP search request with validation and advanced Pydantic 2.11 features.

        **CENTRALIZED APPROACH**: All search operations follow centralized patterns:
        - FlextLdapEntities.SearchRequest.* for request-specific operations
        - Centralized validation through FlextLdapValidations
        - No wrappers, aliases, or fallbacks
        - Direct use of flext-core centralized models
        """

        # Search parameters
        base_dn: str = Field(..., description="Base DN for search")
        filter_str: str = Field(
            default="(objectClass=*)", description="LDAP search filter"
        )
        scope: str = Field(
            default=FlextLdapConstants.Scopes.SUBTREE, description="Search scope"
        )
        attributes: FlextTypes.StringList = Field(
            default_factory=list, description="Attributes to retrieve"
        )

        # Search controls
        size_limit: int = Field(
            default=FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE,
            ge=0,
            le=FlextLdapConstants.Connection.MAX_SIZE_LIMIT,
            description="Maximum number of entries to return",
        )
        time_limit: int = Field(
            default=30, ge=0, le=300, description="Time limit in seconds"
        )

        # Paged search support
        page_size: int = Field(
            default=FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE,
            ge=0,
            description="Page size for paged results",
        )
        paged_cookie: bytes = Field(
            default=b"", description="Cookie for paged search continuation"
        )

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN format."""
            if not FlextLdapValidations.validate_dn(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid base DN: {v}")
            return v

        @field_validator("filter_str")
        @classmethod
        def validate_filter(cls, v: str) -> str:
            """Validate LDAP filter format."""
            if not FlextLdapValidations.validate_filter(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid filter: {v}")
            return v

        @field_validator("scope")
        @classmethod
        def validate_scope(cls, v: str) -> str:
            """Validate search scope."""
            if v not in FlextLdapConstants.Scopes.VALID_SCOPES:
                raise FlextLdapExceptions.ValidationError(
                    f"Invalid scope '{v}'. Must be one of: {FlextLdapConstants.Scopes.VALID_SCOPES}"
                )
            return v

        @classmethod
        def create_user_search(
            cls, uid: str, base_dn: str = "ou=users,dc=example,dc=com"
        ) -> SearchRequest:
            """Factory method to create user search request."""
            return cls(
                base_dn=base_dn,
                filter_str=f"(uid={uid})",
                scope=FlextLdapConstants.Scopes.SUBTREE,
                attributes=["uid", "cn", "sn", "mail", "givenName"],
            )

        @classmethod
        def create_group_search(
            cls, cn: str, base_dn: str = "ou=groups,dc=example,dc=com"
        ) -> SearchRequest:
            """Factory method to create group search request."""
            return cls(
                base_dn=base_dn,
                filter_str=f"(cn={cn})",
                scope=FlextLdapConstants.Scopes.SUBTREE,
                attributes=["cn", "description", "member", "owner"],
            )

    class SearchResponse(FlextLdapBaseModel):
        """LDAP search response containing results and metadata."""

        entries: list[Entry] = Field(
            default_factory=list, description="Search result entries"
        )
        total_count: int = Field(default=0, description="Total number of entries found")
        search_time: float = Field(
            default=0.0, description="Search execution time in seconds"
        )
        has_more: bool = Field(
            default=False, description="Whether more results are available"
        )

        @computed_field
        def entry_count(self) -> int:
            """Get number of entries in response."""
            return len(self.entries)

        def add_entry(self, entry: Entry) -> None:
            """Add entry to response."""
            self.entries.append(entry)
            self.total_count = len(self.entries)

        def get_entries_by_object_class(self, object_class: str) -> list[Entry]:
            """Get entries filtered by object class."""
            return [
                entry for entry in self.entries if entry.has_object_class(object_class)
            ]

    class CreateUserRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """Request object for creating LDAP users.

        **PARAMETER OBJECT PATTERN**: Consolidates user creation parameters
        into a single validated object instead of multiple function parameters.
        """

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new user")
        uid: str = Field(..., description="User ID")
        cn: str = Field(..., description="Common Name")
        sn: str = Field(..., description="Surname")

        # Optional fields
        given_name: str | None = Field(default=None, description="Given Name")
        mail: str | None = Field(default=None, description="Email address")
        user_password: str | SecretStr | None = Field(
            default=None, description="User password"
        )
        telephone_number: str | None = Field(default=None, description="Phone number")
        department: str | None = Field(default=None, description="Department")
        title: str | None = Field(default=None, description="Job title")

        # LDAP-specific
        object_classes: FlextTypes.StringList = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format."""
            if not FlextLdapValidations.validate_dn(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid DN format: {v}")
            return v

        @field_validator("uid")
        @classmethod
        def validate_uid(cls, v: str) -> str:
            """Validate user ID format."""
            if not FlextLdapValidations.validate_uid(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid UID format: {v}")
            return v

        @field_validator("mail")
        @classmethod
        def validate_email(cls, v: str | None) -> str | None:
            """Validate email format."""
            if v and not FlextLdapValidations.validate_email(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid email format: {v}")
            return v

        @model_validator(mode="after")
        def validate_request_consistency(self) -> CreateUserRequest:
            """Validate request consistency."""
            # Ensure UID is in DN
            if f"uid={self.uid}" not in self.dn:
                raise FlextLdapExceptions.ValidationError(
                    "User DN must contain the specified UID"
                )
            return self

    class CreateGroupRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """Request object for creating LDAP groups.

        **PARAMETER OBJECT PATTERN**: Consolidates group creation parameters
        into a single validated object instead of multiple function parameters.
        """

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new group")
        cn: str = Field(..., description="Common Name")

        # Optional fields
        description: str | None = Field(default=None, description="Group description")
        owner: str | None = Field(default=None, description="Group owner DN")
        member: FlextTypes.StringList = Field(
            default_factory=list, description="Initial group members"
        )

        # LDAP-specific
        object_classes: FlextTypes.StringList = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format."""
            if not FlextLdapValidations.validate_dn(v):
                raise FlextLdapExceptions.ValidationError(f"Invalid DN format: {v}")
            return v

        @field_validator("owner", "member")
        @classmethod
        def validate_dns(cls, v: str | list[str] | None) -> str | list[str] | None:
            """Validate DN formats."""
            if isinstance(v, str):
                if v and not FlextLdapValidations.validate_dn(v):
                    raise FlextLdapExceptions.ValidationError(f"Invalid DN: {v}")
            elif isinstance(v, list):
                for dn in v:
                    if dn and not FlextLdapValidations.validate_dn(dn):
                        raise FlextLdapExceptions.ValidationError(f"Invalid DN: {dn}")
            return v
