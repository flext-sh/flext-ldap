"""Domain entities for flext-ldap with Pydantic v2 validation.

This module defines the core domain entities for LDAP operations, including
User, Group, Entry, and request objects. All entities use Pydantic v2 for
type-safe domain modeling with proper validation and serialization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from flext_core import FlextLogger
from flext_ldap.constants import FlextLdapConstants

_logger = FlextLogger(__name__)


class FlextLdapEntities:
    """Namespace class for all LDAP domain entities with Pydantic v2 validation.

    This class provides a unified namespace for all domain entities in flext-ldap,
    implementing Clean Architecture patterns with proper domain modeling.
    """

    class Entry(BaseModel):
        """LDAP entry domain entity representing a directory object.

        This entity represents a complete LDAP directory entry with DN and attributes.
        Used throughout the domain for search results, modifications, and data transfer.

        Attributes:
            dn: Distinguished name of the entry (required)
            attributes: Dictionary of LDAP attributes and their values
            raw_attributes: Optional raw attribute data from ldap3

        """

        dn: str = Field(..., description="Distinguished name of the LDAP entry")
        attributes: dict[str, str | list[str] | bytes | list[bytes]] = Field(
            default_factory=dict, description="LDAP attributes as key-value pairs"
        )
        raw_attributes: dict[str, Any] | None = Field(
            default=None, description="Raw attributes from ldap3 library"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format using domain validation."""
            if not v or not v.strip():
                raise PydanticCustomError("dn_empty", "DN cannot be empty")

            # Basic DN format validation
            if "=" not in v:
                raise PydanticCustomError(
                    "dn_invalid", "DN must contain attribute=value pairs"
                )

            return v.strip()

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> FlextLdapEntities.Entry:
            """Validate overall entry consistency."""
            # Ensure DN is consistent with object classes if present
            object_classes = self.attributes.get("objectClass", [])
            if isinstance(object_classes, str):
                object_classes = [object_classes]
            elif not isinstance(object_classes, list):
                object_classes = []

            # Log validation for debugging
            _logger.debug(
                "Entry validation completed",
                dn=self.dn,
                attribute_count=len(self.attributes),
                object_classes=object_classes,
            )

            return self

        @classmethod
        def from_ldap3_entry(cls, ldap3_entry: Any) -> FlextLdapEntities.Entry:
            """Create Entry from ldap3 Entry object."""
            try:
                return cls(
                    dn=str(ldap3_entry.entry_dn),
                    attributes=dict(ldap3_entry.entry_attributes),
                    raw_attributes=dict(ldap3_entry.entry_raw_attributes),
                )
            except Exception as e:
                _logger.error("Failed to create Entry from ldap3", error=str(e))
                raise

        def get_attribute(self, name: str, default: Any = None) -> Any:
            """Get single attribute value with optional default."""
            return self.attributes.get(name, default)

        def get_attribute_list(self, name: str) -> list[str]:
            """Get attribute as list, handling single values."""
            value = self.attributes.get(name, [])
            if isinstance(value, str):
                return [value]
            if isinstance(value, list):
                return [str(v) for v in value]
            return [str(value)]

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            object_classes = self.get_attribute_list("objectClass")
            return object_class.lower() in [oc.lower() for oc in object_classes]

    class User(Entry):
        """User entity extending Entry with user-specific attributes and validation.

        Represents an LDAP user with common user attributes like uid, cn, mail, etc.
        Includes validation for user-specific constraints and business rules.
        """

        # User-specific fields with validation
        uid: str | None = Field(default=None, description="User ID")
        cn: str | None = Field(default=None, description="Common name")
        sn: str | None = Field(default=None, description="Surname")
        mail: str | None = Field(default=None, description="Email address")
        given_name: str | None = Field(default=None, description="Given name")
        display_name: str | None = Field(default=None, description="Display name")
        user_password: bytes | None = Field(default=None, description="Password hash")

        @model_validator(mode="after")
        def validate_user_attributes(self) -> FlextLdapEntities.User:
            """Validate user-specific attributes and business rules."""
            # Extract from attributes if not set directly
            if not self.uid:
                self.uid = self.get_attribute("uid")
            if not self.cn:
                self.cn = self.get_attribute("cn")
            if not self.sn:
                self.sn = self.get_attribute("sn")
            if not self.mail:
                self.mail = self.get_attribute("mail")
            if not self.given_name:
                self.given_name = self.get_attribute("givenName")
            if not self.display_name:
                self.display_name = self.get_attribute("displayName")

            # Validate user has basic required attributes
            if not self.uid:
                raise PydanticCustomError("user_no_uid", "User must have uid attribute")

            # Validate email format if present
            if self.mail and "@" not in self.mail:
                raise PydanticCustomError(
                    "user_invalid_email", "Email must contain @ symbol"
                )

            return self

        @property
        def full_name(self) -> str:
            """Get user's full name from available attributes."""
            if self.display_name:
                return self.display_name
            if self.given_name and self.sn:
                return f"{self.given_name} {self.sn}"
            if self.cn:
                return self.cn
            return self.uid or "Unknown User"

        def is_active(self) -> bool:
            """Check if user is active based on common LDAP patterns."""
            # Check for disabled accounts (common patterns)
            disabled_attrs = [
                "nsAccountLock",
                "userAccountControl",
                "ds-pwp-account-disabled",
            ]
            for attr in disabled_attrs:
                value = self.get_attribute(attr)
                if value:
                    return False
            return True

    class Group(Entry):
        """Group entity extending Entry with group-specific attributes and validation.

        Represents an LDAP group with members, description, and group-specific validation.
        """

        cn: str | None = Field(default=None, description="Common name")
        description: str | None = Field(default=None, description="Group description")
        member: list[str] | None = Field(default=None, description="Group members")
        member_uid: list[str] | None = Field(default=None, description="Member UIDs")
        gid_number: int | None = Field(default=None, description="Group ID number")

        @model_validator(mode="after")
        def validate_group_attributes(self) -> FlextLdapEntities.Group:
            """Validate group-specific attributes."""
            # Extract from attributes if not set directly
            if not self.cn:
                self.cn = self.get_attribute("cn")
            if not self.description:
                self.description = self.get_attribute("description")
            if not self.member:
                self.member = self.get_attribute_list("member")
            if not self.member_uid:
                self.member_uid = self.get_attribute_list("memberUid")

            # Parse gidNumber if present
            if not self.gid_number:
                gid_str = self.get_attribute("gidNumber")
                if gid_str:
                    try:
                        self.gid_number = int(gid_str)
                    except ValueError:
                        _logger.warning("Invalid gidNumber format", gid=gid_str)

            return self

        def has_member(self, dn: str) -> bool:
            """Check if DN is a member of this group."""
            if not self.member:
                return False
            return dn in self.member

        def member_count(self) -> int:
            """Get number of group members."""
            return len(self.member or [])

    class SearchRequest(BaseModel):
        """Parameter object for LDAP search requests.

        Implements Parameter Object pattern to avoid long parameter lists
        and provide structured search configuration.
        """

        base_dn: str = Field(..., description="Base DN for search")
        filter_str: str = Field(..., description="LDAP filter string")
        scope: str = Field(
            default=FlextLdapConstants.Scopes.SUBTREE, description="Search scope"
        )
        attributes: list[str] | None = Field(
            default=None, description="Attributes to retrieve"
        )
        size_limit: int = Field(
            default=FlextLdapConstants.Connection.DEFAULT_SIZE_LIMIT,
            ge=0,
            description="Maximum number of entries to return",
        )
        time_limit: int = Field(
            default=FlextLdapConstants.Connection.DEFAULT_TIME_LIMIT,
            ge=0,
            description="Time limit in seconds",
        )
        page_size: int = Field(
            default=FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE,
            ge=0,
            description="Page size for paged results",
        )
        paged_cookie: bytes = Field(
            default=b"", description="Cookie for paged results continuation"
        )

        @field_validator("scope")
        @classmethod
        def validate_scope(cls, v: str) -> str:
            """Validate search scope."""
            valid_scopes = [
                FlextLdapConstants.Scopes.BASE,
                FlextLdapConstants.Scopes.ONE,
                FlextLdapConstants.Scopes.SUBTREE,
            ]
            if v not in valid_scopes:
                raise PydanticCustomError(
                    "scope_invalid",
                    "Scope must be one of: {scopes}",
                    {"scopes": ", ".join(valid_scopes)},
                )
            return v

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN format."""
            if not v or not v.strip():
                raise PydanticCustomError("base_dn_empty", "Base DN cannot be empty")
            return v.strip()

        @field_validator("filter_str")
        @classmethod
        def validate_filter(cls, v: str) -> str:
            """Validate LDAP filter format."""
            if not v or not v.strip():
                raise PydanticCustomError("filter_empty", "Filter cannot be empty")

            # Basic filter validation
            v = v.strip()
            if not (v.startswith("(") and v.endswith(")")):
                # Auto-wrap simple filters
                if "=" in v and not any(op in v for op in ["&", "|", "!", "("]):
                    v = f"({v})"
                else:
                    raise PydanticCustomError(
                        "filter_invalid",
                        "Filter must be properly formatted LDAP filter",
                    )

            return v

        @classmethod
        def create_user_search(
            cls,
            uid: str,
            base_dn: str = "ou=users,dc=example,dc=com",
            attributes: list[str] | None = None,
        ) -> FlextLdapEntities.SearchRequest:
            """Factory method for common user search requests."""
            if not uid:
                raise ValueError("User ID cannot be empty")

            return cls(
                base_dn=base_dn,
                filter_str=f"(uid={uid})",
                scope=FlextLdapConstants.Scopes.SUBTREE,
                attributes=attributes or ["uid", "cn", "sn", "mail", "givenName"],
            )

        @classmethod
        def create_group_search(
            cls,
            cn: str,
            base_dn: str = "ou=groups,dc=example,dc=com",
            attributes: list[str] | None = None,
        ) -> FlextLdapEntities.SearchRequest:
            """Factory method for common group search requests."""
            if not cn:
                raise ValueError("Group CN cannot be empty")

            return cls(
                base_dn=base_dn,
                filter_str=f"(cn={cn})",
                scope=FlextLdapConstants.Scopes.SUBTREE,
                attributes=attributes or ["cn", "description", "member", "memberUid"],
            )

    class CreateUserRequest(BaseModel):
        """Parameter object for user creation requests.

        Implements Parameter Object pattern for user creation with validation
        and business rule enforcement.
        """

        dn: str = Field(..., description="Distinguished name for new user")
        uid: str = Field(..., description="User ID")
        cn: str = Field(..., description="Common name")
        sn: str = Field(..., description="Surname")
        mail: str | None = Field(default=None, description="Email address")
        given_name: str | None = Field(default=None, description="Given name")
        user_password: str | None = Field(default=None, description="Password")
        object_classes: list[str] = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
        )

        @field_validator("uid", "cn", "sn")
        @classmethod
        def validate_required_fields(cls, v: str, info) -> str:
            """Validate required string fields."""
            field_name = info.field_name
            if not v or not v.strip():
                raise PydanticCustomError(
                    f"{field_name}_empty", f"{field_name.upper()} cannot be empty"
                )
            return v.strip()

        @field_validator("dn")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format for user creation."""
            if not v or not v.strip():
                raise PydanticCustomError("dn_empty", "DN cannot be empty")

            # Should contain uid attribute
            if "uid=" not in v:
                raise PydanticCustomError(
                    "dn_no_uid", "User DN should contain uid attribute"
                )

            return v.strip()

        @field_validator("mail")
        @classmethod
        def validate_email(cls, v: str | None) -> str | None:
            """Validate email format if provided."""
            if v and "@" not in v:
                raise PydanticCustomError(
                    "email_invalid", "Email must contain @ symbol"
                )
            return v

        @model_validator(mode="after")
        def validate_request_consistency(self) -> FlextLdapEntities.CreateUserRequest:
            """Validate overall request consistency."""
            # Ensure DN contains the uid
            if f"uid={self.uid}" not in self.dn:
                raise PydanticCustomError(
                    "dn_uid_mismatch", "DN must contain the specified uid"
                )

            # Validate object classes are appropriate for users
            required_classes = ["person"]
            if not any(cls in self.object_classes for cls in required_classes):
                self.object_classes.extend(required_classes)

            return self

        def to_attributes(self) -> dict[str, Any]:
            """Convert request to LDAP attributes dictionary."""
            attrs = {
                "objectClass": self.object_classes,
                "uid": self.uid,
                "cn": self.cn,
                "sn": self.sn,
            }

            if self.mail:
                attrs["mail"] = self.mail
            if self.given_name:
                attrs["givenName"] = self.given_name
            if self.user_password:
                attrs["userPassword"] = self.user_password

            return attrs

    class SearchResponse(BaseModel):
        """Response object for search operations.

        Contains search results with metadata about the operation.
        """

        entries: list[FlextLdapEntities.Entry] = Field(
            default_factory=list, description="Search result entries"
        )
        total_count: int = Field(default=0, description="Total number of entries found")
        search_time: float = Field(
            default=0.0, description="Search execution time in seconds"
        )
        is_complete: bool = Field(
            default=True, description="Whether search returned all results"
        )
        next_page_cookie: bytes | None = Field(
            default=None, description="Cookie for next page"
        )

        @property
        def entry_count(self) -> int:
            """Get number of entries returned."""
            return len(self.entries)

        def get_entries_by_class(
            self, object_class: str
        ) -> list[FlextLdapEntities.Entry]:
            """Filter entries by object class."""
            return [e for e in self.entries if e.has_object_class(object_class)]

        def get_users(self) -> list[FlextLdapEntities.User]:
            """Get user entries from results."""
            user_entries = self.get_entries_by_class("person")
            return [
                FlextLdapEntities.User(**entry.model_dump()) for entry in user_entries
            ]

        def get_groups(self) -> list[FlextLdapEntities.Group]:
            """Get group entries from results."""
            group_entries = self.get_entries_by_class("groupOfNames")
            return [
                FlextLdapEntities.Group(**entry.model_dump()) for entry in group_entries
            ]


__all__ = [
    "FlextLdapEntities",
]
