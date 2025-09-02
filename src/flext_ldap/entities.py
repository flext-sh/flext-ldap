"""LDAP Entities - Single FlextLDAPEntities class following FLEXT patterns.

Single class with all LDAP domain entities implementing rich business objects
organized as internal classes for complete backward compatibility.

Examples:
    Search operations::

        from entities import FlextLDAPEntities

        # Create search request
        request = FlextLDAPEntities.SearchRequest(
            base_dn="dc=example,dc=com", filter_str="(uid=john)"
        )

        # Process response
        response = FlextLDAPEntities.SearchResponse(entries=[...])

    Entity operations::

        # Create user
        user = FlextLDAPEntities.User(
            dn="cn=john,ou=users,dc=example,dc=com", uid="john", cn="John Doe"
        )

        # Create group
        group = FlextLDAPEntities.Group(
            dn="cn=admins,ou=groups,dc=example,dc=com", cn="Administrators"
        )

    Legacy compatibility::

        # All previous classes still work as direct imports
        from entities import FlextLDAPUser, FlextLDAPSearchRequest

        user = FlextLDAPUser(dn="cn=user,dc=example,dc=com", uid="user")

"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast, override

from flext_core import (
    FlextLogger,
    FlextModels,
    FlextResult,
)
from pydantic import Field, field_validator

from flext_ldap.typings import LdapAttributeDict, LdapAttributeValue, LdapSearchResult
from flext_ldap.value_objects import FlextLDAPDistinguishedName

# Type alias for explicit pyright recognition
DictEntry = dict[str, object]

logger = FlextLogger(__name__)

# =============================================================================
# SINGLE FLEXT LDAP ENTITIES CLASS - Consolidated entity functionality
# =============================================================================


class FlextLDAPEntities:
    """Single FlextLDAPEntities class with all LDAP domain entities.

    Consolidates ALL LDAP entities into a single class following FLEXT patterns.
    Everything from search requests to domain entities is available as internal classes
    with full backward compatibility and rich business logic.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP entities consolidated
        - Open/Closed: Extensible without modification
        - Liskov Substitution: Consistent interface across all entities
        - Interface Segregation: Organized by entity type for specific access
        - Dependency Inversion: Depends on FlextModels/FlextModels abstractions

    Examples:
        Search operations::

            request = FlextLDAPEntities.SearchRequest(
                base_dn="dc=example,dc=com", filter_str="(uid=john)"
            )
            response = FlextLDAPEntities.SearchResponse(entries=[...])

        Domain entities::

            user = FlextLDAPEntities.User(
                dn="cn=john,ou=users,dc=example,dc=com", uid="john", cn="John Doe"
            )
            group = FlextLDAPEntities.Group(
                dn="cn=admins,ou=groups,dc=example,dc=com", cn="Administrators"
            )

        Request models::

            create_request = FlextLDAPEntities.CreateUserRequest(
                dn="cn=newuser,ou=users,dc=example,dc=com", uid="newuser", cn="New User"
            )

    """

    # =========================================================================
    # SEARCH MODELS - Request and response models for search operations
    # =========================================================================

    class SearchRequest(FlextModels.Value):
        """Request model for LDAP search operations."""

        base_dn: str = Field(..., description="Base DN for search")
        scope: str = Field(default="subtree", description="Search scope")
        filter_str: str = Field(
            default="(objectClass=*)",
            description="LDAP search filter",
        )
        attributes: list[str] | None = Field(
            None,
            description="Attributes to retrieve (None for all)",
        )
        size_limit: int = Field(
            1000,
            description="Maximum number of entries to return",
            gt=0,
            le=10000,
        )
        time_limit: int = Field(
            30,
            description="Search time limit in seconds",
            gt=0,
            le=300,
        )

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate search request business rules."""
            if not self.base_dn:
                return FlextResult[None].fail("Base DN cannot be empty")
            if not self.filter_str:
                return FlextResult[None].fail("Filter cannot be empty")
            return FlextResult[None].ok(None)

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN format."""
            try:
                FlextLDAPDistinguishedName(value=v)
                return v
            except ValueError as e:
                msg = f"Invalid base DN format: {e}"
                raise ValueError(msg) from e

        @field_validator("filter_str")
        @classmethod
        def validate_filter(cls, v: str) -> str:
            """Validate filter format."""
            if not v.startswith("(") or not v.endswith(")"):
                msg = "LDAP filter must be enclosed in parentheses"
                raise ValueError(msg)
            return v

    class SearchResponse(FlextModels.Value):
        """Response model for LDAP searches."""

        entries: list[LdapSearchResult] = Field(
            default_factory=lambda: cast("list[LdapSearchResult]", []),
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

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate search response business rules."""
            if self.total_count < 0:
                return FlextResult[None].fail("Total count cannot be negative")
            if self.search_time_ms < 0:
                return FlextResult[None].fail("Search time cannot be negative")
            return FlextResult[None].ok(None)

    # =========================================================================
    # DOMAIN ENTITIES - Rich LDAP domain objects
    # =========================================================================

    class Entry(FlextModels.Entity):
        """Base LDAP directory entry implementing rich domain model patterns."""

        # Override id field with validator to convert EntityId to str
        id: str = Field(..., description="Entity identifier")

        @field_validator("id", mode="before")
        @classmethod
        def convert_entity_id(cls, v: object) -> str:
            """Convert EntityId to string if needed."""
            if isinstance(v, FlextModels):
                return str(v)
            return str(v)

        dn: str = Field(..., description="Distinguished Name")
        object_classes: list[str] = Field(
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
            default_factory=lambda: datetime.now(UTC),
            description="Creation timestamp",
        )
        modified_at: datetime | None = Field(
            None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format."""
            try:
                FlextLDAPDistinguishedName(value=v)
                return v
            except ValueError as e:
                msg = f"Invalid DN format: {e}"
                raise ValueError(msg) from e

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules."""
            if not self.object_classes:
                return FlextResult[None].fail(
                    "Entry must have at least one object class"
                )
            return FlextResult[None].ok(None)

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
            object.__setattr__(self, "modified_at", datetime.now(UTC))

    class User(Entry):
        """LDAP user entity with user-specific validation."""

        uid: str = Field(..., description="User ID")
        cn: str | None = Field(None, description="Common Name")
        sn: str | None = Field(None, description="Surname")
        given_name: str | None = Field(None, description="Given Name")
        mail: str | None = Field(None, description="Email address")
        user_password: str | None = Field(None, description="User password")

        @field_validator("mail")
        @classmethod
        def validate_email(cls, v: str | None) -> str | None:
            """Validate email format - USES FLEXT-CORE."""
            from flext_core import FlextValidations

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
                return FlextResult[None].fail("User must have 'person' object class")

            if not self.cn and not self.get_attribute("cn"):
                return FlextResult[None].fail("User must have a Common Name")

            return FlextResult[None].ok(None)

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
        members: list[str] = Field(
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
                return FlextResult[None].fail(
                    "Group must have 'groupOfNames' object class"
                )

            return FlextResult[None].ok(None)

        def add_member(self, member_dn: str) -> None:
            """Add member to group."""
            if member_dn not in self.members:
                self.members.append(member_dn)
                self.modified_at = datetime.now(UTC)

        def remove_member(self, member_dn: str) -> None:
            """Remove member from group."""
            if member_dn in self.members:
                self.members.remove(member_dn)
                self.modified_at = datetime.now(UTC)

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
        user_password: str | None = Field(None, description="User password")
        object_classes: list[str] = Field(
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
                return FlextResult[None].fail("DN cannot be empty")
            if not self.uid:
                return FlextResult[None].fail("UID cannot be empty")
            if not self.cn:
                return FlextResult[None].fail("Common Name cannot be empty")
            return FlextResult[None].ok(None)

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format."""
            try:
                FlextLDAPDistinguishedName(value=v)
                return v
            except ValueError as e:
                msg = f"Invalid DN format: {e}"
                raise ValueError(msg) from e

        @field_validator("mail")
        @classmethod
        def validate_email(cls, v: str | None) -> str | None:
            """Validate email format - USES FLEXT-CORE."""
            from flext_core import FlextValidations

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


# =============================================================================
# LEGACY COMPATIBILITY CLASSES - Backward Compatibility
# =============================================================================

# Legacy class aliases for backward compatibility
FlextLDAPSearchRequest = FlextLDAPEntities.SearchRequest
FlextLDAPSearchResponse = FlextLDAPEntities.SearchResponse
FlextLDAPEntry = FlextLDAPEntities.Entry
FlextLDAPUser = FlextLDAPEntities.User
FlextLDAPGroup = FlextLDAPEntities.Group
FlextLDAPCreateUserRequest = FlextLDAPEntities.CreateUserRequest


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Type alias
    "DictEntry",
    "FlextLDAPCreateUserRequest",
    # Primary consolidated class
    "FlextLDAPEntities",
    "FlextLDAPEntry",
    "FlextLDAPGroup",
    # Legacy compatibility classes
    "FlextLDAPSearchRequest",
    "FlextLDAPSearchResponse",
    "FlextLDAPUser",
]
