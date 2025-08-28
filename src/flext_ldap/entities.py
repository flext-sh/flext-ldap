"""LDAP Entities - Single FlextLdapEntities class following FLEXT patterns.

Single class with all LDAP domain entities implementing rich business objects
organized as internal classes for complete backward compatibility.

Examples:
    Search operations::

        from entities import FlextLdapEntities

        # Create search request
        request = FlextLdapEntities.SearchRequest(
            base_dn="dc=example,dc=com", filter_str="(uid=john)"
        )

        # Process response
        response = FlextLdapEntities.SearchResponse(entries=[...])

    Entity operations::

        # Create user
        user = FlextLdapEntities.User(
            dn="cn=john,ou=users,dc=example,dc=com", uid="john", cn="John Doe"
        )

        # Create group
        group = FlextLdapEntities.Group(
            dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com", cn="Administrators"
        )

    Legacy compatibility::

        # All previous classes still work as direct imports
        from entities import FlextLdapUser, FlextLdapSearchRequest

        user = FlextLdapUser(dn="cn=user,dc=example,dc=com", uid="user")

"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast, override

from flext_core import (
    FlextEntity,
    FlextModel,
    FlextModels,
    FlextResult,
    get_logger,
)
from pydantic import Field, field_validator

from flext_ldap.typings import LdapAttributeDict, LdapAttributeValue, LdapSearchResult
from flext_ldap.value_objects import FlextLdapDistinguishedName

# Type alias for explicit pyright recognition
DictEntry = dict[str, object]

logger = get_logger(__name__)

# =============================================================================
# SINGLE FLEXT LDAP ENTITIES CLASS - Consolidated entity functionality
# =============================================================================


class FlextLdapEntities:
    """Single FlextLdapEntities class with all LDAP domain entities.

    Consolidates ALL LDAP entities into a single class following FLEXT patterns.
    Everything from search requests to domain entities is available as internal classes
    with full backward compatibility and rich business logic.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP entities consolidated
        - Open/Closed: Extensible without modification
        - Liskov Substitution: Consistent interface across all entities
        - Interface Segregation: Organized by entity type for specific access
        - Dependency Inversion: Depends on FlextEntity/FlextModel abstractions

    Examples:
        Search operations::

            request = FlextLdapEntities.SearchRequest(
                base_dn="dc=example,dc=com", filter_str="(uid=john)"
            )
            response = FlextLdapEntities.SearchResponse(entries=[...])

        Domain entities::

            user = FlextLdapEntities.User(
                dn="cn=john,ou=users,dc=example,dc=com", uid="john", cn="John Doe"
            )
            group = FlextLdapEntities.Group(
                dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com", cn="Administrators"
            )

        Request models::

            create_request = FlextLdapEntities.CreateUserRequest(
                dn="cn=newuser,ou=users,dc=example,dc=com", uid="newuser", cn="New User"
            )

    """

    # =========================================================================
    # SEARCH MODELS - Request and response models for search operations
    # =========================================================================

    class SearchRequest(FlextModel):
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

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN format."""
            try:
                FlextLdapDistinguishedName(value=v)
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

    class SearchResponse(FlextModel):
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

    # =========================================================================
    # DOMAIN ENTITIES - Rich LDAP domain objects
    # =========================================================================

    class Entry(FlextEntity):
        """Base LDAP directory entry implementing rich domain model patterns."""

        dn: str = Field(..., description="Distinguished Name")
        object_classes: list[str] = Field(
            default_factory=list,
            description="LDAP object classes",
        )
        attributes: LdapAttributeDict = Field(
            default_factory=dict,
            description="LDAP attributes dictionary",
        )

        # Entity metadata
        created_at: FlextModels.Timestamp = Field(
            default_factory=lambda: FlextModels.Timestamp(datetime.now(UTC)),
            description="Creation timestamp",
        )
        modified_at: FlextModels.Timestamp | None = Field(
            None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format."""
            try:
                FlextLdapDistinguishedName(value=v)
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
            self.modified_at = FlextModels.Timestamp(datetime.now(UTC))

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
            from flext_core import FlextValidation

            if v:
                result = FlextValidation.Rules.StringRules.validate_email(v)
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
                self.modified_at = FlextModels.Timestamp(datetime.now(UTC))

        def remove_member(self, member_dn: str) -> None:
            """Remove member from group."""
            if member_dn in self.members:
                self.members.remove(member_dn)
                self.modified_at = FlextModels.Timestamp(datetime.now(UTC))

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group."""
            return member_dn in self.members

    # =========================================================================
    # REQUEST MODELS - Operation request models
    # =========================================================================

    class CreateUserRequest(FlextModel):
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

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format."""
            try:
                FlextLdapDistinguishedName(value=v)
                return v
            except ValueError as e:
                msg = f"Invalid DN format: {e}"
                raise ValueError(msg) from e

        @field_validator("mail")
        @classmethod
        def validate_email(cls, v: str | None) -> str | None:
            """Validate email format - USES FLEXT-CORE."""
            from flext_core import FlextValidation

            if v:
                result = FlextValidation.Rules.StringRules.validate_email(v)
                if not result.is_success:
                    msg = "Invalid email format"
                    raise ValueError(msg)
            return v

        def to_user_entity(self) -> FlextLdapEntities.User:
            """Convert request to user entity."""
            return FlextLdapEntities.User(
                id=FlextEntityId(f"user_{self.uid}"),
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
FlextLdapSearchRequest = FlextLdapEntities.SearchRequest
FlextLdapSearchResponse = FlextLdapEntities.SearchResponse
FlextLdapEntry = FlextLdapEntities.Entry
FlextLdapUser = FlextLdapEntities.User
FlextLdapGroup = FlextLdapEntities.Group
FlextLdapCreateUserRequest = FlextLdapEntities.CreateUserRequest


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Type alias
    "DictEntry",
    "FlextLdapCreateUserRequest",
    # Primary consolidated class
    "FlextLdapEntities",
    "FlextLdapEntry",
    "FlextLdapGroup",
    # Legacy compatibility classes
    "FlextLdapSearchRequest",
    "FlextLdapSearchResponse",
    "FlextLdapUser",
]
