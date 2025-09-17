"""Domain entities for flext-ldap.

This module defines the core domain entities for LDAP operations
using Pydantic v2 models and Clean Architecture patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
)

from flext_core import (
    FlextEntities,
    FlextResult,
)
from flext_ldap.typings import FlextLdapTypes

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


class FlextLdapEntities(FlextEntities):
    """Single FlextLdapEntities class consolidating ALL LDAP entities.

    Consolidates ALL LDAP entity types into a single class following FLEXT patterns.
    Everything from the previous entity definitions is now available as
    internal classes with full backward compatibility.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP entities in one place
        - Open/Closed: Extends FlextEntities without modification
        - Liskov Substitution: Can be used anywhere FlextEntities is expected
        - Interface Segregation: Organized by domain for specific access
        - Dependency Inversion: Depends on FlextEntities abstraction

    Examples:
        Basic entities::

            user: FlextLdapEntities.User = FlextLdapEntities.User(
                dn="cn=john,ou=users,dc=example,dc=com", cn="John Doe"
            )

            group: FlextLdapEntities.Group = FlextLdapEntities.Group(
                dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
                member_dns=["cn=john,ou=users,dc=example,dc=com"],
            )

        LDAP operations::

            search: FlextLdapEntities.SearchRequest = FlextLdapEntities.SearchRequest(
                base_dn="ou=users,dc=example,dc=com",
                filter_str="(objectClass=person)",
                scope="subtree",
            )

    """

    # =========================================================================
    # CORE LDAP ENTITIES - Primary Domain Objects
    # =========================================================================

    class User(BaseModel):
        """LDAP User entity with enterprise attributes."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
            populate_by_name=True,
        )

        # Core identification
        dn: str = Field(..., description="Distinguished Name (unique identifier)")
        cn: str = Field(..., description="Common Name")
        uid: str | None = Field(None, description="User ID")
        sn: str | None = Field(None, description="Surname")
        given_name: str | None = Field(
            None, description="Given Name", alias="givenName"
        )

        # Contact information
        mail: str | None = Field(None, description="Primary email address")
        telephone_number: str | None = Field(
            None, description="Primary phone number", alias="telephoneNumber"
        )
        mobile: str | None = Field(None, description="Mobile phone number")

        # Organizational
        department: str | None = Field(None, description="Department")
        title: str | None = Field(None, description="Job title")
        organization: str | None = Field(None, description="Organization", alias="o")
        organizational_unit: str | None = Field(
            None, description="Organizational Unit", alias="ou"
        )

        # Authentication
        user_password: SecretStr | None = Field(
            None, description="User password", alias="userPassword"
        )

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
            alias="objectClass",
        )

        # Additional attributes as flexible dict
        additional_attributes: dict[str, FlextLdapTypes.Entry.AttributeValue] = Field(
            default_factory=dict, description="Additional LDAP attributes"
        )

        # Timestamps
        created_timestamp: datetime | None = Field(
            None, description="Creation timestamp", alias="createTimestamp"
        )
        modified_timestamp: datetime | None = Field(
            None, description="Last modification timestamp", alias="modifyTimestamp"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            if not v or not v.strip():
                raise ValueError("DN cannot be empty")
            if "=" not in v:
                raise ValueError("DN must contain at least one attribute=value pair")
            return v.strip()

        @field_validator("object_classes")
        @classmethod
        def validate_object_classes(cls, v: list[str]) -> list[str]:
            """Validate object classes."""
            if not v:
                raise ValueError("At least one object class is required")
            return v

        def get_attribute(
            self, name: str
        ) -> FlextLdapTypes.Entry.AttributeValue | None:
            """Get attribute value by name."""
            return self.additional_attributes.get(name)

        def set_attribute(
            self, name: str, value: FlextLdapTypes.Entry.AttributeValue
        ) -> None:
            """Set attribute value by name."""
            self.additional_attributes[name] = value

        def get_rdn(self) -> str:
            """Extract Relative Distinguished Name (first component)."""
            return self.dn.split(",")[0] if "," in self.dn else self.dn

        def get_parent_dn(self) -> str | None:
            """Extract parent DN."""
            parts = self.dn.split(",", 1)
            return parts[1] if len(parts) > 1 else None

    class Group(BaseModel):
        """LDAP Group entity with membership management."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
            populate_by_name=True,
        )

        # Core identification
        dn: str = Field(..., description="Distinguished Name")
        cn: str = Field(..., description="Common Name")
        gid_number: int | None = Field(
            None, description="Group ID Number", alias="gidNumber"
        )

        # Group membership
        member_dns: list[str] = Field(
            default_factory=list,
            description="Member Distinguished Names",
            alias="member",
        )
        unique_member_dns: list[str] = Field(
            default_factory=list,
            description="Unique Member Distinguished Names",
            alias="uniqueMember",
        )

        # Metadata
        description: str | None = Field(None, description="Group description")
        object_classes: list[str] = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
            alias="objectClass",
        )

        # Additional attributes
        additional_attributes: dict[str, FlextLdapTypes.Entry.AttributeValue] = Field(
            default_factory=dict, description="Additional LDAP attributes"
        )

        # Timestamps
        created_timestamp: datetime | None = Field(
            None, description="Creation timestamp", alias="createTimestamp"
        )
        modified_timestamp: datetime | None = Field(
            None, description="Last modification timestamp", alias="modifyTimestamp"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            if not v or not v.strip():
                raise ValueError("DN cannot be empty")
            return v.strip()

        def add_member(self, member_dn: str) -> None:
            """Add member to group."""
            if member_dn not in self.member_dns:
                self.member_dns.append(member_dn)

        def remove_member(self, member_dn: str) -> None:
            """Remove member from group."""
            if member_dn in self.member_dns:
                self.member_dns.remove(member_dn)

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group."""
            return member_dn in self.member_dns or member_dn in self.unique_member_dns

    class Entry(BaseModel):
        """Generic LDAP Entry entity."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
            populate_by_name=True,
        )

        # Core identification
        dn: str = Field(..., description="Distinguished Name")

        # LDAP attributes as flexible dict
        attributes: dict[str, FlextLdapTypes.Entry.AttributeValue] = Field(
            default_factory=dict, description="LDAP entry attributes"
        )

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=list,
            description="LDAP object classes",
            alias="objectClass",
        )

        # Timestamps
        created_timestamp: datetime | None = Field(
            None, description="Creation timestamp", alias="createTimestamp"
        )
        modified_timestamp: datetime | None = Field(
            None, description="Last modification timestamp", alias="modifyTimestamp"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            if not v or not v.strip():
                msg = "DN cannot be empty"
                raise ValueError(msg)
            return v.strip()

        def get_attribute(
            self, name: str
        ) -> FlextLdapTypes.Entry.AttributeValue | None:
            """Get attribute value by name."""
            return self.attributes.get(name)

        def set_attribute(
            self, name: str, value: FlextLdapTypes.Entry.AttributeValue
        ) -> None:
            """Set attribute value by name."""
            self.attributes[name] = value

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return name in self.attributes

        def get_rdn(self) -> str:
            """Extract Relative Distinguished Name."""
            return self.dn.split(",")[0] if "," in self.dn else self.dn

    # =========================================================================
    # LDAP OPERATION ENTITIES - Request/Response Objects
    # =========================================================================

    class SearchRequest(BaseModel):
        """LDAP Search Request entity with comprehensive parameters."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
        )

        # Search scope
        base_dn: str = Field(..., description="Search base Distinguished Name")
        filter_str: str = Field(..., description="LDAP search filter", alias="filter")
        scope: str = Field(
            default="subtree",
            description="Search scope: base, onelevel, subtree",
            pattern="^(base|onelevel|subtree)$",
        )

        # Attribute selection
        attributes: list[str] = Field(
            default_factory=list, description="Attributes to return (empty = all)"
        )

        # Search limits
        size_limit: int = Field(
            default=1000, description="Maximum number of entries to return", ge=0
        )
        time_limit: int = Field(
            default=60, description="Search timeout in seconds", ge=0
        )

        # Paging
        page_size: int | None = Field(
            None, description="Page size for paged results", ge=1
        )
        paged_cookie: bytes | None = Field(
            None, description="Paging cookie for continuation"
        )

        # Advanced options
        types_only: bool = Field(
            default=False, description="Return attribute types only (no values)"
        )
        deref_aliases: str = Field(
            default="never",
            description="Alias dereferencing: never, searching, finding, always",
            pattern="^(never|searching|finding|always)$",
        )

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN format."""
            if not v or not v.strip():
                raise ValueError("Base DN cannot be empty")
            return v.strip()

        @field_validator("filter_str")
        @classmethod
        def validate_filter(cls, v: str) -> str:
            """Validate LDAP filter format."""
            if not v or not v.strip():
                msg = "Filter cannot be empty"
                raise ValueError(msg)
            v = v.strip()
            if not (v.startswith("(") and v.endswith(")")):
                msg = "LDAP filter must be enclosed in parentheses"
                raise ValueError(msg)
            return v

        @classmethod
        def create_user_search(
            cls,
            uid: str,
            base_dn: str = "ou=users,dc=example,dc=com",
            attributes: list[str] | None = None,
        ) -> FlextLdapEntities.SearchRequest:
            """Factory method for user search."""
            return cls(
                base_dn=base_dn,
                filter_str=f"(&(objectClass=person)(uid={uid}))",
                attributes=attributes or ["uid", "cn", "mail", "sn"],
            )

        @classmethod
        def create_group_search(
            cls,
            cn: str,
            base_dn: str = "ou=groups,dc=example,dc=com",
            attributes: list[str] | None = None,
        ) -> FlextLdapEntities.SearchRequest:
            """Factory method for group search."""
            return cls(
                base_dn=base_dn,
                filter_str=f"(&(objectClass=groupOfNames)(cn={cn}))",
                attributes=attributes or ["cn", "member", "description"],
            )

    class SearchResult(BaseModel):
        """LDAP Search Result entity."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
        )

        # Results
        entries: list[FlextLdapEntities.Entry] = Field(
            default_factory=list, description="Search result entries"
        )

        # Result metadata
        result_code: int = Field(0, description="LDAP result code")
        result_description: str = Field("", description="Result description")
        matched_dn: str = Field("", description="Matched DN")

        # Paging information
        has_more_pages: bool = Field(default=False, description="More pages available")
        next_cookie: bytes | None = Field(None, description="Next page cookie")

        # Statistics
        entries_returned: int = Field(0, description="Number of entries returned")
        time_elapsed: float = Field(0.0, description="Search time in seconds")

        @field_validator("entries_returned", mode="before")
        @classmethod
        def set_entries_returned(cls, v: int, info: ValidationInfo) -> int:
            """Auto-calculate entries returned from entries list."""
            if info.data and "entries" in info.data:
                return len(info.data["entries"])
            return v

    class CreateUserRequest(BaseModel):
        """LDAP User Creation Request entity."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
        )

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new user")
        uid: str = Field(..., description="User ID")
        cn: str = Field(..., description="Common Name")
        sn: str = Field(..., description="Surname")

        # Optional user attributes
        given_name: str | None = Field(None, description="Given Name")
        mail: str | None = Field(None, description="Email address")
        user_password: SecretStr | None = Field(None, description="User password")
        telephone_number: str | None = Field(None, description="Phone number")

        # Organizational
        department: str | None = Field(None, description="Department")
        title: str | None = Field(None, description="Job title")
        organization: str | None = Field(None, description="Organization")

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
        )

        # Additional attributes
        additional_attributes: dict[str, FlextLdapTypes.Entry.AttributeValue] = Field(
            default_factory=dict, description="Additional LDAP attributes"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format."""
            if not v or not v.strip():
                raise ValueError("DN cannot be empty")
            return v.strip()

        @field_validator("uid", "cn", "sn")
        @classmethod
        def validate_required_string(cls, v: str) -> str:
            """Validate required string fields."""
            if not v or not v.strip():
                raise ValueError("Required field cannot be empty")
            return v.strip()

        def to_user_entity(self) -> FlextLdapEntities.User:
            """Convert to User entity."""
            return FlextLdapEntities.User(
                dn=self.dn,
                uid=self.uid,
                cn=self.cn,
                sn=self.sn,
                given_name=self.given_name,
                mail=self.mail,
                user_password=self.user_password,
                telephone_number=self.telephone_number,
                department=self.department,
                title=self.title,
                organization=self.organization,
                object_classes=self.object_classes,
                additional_attributes=self.additional_attributes,
            )

    # =========================================================================
    # CONNECTION AND CONFIGURATION ENTITIES
    # =========================================================================

    class ConnectionInfo(BaseModel):
        """LDAP Connection Information entity."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
        )

        # Connection details
        server: str = Field(..., description="LDAP server hostname/IP")
        port: int = Field(389, description="LDAP server port", ge=1, le=65535)
        use_ssl: bool = Field(False, description="Use SSL/TLS encryption")
        use_tls: bool = Field(False, description="Use StartTLS")

        # Authentication
        bind_dn: str | None = Field(None, description="Bind Distinguished Name")
        bind_password: SecretStr | None = Field(None, description="Bind password")

        # Connection options
        timeout: int = Field(30, description="Connection timeout in seconds", ge=1)
        pool_size: int = Field(10, description="Connection pool size", ge=1)
        pool_keepalive: int = Field(3600, description="Pool keepalive in seconds", ge=0)

        # SSL/TLS options
        verify_certificates: bool = Field(True, description="Verify SSL certificates")
        ca_certs_file: str | None = Field(None, description="CA certificates file path")

        @field_validator("server")
        @classmethod
        def validate_server(cls, v: str) -> str:
            """Validate server hostname/IP."""
            if not v or not v.strip():
                raise ValueError("Server cannot be empty")
            return v.strip()

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            """Validate port number."""
            if v <= 0 or v > 65535:
                raise ValueError("Port must be between 1 and 65535")
            return v

    # =========================================================================
    # ERROR AND STATUS ENTITIES
    # =========================================================================

    class LdapError(BaseModel):
        """LDAP Error entity with detailed information."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
        )

        # Error details
        error_code: int = Field(..., description="LDAP error code")
        error_message: str = Field(..., description="Error message")
        matched_dn: str = Field("", description="Matched DN")

        # Context
        operation: str = Field("", description="Operation that failed")
        target_dn: str = Field("", description="Target DN")

        # Additional details
        server_info: dict[str, Any] = Field(
            default_factory=dict, description="Server information"
        )

        # Timestamp
        timestamp: datetime = Field(
            default_factory=datetime.now, description="Error timestamp"
        )

        @field_validator("error_code")
        @classmethod
        def validate_error_code(cls, v: int) -> int:
            """Validate LDAP error code."""
            if v < 0:
                raise ValueError("Error code must be non-negative")
            return v

    class OperationResult(BaseModel):
        """LDAP Operation Result entity."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
        )

        # Result status
        success: bool = Field(..., description="Operation success status")
        result_code: int = Field(0, description="LDAP result code")
        result_message: str = Field("", description="Result message")

        # Operation details
        operation_type: str = Field("", description="Type of operation")
        target_dn: str = Field("", description="Target DN")

        # Performance metrics
        duration_ms: float = Field(
            0.0, description="Operation duration in milliseconds"
        )

        # Additional data
        data: dict[str, Any] = Field(
            default_factory=dict, description="Additional result data"
        )

        # Timestamp
        timestamp: datetime = Field(
            default_factory=datetime.now, description="Operation timestamp"
        )

        @classmethod
        def success_result(
            cls,
            operation_type: str,
            target_dn: str = "",
            data: dict[str, Any] | None = None,
            duration_ms: float = 0.0,
        ) -> FlextLdapEntities.OperationResult:
            """Create success result."""
            return cls(
                success=True,
                result_code=0,
                result_message="Success",
                operation_type=operation_type,
                target_dn=target_dn,
                data=data or {},
                duration_ms=duration_ms,
            )

        @classmethod
        def error_result(
            cls,
            operation_type: str,
            error_code: int,
            error_message: str,
            target_dn: str = "",
            duration_ms: float = 0.0,
        ) -> FlextLdapEntities.OperationResult:
            """Create error result."""
            return cls(
                success=False,
                result_code=error_code,
                result_message=error_message,
                operation_type=operation_type,
                target_dn=target_dn,
                duration_ms=duration_ms,
            )


# FlextLdapTypes.Entry.AttributeDict already imported in TYPE_CHECKING block above

# Rebuild models after all definitions are complete
FlextLdapEntities.User.model_rebuild()
FlextLdapEntities.Group.model_rebuild()
FlextLdapEntities.Entry.model_rebuild()
FlextLdapEntities.SearchRequest.model_rebuild()
FlextLdapEntities.SearchResponse.model_rebuild()
FlextLdapEntities.CreateUserRequest.model_rebuild()
FlextLdapEntities.CreateGroupRequest.model_rebuild()
FlextLdapEntities.UpdateGroupRequest.model_rebuild()


__all__ = [
    # Primary consolidated class
    "FlextLdapEntities",
]

# Export module-level aliases eliminated - use FlextLdapEntities.* directly following flext-core pattern
