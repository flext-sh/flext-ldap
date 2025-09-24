"""Unified LDAP models for flext-ldap - ALL models consolidated into FlextLdapModels.

This module consolidates ALL LDAP models, entities, and value objects into a single
FlextLdapModels class following FLEXT one-class-per-module standards.

Eliminates previous triple model system (models.py + entities.py + value_objects.py).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Final

from pydantic import BaseModel, Field, SecretStr, ValidationInfo, field_validator

from flext_core import FlextModels, FlextResult
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapModels(FlextModels):
    """Unified LDAP models class consolidating ALL models, entities, and value objects.

    This class consolidates:
    - Previous FlextLdapModels (legacy models)
    - Previous FlextLdapEntities (domain entities)
    - Previous FlextLdapValueObjects (value objects)

    Into a single unified class following FLEXT patterns. ALL LDAP data structures
    are now available as nested classes within FlextLdapModels.

    NO legacy compatibility maintained - clean consolidated implementation only.
    """

    # =========================================================================
    # VALUE OBJECTS - Immutable LDAP value objects
    # =========================================================================

    @dataclass(frozen=True)
    class DistinguishedName:
        """LDAP Distinguished Name value object with RFC 2253 compliance."""

        value: str

        def __post_init__(self) -> None:
            """Validate Distinguished Name format and content."""
            if not self.value or not self.value.strip():
                msg = "Distinguished Name cannot be empty"
                raise ValueError(msg)
            # Basic DN validation - full RFC 2253 validation would be more complex
            if "=" not in self.value:
                msg = "Invalid DN format - missing attribute=value pairs"
                raise ValueError(msg)

        @property
        def rdn(self) -> str:
            """Get the Relative Distinguished Name (first component)."""
            return self.value.split(",")[0].strip()

        @classmethod
        def create(
            cls,
            dn_string: str,
        ) -> FlextResult[FlextLdapModels.DistinguishedName]:
            """Create DN with validation."""
            try:
                dn_obj = cls(value=dn_string.strip())
                return FlextResult[FlextLdapModels.DistinguishedName].ok(dn_obj)
            except ValueError as e:
                return FlextResult[FlextLdapModels.DistinguishedName].fail(str(e))

    @dataclass(frozen=True)
    class Filter:
        """LDAP filter value object with RFC 4515 compliance."""

        expression: str

        def __post_init__(self) -> None:
            """Validate LDAP filter syntax and format."""
            if not self.expression or not self.expression.strip():
                msg = "LDAP filter cannot be empty"
                raise ValueError(msg)
            # Basic filter validation
            if not (self.expression.startswith("(") and self.expression.endswith(")")):
                msg = "LDAP filter must be enclosed in parentheses"
                raise ValueError(msg)

        @classmethod
        def equals(cls, attribute: str, value: str) -> FlextLdapModels.Filter:
            """Create equality filter."""
            return cls(expression=f"({attribute}={value})")

        @classmethod
        def starts_with(
            cls,
            attribute: str,
            value: str,
        ) -> FlextLdapModels.Filter:
            """Create starts-with filter."""
            return cls(expression=f"({attribute}={value}*)")

        @classmethod
        def object_class(cls, object_class: str) -> FlextLdapModels.Filter:
            """Create objectClass filter."""
            return cls(expression=f"(objectClass={object_class})")

    @dataclass(frozen=True)
    class Scope:
        """LDAP search scope value object."""

        value: str

        BASE: Final[str] = "base"
        ONELEVEL: Final[str] = "onelevel"
        SUBTREE: Final[str] = "subtree"

        def __post_init__(self) -> None:
            """Validate LDAP search scope value."""
            valid_scopes = {self.BASE, self.ONELEVEL, self.SUBTREE}
            if self.value not in valid_scopes:
                error_msg = (
                    f"Invalid scope: {self.value}. Must be one of {valid_scopes}"
                )
                raise ValueError(error_msg)

        @classmethod
        def base(cls) -> FlextLdapModels.Scope:
            """Create base scope."""
            return cls(value=cls.BASE)

        @classmethod
        def onelevel(cls) -> FlextLdapModels.Scope:
            """Create onelevel scope."""
            return cls(value=cls.ONELEVEL)

        @classmethod
        def subtree(cls) -> FlextLdapModels.Scope:
            """Create subtree scope."""
            return cls(value=cls.SUBTREE)

    # =========================================================================
    # SCHEMA MODELS - LDAP schema discovery and server quirks handling
    # =========================================================================

    class LdapServerType(Enum):
        """Known LDAP server types for quirks handling."""

        UNKNOWN = "unknown"
        OPENLDAP = "openldap"
        ACTIVE_DIRECTORY = "active_directory"
        ORACLE_DIRECTORY = "oracle_directory"
        ORACLE_OUD = "oracle_oud"
        SUN_OPENDS = "sun_opends"
        APACHE_DIRECTORY = "apache_directory"
        NOVELL_EDIRECTORY = "novell_edirectory"
        IBM_DIRECTORY = "ibm_directory"
        GENERIC = "generic"

    @dataclass(frozen=True)
    class SchemaAttribute:
        """LDAP schema attribute definition."""

        name: str
        oid: str
        syntax: str
        is_single_valued: bool
        is_operational: bool = False
        is_collective: bool = False
        is_no_user_modification: bool = False
        usage: str = "userApplications"  # userApplications, directoryOperation, distributedOperation, dSAOperation
        equality: str | None = None
        ordering: str | None = None
        substr: str | None = None
        superior: str | None = None

    @dataclass(frozen=True)
    class SchemaObjectClass:
        """LDAP schema object class definition."""

        name: str
        oid: str
        superior: list[str] = field(default_factory=list)
        must: list[str] = field(default_factory=list)
        may: list[str] = field(default_factory=list)
        kind: str = "STRUCTURAL"  # STRUCTURAL, AUXILIARY, ABSTRACT
        is_obsolete: bool = False

    @dataclass(frozen=True)
    class ServerQuirks:
        """LDAP server-specific quirks and behaviors."""

        server_type: FlextLdapModels.LdapServerType
        case_sensitive_dns: bool = True
        case_sensitive_attributes: bool = True
        supports_paged_results: bool = True
        supports_vlv: bool = False
        supports_sync: bool = False
        max_page_size: int = 1000
        default_timeout: int = 30
        supports_start_tls: bool = True
        requires_explicit_bind: bool = False
        attribute_name_mappings: dict[str, str] = field(default_factory=dict)
        object_class_mappings: dict[str, str] = field(default_factory=dict)
        dn_format_preferences: list[str] = field(default_factory=list)
        search_scope_limitations: set[str] = field(default_factory=set)
        filter_syntax_quirks: list[str] = field(default_factory=list)
        modify_operation_quirks: list[str] = field(default_factory=list)

    @dataclass(frozen=True)
    class SchemaDiscoveryResult:
        """Result of LDAP schema discovery operation."""

        server_info: dict[str, Any]
        server_type: FlextLdapModels.LdapServerType
        server_quirks: FlextLdapModels.ServerQuirks
        attributes: dict[str, FlextLdapModels.SchemaAttribute]
        object_classes: dict[str, FlextLdapModels.SchemaObjectClass]
        naming_contexts: list[str]
        supported_controls: list[str]
        supported_extensions: list[str]

    # =========================================================================
    # BASE CLASSES - Common functionality for LDAP entities
    # =========================================================================

    class FlextLdapBaseModel(FlextModels.ArbitraryTypesModel):
        """Base model class with common LDAP entity configuration and validation.

        Extends FlextModels.ArbitraryTypesModel to inherit FLEXT model patterns
        and provides LDAP-specific configuration for all entity models.
        """

    class FlextLdapValidationMixin:
        """Mixin providing common field validation methods for LDAP entities.

        Centralizes validation logic to eliminate duplication across model classes.
        """

        @staticmethod
        def validate_dn_field(v: str) -> str:
            """Common DN validation using centralized validation."""
            validation_result = FlextLdapValidations.validate_dn(v)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return v.strip()

        @staticmethod
        def validate_email_field(value: str | None) -> str | None:
            """Common email validation using centralized validation."""
            validation_result = FlextLdapValidations.validate_email(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value

        @staticmethod
        def validate_password_field(value: str | None) -> str | None:
            """Common password validation using centralized validation."""
            validation_result = FlextLdapValidations.validate_password(value)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value

        @staticmethod
        def validate_required_string_field(v: str) -> str:
            """Common validation for required string fields."""
            if not v or not v.strip():
                msg = "Required field cannot be empty"
                raise ValueError(msg)
            return v.strip()

    class FlextLdapEntityBase(FlextLdapBaseModel, FlextLdapValidationMixin):
        """Base class for LDAP entities with common fields and validation.

        Provides common fields and validation methods that are shared
        across multiple LDAP entity types.
        """

        # Common timestamp fields
        created_timestamp: datetime | None = Field(
            None,
            description="Creation timestamp",
        )
        modified_timestamp: datetime | None = Field(
            None,
            description="Last modification timestamp",
        )

        # Common additional attributes field
        additional_attributes: dict[str, FlextLdapTypes.EntryAttributeValue] = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )

    # =========================================================================
    # CORE LDAP ENTITIES - Primary Domain Objects
    # =========================================================================

    class LdapUser(FlextLdapEntityBase):
        """LDAP User entity with enterprise attributes."""

        # Core identification
        dn: str = Field(..., description="Distinguished Name (unique identifier)")
        cn: str = Field(..., description="Common Name")
        uid: str | None = Field(None, description="User ID")
        sn: str | None = Field(None, description="Surname")
        given_name: str | None = Field(None, description="Given Name")

        # Contact information
        mail: str | None = Field(None, description="Primary email address")
        telephone_number: str | None = Field(None, description="Primary phone number")
        mobile: str | None = Field(None, description="Mobile phone number")

        # Organizational
        department: str | None = Field(None, description="Department")
        title: str | None = Field(None, description="Job title")
        organization: str | None = Field(None, description="Organization")
        organizational_unit: str | None = Field(None, description="Organizational Unit")

        # Authentication
        user_password: SecretStr | None = Field(None, description="User password")

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
        )

        # Legacy compatibility fields
        id: str = Field(default="", description="Legacy ID field")
        attributes: FlextLdapTypes.EntryAttributeDict = Field(
            default_factory=dict,
            description="Legacy attributes dict",
        )
        status: str | None = Field(default=None, description="User status")
        created_at: str | None = Field(default=None, description="Creation timestamp")
        display_name: str | None = Field(default=None, description="Display Name")
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            return cls.validate_email_field(value)

        @field_validator("cn")
        @classmethod
        def validate_cn(cls, v: str) -> str:
            """Validate Common Name."""
            return cls.validate_required_string_field(v)

        @field_validator("object_classes")
        @classmethod
        def validate_object_classes(cls, v: list[str]) -> list[str]:
            """Validate object classes."""
            if not v:
                msg = "At least one object class is required"
                raise ValueError(msg)
            return v

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate user business rules."""
            # User-specific validations
            if "person" not in self.object_classes:
                return FlextResult[None].fail("User must have 'person' object class")

            if not self.cn:
                return FlextResult[None].fail("User must have a Common Name")

            return FlextResult[None].ok(None)

        def get_attribute(
            self,
            name: str,
        ) -> FlextLdapTypes.EntryAttributeValue | None:
            """Get attribute value by name."""
            return self.additional_attributes.get(name)

        def set_attribute(
            self,
            name: str,
            value: FlextLdapTypes.EntryAttributeValue,
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

    class Group(FlextLdapEntityBase):
        """LDAP Group entity with membership management."""

        # Core identification
        dn: str = Field(..., description="Distinguished Name")
        cn: str = Field(..., description="Common Name")
        gid_number: int | None = Field(None, description="Group ID Number")

        # Group membership
        member_dns: list[str] = Field(
            default_factory=list,
            description="Member Distinguished Names",
        )
        unique_member_dns: list[str] = Field(
            default_factory=list,
            description="Unique Member Distinguished Names",
        )

        # Legacy compatibility
        id: str = Field(default="", description="Legacy ID field")
        members: list[str] = Field(
            default_factory=list,
            description="Legacy members list",
        )
        attributes: FlextLdapTypes.EntryAttributeDict = Field(
            default_factory=dict,
            description="Legacy attributes dict",
        )
        status: str | None = Field(default=None, description="Group status")
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )

        # Metadata
        description: str | None = Field(None, description="Group description")
        object_classes: list[str] = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

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
            return (
                member_dn in self.member_dns
                or member_dn in self.unique_member_dns
                or member_dn in self.members
            )

        def add_member(self, member_dn: str) -> FlextResult[None]:
            """Add member to group."""
            if member_dn not in self.member_dns:
                self.member_dns.append(member_dn)
            if member_dn not in self.members:
                self.members.append(member_dn)
            return FlextResult[None].ok(None)

        def remove_member(self, member_dn: str) -> FlextResult[None]:
            """Remove member from group."""
            if member_dn in self.member_dns:
                self.member_dns.remove(member_dn)
            if member_dn in self.members:
                self.members.remove(member_dn)
                return FlextResult[None].ok(None)
            return FlextResult[None].fail(f"Member {member_dn} not found in group")

    class Entry(FlextLdapEntityBase):
        """Generic LDAP Entry entity."""

        # Core identification
        dn: str = Field(..., description="Distinguished Name")

        # LDAP attributes as flexible dict
        attributes: dict[str, FlextLdapTypes.EntryAttributeValue] = Field(
            default_factory=dict,
            description="LDAP entry attributes",
        )

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=list,
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

        def get_attribute(
            self,
            name: str,
        ) -> FlextLdapTypes.EntryAttributeValue | None:
            """Get attribute value by name.

            Args:
                name: Attribute name.

            Returns:
                Attribute value or None if not found.

            """
            attribute_value = self.attributes.get(name)
            if attribute_value is None:
                return None

            # Convert different types to string list for consistent access
            if isinstance(attribute_value, str):
                return [attribute_value]
            if isinstance(attribute_value, bytes):
                return [attribute_value.decode("utf-8")]
            # attribute_value is list[str] | list[bytes] at this point
            # Convert all items to strings
            return [
                item.decode("utf-8") if isinstance(item, bytes) else str(item)
                for item in attribute_value
            ]

        def set_attribute(
            self,
            name: str,
            value: FlextLdapTypes.EntryAttributeValue,
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

    class SearchRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP Search Request entity with comprehensive parameters."""

        # Search scope
        base_dn: str = Field(..., description="Search base Distinguished Name")
        filter_str: str = Field(..., description="LDAP search filter")
        scope: str = Field(
            default="subtree",
            description="Search scope: base, onelevel, subtree",
            pattern="^(base|onelevel|subtree)$",
        )

        # Attribute selection
        attributes: list[str] | None = Field(
            default=None,
            description="Attributes to return (None = all)",
        )

        # Search limits
        size_limit: int = Field(
            default=1000,
            description="Maximum number of entries to return",
            ge=0,
        )
        time_limit: int = Field(
            default=60,
            description="Search timeout in seconds",
            ge=0,
        )

        # Paging
        page_size: int | None = Field(
            None,
            description="Page size for paged results",
            ge=1,
        )
        paged_cookie: bytes | None = Field(
            None,
            description="Paging cookie for continuation",
        )

        # Advanced options
        types_only: bool = Field(
            default=False,
            description="Return attribute types only (no values)",
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
            return cls.validate_required_string_field(v)

        @field_validator("filter_str")
        @classmethod
        def validate_filter(cls, v: str) -> str:
            """Validate LDAP filter format using centralized validation."""
            validation_result = FlextLdapValidations.validate_filter(v)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
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
        ) -> FlextLdapModels.SearchRequest:
            """Create search request for user."""
            return cls.model_validate(
                {
                    "base_dn": base_dn,
                    "filter": f"(&(objectClass=person)(uid={uid}))",
                    "attributes": attributes or ["uid", "cn", "mail", "sn"],
                    "page_size": None,
                    "paged_cookie": None,
                },
            )

        @classmethod
        def create_group_search(
            cls,
            cn: str,
            base_dn: str = "ou=groups,dc=example,dc=com",
            attributes: list[str] | None = None,
        ) -> FlextLdapModels.SearchRequest:
            """Create search request for group."""
            return cls.model_validate(
                {
                    "base_dn": base_dn,
                    "filter": f"(&(objectClass=groupOfNames)(cn={cn}))",
                    "attributes": attributes or ["cn", "member", "description"],
                    "page_size": None,
                    "paged_cookie": None,
                },
            )

    class SearchResponse(FlextLdapBaseModel):
        """LDAP Search Response entity."""

        # Results
        entries: list[dict[str, object]] = Field(
            default_factory=list,
            description="Search result entries",
        )

        # Result metadata
        total_count: int = Field(0, description="Total number of entries")
        has_more: bool = Field(default=False, description="More results available")

        # Legacy compatibility
        result_code: int = Field(0, description="LDAP result code")
        result_description: str = Field("", description="Result description")
        matched_dn: str = Field("", description="Matched DN")
        has_more_pages: bool = Field(default=False, description="More pages available")
        next_cookie: bytes | None = Field(None, description="Next page cookie")
        entries_returned: int = Field(0, description="Number of entries returned")
        time_elapsed: float = Field(0.0, description="Search time in seconds")

        @field_validator("entries_returned", mode="before")
        @classmethod
        def set_entries_returned(cls, v: int, info: ValidationInfo) -> int:
            """Auto-calculate entries returned from entries list."""
            if info.data and "entries" in info.data:
                entries = info.data["entries"]
                if isinstance(entries, list):
                    # Type-safe length calculation
                    return len(entries)
                return 0
            return v

    class CreateUserRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP User Creation Request entity."""

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new user")
        uid: str = Field(..., description="User ID")
        cn: str = Field(..., description="Common Name")
        sn: str = Field(..., description="Surname")

        # Optional user attributes
        given_name: str | None = Field(None, description="Given Name")
        mail: str | None = Field(None, description="Email address")
        user_password: str | None = Field(None, description="User password")
        telephone_number: str | None = Field(None, description="Phone number")
        description: str | None = Field(None, description="User description")

        # Organizational
        department: str | None = Field(None, description="Department")
        title: str | None = Field(None, description="Job title")
        organization: str | None = Field(None, description="Organization")

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=lambda: [
                FlextLdapConstants.ObjectClasses.TOP,
                FlextLdapConstants.ObjectClasses.PERSON,
                FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
            ],
            description="LDAP object classes",
        )

        # Additional attributes
        additional_attributes: dict[str, FlextLdapTypes.EntryAttributeValue] = Field(
            default_factory=dict,
            description="Additional user attributes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            return cls.validate_email_field(value)

        @field_validator("user_password")
        @classmethod
        def validate_password(cls, value: str | None) -> str | None:
            """Validate password requirements using centralized validation."""
            return cls.validate_password_field(value)

        @field_validator("uid", "cn", "sn")
        @classmethod
        def validate_required_string(cls, v: str) -> str:
            """Validate required string fields."""
            return cls.validate_required_string_field(v)

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate create user request business rules."""
            if not self.dn:
                return FlextResult[None].fail("DN cannot be empty")
            if not self.uid:
                return FlextResult[None].fail("UID cannot be empty")
            if not self.cn:
                return FlextResult[None].fail("Common Name cannot be empty")
            return FlextResult[None].ok(None)

        def to_user_entity(self) -> FlextLdapModels.LdapUser:
            """Convert request to user entity."""
            return FlextLdapModels.LdapUser(
                id=f"user_{self.uid}",
                dn=self.dn,
                uid=self.uid,
                cn=self.cn,
                sn=self.sn,
                given_name=self.given_name,
                mail=self.mail,
                telephone_number=self.telephone_number,
                mobile=None,
                department=self.department,
                title=self.title,
                organization=self.organization,
                organizational_unit=None,
                user_password=SecretStr(self.user_password)
                if self.user_password
                else None,
                object_classes=self.object_classes,
                additional_attributes=self.additional_attributes,
                created_timestamp=None,
                modified_timestamp=None,
            )

    class CreateGroupRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP Group Creation Request entity."""

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new group")
        cn: str = Field(..., description="Common Name")

        # Optional group attributes
        description: str | None = Field(None, description="Group description")
        members: list[str] | None = Field(None, description="Initial group members")

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

        @field_validator("cn")
        @classmethod
        def validate_cn(cls, v: str) -> str:
            """Validate Common Name."""
            return cls.validate_required_string_field(v)

    # =========================================================================
    # CONNECTION AND CONFIGURATION ENTITIES
    # =========================================================================

    class ConnectionInfo(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP Connection Information entity."""

        # Connection details
        server: str = Field(..., description="LDAP server hostname/IP")
        port: int = Field(
            389,
            description="LDAP server port",
            ge=1,
            le=FlextLdapConstants.Protocol.MAX_PORT,
        )
        use_ssl: bool = Field(default=False, description="Use SSL/TLS encryption")
        use_tls: bool = Field(default=False, description="Use StartTLS")

        # Authentication
        bind_dn: str | None = Field(None, description="Bind Distinguished Name")
        bind_password: SecretStr | None = Field(None, description="Bind password")

        # Connection options
        timeout: int = Field(30, description="Connection timeout in seconds", ge=1)
        pool_size: int = Field(10, description="Connection pool size", ge=1)
        pool_keepalive: int = Field(3600, description="Pool keepalive in seconds", ge=0)

        # SSL/TLS options
        verify_certificates: bool = Field(
            default=True,
            description="Verify SSL certificates",
        )
        ca_certs_file: str | None = Field(None, description="CA certificates file path")

        @field_validator("server")
        @classmethod
        def validate_server(cls, v: str) -> str:
            """Validate server hostname/IP."""
            return cls.validate_required_string_field(v)

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            """Validate port number."""
            if v <= 0 or v > FlextLdapConstants.Protocol.MAX_PORT:
                msg = (
                    f"Port must be between 1 and {FlextLdapConstants.Protocol.MAX_PORT}"
                )
                raise ValueError(msg)
            return v

    # =========================================================================
    # ERROR AND STATUS ENTITIES
    # =========================================================================

    class LdapError(FlextLdapBaseModel):
        """LDAP Error entity with detailed information."""

        # Error details
        error_code: int = Field(..., description="LDAP error code")
        error_message: str = Field(..., description="Error message")
        matched_dn: str = Field("", description="Matched DN")

        # Context
        operation: str = Field("", description="Operation that failed")
        target_dn: str = Field("", description="Target DN")

        # Additional details
        server_info: dict[str, object] = Field(
            default_factory=dict,
            description="Server information",
        )

        # Timestamp
        timestamp: datetime = Field(
            default_factory=datetime.now,
            description="Error timestamp",
        )

        @field_validator("error_code")
        @classmethod
        def validate_error_code(cls, v: int) -> int:
            """Validate LDAP error code."""
            if v < 0:
                msg = "Error code must be non-negative"
                raise ValueError(msg)
            return v

    class OperationResult(FlextLdapBaseModel):
        """LDAP Operation Result entity."""

        # Result status
        success: bool = Field(..., description="Operation success status")
        result_code: int = Field(0, description="LDAP result code")
        result_message: str = Field("", description="Result message")

        # Operation details
        operation_type: str = Field("", description="Type of operation")
        target_dn: str = Field("", description="Target DN")

        # Performance metrics
        duration_ms: float = Field(
            0.0,
            description="Operation duration in milliseconds",
        )

        # Additional data
        data: dict[str, object] = Field(
            default_factory=dict,
            description="Additional result data",
        )

        # Timestamp
        timestamp: datetime = Field(
            default_factory=datetime.now,
            description="Operation timestamp",
        )

        @classmethod
        def success_result(
            cls,
            operation_type: str,
            target_dn: str = "",
            data: dict[str, object] | None = None,
            duration_ms: float = 0.0,
        ) -> FlextLdapModels.OperationResult:
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
        ) -> FlextLdapModels.OperationResult:
            """Create error result."""
            return cls(
                success=False,
                result_code=error_code,
                result_message=error_message,
                operation_type=operation_type,
                target_dn=target_dn,
                duration_ms=duration_ms,
            )

    @dataclass(frozen=True)
    class ConnectionConfig:
        """LDAP connection configuration value object."""

        server: str
        port: int = 389
        use_ssl: bool = False
        bind_dn: str | None = None
        bind_password: str | None = None
        timeout: int = 30

    # =========================================================================
    # ACL MODELS - Access Control List models (consolidated from acl/models.py)
    # =========================================================================

    class AclTarget(BaseModel):
        """ACL target specification - what is being protected."""

        target_type: str = Field(
            ..., description="Type of target (dn, attributes, entry)"
        )
        dn_pattern: str = Field(default="*", description="DN pattern for the target")
        attributes: list[str] = Field(
            default_factory=list, description="Specific attributes targeted"
        )
        filter_expression: str = Field(
            default="", description="LDAP filter for dynamic targeting"
        )
        scope: str = Field(default="subtree", description="Scope: base, one, subtree")

        @classmethod
        def create(
            cls,
            target_type: str,
            dn_pattern: str = "*",
            attributes: list[str] | None = None,
            filter_expression: str = "",
            scope: str = "subtree",
        ) -> FlextResult[FlextLdapModels.AclTarget]:
            """Create ACL target with validation."""
            try:
                instance = cls(
                    target_type=target_type,
                    dn_pattern=dn_pattern,
                    attributes=attributes or [],
                    filter_expression=filter_expression,
                    scope=scope,
                )
                return FlextResult[FlextLdapModels.AclTarget].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.AclTarget].fail(
                    f"ACL target creation failed: {e}"
                )

    class AclSubject(BaseModel):
        """ACL subject specification - who has access."""

        subject_type: str = Field(
            ..., description="Type of subject (user, group, dn, self)"
        )
        identifier: str = Field(
            default="*", description="Subject identifier (DN, group name, etc.)"
        )
        authentication_level: str = Field(
            default="any", description="Required authentication level"
        )

        @classmethod
        def create(
            cls,
            subject_type: str,
            identifier: str = "*",
            authentication_level: str = "any",
        ) -> FlextResult[FlextLdapModels.AclSubject]:
            """Create ACL subject with validation."""
            try:
                instance = cls(
                    subject_type=subject_type,
                    identifier=identifier,
                    authentication_level=authentication_level,
                )
                return FlextResult[FlextLdapModels.AclSubject].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.AclSubject].fail(
                    f"ACL subject creation failed: {e}"
                )

    class AclPermissions(BaseModel):
        """ACL permissions specification."""

        permissions: list[str] = Field(
            default_factory=list, description="List of granted permissions"
        )
        denied_permissions: list[str] = Field(
            default_factory=list, description="List of explicitly denied permissions"
        )
        grant_type: str = Field(
            default="allow", description="Grant type: allow or deny"
        )

        @classmethod
        def create(
            cls,
            permissions: list[str] | None = None,
            denied_permissions: list[str] | None = None,
            grant_type: str = "allow",
        ) -> FlextResult[FlextLdapModels.AclPermissions]:
            """Create ACL permissions with validation."""
            try:
                instance = cls(
                    permissions=permissions or [],
                    denied_permissions=denied_permissions or [],
                    grant_type=grant_type,
                )
                return FlextResult[FlextLdapModels.AclPermissions].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.AclPermissions].fail(
                    f"ACL permissions creation failed: {e}"
                )

    class UnifiedAcl(BaseModel):
        """Unified ACL representation - intermediate format for conversion."""

        name: str = Field(default="", description="ACL rule name")
        target: FlextLdapModels.AclTarget = Field(..., description="ACL target")
        subject: FlextLdapModels.AclSubject = Field(..., description="ACL subject")
        permissions: FlextLdapModels.AclPermissions = Field(
            ..., description="ACL permissions"
        )
        priority: int = Field(default=0, description="ACL evaluation priority")
        conditions: dict[str, Any] = Field(
            default_factory=dict, description="Additional conditions (time, IP, etc.)"
        )
        metadata: dict[str, Any] = Field(
            default_factory=dict, description="Format-specific metadata"
        )

        @classmethod
        def create(
            cls,
            target: FlextLdapModels.AclTarget,
            subject: FlextLdapModels.AclSubject,
            permissions: FlextLdapModels.AclPermissions,
            name: str = "",
            priority: int = 0,
            conditions: dict[str, Any] | None = None,
            metadata: dict[str, Any] | None = None,
        ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
            """Create unified ACL with validation."""
            try:
                instance = cls(
                    name=name,
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    priority=priority,
                    conditions=conditions or {},
                    metadata=metadata or {},
                )
                return FlextResult[FlextLdapModels.UnifiedAcl].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    f"Unified ACL creation failed: {e}"
                )

    class OpenLdapAcl(BaseModel):
        """OpenLDAP ACL format representation."""

        access_line: str = Field(..., description="Complete OpenLDAP access line")
        target_spec: str = Field(default="*", description="Target specification")
        by_clauses: list[dict[str, str]] = Field(
            default_factory=list, description="List of by clauses"
        )

        @classmethod
        def create(
            cls,
            access_line: str,
            target_spec: str = "*",
            by_clauses: list[dict[str, str]] | None = None,
        ) -> FlextResult[FlextLdapModels.OpenLdapAcl]:
            """Create OpenLDAP ACL representation."""
            try:
                instance = cls(
                    access_line=access_line,
                    target_spec=target_spec,
                    by_clauses=by_clauses or [],
                )
                return FlextResult[FlextLdapModels.OpenLdapAcl].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.OpenLdapAcl].fail(
                    f"OpenLDAP ACL creation failed: {e}"
                )

    class OracleAcl(BaseModel):
        """Oracle Directory ACL format representation."""

        orclaci_value: str = Field(..., description="Oracle orclaci attribute value")
        target_type: str = Field(
            default="entry", description="Target type (entry, attr)"
        )
        attributes: list[str] = Field(
            default_factory=list, description="Targeted attributes"
        )
        subject_spec: str = Field(default="", description="Subject specification")
        permissions: list[str] = Field(
            default_factory=list, description="Permissions list"
        )

        @classmethod
        def create(
            cls,
            orclaci_value: str,
            target_type: str = "entry",
            attributes: list[str] | None = None,
            subject_spec: str = "",
            permissions: list[str] | None = None,
        ) -> FlextResult[FlextLdapModels.OracleAcl]:
            """Create Oracle ACL representation."""
            try:
                instance = cls(
                    orclaci_value=orclaci_value,
                    target_type=target_type,
                    attributes=attributes or [],
                    subject_spec=subject_spec,
                    permissions=permissions or [],
                )
                return FlextResult[FlextLdapModels.OracleAcl].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.OracleAcl].fail(
                    f"Oracle ACL creation failed: {e}"
                )

    class AciFormat(BaseModel):
        """389 DS/Apache DS ACI format representation."""

        aci_value: str = Field(..., description="Complete ACI string")
        target_dn: str = Field(default="", description="Target DN")
        target_attrs: list[str] = Field(
            default_factory=list, description="Target attributes"
        )
        acl_name: str = Field(default="", description="ACL name")
        grant_type: str = Field(default="allow", description="allow or deny")
        permissions: list[str] = Field(default_factory=list, description="Permissions")
        bind_rules: dict[str, str] = Field(
            default_factory=dict, description="Bind rule specifications"
        )

        @classmethod
        def create(
            cls,
            aci_value: str,
            target_dn: str = "",
            target_attrs: list[str] | None = None,
            acl_name: str = "",
            grant_type: str = "allow",
            permissions: list[str] | None = None,
            bind_rules: dict[str, str] | None = None,
        ) -> FlextResult[FlextLdapModels.AciFormat]:
            """Create ACI format representation."""
            try:
                instance = cls(
                    aci_value=aci_value,
                    target_dn=target_dn,
                    target_attrs=target_attrs or [],
                    acl_name=acl_name,
                    grant_type=grant_type,
                    permissions=permissions or [],
                    bind_rules=bind_rules or {},
                )
                return FlextResult[FlextLdapModels.AciFormat].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.AciFormat].fail(
                    f"ACI format creation failed: {e}"
                )

    class ConversionResult(BaseModel):
        """Result of ACL conversion with warnings and metadata."""

        converted_acl: str = Field(..., description="Converted ACL string")
        source_format: str = Field(..., description="Source ACL format")
        target_format: str = Field(..., description="Target ACL format")
        warnings: list[str] = Field(
            default_factory=list, description="Conversion warnings"
        )
        metadata: dict[str, Any] = Field(
            default_factory=dict, description="Conversion metadata"
        )

        @classmethod
        def create(
            cls,
            converted_acl: str,
            source_format: str,
            target_format: str,
            warnings: list[str] | None = None,
            metadata: dict[str, Any] | None = None,
        ) -> FlextResult[FlextLdapModels.ConversionResult]:
            """Create conversion result."""
            try:
                instance = cls(
                    converted_acl=converted_acl,
                    source_format=source_format,
                    target_format=target_format,
                    warnings=warnings or [],
                    metadata=metadata or {},
                )
                return FlextResult[FlextLdapModels.ConversionResult].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    f"Conversion result creation failed: {e}"
                )


__all__ = [
    "FlextLdapModels",
]
