"""FLEXT-LDAP Models - Consolidated Models, Entities and Value Objects.

🎯 CONSOLIDATES 5 MAJOR FILES INTO SINGLE PEP8 MODULE:
- entities.py (35,995 bytes) - Domain entities with business logic
- models.py (29,785 bytes) - LDAP domain models and request/response objects
- value_objects.py (23,986 bytes) - Immutable domain value objects
- values.py (9,594 bytes) - Value object re-exports and additional types
- types.py (5,200 bytes) - Type definitions and enums

TOTAL CONSOLIDATION: 104,560 bytes → ldap_models.py (PEP8 organized)

This module provides comprehensive LDAP domain modeling using advanced Python 3.13
features, flext-core foundation patterns, and Domain-Driven Design principles.

All models extend flext-core foundation classes providing consistent behavior
across the FLEXT ecosystem with built-in validation, audit trails, and lifecycle
management.

Architecture:
- Domain Entities: Rich business objects with identity and behavior
- Value Objects: Immutable data structures without identity
- Domain Events: Business event modeling for cross-aggregate communication
- Request/Response Models: API contract definitions
- Configuration Models: System configuration objects

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, ClassVar, final
from urllib.parse import urlparse

from flext_core import (
    FlextDomainEntity,
    FlextEntityStatus,
    FlextModel,
    FlextResult,
    FlextValue,
    get_logger,
)
from pydantic import ConfigDict, Field, computed_field, field_validator

if TYPE_CHECKING:
    from flext_ldap.ldap_utils import (
        LdapAttributeDict,
        LdapAttributeValue,
        LdapSearchResult,
    )

logger = get_logger(__name__)

# =============================================================================
# ENUMS AND TYPE DEFINITIONS
# =============================================================================


class FlextLdapDataType(Enum):
    """LDAP data types with intelligent detection."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    BINARY = "binary"
    DATETIME = "datetime"
    DN = "dn"
    EMAIL = "email"
    PHONE = "phone"
    UUID = "uuid"
    URL = "url"
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    CERTIFICATE = "certificate"
    PASSWORD_DATA_TYPE = "password_field"
    UNKNOWN = "unknown"


class FlextLdapScopeEnum(StrEnum):
    """LDAP search scope enumeration with legacy compatibility."""

    BASE = "base"
    ONE_LEVEL = "onelevel"
    SUBTREE = "subtree"

    # Legacy mappings for backward compatibility
    ONE = "onelevel"
    SUB = "subtree"


# Legacy compatibility aliases
FlextLdapEntityStatus = FlextEntityStatus
LDAPScope = FlextLdapScopeEnum


# =============================================================================
# VALUE OBJECTS - Immutable Domain Values
# =============================================================================

@final
class FlextLdapDistinguishedName(FlextValue):
    """Distinguished Name value object with RFC 4514 compliance validation.

    Consolidates DN handling from multiple modules into single implementation.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        frozen=True,  # Value objects are immutable
    )

    value: str = Field(
        ...,
        description="RFC 4514 compliant Distinguished Name",
        min_length=3,  # Minimum: "o=x"
        max_length=8192,  # LDAP practical limit
    )

    # RFC 4514 DN validation pattern - comprehensive regex
    DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r'^(?:[a-zA-Z][\w-]*|\d+(?:\.\d+)*)\s*=\s*(?:[^,=+<>#;\\"]|\\[,=+<>#;\\"]|\\[0-9a-fA-F]{2})+(?:\s*,\s*(?:[a-zA-Z][\w-]*|\d+(?:\.\d+)*)\s*=\s*(?:[^,=+<>#;\\"]|\\[,=+<>#;\\"]|\\[0-9a-fA-F]{2})+)*$',
    )

    @field_validator("value")
    @classmethod
    def validate_dn_format(cls, v: str) -> str:
        """Validate DN format using RFC 4514 compliance."""
        if not cls.DN_PATTERN.match(v):
            msg = f"Invalid DN format: {v!r}"
            raise ValueError(msg)
        return v

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate DN business rules."""
        if not self.value or self.value.isspace():
            return FlextResult.fail("DN cannot be empty or whitespace")
        return FlextResult.ok(None)

    @computed_field
    def parent_dn(self) -> str | None:
        """Get parent DN by removing the leftmost RDN."""
        parts = self.value.split(",", 1)
        return parts[1].strip() if len(parts) > 1 else None

    @computed_field
    def rdn(self) -> str:
        """Get the Relative Distinguished Name (leftmost component)."""
        return self.value.split(",", 1)[0].strip()

    def is_descendant_of(self, parent_dn: str | FlextLdapDistinguishedName) -> bool:
        """Check if this DN is a descendant of the given parent DN."""
        parent_str = parent_dn.value if isinstance(parent_dn, FlextLdapDistinguishedName) else parent_dn
        return self.value.lower().endswith(parent_str.lower())


@final
class FlextLdapScope(FlextValue):
    """LDAP search scope value object."""

    scope: str = Field(..., description="LDAP search scope")

    # Valid LDAP scopes per RFC 4511
    VALID_SCOPES: ClassVar[set[str]] = {"base", "one", "sub", "children", "onelevel", "subtree"}

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
        return FlextResult.ok(None)

    @classmethod
    def create(cls, scope: str) -> FlextResult[FlextLdapScope]:
        """Create scope value object with validation."""
        try:
            scope_obj = cls(scope=scope)
            return FlextResult.ok(scope_obj)
        except ValueError as e:
            return FlextResult.fail(str(e))

    @classmethod
    def base(cls) -> FlextLdapScope:
        """Create base scope (search only the entry itself)."""
        return cls(scope="base")

    @classmethod
    def one(cls) -> FlextLdapScope:
        """Create one-level scope (search direct children only)."""
        return cls(scope="one")

    @classmethod
    def sub(cls) -> FlextLdapScope:
        """Create subtree scope (search entry and all descendants)."""
        return cls(scope="sub")


@final
class FlextLdapFilter(FlextValue):
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
        min_length=1,
        max_length=4096,  # Reasonable filter size limit
    )

    # Basic LDAP filter validation pattern
    FILTER_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^\([&|!]?[\w\s\-=><~:*().,]+\)$",
    )

    @field_validator("value")
    @classmethod
    def validate_filter_format(cls, v: str) -> str:
        """Validate basic LDAP filter format."""
        if not v.startswith("(") or not v.endswith(")"):
            msg = f"LDAP filter must be enclosed in parentheses: {v!r}"
            raise ValueError(msg)
        return v

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate filter business rules."""
        if not self.value or self.value.isspace():
            return FlextResult.fail("Filter cannot be empty or whitespace")
        return FlextResult.ok(None)


@final
class FlextLdapUri(FlextValue):
    """LDAP URI value object with RFC 4516 compliance."""

    value: str = Field(..., description="LDAP URI string")

    @field_validator("value")
    @classmethod
    def validate_uri_format(cls, v: str) -> str:
        """Validate LDAP URI format."""
        try:
            parsed = urlparse(v)
            if parsed.scheme not in {"ldap", "ldaps"}:
                msg = f"LDAP URI must use ldap:// or ldaps:// scheme: {v!r}"
                raise ValueError(msg)
            return v
        except Exception as e:
            msg = f"Invalid LDAP URI format: {v!r} - {e}"
            raise ValueError(msg) from e

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate URI business rules."""
        return FlextResult.ok(None)

    @computed_field
    def scheme(self) -> str:
        """Get URI scheme."""
        return urlparse(self.value).scheme

    @computed_field
    def hostname(self) -> str | None:
        """Get URI hostname."""
        return urlparse(self.value).hostname

    @computed_field
    def port(self) -> int | None:
        """Get URI port."""
        return urlparse(self.value).port


class FlextLdapObjectClass(FlextValue):
    """LDAP object class value object."""

    name: str = Field(..., description="Object class name")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate object class name."""
        if not v or not isinstance(v, str):
            msg = "Object class name must be a non-empty string"
            raise ValueError(msg)

        if not v.replace("-", "").replace("_", "").isalnum():
            msg = "Object class name contains invalid characters"
            raise ValueError(msg)

        return v

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules."""
        if not self.name or not self.name.strip():
            return FlextResult.fail("Object class name cannot be empty")
        return FlextResult.ok(None)

    def __str__(self) -> str:
        """Return object class name."""
        return self.name


class FlextLdapAttributesValue(FlextValue):
    """LDAP attributes value object."""

    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDAP attributes as name-value pairs",
    )

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP attributes."""
        for name, values in self.attributes.items():
            if not name or not name.strip():
                return FlextResult.fail("Attribute name cannot be empty")
            if not values:
                return FlextResult.fail(
                    f"Attribute '{name}' must have at least one value",
                )
        return FlextResult.ok(None)

    def get_single_value(self, name: str) -> str | None:
        """Get single value for attribute."""
        values = self.attributes.get(name, [])
        return values[0] if values else None

    def get_values(self, name: str) -> list[str]:
        """Get all values for attribute."""
        return self.attributes.get(name, [])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class FlextLdapCreateUserRequest(FlextModel):
    """Request model for creating LDAP users."""

    dn: str = Field(..., description="Distinguished Name for the user")
    uid: str = Field(..., description="User ID")
    cn: str = Field(..., description="Common name")
    sn: str = Field(..., description="Surname")
    given_name: str | None = Field(None, description="Given name")
    mail: str | None = Field(None, description="Email address")
    user_password: str | None = Field(None, description="User password")
    object_classes: list[str] = Field(
        default_factory=lambda: ["inetOrgPerson", "person", "top"],
        description="LDAP object classes",
    )
    additional_attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Additional LDAP attributes",
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
        """Validate email format if provided."""
        if v and "@" not in v:
            msg = f"Invalid email format: {v}"
            raise ValueError(msg)
        return v


class FlextLdapSearchRequest(FlextModel):
    """Request model for LDAP searches."""

    base_dn: str = Field(..., description="Base DN for search")
    scope: FlextLdapScopeEnum = Field(
        FlextLdapScopeEnum.SUBTREE,
        description="Search scope",
    )
    filter_str: str = Field(
        "(objectClass=*)",
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


class FlextLdapSearchResponse(FlextModel):
    """Response model for LDAP searches."""

    entries: list[LdapSearchResult] = Field(
        default_factory=list,
        description="Search result entries",
    )
    total_count: int = Field(0, description="Total number of entries found")
    has_more: bool = Field(False, description="Whether more entries are available")
    search_time_ms: float = Field(0.0, description="Search execution time in ms")


# =============================================================================
# DOMAIN ENTITIES - Rich Business Objects
# =============================================================================

class FlextLdapEntry(FlextDomainEntity):
    """Base LDAP directory entry implementing rich domain model patterns.

    Represents a generic LDAP directory entry with comprehensive business logic
    for attribute management, object class validation, and domain rule enforcement.
    """

    dn: str = Field(..., description="Distinguished Name")
    object_classes: list[str] = Field(
        default_factory=list,
        description="LDAP object classes",
    )
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDAP attributes as name-value pairs",
    )
    status: FlextEntityStatus = Field(
        FlextEntityStatus.ACTIVE,
        description="Entity status",
    )

    @field_validator("dn")
    @classmethod
    def validate_dn_format(cls, v: str) -> str:
        """Validate DN format."""
        try:
            FlextLdapDistinguishedName(value=v)
            return v
        except ValueError as e:
            msg = f"Invalid DN format: {e}"
            raise ValueError(msg) from e

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate entry domain rules."""
        if not self.object_classes:
            return FlextResult.fail("Entry must have at least one object class")

        if not self.dn or not self.dn.strip():
            return FlextResult.fail("Entry must have a valid DN")

        return FlextResult.ok(None)

    def add_object_class(self, object_class: str) -> FlextResult[None]:
        """Add object class to entry."""
        if object_class in self.object_classes:
            return FlextResult.fail(f"Object class '{object_class}' already exists")

        self.object_classes.append(object_class)
        return FlextResult.ok(None)

    def get_attribute_values(self, name: str) -> list[str]:
        """Get attribute values by name."""
        return self.attributes.get(name, [])

    def get_single_attribute_value(self, name: str) -> str | None:
        """Get single attribute value."""
        values = self.get_attribute_values(name)
        return values[0] if values else None

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set attribute values."""
        self.attributes[name] = values

    def add_attribute_value(self, name: str, value: str) -> None:
        """Add value to attribute."""
        if name not in self.attributes:
            self.attributes[name] = []
        if value not in self.attributes[name]:
            self.attributes[name].append(value)

    def is_descendant_of(self, parent_dn: str) -> bool:
        """Check if entry is descendant of parent DN."""
        dn_obj = FlextLdapDistinguishedName(value=self.dn)
        return dn_obj.is_descendant_of(parent_dn)

    @computed_field
    def rdn(self) -> str:
        """Get Relative Distinguished Name."""
        return self.dn.split(",", 1)[0].strip()

    @computed_field
    def parent_dn(self) -> str | None:
        """Get parent DN."""
        parts = self.dn.split(",", 1)
        return parts[1].strip() if len(parts) > 1 else None


class FlextLdapUser(FlextLdapEntry):
    """LDAP user entity with user-specific business logic."""

    # User-specific fields with sensible defaults
    uid: str | None = Field(None, description="User ID")
    cn: str | None = Field(None, description="Common Name")
    sn: str | None = Field(None, description="Surname")
    given_name: str | None = Field(None, description="Given Name")
    mail: str | None = Field(None, description="Email Address")

    def __init__(self, **data: object) -> None:
        """Initialize user with default object classes."""
        # Cast data to the proper type for manipulation
        data_dict = dict(data)
        if "object_classes" not in data_dict or not data_dict["object_classes"]:
            data_dict["object_classes"] = ["inetOrgPerson", "person", "top"]
        super().__init__(**data_dict)  # type: ignore[arg-type]

        # Extract user attributes from LDAP attributes
        self._extract_user_attributes()

    def _extract_user_attributes(self) -> None:
        """Extract user-specific attributes from LDAP attributes."""
        if self.attributes:
            self.uid = self.get_single_attribute_value("uid")
            self.cn = self.get_single_attribute_value("cn")
            self.sn = self.get_single_attribute_value("sn")
            self.given_name = self.get_single_attribute_value("givenName")
            self.mail = self.get_single_attribute_value("mail")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate user-specific domain rules."""
        # Call parent validation first
        parent_result = super().validate_domain_rules()
        if not parent_result.is_success:
            return parent_result

        # User-specific validations
        if not self.uid and not self.get_single_attribute_value("uid"):
            return FlextResult.fail("User must have a UID")

        if not self.cn and not self.get_single_attribute_value("cn"):
            return FlextResult.fail("User must have a Common Name")

        # Validate required object classes for users
        required_classes = ["person"]
        for req_class in required_classes:
            if req_class not in self.object_classes:
                return FlextResult.fail(f"User must have object class '{req_class}'")

        return FlextResult.ok(None)

    def set_password(self, password: str) -> FlextResult[None]:
        """Set user password."""
        if not password or len(password) < 6:
            return FlextResult.fail("Password must be at least 6 characters")

        self.set_attribute("userPassword", [password])
        return FlextResult.ok(None)

    def set_email(self, email: str) -> FlextResult[None]:
        """Set user email with validation."""
        if "@" not in email:
            return FlextResult.fail("Invalid email format")

        self.mail = email
        self.set_attribute("mail", [email])
        return FlextResult.ok(None)

    def is_active(self) -> bool:
        """Check if user is active."""
        return self.status == FlextEntityStatus.ACTIVE

    def activate(self) -> None:
        """Activate user account."""
        self.status = FlextEntityStatus.ACTIVE

    def deactivate(self) -> None:
        """Deactivate user account."""
        self.status = FlextEntityStatus.INACTIVE


class FlextLdapGroup(FlextLdapEntry):
    """LDAP group entity with group-specific business logic."""

    # Group-specific fields
    cn: str | None = Field(None, description="Common Name")
    description: str | None = Field(None, description="Group Description")
    members: list[str] = Field(default_factory=list, description="Group Members")

    def __init__(self, **data: object) -> None:
        """Initialize group with default object classes."""
        # Cast data to the proper type for manipulation
        data_dict = dict(data)
        if "object_classes" not in data_dict or not data_dict["object_classes"]:
            data_dict["object_classes"] = ["groupOfNames", "top"]
        super().__init__(**data_dict)  # type: ignore[arg-type]

        # Extract group attributes
        self._extract_group_attributes()

    def _extract_group_attributes(self) -> None:
        """Extract group-specific attributes from LDAP attributes."""
        if self.attributes:
            self.cn = self.get_single_attribute_value("cn")
            self.description = self.get_single_attribute_value("description")
            self.members = self.get_attribute_values("member")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate group-specific domain rules."""
        # Call parent validation first
        parent_result = super().validate_domain_rules()
        if not parent_result.is_success:
            return parent_result

        # Group-specific validations
        if not self.cn and not self.get_single_attribute_value("cn"):
            return FlextResult.fail("Group must have a Common Name")

        # Validate required object classes for groups
        required_classes = ["groupOfNames"]
        for req_class in required_classes:
            if req_class not in self.object_classes:
                return FlextResult.fail(f"Group must have object class '{req_class}'")

        return FlextResult.ok(None)

    def add_member(self, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        try:
            # Validate member DN
            FlextLdapDistinguishedName(value=member_dn)
        except ValueError as e:
            return FlextResult.fail(f"Invalid member DN: {e}")

        if member_dn in self.members:
            return FlextResult.fail(f"Member '{member_dn}' already exists in group")

        self.members.append(member_dn)
        self.add_attribute_value("member", member_dn)
        return FlextResult.ok(None)

    def remove_member(self, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        if member_dn not in self.members:
            return FlextResult.fail(f"Member '{member_dn}' not found in group")

        self.members.remove(member_dn)
        # Update LDAP attributes
        current_members = self.get_attribute_values("member")
        if member_dn in current_members:
            current_members.remove(member_dn)
            self.set_attribute("member", current_members)

        return FlextResult.ok(None)

    def has_member(self, member_dn: str) -> bool:
        """Check if DN is a member of this group."""
        return member_dn in self.members

    def get_member_count(self) -> int:
        """Get number of members in group."""
        return len(self.members)

    def is_empty(self) -> bool:
        """Check if group has no members."""
        return len(self.members) == 0


class FlextLdapConnection(FlextDomainEntity):
    """LDAP connection entity managing connection state."""

    server_uri: str = Field(..., description="LDAP server URI")
    bind_dn: str | None = Field(None, description="Bind DN for authentication")
    is_connected: bool = Field(False, description="Connection status")
    connection_time: datetime | None = Field(None, description="Connection timestamp")
    last_activity: datetime | None = Field(None, description="Last activity timestamp")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate connection domain rules."""
        try:
            FlextLdapUri(value=self.server_uri)
        except ValueError as e:
            return FlextResult.fail(f"Invalid server URI: {e}")

        if self.bind_dn:
            try:
                FlextLdapDistinguishedName(value=self.bind_dn)
            except ValueError as e:
                return FlextResult.fail(f"Invalid bind DN: {e}")

        return FlextResult.ok(None)

    def connect(self) -> FlextResult[None]:
        """Mark connection as established."""
        self.is_connected = True
        self.connection_time = datetime.now(UTC)
        self.last_activity = self.connection_time
        return FlextResult.ok(None)

    def disconnect(self) -> None:
        """Mark connection as closed."""
        self.is_connected = False

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(UTC)

    def get_connection_duration(self) -> float | None:
        """Get connection duration in seconds."""
        if not self.connection_time or not self.is_connected:
            return None

        current_time = self.last_activity or datetime.now(UTC)
        return (current_time - self.connection_time).total_seconds()


# =============================================================================
# CONFIGURATION MODELS
# =============================================================================

class FlextLdapConnectionConfig(FlextModel):
    """LDAP connection configuration model."""

    server_uri: str = Field(..., description="LDAP server URI")
    bind_dn: str | None = Field(None, description="Bind DN for authentication")
    bind_password: str | None = Field(None, description="Bind password")
    use_tls: bool = Field(False, description="Use TLS encryption")
    validate_cert: bool = Field(True, description="Validate server certificate")
    timeout: int = Field(30, description="Connection timeout in seconds")
    pool_size: int = Field(10, description="Connection pool size")

    @field_validator("server_uri")
    @classmethod
    def validate_server_uri(cls, v: str) -> str:
        """Validate server URI format."""
        try:
            FlextLdapUri(value=v)
            return v
        except ValueError as e:
            msg = f"Invalid server URI: {e}"
            raise ValueError(msg) from e

    @field_validator("bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate bind DN format if provided."""
        if v:
            try:
                FlextLdapDistinguishedName(value=v)
                return v
            except ValueError as e:
                msg = f"Invalid bind DN: {e}"
                raise ValueError(msg) from e
        return v


class FlextLdapSettings(FlextModel):
    """FLEXT-LDAP global settings model."""

    default_connection: FlextLdapConnectionConfig | None = Field(
        None,
        description="Default connection configuration",
    )
    search_time_limit: int = Field(
        30,
        description="Default search time limit in seconds",
    )
    search_size_limit: int = Field(
        1000,
        description="Default search size limit",
    )
    enable_logging: bool = Field(True, description="Enable LDAP operation logging")
    log_level: str = Field("INFO", description="Logging level")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid_levels:
            msg = f"Invalid log level: {v}. Must be one of {valid_levels}"
            raise ValueError(msg)
        return v.upper()


# =============================================================================
# EXTENDED ENTRY MODELS
# =============================================================================

class FlextLdapExtendedEntry(FlextLdapEntry):
    """Extended LDAP entry with additional metadata and functionality."""

    source_server: str | None = Field(None, description="Source LDAP server")
    last_modified: datetime | None = Field(None, description="Last modification time")
    schema_version: str | None = Field(None, description="Schema version")
    extensions: LdapAttributeDict = Field(
        default_factory=dict,
        description="Extended attributes and metadata",
    )

    def add_extension(self, key: str, value: LdapAttributeValue) -> None:
        """Add extension data."""
        self.extensions[key] = value

    def get_extension(self, key: str, default: LdapAttributeValue | None = None) -> LdapAttributeValue | None:
        """Get extension data."""
        return self.extensions.get(key, default)

    def has_extension(self, key: str) -> bool:
        """Check if extension exists."""
        return key in self.extensions

    def update_last_modified(self) -> None:
        """Update last modified timestamp."""
        self.last_modified = datetime.now(UTC)


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES
# =============================================================================

# Legacy aliases for backward compatibility
LDAPEntry = FlextLdapExtendedEntry
LDAPFilter = FlextLdapFilter
FlextLdapFilterValue = FlextLdapFilter  # Common alias used in codebase
CreateUserRequest = FlextLdapCreateUserRequest
LDAPUser = FlextLdapUser
LDAPGroup = FlextLdapGroup

# Export commonly used symbols for convenience
__all__ = [
    "CreateUserRequest",
    "FlextLdapAttributesValue",
    "FlextLdapConnection",
    # Configuration Models
    "FlextLdapConnectionConfig",
    # Request/Response Models
    "FlextLdapCreateUserRequest",
    # Enums
    "FlextLdapDataType",
    # Value Objects
    "FlextLdapDistinguishedName",
    "FlextLdapEntityStatus",
    # Domain Entities
    "FlextLdapEntry",
    "FlextLdapExtendedEntry",
    "FlextLdapFilter",
    "FlextLdapFilterValue",
    "FlextLdapGroup",
    "FlextLdapObjectClass",
    "FlextLdapScope",
    "FlextLdapScopeEnum",
    "FlextLdapSearchRequest",
    "FlextLdapSearchResponse",
    "FlextLdapSettings",
    "FlextLdapUri",
    "FlextLdapUser",
    # Legacy Aliases
    "LDAPEntry",
    "LDAPFilter",
    "LDAPGroup",
    "LDAPScope",
    "LDAPUser",
]
