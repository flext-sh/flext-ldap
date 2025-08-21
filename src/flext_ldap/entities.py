"""LDAP domain entities implementing rich business objects."""

from __future__ import annotations

from datetime import UTC, datetime

from flext_core import (
    FlextEntity,
    FlextEntityId,
    FlextEntityStatus,
    FlextModel,
    FlextResult,
    get_logger,
)
from pydantic import ConfigDict, Field, field_validator, model_validator

from flext_ldap.fields import LdapAttributeProcessor
from flext_ldap.typings import LdapAttributeValue, LdapSearchResult
from flext_ldap.value_objects import FlextLdapDistinguishedName

logger = get_logger(__name__)


class FlextLdapSearchRequest(FlextModel):
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


class FlextLdapSearchResponse(FlextModel):
    """Response model for LDAP searches."""

    entries: list[LdapSearchResult] = Field(
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


class FlextLdapEntry(FlextEntity):
    """Base LDAP directory entry implementing rich domain model patterns.

    Represents a generic LDAP directory entry with comprehensive business logic
    for attribute management, object class validation, and domain rule enforcement.
    """

    dn: str = Field(..., description="Distinguished Name")
    object_classes: list[str] = Field(
        default_factory=list,
        description="LDAP object classes",
    )
    attributes: dict[str, object] = Field(
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

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate entry business rules."""
        if not self.object_classes:
            return FlextResult[None].fail("Entry must have at least one object class")

        if not self.dn or not self.dn.strip():
            return FlextResult[None].fail("Entry must have a valid DN")

        return FlextResult[None].ok(None)

    @field_validator("attributes", mode="before")
    @classmethod
    def _coerce_attributes(cls, v: object) -> dict[str, object] | object:
        """Normalize mapping using LdapAttributeProcessor."""
        if v is None:
            return {}
        if isinstance(v, dict):
            return LdapAttributeProcessor.normalize_attributes(v)
        return v

    def add_object_class(self, object_class: str) -> FlextResult[None]:
        """Add object class to entry."""
        if object_class in self.object_classes:
            return FlextResult[None].fail(
                f"Object class '{object_class}' already exists"
            )

        self.object_classes.append(object_class)
        return FlextResult[None].ok(None)

    def get_attribute_values(self, name: str) -> list[str]:
        """Get attribute values by name, always as list[str]."""
        raw = self.attributes.get(name)
        if raw is None:
            return []
        if isinstance(raw, list):
            return [str(x) for x in raw]
        return [str(raw)]

    def get_single_attribute_value(self, name: str) -> str | None:
        """Get single attribute value."""
        values = self.get_attribute_values(name)
        return values[0] if values else None

    # Convenience API expected by tests
    def get_attribute(self, name: str) -> str | None:
        """Get single attribute value (convenience method)."""
        return self.get_single_attribute_value(name)

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return bool(self.get_attribute_values(name))

    def set_attribute(self, name: str, values: list[str] | str) -> None:
        """Set attribute values."""
        if isinstance(values, str):
            self.attributes[name] = values
        else:
            self.attributes[name] = values


class FlextLdapUser(FlextLdapEntry):
    """LDAP user entity with user-specific business logic."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    uid: str = Field(..., description="User ID")
    cn: str = Field(..., description="Common Name")
    sn: str = Field(..., description="Surname")
    given_name: str | None = Field(None, description="Given name")
    mail: str | None = Field(None, description="Email address")
    phone: str | None = Field(None, description="Phone number")

    @model_validator(mode="after")
    def ensure_object_classes(self) -> FlextLdapUser:
        """Ensure user has required object classes."""
        if "inetOrgPerson" not in self.object_classes:
            self.object_classes.append("inetOrgPerson")
        if "person" not in self.object_classes:
            self.object_classes.append("person")
        return self

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate user-specific business rules."""
        # Call parent validation first
        parent_result = super().validate_business_rules()
        if not parent_result.is_success:
            return parent_result

        # User-specific validations
        if not self.uid or not self.uid.strip():
            return FlextResult[None].fail("User must have a valid UID")

        if not self.cn or not self.cn.strip():
            return FlextResult[None].fail("User must have a valid CN")

        if not self.sn or not self.sn.strip():
            return FlextResult[None].fail("User must have a valid surname")

        # Validate required object classes
        required_classes = {"inetOrgPerson", "person"}
        if not required_classes.issubset(set(self.object_classes)):
            return FlextResult[None].fail(
                f"User must have object classes: {required_classes}",
            )

        return FlextResult[None].ok(None)


class FlextLdapGroup(FlextLdapEntry):
    """LDAP group entity with group-specific business logic."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    cn: str = Field(..., description="Group name")
    description: str | None = Field(None, description="Group description")
    members: list[str] = Field(
        default_factory=list,
        description="Group member DNs",
    )

    @model_validator(mode="after")
    def ensure_object_classes(self) -> FlextLdapGroup:
        """Ensure group has required object classes."""
        if "groupOfNames" not in self.object_classes:
            self.object_classes.append("groupOfNames")
        return self

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate group-specific business rules."""
        # Call parent validation first
        parent_result = super().validate_business_rules()
        if not parent_result.is_success:
            return parent_result

        # Group-specific validations
        if not self.cn or not self.cn.strip():
            return FlextResult[None].fail("Group must have a valid CN")

        # Validate required object classes
        if "groupOfNames" not in self.object_classes:
            return FlextResult[None].fail("Group must have 'groupOfNames' object class")

        return FlextResult[None].ok(None)

    def add_member(self, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        if member_dn in self.members:
            return FlextResult[None].fail(f"Member '{member_dn}' already in group")

        try:
            # Validate DN format
            FlextLdapDistinguishedName(value=member_dn)
            self.members.append(member_dn)
            return FlextResult[None].ok(None)
        except ValueError as e:
            return FlextResult[None].fail(f"Invalid member DN: {e}")

    def remove_member(self, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        if member_dn not in self.members:
            return FlextResult[None].fail(f"Member '{member_dn}' not in group")

        self.members.remove(member_dn)
        return FlextResult[None].ok(None)

    def has_member(self, member_dn: str) -> bool:
        """Check if DN is a member of this group."""
        return member_dn in self.members


class FlextLdapCreateUserRequest(FlextModel):
    """Request model for creating LDAP users."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    dn: str = Field(..., description="Distinguished Name for the new user")
    uid: str = Field(..., description="User ID", min_length=1)
    cn: str = Field(..., description="Common Name", min_length=1)
    sn: str = Field(..., description="Surname", min_length=1)
    given_name: str | None = Field(None, description="Given name")
    mail: str | None = Field(None, description="Email address")
    phone: str | None = Field(None, description="Phone number")
    additional_attributes: dict[str, LdapAttributeValue] = Field(
        default_factory=dict,
        description="Additional LDAP attributes",
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

    def to_user_entity(self) -> FlextLdapUser:
        """Convert request to user entity."""
        attributes = dict(self.additional_attributes)
        attributes.update(
            {
                "uid": self.uid,
                "cn": self.cn,
                "sn": self.sn,
            }
        )

        if self.given_name:
            attributes["givenName"] = self.given_name
        if self.mail:
            attributes["mail"] = self.mail
        if self.phone:
            attributes["telephoneNumber"] = self.phone

        return FlextLdapUser(
            id=FlextEntityId(f"user_req_{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"),
            dn=self.dn,
            uid=self.uid,
            cn=self.cn,
            sn=self.sn,
            given_name=self.given_name,
            mail=self.mail,
            phone=self.phone,
            attributes=dict(attributes),
            status=FlextEntityStatus.ACTIVE,
        )
