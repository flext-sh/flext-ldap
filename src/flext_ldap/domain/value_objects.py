"""LDAP Domain Value Objects - Version 0.7.0.

Immutable value objects for LDAP domain.
"""

from __future__ import annotations

from flext_core.domain.pydantic_base import DomainValueObject
from pydantic import field_validator


class DistinguishedName(DomainValueObject):
    """LDAP Distinguished Name value object."""

    value: str

    @field_validator("value")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate LDAP Distinguished Name format.

        Args:
            v: DN string to validate.

        Returns:
            Validated and normalized DN string.

        Raises:
            ValueError: If DN is empty or has invalid format.

        """
        if not v or not v.strip():
            msg = "Distinguished name cannot be empty"
            raise ValueError(msg)
        # Basic DN validation - must contain at least one RDN
        if "=" not in v:
            msg = "Distinguished name must contain at least one RDN (attribute=value)"
            raise ValueError(msg)
        return v.strip()

    def get_rdn(self) -> str:
        """Get the relative distinguished name (first component)."""
        return self.value.split(",")[0].strip()

    def get_parent_dn(self) -> str | None:
        """Get the parent DN (all components except first)."""
        parts = self.value.split(",", 1)
        return parts[1].strip() if len(parts) > 1 else None

    def __str__(self) -> str:
        """Return string representation of the distinguished name."""
        return self.value


class LDAPAttribute(DomainValueObject):
    """LDAP attribute with multiple values."""

    name: str
    values: list[str]
    binary: bool = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate LDAP attribute name.

        Args:
            v: Attribute name to validate.

        Returns:
            Validated and normalized attribute name.

        Raises:
            ValueError: If attribute name is empty.

        """
        if not v or not v.strip():
            msg = "LDAP attribute name cannot be empty"
            raise ValueError(msg)
        return v.strip().lower()

    @field_validator("values")
    @classmethod
    def validate_values(cls, v: list[str]) -> list[str]:
        """Validate LDAP attribute values.

        Args:
            v: List of attribute values to validate.

        Returns:
            Validated and normalized attribute values.

        Raises:
            ValueError: If attribute has no values.

        """
        if not v:
            msg = "LDAP attribute must have at least one value"
            raise ValueError(msg)
        return [val.strip() for val in v if val.strip()]

    def has_value(self, value: str) -> bool:
        """Check if attribute has a specific value."""
        return value in self.values

    def add_value(self, value: str) -> LDAPAttribute:
        """Add a value to the attribute (immutable operation)."""
        if value not in self.values:
            new_values = [*self.values, value]
            return LDAPAttribute(name=self.name, values=new_values, binary=self.binary)
        return self

    def remove_value(self, value: str) -> LDAPAttribute | None:
        """Remove a value from the attribute (immutable operation)."""
        new_values = [v for v in self.values if v != value]
        if not new_values:
            return None
        return LDAPAttribute(name=self.name, values=new_values, binary=self.binary)


class CreateUserRequest(DomainValueObject):
    """Value object for creating LDAP users with validation."""

    dn: str
    uid: str
    cn: str
    sn: str
    mail: str | None = None
    phone: str | None = None
    ou: str | None = None
    department: str | None = None
    title: str | None = None
    object_classes: list[str] | None = None

    @field_validator("dn")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate DN is not empty."""
        if not v or v.isspace():
            msg = "DN cannot be empty or whitespace only"
            raise ValueError(msg)
        return v.strip()

    @field_validator("uid", "cn", "sn")
    @classmethod
    def validate_required_fields(cls, v: str) -> str:
        """Validate required fields are not empty."""
        if not v or v.isspace():
            msg = "Required field cannot be empty or whitespace only"
            raise ValueError(msg)
        return v.strip()
