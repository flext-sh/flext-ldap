"""LDAP Domain Value Objects - Immutable Values.

🏗️ CLEAN ARCHITECTURE: Domain Value Objects
Built on flext-core foundation patterns.

Value objects represent immutable concepts in the LDAP domain.
"""

from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlparse

from flext_core import DomainValueObject
from pydantic import Field, field_validator


class LDAPScope(StrEnum):
    """LDAP search scope enumeration."""

    BASE = "base"
    ONE_LEVEL = "onelevel"
    SUBTREE = "subtree"


class DistinguishedName(DomainValueObject):
    """Distinguished Name value object.

    Represents an immutable LDAP distinguished name.
    """

    value: str = Field(..., description="DN string value")

    @field_validator("value")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate DN format.

        Args:
            v: DN string to validate

        Returns:
            Validated DN string

        Raises:
            ValueError: If DN format is invalid

        """
        if not v or not isinstance(v, str):
            msg = "DN must be a non-empty string"
            raise ValueError(msg)

        if "=" not in v:
            msg = "DN must contain at least one attribute=value pair"
            raise ValueError(msg)

        # Validate each component
        components = v.split(",")
        for raw_component in components:
            component = raw_component.strip()
            if "=" not in component:
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

            attr_name, attr_value = component.split("=", 1)
            if not attr_name.strip() or not attr_value.strip():
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return DN string value."""
        return self.value

    def get_rdn(self) -> str:
        """Get relative distinguished name (first component).

        Returns:
            The RDN (leftmost component)

        """
        return self.value.split(",")[0].strip()

    def get_parent_dn(self) -> DistinguishedName | None:
        """Get parent DN.

        Returns:
            Parent DN or None if this is root

        """
        components = self.value.split(",")
        if len(components) <= 1:
            return None

        parent_dn = ",".join(components[1:]).strip()
        return DistinguishedName(value=parent_dn)

    def is_child_of(self, parent: DistinguishedName) -> bool:
        """Check if this DN is a child of another DN.

        Args:
            parent: Potential parent DN

        Returns:
            True if this DN is a child of parent

        """
        return self.value.lower().endswith(parent.value.lower())


class LDAPFilter(DomainValueObject):
    """LDAP search filter value object."""

    value: str = Field(..., description="LDAP filter string")

    @field_validator("value")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        """Validate LDAP filter format.

        Args:
            v: Filter string to validate

        Returns:
            Validated filter string

        Raises:
            ValueError: If filter format is invalid

        """
        if not v or not isinstance(v, str):
            msg = "Filter must be a non-empty string"
            raise ValueError(msg)

        if not (v.startswith("(") and v.endswith(")")):
            msg = "Filter must be wrapped in parentheses"
            raise ValueError(msg)

        # Check for balanced parentheses
        open_count = v.count("(")
        close_count = v.count(")")
        if open_count != close_count:
            msg = "Filter has unbalanced parentheses"
            raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return filter string value."""
        return self.value

    @classmethod
    def equals(cls, attribute: str, value: str) -> LDAPFilter:
        """Create equality filter.

        Args:
            attribute: Attribute name
            value: Attribute value

        Returns:
            Equality filter

        """
        return cls(value=f"({attribute}={value})")

    @classmethod
    def present(cls, attribute: str) -> LDAPFilter:
        """Create presence filter.

        Args:
            attribute: Attribute name

        Returns:
            Presence filter

        """
        return cls(value=f"({attribute}=*)")

    @classmethod
    def and_filters(cls, *filters: LDAPFilter) -> LDAPFilter:
        """Combine filters with AND logic.

        Args:
            filters: Filters to combine

        Returns:
            Combined filter

        """
        if len(filters) == 0:
            msg = "At least one filter required"
            raise ValueError(msg)
        if len(filters) == 1:
            return filters[0]

        filter_strings = [f.value for f in filters]
        combined = f"(&{''.join(filter_strings)})"
        return cls(value=combined)

    @classmethod
    def or_filters(cls, *filters: LDAPFilter) -> LDAPFilter:
        """Combine filters with OR logic.

        Args:
            filters: Filters to combine

        Returns:
            Combined filter

        """
        if len(filters) == 0:
            msg = "At least one filter required"
            raise ValueError(msg)
        if len(filters) == 1:
            return filters[0]

        filter_strings = [f.value for f in filters]
        combined = f"(|{''.join(filter_strings)})"
        return cls(value=combined)


class LDAPUri(DomainValueObject):
    """LDAP URI value object."""

    value: str = Field(..., description="LDAP URI string")

    @field_validator("value")
    @classmethod
    def validate_uri(cls, v: str) -> str:
        """Validate LDAP URI format.

        Args:
            v: URI string to validate

        Returns:
            Validated URI string

        Raises:
            ValueError: If URI format is invalid

        """
        if not v or not isinstance(v, str):
            msg = "URI must be a non-empty string"
            raise ValueError(msg)

        parsed = urlparse(v)
        if parsed.scheme not in {"ldap", "ldaps"}:
            msg = "URI must use ldap:// or ldaps:// scheme"
            raise ValueError(msg)

        if not parsed.hostname:
            msg = "URI must specify hostname"
            raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return URI string value."""
        return self.value

    @property
    def hostname(self) -> str:
        """Get hostname from URI."""
        return urlparse(self.value).hostname or ""

    @property
    def port(self) -> int:
        """Get port from URI."""
        parsed = urlparse(self.value)
        if parsed.port:
            return parsed.port
        return 636 if parsed.scheme == "ldaps" else 389

    @property
    def is_secure(self) -> bool:
        """Check if URI uses secure connection."""
        return urlparse(self.value).scheme == "ldaps"


class LDAPObjectClass(DomainValueObject):
    """LDAP object class value object."""

    name: str = Field(..., description="Object class name")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate object class name.

        Args:
            v: Object class name to validate

        Returns:
            Validated object class name

        Raises:
            ValueError: If name is invalid

        """
        if not v or not isinstance(v, str):
            msg = "Object class name must be a non-empty string"
            raise ValueError(msg)

        # Basic validation - alphanumeric and common chars
        if not v.replace("-", "").replace("_", "").isalnum():
            msg = "Object class name contains invalid characters"
            raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return object class name."""
        return self.name


class LDAPAttributes(DomainValueObject):
    """LDAP attributes value object."""

    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDAP attributes as name-value pairs",
    )

    def get_single_value(self, name: str) -> str | None:
        """Get single value for attribute.

        Args:
            name: Attribute name

        Returns:
            First value or None if not found

        """
        values = self.attributes.get(name, [])
        return values[0] if values else None

    def get_values(self, name: str) -> list[str]:
        """Get all values for attribute.

        Args:
            name: Attribute name

        Returns:
            List of values (empty if not found)

        """
        return self.attributes.get(name, [])

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists.

        Args:
            name: Attribute name

        Returns:
            True if attribute exists

        """
        return name in self.attributes

    def add_value(self, name: str, value: str) -> LDAPAttributes:
        """Add value to attribute.

        Args:
            name: Attribute name
            value: Value to add

        Returns:
            New LDAPAttributes instance with added value

        """
        new_attrs = self.attributes.copy()
        if name not in new_attrs:
            new_attrs[name] = []
        new_attrs[name] += [value]
        return LDAPAttributes(attributes=new_attrs)

    def remove_value(self, name: str, value: str) -> LDAPAttributes:
        """Remove value from attribute.

        Args:
            name: Attribute name
            value: Value to remove

        Returns:
            New LDAPAttributes instance with removed value

        """
        new_attrs = self.attributes.copy()
        if name in new_attrs:
            new_values = [v for v in new_attrs[name] if v != value]
            if new_values:
                new_attrs[name] = new_values
            else:
                del new_attrs[name]
        return LDAPAttributes(attributes=new_attrs)


class LDAPConnectionInfo(DomainValueObject):
    """LDAP connection information value object."""

    server_uri: LDAPUri
    bind_dn: DistinguishedName | None = None
    is_authenticated: bool = False
    is_secure: bool = False
    protocol_version: int = 3

    @property
    def connection_string(self) -> str:
        """Get connection string representation."""
        auth_status = "authenticated" if self.is_authenticated else "anonymous"
        security = "secure" if self.is_secure else "insecure"
        return f"{self.server_uri} ({auth_status}, {security})"
