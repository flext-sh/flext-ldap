"""LDAP Domain Value Objects - Immutable Values.

🏗️ CLEAN ARCHITECTURE: Domain Value Objects
Built on flext-core foundation patterns.

Value objects represent immutable concepts in the LDAP domain.
"""

from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlparse

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext_core root imports
from flext_core import FlextResult, FlextValueObject
from pydantic import Field, field_validator


class FlextLdapScopeEnum(StrEnum):
    """LDAP search scope enumeration."""

    BASE = "base"
    ONE_LEVEL = "onelevel"
    SUBTREE = "subtree"

    # Legacy mappings for backward compatibility (from models.py)
    ONE = "onelevel"  # Map ONE to ONE_LEVEL
    SUB = "subtree"  # Map SUB to SUBTREE


class FlextLdapDistinguishedName(FlextValueObject):
    """Distinguished Name value object.

    Represents an immutable LDAP distinguished name.
    """

    value: str = Field(..., description="DN string value")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for DN."""
        if not self.value or not self.value.strip():
            return FlextResult.fail("Distinguished name cannot be empty")
        if "=" not in self.value:
            return FlextResult.fail("Distinguished name must contain at least one RDN")
        return FlextResult.ok(None)

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

    def get_parent_dn(self) -> FlextLdapDistinguishedName | None:
        """Get parent DN.

        Returns:
            Parent DN or None if this is root

        """
        components = self.value.split(",")
        if len(components) <= 1:
            return None

        parent_dn = ",".join(components[1:]).strip()
        return FlextLdapDistinguishedName(value=parent_dn)

    def get_components(self) -> list[str]:
        """Get all DN components.

        Returns:
            List of DN components.

        """
        return [component.strip() for component in self.value.split(",")]

    def is_child_of(self, parent: FlextLdapDistinguishedName) -> bool:
        """Check if this DN is a child of another DN.

        Args:
            parent: Potential parent DN

        Returns:
            True if this DN is a child of parent

        """
        return self.value.lower().endswith(parent.value.lower())


class FlextLdapFilterValue(FlextValueObject):
    """LDAP search filter value object."""

    value: str = Field(..., description="LDAP filter string")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP filter."""
        if not self.value:
            return FlextResult.fail("LDAP filter cannot be empty")
        if not (self.value.startswith("(") and self.value.endswith(")")):
            return FlextResult.fail("LDAP filter must be enclosed in parentheses")
        # Check for balanced parentheses
        open_count = self.value.count("(")
        close_count = self.value.count(")")
        if open_count != close_count:
            return FlextResult.fail("LDAP filter has unbalanced parentheses")
        return FlextResult.ok(None)

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
    def equals(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create equality filter.

        Args:
            attribute: Attribute name
            value: Attribute value

        Returns:
            Equality filter

        """
        return cls(value=f"({attribute}={value})")

    @classmethod
    def present(cls, attribute: str) -> FlextLdapFilterValue:
        """Create presence filter.

        Args:
            attribute: Attribute name

        Returns:
            Presence filter

        """
        return cls(value=f"({attribute}=*)")

    @classmethod
    def and_filters(cls, *filters: FlextLdapFilterValue) -> FlextLdapFilterValue:
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
    def or_filters(cls, *filters: FlextLdapFilterValue) -> FlextLdapFilterValue:
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

    @classmethod
    def contains(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create a contains filter (consolidated from models.py)."""
        return cls(value=f"({attribute}=*{value}*)")

    @classmethod
    def starts_with(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create a starts-with filter (consolidated from models.py)."""
        return cls(value=f"({attribute}={value}*)")

    @classmethod
    def ends_with(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create an ends-with filter (consolidated from models.py)."""
        return cls(value=f"({attribute}=*{value})")

    @classmethod
    def not_equals(cls, attribute: str, value: str) -> FlextLdapFilterValue:
        """Create a not-equals filter (consolidated from models.py)."""
        return cls(value=f"(!({attribute}={value}))")

    @classmethod
    def person_filter(cls) -> FlextLdapFilterValue:
        """Create a filter for person objects (consolidated from models.py)."""
        return cls(value="(objectClass=person)")

    @classmethod
    def group_filter(cls) -> FlextLdapFilterValue:
        """Create a filter for group objects (consolidated from models.py)."""
        return cls.or_filters(
            cls(value="(objectClass=group)"),
            cls(value="(objectClass=groupOfNames)"),
            cls(value="(objectClass=groupOfUniqueNames)"),
        )

    def __and__(self, other: FlextLdapFilterValue) -> FlextLdapFilterValue:
        """Combine filters with AND operation (consolidated from models.py)."""
        return self.and_filters(self, other)

    def __or__(self, other: FlextLdapFilterValue) -> FlextLdapFilterValue:
        """Combine filters with OR operation (consolidated from models.py)."""
        return self.or_filters(self, other)


class FlextLdapUri(FlextValueObject):
    """LDAP URI value object."""

    value: str = Field(..., description="LDAP URI string")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP URI."""
        if not self.value:
            return FlextResult.fail("LDAP URI cannot be empty")
        parsed = urlparse(self.value)
        if parsed.scheme not in {"ldap", "ldaps"}:
            return FlextResult.fail("LDAP URI must use ldap:// or ldaps:// scheme")
        if not parsed.hostname:
            return FlextResult.fail("LDAP URI must specify hostname")
        return FlextResult.ok(None)

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


class FlextLdapObjectClass(FlextValueObject):
    """LDAP object class value object."""

    name: str = Field(..., description="Object class name")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP object class."""
        if not self.name or not self.name.strip():
            return FlextResult.fail("Object class name cannot be empty")
        # Basic validation - alphanumeric and common chars
        if not self.name.replace("-", "").replace("_", "").isalnum():
            return FlextResult.fail("Object class name contains invalid characters")
        return FlextResult.ok(None)

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


class FlextLdapAttributesValue(FlextValueObject):
    """LDAP attributes value object."""

    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDAP attributes as name-value pairs",
    )

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP attributes."""
        for name, values in self.attributes.items():
            if not name or not name.strip():
                return FlextResult.fail("Attribute name cannot be empty")
            if not values:
                return FlextResult.fail(
                    f"Attribute '{name}' must have at least one value",
                )
        return FlextResult.ok(None)

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

    def add_value(self, name: str, value: str) -> FlextLdapAttributesValue:
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
        return FlextLdapAttributesValue(attributes=new_attrs)

    def remove_value(self, name: str, value: str) -> FlextLdapAttributesValue:
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
        return FlextLdapAttributesValue(attributes=new_attrs)


class FlextLdapConnectionInfo(FlextValueObject):
    """LDAP connection information value object."""

    server_uri: FlextLdapUri
    bind_dn: FlextLdapDistinguishedName | None = None
    is_authenticated: bool = False
    is_secure: bool = False
    protocol_version: int = 3

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP connection info."""
        if not self.server_uri:
            return FlextResult.fail("Connection info must have server_uri")
        if self.protocol_version not in {2, 3}:
            return FlextResult.fail("Protocol version must be 2 or 3")
        return FlextResult.ok(None)

    @property
    def connection_string(self) -> str:
        """Get connection string representation."""
        auth_status = "authenticated" if self.is_authenticated else "anonymous"
        security = "secure" if self.is_secure else "insecure"
        return f"{self.server_uri} ({auth_status}, {security})"


class FlextLdapExtendedEntry(FlextValueObject):
    """Extended LDAP entry with utility methods (consolidated from models.py)."""

    dn: str = Field(..., description="Distinguished Name")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDAP attributes",
    )

    def get_attribute(self, name: str) -> list[str] | None:
        """Get LDAP attribute values by name."""
        return self.attributes.get(name)

    def has_attribute(self, name: str) -> bool:
        """Check if LDAP entry has a specific attribute."""
        return name in self.attributes

    def get_single_attribute(self, name: str) -> str | None:
        """Get single value from an LDAP attribute."""
        values = self.get_attribute(name)
        return values[0] if values else None

    def get_cn(self) -> str | None:
        """Get the common name (cn) attribute."""
        return self.get_single_attribute("cn")

    def get_uid(self) -> str | None:
        """Get the user identifier (uid) attribute."""
        return self.get_single_attribute("uid")

    def get_mail(self) -> str | None:
        """Get the email (mail) attribute."""
        return self.get_single_attribute("mail")

    def is_person(self) -> bool:
        """Check if this LDAP entry represents a person."""
        object_classes = self.get_attribute("objectClass")
        return bool(
            object_classes and "person" in [oc.lower() for oc in object_classes],
        )

    def is_group(self) -> bool:
        """Check if this LDAP entry represents a group."""
        object_classes = self.get_attribute("objectClass")
        return bool(
            object_classes
            and any(
                oc.lower() in {"group", "groupofnames", "groupofuniquenames"}
                for oc in object_classes
            ),
        )

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP extended entry."""
        if not self.dn:
            return FlextResult.fail("LDAP entry must have a distinguished name")
        return FlextResult.ok(None)


class FlextLdapCreateUserRequest(FlextValueObject):
    """Value object for creating LDAP users with validation."""

    dn: str = Field(..., description="Distinguished name for the user")
    uid: str = Field(..., description="User identifier")
    cn: str = Field(..., description="Common name")
    sn: str = Field(..., description="Surname")
    mail: str | None = Field(None, description="Email address")
    phone: str | None = Field(None, description="Phone number")
    ou: str | None = Field(None, description="Organizational unit")
    department: str | None = Field(None, description="Department")
    title: str | None = Field(None, description="Job title")
    object_classes: list[str] | None = Field(None, description="LDAP object classes")

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for user creation request."""
        if not self.dn or not self.dn.strip():
            return FlextResult.fail("DN cannot be empty")
        if not self.uid or not self.uid.strip():
            return FlextResult.fail("UID cannot be empty")
        if self.mail and "@" not in self.mail:
            return FlextResult.fail("Email must be valid format")
        return FlextResult.ok(None)

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


# Backward compatibility aliases
LDAPScope = FlextLdapScopeEnum
FlextLdapDistinguishedName = FlextLdapDistinguishedName
LDAPFilter = FlextLdapFilterValue
LDAPUri = FlextLdapUri
LDAPObjectClass = FlextLdapObjectClass
LDAPAttributes = FlextLdapAttributesValue
LDAPConnectionInfo = FlextLdapConnectionInfo
# Consolidated from models.py
ExtendedLDAPEntry = FlextLdapExtendedEntry
LDAPEntry = FlextLdapExtendedEntry  # Default entry type
# Enhanced filter with builder methods from models.py
FlextLdapFilter = FlextLdapFilterValue  # Use our comprehensive filter implementation
