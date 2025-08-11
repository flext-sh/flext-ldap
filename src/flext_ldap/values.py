"""FLEXT-LDAP Domain Value Objects - Centralized Types Re-export.

This module provides centralized re-export of value objects that are now defined
in the types.py module, eliminating duplications and following DRY principle.

All value objects follow docs/patterns/foundation.md patterns and extend flext-core
foundation classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import ABCMeta

from flext_core import (
    FlextResult,
    FlextValueObject,
    get_logger,
)
from pydantic import Field, field_validator

from flext_ldap.types import (
    FlextLdapScopeEnum,
    FlextLdapUri,
)

# Import consolidated value objects - ELIMINATES ALL DUPLICATIONS
from flext_ldap.value_objects import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName as _FlextLdapDistinguishedName,
    FlextLdapFilter as FlextLdapFilterValue,  # Alias for compatibility
)

logger = get_logger(__name__)

# ADDITIONAL VALUE OBJECTS - Only unique ones not in types.py


class FlextLdapObjectClass(FlextValueObject, metaclass=ABCMeta):
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
        """Validate object class name."""
        if not v or not isinstance(v, str):
            msg = "Object class name must be a non-empty string"
            raise ValueError(msg)

        if not v.replace("-", "").replace("_", "").isalnum():
            msg = "Object class name contains invalid characters"
            raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return object class name."""
        return self.name


class FlextLdapAttributesValue(FlextValueObject, metaclass=ABCMeta):
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
        """Get single value for attribute."""
        values = self.attributes.get(name, [])
        return values[0] if values else None

    def get_values(self, name: str) -> list[str]:
        """Get all values for attribute."""
        return self.attributes.get(name, [])

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return name in self.attributes

    def add_value(self, name: str, value: str) -> FlextLdapAttributesValue:
        """Add value to attribute."""
        new_attrs = self.attributes.copy()
        if name not in new_attrs:
            new_attrs[name] = []
        new_attrs[name] += [value]
        return FlextLdapAttributesValue(attributes=new_attrs)

    def remove_value(self, name: str, value: str) -> FlextLdapAttributesValue:
        """Remove value from attribute."""
        new_attrs = self.attributes.copy()
        if name in new_attrs:
            new_values = [v for v in new_attrs[name] if v != value]
            if new_values:
                new_attrs[name] = new_values
            else:
                del new_attrs[name]
        return FlextLdapAttributesValue(attributes=new_attrs)


class FlextLdapConnectionInfo(FlextValueObject, metaclass=ABCMeta):
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
    """Extended LDAP entry value object with rich domain operations."""

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

    def classify_entry_type(self) -> str:
        """Classify LDAP entry type based on object classes.

        Returns:
            str: Entry type classification - 'user', 'group', 'organizational_unit', or 'other'

        """
        object_classes = self.get_attribute("objectClass")
        if not object_classes:
            return "other"

        # Convert to lowercase for case-insensitive comparison
        oc_lower = [oc.lower() for oc in object_classes]

        # Check for user/person entries
        if "inetorgperson" in oc_lower or "person" in oc_lower:
            return "user"

        # Check for group entries
        if any(
            oc in oc_lower for oc in ["groupofnames", "groupofuniquenames", "group"]
        ):
            return "group"

        # Check for organizational unit entries
        if "organizationalunit" in oc_lower:
            return "organizational_unit"

        # Default for unrecognized types
        return "other"

    # Bridge abstract method name difference: flext-core expects validate_business_rules
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP extended entry."""
        if not self.dn:
            return FlextResult.fail("LDAP entry must have a distinguished name")
        return FlextResult.ok(None)


# BACKWARD COMPATIBILITY ALIASES - Centralized
LDAPScope = FlextLdapScopeEnum
LDAPFilter = FlextLdapFilterValue
LDAPUri = FlextLdapUri
LDAPObjectClass = FlextLdapObjectClass
LDAPAttributes = FlextLdapAttributesValue
LDAPConnectionInfo = FlextLdapConnectionInfo
ExtendedLDAPEntry = FlextLdapExtendedEntry
LDAPEntry = FlextLdapExtendedEntry  # Default entry type
FlextLdapFilter = FlextLdapFilterValue  # Use comprehensive filter implementation
FlextLdapDistinguishedName = _FlextLdapDistinguishedName

# PUBLIC API EXPORTS
__all__ = [
    # Legacy aliases
    "ExtendedLDAPEntry",
    # Local value objects
    "FlextLdapAttributesValue",
    "FlextLdapConnectionInfo",
    # Re-exported from types.py
    "FlextLdapCreateUserRequest",
    "FlextLdapDistinguishedName",
    "FlextLdapExtendedEntry",
    "FlextLdapFilter",
    "FlextLdapFilterValue",
    "FlextLdapObjectClass",
    "FlextLdapScopeEnum",
    "FlextLdapUri",
    "LDAPAttributes",
    "LDAPConnectionInfo",
    "LDAPEntry",
    "LDAPFilter",
    "LDAPObjectClass",
    "LDAPScope",
    "LDAPUri",
]
