# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""LDAP Models using flext-core patterns."""

from __future__ import annotations

from enum import StrEnum

# Use centralized models from flext-core - NO DIRECT PYDANTIC IMPORTS
from flext_core import DomainValueObject, Field

__all__ = ["ExtendedLDAPEntry", "LDAPEntry", "LDAPFilter", "LDAPScope"]


class LDAPScope(StrEnum):
    """LDAP search scope using flext-core StrEnum."""

    BASE = "BASE"
    ONE = "ONE"
    SUB = "SUB"

    # Legacy mappings for backward compatibility
    ONELEVEL = "ONE"  # Map ONELEVEL to ONE
    SUBTREE = "SUB"  # Map SUBTREE to SUB


class ExtendedLDAPEntry(DomainValueObject):
    """Extended LDAP entry with additional utility methods using flext-core patterns."""

    dn: str = Field(..., description="Distinguished Name")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDAP attributes",
    )

    def get_attribute(self, name: str) -> list[str] | None:
        """Get LDAP attribute values by name.

        Args:
            name: The attribute name to retrieve

        Returns:
            List of attribute values if found, None otherwise

        """
        return self.attributes.get(name)

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set LDAP attribute values.

        Args:
            name: The attribute name to set
            values: List of values to set for the attribute

        """
        # Create new dict to ensure Pydantic model updates
        new_attrs = dict(self.attributes)
        new_attrs[name] = values
        # Use model_copy to update attributes since they're readonly
        updated = self.model_copy(update={"attributes": new_attrs})
        # Copy fields back to self
        object.__setattr__(self, "attributes", updated.attributes)

    def has_attribute(self, name: str) -> bool:
        """Check if LDAP entry has a specific attribute.

        Args:
            name: The attribute name to check

        Returns:
            True if attribute exists, False otherwise

        """
        return name in self.attributes

    def get_single_attribute(self, name: str) -> str | None:
        """Get single value from an LDAP attribute.

        Args:
            name: The attribute name to retrieve

        Returns:
            First attribute value if found, None otherwise

        """
        values = self.get_attribute(name)
        return values[0] if values else None

    def get_cn(self) -> str | None:
        """Get the common name (cn) attribute.

        Returns:
            The common name value if found, None otherwise

        """
        return self.get_single_attribute("cn")

    def get_uid(self) -> str | None:
        """Get the user identifier (uid) attribute.

        Returns:
            The user identifier value if found, None otherwise

        """
        return self.get_single_attribute("uid")

    def get_mail(self) -> str | None:
        """Get the email (mail) attribute.

        Returns:
            The email value if found, None otherwise

        """
        return self.get_single_attribute("mail")

    def is_person(self) -> bool:
        """Check if this LDAP entry represents a person.

        Returns:
            True if entry has person object class, False otherwise

        """
        object_classes = self.get_attribute("objectClass")
        return bool(
            object_classes and "person" in [oc.lower() for oc in object_classes],
        )

    def is_group(self) -> bool:
        """Check if this LDAP entry represents a group.

        Returns:
            True if entry has group object class, False otherwise

        """
        object_classes = self.get_attribute("objectClass")
        return bool(
            object_classes
            and any(
                oc.lower() in {"group", "groupofnames", "groupofuniquenames"}
                for oc in object_classes
            ),
        )


# Use ExtendedLDAPEntry as the default LDAPEntry for backward compatibility
LDAPEntry = ExtendedLDAPEntry


class LDAPFilter(DomainValueObject):
    """LDAP filter with validation using flext-core patterns."""

    filter_string: str = Field(..., description="LDAP filter string")

    @classmethod
    def equals(cls, attribute: str, value: str) -> LDAPFilter:
        """Create an equals filter.

        Args:
            attribute: LDAP attribute name
            value: Value to match exactly

        Returns:
            LDAPFilter for exact match

        """
        return cls(filter_string=f"({attribute}={value})")

    @classmethod
    def contains(cls, attribute: str, value: str) -> LDAPFilter:
        """Create a contains filter.

        Args:
            attribute: LDAP attribute name
            value: Value that must be contained

        Returns:
            LDAPFilter for substring match

        """
        return cls(filter_string=f"({attribute}=*{value}*)")

    @classmethod
    def starts_with(cls, attribute: str, value: str) -> LDAPFilter:
        """Create a starts-with filter.

        Args:
            attribute: LDAP attribute name
            value: Value that must be at the start

        Returns:
            LDAPFilter for prefix match

        """
        return cls(filter_string=f"({attribute}={value}*)")

    @classmethod
    def ends_with(cls, attribute: str, value: str) -> LDAPFilter:
        """Create an ends-with filter.

        Args:
            attribute: LDAP attribute name
            value: Value that must be at the end

        Returns:
            LDAPFilter for suffix match

        """
        return cls(filter_string=f"({attribute}=*{value})")

    @classmethod
    def present(cls, attribute: str) -> LDAPFilter:
        """Create a presence filter.

        Args:
            attribute: LDAP attribute name

        Returns:
            LDAPFilter that matches if attribute is present

        """
        return cls(filter_string=f"({attribute}=*)")

    @classmethod
    def not_equals(cls, attribute: str, value: str) -> LDAPFilter:
        """Create a not-equals filter.

        Args:
            attribute: LDAP attribute name
            value: Value that must not match

        Returns:
            LDAPFilter for negated exact match

        """
        return cls(filter_string=f"(!({attribute}={value}))")

    @classmethod
    def and_filter(cls, *filters: LDAPFilter) -> LDAPFilter:
        """Create an AND filter combining multiple filters.

        Args:
            *filters: Variable number of LDAPFilter objects

        Returns:
            LDAPFilter that matches when all filters match

        """
        filter_list = [f.filter_string for f in filters]
        return cls(filter_string=f"(&{''.join(filter_list)})")

    @classmethod
    def or_filter(cls, *filters: LDAPFilter) -> LDAPFilter:
        """Create an OR filter combining multiple filters.

        Args:
            *filters: Variable number of LDAPFilter objects

        Returns:
            LDAPFilter that matches when any filter matches

        """
        filter_list = [f.filter_string for f in filters]
        return cls(filter_string=f"(|{''.join(filter_list)})")

    @classmethod
    def not_filter(cls, filter_obj: LDAPFilter) -> LDAPFilter:
        """Create a NOT filter negating another filter.

        Args:
            filter_obj: LDAPFilter to negate

        Returns:
            LDAPFilter that matches when the input filter does not match

        """
        return cls(filter_string=f"(!{filter_obj.filter_string})")

    @classmethod
    def person_filter(cls) -> LDAPFilter:
        """Create a filter for person objects.

        Returns:
            LDAPFilter that matches person object class

        """
        return cls(filter_string="(object_class=person)")

    @classmethod
    def group_filter(cls) -> LDAPFilter:
        """Create a filter for group objects.

        Returns:
            LDAPFilter that matches group object classes

        """
        return cls.or_filter(
            cls(filter_string="(object_class=group)"),
            cls(filter_string="(object_class=groupOfNames)"),
            cls(filter_string="(object_class=groupOfUniqueNames)"),
        )

    def __str__(self) -> str:
        """Return string representation of the LDAP filter."""
        return str(self.filter_string)

    def __and__(self, other: LDAPFilter) -> LDAPFilter:
        """Combine filters with AND operation."""
        return self.and_filter(self, other)

    def __or__(self, other: LDAPFilter) -> LDAPFilter:
        """Combine filters with OR operation."""
        return self.or_filter(self, other)

    def __invert__(self) -> LDAPFilter:
        """Invert filter with NOT operation."""
        return self.not_filter(self)
