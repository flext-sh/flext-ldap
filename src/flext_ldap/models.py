# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""LDAP Models with strict Python 3.13 typing and Pydantic v2."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class LDAPScope(StrEnum):
    """LDAP search scope enumeration."""

    BASE = "BASE"
    ONELEVEL = "LEVEL"
    SUBTREE = "SUBTREE"


class LDAPEntry(BaseModel):
    """LDAP entry model with strict validation."""

    dn: str = Field(..., description="Distinguished Name")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Entry attributes",
    )

    def get_attribute(self, name: str) -> list[str] | None:
        """Get attribute values.

        Returns:
            List of attribute values if found, None otherwise.

        """
        return self.attributes.get(name)  # pylint: disable=no-member

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set attribute values."""
        self.attributes[name] = values


class LDAPFilter(BaseModel):
    """LDAP filter with validation."""

    filter_string: str = Field(..., description="LDAP filter string")

    @classmethod
    def equals(cls, attribute: str, value: str) -> LDAPFilter:
        """Create equality filter.

        Returns:
            LDAPFilter instance with equality comparison.

        """
        return cls(filter_string=f"({attribute}={value})")

    @classmethod
    def and_filter(cls, *filters: LDAPFilter) -> LDAPFilter:
        """Create AND filter.

        Returns:
            LDAPFilter instance combining all filters with AND logic.

        """
        filter_list = [f.filter_string for f in filters]
        return cls(filter_string=f"(&{''.join(filter_list)})")

    @classmethod
    def or_filter(cls, *filters: LDAPFilter) -> LDAPFilter:
        """Create OR filter.

        Returns:
            LDAPFilter instance combining all filters with OR logic.

        """
        filter_list = [f.filter_string for f in filters]
        return cls(filter_string=f"(|{''.join(filter_list)})")

    def __str__(self) -> str:
        """Return string representation.

        Returns:
            The LDAP filter string.

        """
        return self.filter_string
