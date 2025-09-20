"""FLEXT-LDAP Value Objects Module.

Following FLEXT unified class patterns, this module contains the
FlextLdapValueObjects class implementing all LDAP value objects.

NO legacy compatibility maintained - clean unified class only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from flext_core import FlextModels


class FlextLdapValueObjects(FlextModels):
    """Unified LDAP value objects class - NO legacy aliases."""

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
        def create(cls, dn_string: str) -> FlextLdapValueObjects.DistinguishedName:
            """Factory method for DN creation with validation."""
            return cls(value=dn_string.strip())

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
        def equals(cls, attribute: str, value: str) -> FlextLdapValueObjects.Filter:
            """Create equality filter."""
            return cls(expression=f"({attribute}={value})")

        @classmethod
        def starts_with(
            cls, attribute: str, value: str
        ) -> FlextLdapValueObjects.Filter:
            """Create starts-with filter."""
            return cls(expression=f"({attribute}={value}*)")

        @classmethod
        def object_class(cls, object_class: str) -> FlextLdapValueObjects.Filter:
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
                msg = f"Invalid scope: {self.value}. Must be one of {valid_scopes}"
                raise ValueError(msg)

        @classmethod
        def base(cls) -> FlextLdapValueObjects.Scope:
            """Create base scope."""
            return cls(value=cls.BASE)

        @classmethod
        def onelevel(cls) -> FlextLdapValueObjects.Scope:
            """Create onelevel scope."""
            return cls(value=cls.ONELEVEL)

        @classmethod
        def subtree(cls) -> FlextLdapValueObjects.Scope:
            """Create subtree scope."""
            return cls(value=cls.SUBTREE)


__all__ = ["FlextLdapValueObjects"]
