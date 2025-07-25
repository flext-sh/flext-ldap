"""LDAP Domain Value Objects - DEPRECATED.

🚨 DEPRECATION NOTICE: This module is deprecated.
Use flext_ldap.domain.values instead.

This module will be removed in version 1.0.0.
"""

from __future__ import annotations

import warnings

# Import all value objects from the new unified module
from flext_ldap.domain.values import (
    FlextLdapAttributesValue,
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapFilterValue,
    FlextLdapObjectClass,
    FlextLdapUri,
)

# Issue deprecation warning
warnings.warn(
    "flext_ldap.domain.value_objects is deprecated. "
    "Use flext_ldap.domain.values instead. "
    "This module will be removed in version 1.0.0.",
    DeprecationWarning,
    stacklevel=2,
)


# Legacy class for FlextLdapAttribute - only existed in value_objects
class FlextLdapAttribute:
    """DEPRECATED: LDAP attribute with multiple values.

    Use FlextLdapAttributesValue from flext_ldap.domain.values instead.
    """

    def __init__(
        self,
        name: str,
        values: list[str],
        *,
        binary: bool = False,
    ) -> None:
        """Initialize LDAP attribute.

        Args:
            name: Attribute name
            values: List of attribute values
            binary: Whether the attribute contains binary data

        """
        warnings.warn(
            "FlextLdapAttribute is deprecated. Use FlextLdapAttributesValue instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.name = name
        self.values = values
        self.binary = binary


# Backward compatibility aliases
DistinguishedName = FlextLdapDistinguishedName

# Explicit exports for MyPy
__all__ = [
    "DistinguishedName",
    "FlextLdapAttribute",
    "FlextLdapAttributesValue",
    "FlextLdapCreateUserRequest",
    "FlextLdapDistinguishedName",
    "FlextLdapFilterValue",
    "FlextLdapObjectClass",
    "FlextLdapUri",
]
