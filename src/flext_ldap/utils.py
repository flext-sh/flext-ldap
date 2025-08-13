"""FLEXT-LDAP Utils - Consolidated Utilities and Protocols.

🎯 CONSOLIDATES 2 FILES INTO SINGLE PEP8 MODULE:
- utils.py (9,399 bytes) - LDAP utilities and helper functions
- protocols.py (25,959 bytes) - Type protocols and interfaces

This module provides utility functions and protocol definitions for FLEXT-LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_ldap.types import LdapAttributeDict as UtilsLdapAttributeDict

# =============================================================================
# VALIDATION UTILITIES
# =============================================================================


class FlextLdapUtils:
    """Utility functions for LDAP operations."""

    @staticmethod
    def validate_dn(dn: str) -> bool:
        """Validate Distinguished Name format."""
        if not dn or not isinstance(dn, str):
            return False

        # Basic DN validation pattern
        dn_pattern = re.compile(
            r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$",
        )

        return bool(dn_pattern.match(dn.strip()))

    @staticmethod
    def validate_attribute_name(name: str) -> bool:
        """Validate LDAP attribute name."""
        if not name or not isinstance(name, str):
            return False

        # LDAP attribute names: alphanumeric, hyphen, semicolon
        attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9;-]*$")
        return bool(attr_pattern.match(name))

    @staticmethod
    def validate_attribute_value(value: object) -> bool:
        """Validate LDAP attribute value."""
        if not isinstance(value, str):
            return False

        # Basic validation - no null characters
        return "\x00" not in value

    @staticmethod
    def sanitize_attribute_name(name: str) -> str:
        """Sanitize LDAP attribute name."""
        if not name:
            return ""

        # Remove invalid characters and normalize
        sanitized = re.sub(r"[^a-zA-Z0-9;-]", "", name)
        return sanitized.lower()


# Protocols are now in types.py for centralization


# =============================================================================
# EXPORTS
# =============================================================================


# Backward-compatible functional API expected by imports/tests
def flext_ldap_validate_dn(dn: str) -> bool:
    """Validate Distinguished Name format."""
    return FlextLdapUtils.validate_dn(dn)


def flext_ldap_validate_attribute_name(name: str) -> bool:
    """Validate LDAP attribute name."""
    return FlextLdapUtils.validate_attribute_name(name)


def flext_ldap_validate_attribute_value(value: object) -> bool:
    """Validate LDAP attribute value."""
    return FlextLdapUtils.validate_attribute_value(value)


def flext_ldap_sanitize_attribute_name(name: str) -> str:
    """Sanitize LDAP attribute name."""
    return FlextLdapUtils.sanitize_attribute_name(name)


# Backward-compat alias with the exact expected export name
LdapAttributeDict = UtilsLdapAttributeDict

__all__ = [
    "FlextLdapUtils",
    # Backward-compat type alias
    "LdapAttributeDict",
    "UtilsLdapAttributeDict",
    "flext_ldap_sanitize_attribute_name",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    "flext_ldap_validate_dn",
]
