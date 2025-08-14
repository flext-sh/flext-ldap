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

# No circular imports needed - performance helpers are self-contained
# =============================================================================
# PERFORMANCE HELPERS - CACHING AND OPTIMIZATION
# =============================================================================
from typing import ClassVar
from urllib.parse import urlparse

from flext_ldap.types import LdapAttributeDict as UtilsLdapAttributeDict


class FlextLdapPerformanceHelpers:
    """Performance optimization helpers for common operations."""

    # Simple cache for frequently accessed configurations
    _config_cache: ClassVar[dict[str, object]] = {}
    _validation_cache: ClassVar[dict[str, bool]] = {}

    @classmethod
    def cache_config(cls, key: str, config: object) -> None:
        """Cache configuration objects for reuse."""
        cls._config_cache[key] = config

    @classmethod
    def get_cached_config(cls, key: str) -> object | None:
        """Retrieve cached configuration."""
        return cls._config_cache.get(key)

    @classmethod
    def cache_validation_result(
        cls,
        value: str,
        validation_type: str,
        *,
        result: bool,
    ) -> None:
        """Cache validation results for repeated calls."""
        cache_key = f"{validation_type}:{value}"
        cls._validation_cache[cache_key] = result

    @classmethod
    def get_cached_validation(cls, value: str, validation_type: str) -> bool | None:
        """Get cached validation result."""
        cache_key = f"{validation_type}:{value}"
        return cls._validation_cache.get(cache_key)

    @classmethod
    def clear_cache(cls) -> None:
        """Clear all caches."""
        cls._config_cache.clear()
        cls._validation_cache.clear()

    @staticmethod
    def optimize_attribute_processing(attributes: dict[str, object]) -> dict[str, object]:
        """Optimize attribute processing with pre-allocation."""
        if not attributes:
            return {}

        # Inline attribute coercion for better performance (avoid import)
        def coerce_value(value: object) -> str | list[str]:
            if isinstance(value, list):
                return [str(item) for item in value]
            return str(value)

        # Pre-allocate dictionary with known size for better performance
        result: dict[str, object] = {}
        result.update({
            key: coerce_value(value)
            for key, value in attributes.items()
            if value is not None  # Skip None values early
        })
        return result


# =============================================================================
# VALIDATION UTILITIES
# =============================================================================


class FlextLdapUtils:
    """Utility functions for LDAP operations."""

    @staticmethod
    def validate_dn(dn: str) -> bool:
        """Validate Distinguished Name format with caching."""
        if not dn or not isinstance(dn, str):
            return False

        # Check cache first for performance
        cached_result = FlextLdapPerformanceHelpers.get_cached_validation(dn, "dn")
        if cached_result is not None:
            return cached_result

        # Basic DN validation pattern
        dn_pattern = re.compile(
            r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$",
        )

        result = bool(dn_pattern.match(dn.strip()))

        # Cache the result
        FlextLdapPerformanceHelpers.cache_validation_result(dn, "dn", result=result)
        return result

    @staticmethod
    def validate_attribute_name(name: str) -> bool:
        """Validate LDAP attribute name."""
        if not name or not isinstance(name, str):
            return False

        # LDAP attribute names per RFC 4512: base name + optional language tags/options
        # Supports: displayname;lang-es_es, orclinstancecount;oid-prd-app01.network.ctbc
        attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9_.-]+)*$")
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
# PYDANTIC VALIDATION HELPERS - ELIMINATE DUPLICATION
# =============================================================================


class FlextLdapValidationHelpers:
    """Centralized Pydantic validators to eliminate code duplication."""

    @staticmethod
    def validate_non_empty_string(value: str, field_name: str) -> str:
        """Standard validation for non-empty string fields."""
        if not value or not value.strip():
            msg = f"{field_name} cannot be empty"
            raise ValueError(msg)
        return value.strip()

    @staticmethod
    def validate_dn_field(value: str) -> str:
        """Standard DN validation for Pydantic models."""
        return FlextLdapValidationHelpers.validate_non_empty_string(value, "DN")

    @staticmethod
    def validate_filter_field(value: str) -> str:
        """Standard filter validation for Pydantic models."""
        return FlextLdapValidationHelpers.validate_non_empty_string(value, "Search filter")

    @staticmethod
    def validate_cn_field(value: str) -> str:
        """Standard common name validation for Pydantic models."""
        return FlextLdapValidationHelpers.validate_non_empty_string(value, "Common name")

    @staticmethod
    def validate_file_path_field(value: str) -> str:
        """Standard file path validation for Pydantic models."""
        return FlextLdapValidationHelpers.validate_non_empty_string(value, "File path")

    @staticmethod
    def validate_uri_field(value: str) -> str:
        """Standard URI validation for Pydantic models."""
        validated = FlextLdapValidationHelpers.validate_non_empty_string(value, "URI")
        parsed = urlparse(validated)
        if parsed.scheme not in {"ldap", "ldaps"}:
            msg = "URI must use ldap:// or ldaps:// scheme"
            raise ValueError(msg)
        return validated

    @staticmethod
    def validate_base_dn_field(value: str) -> str:
        """Standard base DN validation for Pydantic models."""
        validated = FlextLdapValidationHelpers.validate_non_empty_string(value, "Base DN")
        if not FlextLdapUtils.validate_dn(validated):
            msg = "Invalid DN format"
            raise ValueError(msg)
        return validated


# =============================================================================
# ERROR HANDLING HELPERS - ELIMINATE REPEATED PATTERNS
# =============================================================================


class FlextLdapErrorHelpers:
    """Centralized error handling helpers to eliminate duplication."""

    @staticmethod
    def connection_failed_error(error: str | None = None, context: str = "") -> str:
        """Standard connection failure error message."""
        base_msg = "Connection failed"
        if context:
            base_msg = f"{context} connection failed"
        if error:
            return f"{base_msg}: {error}"
        return base_msg

    @staticmethod
    def operation_failed_error(operation: str, error: str | None = None) -> str:
        """Standard operation failure error message."""
        base_msg = f"{operation.title()} operation failed"
        if error:
            return f"{base_msg}: {error}"
        return base_msg

    @staticmethod
    def validation_failed_error(field: str, reason: str | None = None) -> str:
        """Standard validation failure error message."""
        base_msg = f"{field} validation failed"
        if reason:
            return f"{base_msg}: {reason}"
        return base_msg


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
    "FlextLdapErrorHelpers",
    "FlextLdapPerformanceHelpers",
    "FlextLdapUtils",
    "FlextLdapValidationHelpers",
    # Backward-compat type alias
    "LdapAttributeDict",
    "UtilsLdapAttributeDict",
    "flext_ldap_sanitize_attribute_name",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    "flext_ldap_validate_dn",
]
