"""FLEXT-LDAP Utils."""

from __future__ import annotations

import re

# No circular imports needed - performance helpers are self-contained
# =============================================================================
# PERFORMANCE HELPERS - CACHING AND OPTIMIZATION
# =============================================================================
from typing import ClassVar
from urllib.parse import urlparse

from flext_ldap.constants import FlextLdapValidationMessages
from flext_ldap.types import LdapAttributeDict as UtilsLdapAttributeDict


class FlextLdapPerformanceHelpers:
    """Performance helpers for caching and micro-optimizations."""

    # Simple cache for frequently accessed configurations
    _config_cache: ClassVar[dict[str, object]] = {}
    _validation_cache: ClassVar[dict[str, bool]] = {}

    @classmethod
    def cache_config(cls, key: str, config: object) -> None:
        cls._config_cache[key] = config

    @classmethod
    def get_cached_config(cls, key: str) -> object | None:
        return cls._config_cache.get(key)

    @classmethod
    def cache_validation_result(
        cls,
        value: str,
        validation_type: str,
        *,
        result: bool,
    ) -> None:
        cache_key = f"{validation_type}:{value}"
        cls._validation_cache[cache_key] = result

    @classmethod
    def get_cached_validation(cls, value: str, validation_type: str) -> bool | None:
        cache_key = f"{validation_type}:{value}"
        return cls._validation_cache.get(cache_key)

    @classmethod
    def clear_cache(cls) -> None:
        cls._config_cache.clear()
        cls._validation_cache.clear()

    @staticmethod
    def optimize_attribute_processing(
        attributes: dict[str, object],
    ) -> dict[str, object]:
        if not attributes:
            return {}

        # Inline attribute coercion for better performance (avoid import)
        def coerce_value(value: object) -> str | list[str]:
            if isinstance(value, list):
                return [str(item) for item in value]
            return str(value)

        # Pre-allocate dictionary with known size for better performance
        result: dict[str, object] = {}
        result.update(
            {
                key: coerce_value(value)
                for key, value in attributes.items()
                if value is not None  # Skip None values early
            }
        )
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
            msg = FlextLdapValidationMessages.FIELD_CANNOT_BE_EMPTY.format(
                field_name=field_name
            )
            raise ValueError(msg)
        return value.strip()

    @staticmethod
    def validate_dn_field(value: str) -> str:
        """Standard DN validation for Pydantic models."""
        return FlextLdapValidationHelpers.validate_non_empty_string(
            value, FlextLdapValidationMessages.DN_FIELD_NAME
        )

    @staticmethod
    def validate_filter_field(value: str) -> str:
        """Standard filter validation for Pydantic models."""
        return FlextLdapValidationHelpers.validate_non_empty_string(
            value, FlextLdapValidationMessages.SEARCH_FILTER_FIELD_NAME
        )

    @staticmethod
    def validate_cn_field(value: str) -> str:
        """Standard common name validation for Pydantic models."""
        return FlextLdapValidationHelpers.validate_non_empty_string(
            value, FlextLdapValidationMessages.COMMON_NAME_FIELD_NAME
        )

    @staticmethod
    def validate_file_path_field(value: str) -> str:
        """Standard file path validation for Pydantic models."""
        return FlextLdapValidationHelpers.validate_non_empty_string(
            value, FlextLdapValidationMessages.FILE_PATH_FIELD_NAME
        )

    @staticmethod
    def validate_uri_field(value: str) -> str:
        """Standard URI validation for Pydantic models."""
        validated = FlextLdapValidationHelpers.validate_non_empty_string(
            value, FlextLdapValidationMessages.URI_FIELD_NAME
        )
        parsed = urlparse(validated)
        if parsed.scheme not in {"ldap", "ldaps"}:
            msg = FlextLdapValidationMessages.INVALID_URI_SCHEME
            raise ValueError(msg)
        return validated

    @staticmethod
    def validate_base_dn_field(value: str) -> str:
        """Standard base DN validation for Pydantic models."""
        validated = FlextLdapValidationHelpers.validate_non_empty_string(
            value, FlextLdapValidationMessages.BASE_DN_FIELD_NAME
        )
        if not FlextLdapUtils.validate_dn(validated):
            msg = FlextLdapValidationMessages.INVALID_DN_FORMAT
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
        base_msg = FlextLdapValidationMessages.CONNECTION_FAILED
        if context:
            base_msg = (
                FlextLdapValidationMessages.CONNECTION_FAILED_WITH_CONTEXT.format(
                    context=context
                )
            )
        if error:
            return f"{base_msg}: {error}"
        return base_msg

    @staticmethod
    def operation_failed_error(operation: str, error: str | None = None) -> str:
        """Standard operation failure error message."""
        base_msg = FlextLdapValidationMessages.OPERATION_FAILED.format(
            operation=operation.title()
        )
        if error:
            return f"{base_msg}: {error}"
        return base_msg

    @staticmethod
    def validation_failed_error(field: str, reason: str | None = None) -> str:
        """Standard validation failure error message."""
        base_msg: str = FlextLdapValidationMessages.VALIDATION_FAILED.format(
            field=field
        )
        if reason:
            return f"{base_msg}: {reason}"
        return base_msg


# =============================================================================
# EXPORTS
# =============================================================================


# Testing convenience functional API expected by imports/tests
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


# Testing convenience alias with the exact expected export name
LdapAttributeDict = UtilsLdapAttributeDict

__all__ = [
    "FlextLdapErrorHelpers",
    "FlextLdapPerformanceHelpers",
    "FlextLdapUtils",
    "FlextLdapValidationHelpers",
    # Testing convenience type alias
    "LdapAttributeDict",
    "UtilsLdapAttributeDict",
    "flext_ldap_sanitize_attribute_name",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    "flext_ldap_validate_dn",
]
