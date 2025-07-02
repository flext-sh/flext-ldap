"""LDAP Validation Module - True Facade with Pure Delegation to Existing Validation.

This module implements the True Facade pattern by providing validation operations
that delegate entirely to the existing utils/ldap_validation.py infrastructure.

TRUE FACADE PATTERN: 100% DELEGATION TO EXISTING VALIDATION INFRASTRUCTURE
- Delegates ALL validation to utils.ldap_validation module
- Provides semantic business-friendly validation interface
- Maintains consistent Result patterns
- Zero code duplication - pure delegation
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from flext_ldap.api.config import LDAPConfig
from flext_ldap.core.logging import get_logger

# Delegate to existing validation infrastructure
from flext_ldap.utils.ldap_validation import (
    validate_and_normalize_attribute_name,
    validate_and_normalize_attribute_value,
    validate_and_normalize_file_path,
    validate_and_normalize_ldap_entry,
    validate_configuration_value,
    validate_dn,
)

if TYPE_CHECKING:
    from flext_ldap.domain.results import Result

logger = get_logger(__name__)


class LDAPValidation:
    """LDAP Validation - True Facade with Pure Delegation to Existing Validation.

    TRUE FACADE PATTERN: 100% DELEGATION TO EXISTING VALIDATION INFRASTRUCTURE
    ==========================================================================

    This class implements the True Facade pattern by providing validation operations
    that delegate entirely to the existing utils/ldap_validation.py infrastructure
    without any reimplementation.

    PURE DELEGATION ARCHITECTURE:
    - Delegates ALL validation to utils.ldap_validation functions
    - Provides semantic business-friendly validation interface
    - Maintains consistent Result[T] patterns
    - Zero code duplication - pure delegation
    - Uses existing production-tested validation infrastructure

    DELEGATION TARGETS:
    - utils.ldap_validation.validate_and_normalize_ldap_entry
    - utils.ldap_validation.validate_and_normalize_attribute_name
    - utils.ldap_validation.validate_and_normalize_attribute_value
    - utils.ldap_validation.validate_dn
    - utils.ldap_validation.validate_configuration_value

    USAGE PATTERNS:
    - Entry validation:
        >>> result = validator.validate_entry(entry_dict)
        >>> if result.success: print("Entry is valid")

    - Configuration validation:
        >>> result = validator.validate_config(config)
        >>> if result.success: print("Config is valid")

    TRUE FACADE BENEFITS:
    - Leverages existing production-tested validation logic
    - No functionality duplication
    - Consistent validation behavior across all operations
    - Automatic improvements from utils module enhancements
    """

    def __init__(self, config: LDAPConfig | None = None) -> None:
        """Initialize validation facade.

        Args:
            config: Optional LDAP configuration for context-specific validation

        """
        self._config = config

    # ===========================================================================
    # PURE DELEGATION METHODS - All validation delegates to utils infrastructure
    # ===========================================================================

    def validate_entry(self, entry: dict[str, Any]) -> Result[dict[str, Any]]:
        """Validate LDAP entry - delegates to existing validation infrastructure.

        Pure delegation to utils.ldap_validation.validate_and_normalize_ldap_entry
        which provides comprehensive entry validation and normalization.
        """
        from flext_ldap.domain.results import Result

        try:
            # Pure delegation to existing validation infrastructure
            normalized_entry = validate_and_normalize_ldap_entry(entry)
            return Result.ok(
                normalized_entry,
                message="Entry validation delegated to utils.ldap_validation",
            )
        except Exception as e:
            return Result.from_exception(e, default_data={})

    def validate_attribute(self, name: str, value: Any) -> Result[tuple[str, Any]]:
        """Validate LDAP attribute - delegates to existing validation infrastructure."""
        from flext_ldap.domain.results import Result

        try:
            # Pure delegation to existing validation infrastructure
            normalized_name = validate_and_normalize_attribute_name(name)
            normalized_value = validate_and_normalize_attribute_value(value)
            return Result.ok(
                (normalized_name, normalized_value),
                message="Attribute validation delegated to utils.ldap_validation",
            )
        except Exception as e:
            return Result.from_exception(e, default_data=(name, value))

    def validate_dn(self, dn: str) -> Result[str]:
        """Validate DN - delegates to existing validation infrastructure."""
        from flext_ldap.domain.results import Result

        try:
            # Pure delegation to existing validation infrastructure
            normalized_dn = validate_dn(dn)
            return Result.ok(
                normalized_dn,
                message="DN validation delegated to utils.ldap_validation",
            )
        except Exception as e:
            return Result.from_exception(e, default_data=dn)

    def validate_config(self, config: LDAPConfig) -> Result[bool]:
        """Validate LDAP configuration - delegates to existing validation infrastructure."""
        from flext_ldap.domain.results import Result

        try:
            # Delegate to existing configuration validation
            if hasattr(config, "server"):
                validate_configuration_value(config.server, "server")
            if hasattr(config, "base_dn"):
                validate_dn(config.base_dn)
            if hasattr(config, "auth_dn"):
                validate_dn(config.auth_dn)

            return Result.ok(
                True,
                message="Config validation delegated to utils.ldap_validation",
            )
        except Exception as e:
            return Result.from_exception(e, default_data=False)

    def validate_file_path(self, path: str) -> Result[str]:
        """Validate file path - delegates to existing validation infrastructure."""
        from flext_ldap.domain.results import Result

        try:
            # Pure delegation to existing path validation infrastructure
            normalized_path = validate_and_normalize_file_path(path)
            return Result.ok(
                normalized_path,
                message="Path validation delegated to utils.ldap_validation",
            )
        except Exception as e:
            return Result.from_exception(e, default_data=path)


# ==============================================================================
# CONVENIENCE FUNCTIONS - Direct delegation for common validation operations
# ==============================================================================


def validate_ldap_config(config: LDAPConfig) -> Result[bool]:
    """Validate LDAP configuration - convenience function with pure delegation."""
    validator = LDAPValidation(config)
    return validator.validate_config(config)


def validate_ldap_entry(entry: dict[str, Any]) -> Result[dict[str, Any]]:
    """Validate LDAP entry - convenience function with pure delegation."""
    validator = LDAPValidation()
    return validator.validate_entry(entry)


def validate_ldap_dn(dn: str) -> Result[str]:
    """Validate LDAP DN - convenience function with pure delegation."""
    validator = LDAPValidation()
    return validator.validate_dn(dn)
