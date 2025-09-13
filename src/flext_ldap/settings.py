"""FLEXT LDAP Settings - Single class following flext-core patterns.

Unified settings class consolidating ALL LDAP configuration using Pydantic models
and flext-core patterns. Now uses FlextLDAPConfig as the single source of truth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import final

import yaml
from flext_core import FlextResult, FlextTypes

from flext_ldap.config import (
    FlextLDAPConfig,
    get_flext_ldap_config,
    set_flext_ldap_config,
)
from flext_ldap.connection_config import FlextLDAPConnectionConfig

# Python 3.13 type aliases for LDAP settings
type LdapSettingsDict = FlextTypes.Core.Dict
type LdapConnectionName = str
type LdapConfigPath = str | Path

# YAML module will be imported dynamically when needed


def _safe_yaml_load(content: str) -> dict[str, object]:
    try:
        return yaml.safe_load(content) or {}
    except Exception as e:
        yaml_parse_error_msg = f"Failed to parse YAML content: {e}"
        raise ValueError(yaml_parse_error_msg) from e


@final
class FlextLDAPSettings:
    """FLEXT LDAP Settings - Simple wrapper around FlextLDAPConfig singleton.

    This class provides backward compatibility while delegating to the singleton
    FlextLDAPConfig instance for actual configuration management.

    DEPRECATED: Use FlextLDAPConfig.get_global_instance() directly for new code.
    """

    def __init__(self) -> None:
        """Initialize settings by delegating to FlextLDAPConfig singleton."""
        # Store reference to singleton
        self._ldap_config = get_flext_ldap_config()

    def __getattr__(self, name: str) -> object:
        """Delegate all attribute access to the singleton FlextLDAPConfig."""
        return getattr(self._ldap_config, name)

    def __setattr__(self, name: str, value: object) -> None:
        """Delegate attribute setting to the singleton FlextLDAPConfig."""
        if name.startswith("_"):
            super().__setattr__(name, value)
        else:
            setattr(self._ldap_config, name, value)

    # No fields needed - all delegated to FlextLDAPConfig singleton

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate settings by delegating to FlextLDAPConfig singleton."""
        return self._ldap_config.validate_business_rules()

    # All validation methods delegated to FlextLDAPConfig singleton

    def get_effective_connection(
        self,
        override: FlextLDAPConnectionConfig | None = None,
    ) -> FlextLDAPConnectionConfig:
        """Get effective connection configuration with optional override."""
        # Delegate to FlextLDAPConfig singleton
        return self._ldap_config.get_effective_connection(override)

    def get_effective_auth_config(self) -> FlextTypes.Core.Dict | None:
        """Get effective authentication configuration as dictionary."""
        # Delegate to FlextLDAPConfig singleton
        return self._ldap_config.get_effective_auth_config()

    # Testing convenience: expose `.connection` attribute used by some callers/tests
    @property
    def connection(self) -> FlextLDAPConnectionConfig | None:
        """Get connection configuration."""
        return self._ldap_config.ldap_default_connection

    @connection.setter
    def connection(self, value: FlextLDAPConnectionConfig | None) -> None:
        """Set connection configuration."""
        if value is not None:
            self._ldap_config.update_connection_config(value)

    # Removed unnecessary alias method - use validate_business_rules() directly per SOURCE OF TRUTH

    @classmethod
    def from_env(cls) -> FlextLDAPSettings:
        """Create FlextLDAPSettings from environment variables.

        Now delegates to FlextLDAPConfig singleton for environment loading.

        Returns:
            FlextLDAPSettings: Settings instance using FlextLDAPConfig singleton

        """
        # Create settings instance that delegates to the singleton
        return cls()

    @classmethod
    def from_file(cls, file_path: str) -> FlextResult[FlextLDAPSettings]:
        """Create FlextLDAPSettings from YAML/JSON file.

        Args:
            file_path: Path to configuration file

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is invalid

        Returns:
            FlextResult["FlextLDAPSettings"]:: Description of return value.

        """
        # Error messages as constants
        file_not_found_msg = f"Configuration file not found: {file_path}"

        # Check if file exists
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            raise FileNotFoundError(file_not_found_msg)

        try:
            with file_path_obj.open(encoding="utf-8") as f:
                content = f.read()

            # Try to parse as JSON first
            try:
                config_dict = json.loads(content)
            except json.JSONDecodeError:
                # Try to parse as YAML using helper function
                config_dict = _safe_yaml_load(content)
        except (FileNotFoundError, ValueError):
            raise
        except OSError as e:
            msg = f"Failed to read configuration file: {e}"
            raise ValueError(msg) from e

        try:
            # Use runtime method resolution to avoid MyPy attr-defined issues
            validate_method = getattr(cls, "model_validate", None)
            if validate_method is None:
                return FlextResult.fail("model_validate method not available")
            instance = validate_method(config_dict)
            return FlextResult.ok(instance)
        except ValueError as e:
            return FlextResult.fail(
                f"Configuration validation error: {e}",
            )
        except TypeError as e:
            return FlextResult.fail(
                f"Configuration type error: {e}",
            )

    @classmethod
    def create_development(cls) -> FlextLDAPSettings:
        """Create development configuration using FlextLDAPConfig singleton."""
        # Create development LDAP config
        dev_config_result = FlextLDAPConfig.create_development_ldap_config()
        if dev_config_result.is_failure:
            error_msg = (
                f"Failed to create development config: {dev_config_result.error}"
            )
            raise ValueError(error_msg)

        # Set as global instance
        set_flext_ldap_config(dev_config_result.value)

        # Return settings instance that delegates to singleton
        return cls()

    @classmethod
    def create_test(cls) -> FlextLDAPSettings:
        """Create test configuration using FlextLDAPConfig singleton."""
        # Create test LDAP config
        test_config_result = FlextLDAPConfig.create_test_ldap_config()
        if test_config_result.is_failure:
            error_msg = f"Failed to create test config: {test_config_result.error}"
            raise ValueError(error_msg)

        # Set as global instance
        set_flext_ldap_config(test_config_result.value)

        # Return settings instance that delegates to singleton
        return cls()

    @classmethod
    def create_production(cls) -> FlextLDAPSettings:
        """Create production configuration using FlextLDAPConfig singleton."""
        # Create production LDAP config
        prod_config_result = FlextLDAPConfig.create_production_ldap_config()
        if prod_config_result.is_failure:
            error_msg = (
                f"Failed to create production config: {prod_config_result.error}"
            )
            raise ValueError(error_msg)

        # Set as global instance
        set_flext_ldap_config(prod_config_result.value)

        # Return settings instance that delegates to singleton
        return cls()


__all__ = [
    "FlextLDAPSettings",
]
