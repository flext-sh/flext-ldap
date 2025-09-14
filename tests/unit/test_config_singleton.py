"""Tests for FlextLDAPConfig singleton functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError

from flext_ldap.config import (
    FlextLDAPConfig,
    clear_flext_ldap_config,
    get_flext_ldap_config,
    set_flext_ldap_config,
)
from flext_ldap.connection_config import FlextLDAPConnectionConfig


class TestFlextLDAPConfigSingleton:
    """Test FlextLDAPConfig singleton functionality."""

    def setup_method(self) -> None:
        """Clear global instance before each test."""
        clear_flext_ldap_config()

    def teardown_method(self) -> None:
        """Clear global instance after each test."""
        clear_flext_ldap_config()

    def test_singleton_instance_creation(self) -> None:
        """Test that get_global_instance returns the same instance."""
        # Get first instance
        config1 = FlextLDAPConfig.get_global_instance()

        # Get second instance
        config2 = FlextLDAPConfig.get_global_instance()

        # Should be the same instance
        assert config1 is config2
        assert id(config1) == id(config2)

    def test_convenience_function_get_config(self) -> None:
        """Test that get_flext_ldap_config returns the singleton instance."""
        config1 = get_flext_ldap_config()
        config2 = get_flext_ldap_config()

        assert config1 is config2
        assert isinstance(config1, FlextLDAPConfig)

    def test_set_global_instance(self) -> None:
        """Test setting a custom global instance."""
        # Create custom config
        custom_config = FlextLDAPConfig(
            app_name="test-app",
            ldap_bind_dn="cn=test,dc=example,dc=com",
            ldap_bind_password=SecretStr("test123"),
        )

        # Set as global
        set_flext_ldap_config(custom_config)

        # Get global instance
        global_config = get_flext_ldap_config()

        # Should be the custom instance
        assert global_config is custom_config
        assert global_config.app_name == "test-app"
        assert global_config.ldap_bind_dn == "cn=test,dc=example,dc=com"

    def test_clear_global_instance(self) -> None:
        """Test clearing the global instance."""
        # Get initial instance
        config1 = get_flext_ldap_config()

        # Clear global instance
        clear_flext_ldap_config()

        # Get new instance
        config2 = get_flext_ldap_config()

        # Should be different instances
        assert config1 is not config2

    def test_environment_variable_loading(self) -> None:
        """Test loading configuration from environment variables."""
        with patch.dict(
            os.environ,
            {
                "FLEXT_LDAP_BIND_DN": "cn=env,dc=example,dc=com",
                "FLEXT_LDAP_BIND_PASSWORD": "env123",
                "FLEXT_LDAP_USE_SSL": "true",
                "FLEXT_LDAP_SIZE_LIMIT": "500",
            },
        ):
            # Clear and reload
            clear_flext_ldap_config()
            config = get_flext_ldap_config()

            # Should load from environment
            assert config.ldap_bind_dn == "cn=env,dc=example,dc=com"
            assert config.ldap_bind_password is not None
            assert config.ldap_bind_password.get_secret_value() == "env123"
            assert config.ldap_use_ssl is True
            assert config.ldap_size_limit == 500

    def test_config_file_loading(self) -> None:
        """Test loading configuration from JSON file."""
        config_data = {
            "app_name": "file-app",
            "ldap_bind_dn": "cn=file,dc=example,dc=com",
            "ldap_bind_password": "file123",
            "ldap_use_ssl": False,
        }

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            # Create config from file
            config_result = FlextLDAPConfig.load_from_file(config_file)
            assert config_result.is_success

            config = config_result.value
            assert config.app_name == "file-app"
            # Convert to FlextLDAPConfig to access LDAP-specific attributes
            ldap_config = FlextLDAPConfig.model_validate(config.model_dump())
            assert ldap_config.ldap_bind_dn == "cn=file,dc=example,dc=com"
            assert ldap_config.ldap_bind_password is not None
            assert ldap_config.ldap_bind_password.get_secret_value() == "file123"
            assert ldap_config.ldap_use_ssl is False

        finally:
            Path(config_file).unlink()

    def test_development_config_factory(self) -> None:
        """Test development configuration factory method."""
        dev_config_result = FlextLDAPConfig.create_development_ldap_config()

        assert dev_config_result.is_success
        config = dev_config_result.value

        assert config.environment == "development"
        assert config.debug is True
        assert config.ldap_enable_debug is True
        assert config.ldap_log_queries is True
        assert config.ldap_enable_debug_mode is True
        assert config.ldap_enable_caching is False

    def test_test_config_factory(self) -> None:
        """Test test configuration factory method."""
        test_config_result = FlextLDAPConfig.create_test_ldap_config()

        assert test_config_result.is_success
        config = test_config_result.value

        assert config.environment == "test"
        assert config.debug is True
        assert config.ldap_enable_test_mode is True
        assert config.ldap_enable_caching is False

    def test_production_config_factory(self) -> None:
        """Test production configuration factory method."""
        prod_config_result = FlextLDAPConfig.create_production_ldap_config()

        assert prod_config_result.is_success
        config = prod_config_result.value

        assert config.environment == "production"
        assert config.debug is False
        assert config.ldap_use_ssl is True
        assert config.ldap_verify_certificates is True
        assert config.ldap_enable_caching is True
        assert config.ldap_cache_ttl == 600

    def test_ldap_specific_methods(self) -> None:
        """Test LDAP-specific configuration methods."""
        config = FlextLDAPConfig()
        config.ldap_default_connection = FlextLDAPConnectionConfig(
            server="ldap://test.example.com",
            port=389,
        )
        config.ldap_bind_dn = "cn=test,dc=example,dc=com"
        config.ldap_bind_password = SecretStr("test123")
        config.ldap_use_ssl = False

        # Test effective connection
        connection = config.get_effective_connection()
        assert connection.server == "ldap://test.example.com"
        assert connection.port == 389

        # Test effective auth config
        auth_config = config.get_effective_auth_config()
        assert auth_config is not None
        assert auth_config["bind_dn"] == "cn=test,dc=example,dc=com"
        assert auth_config["use_ssl"] is False

        # Test search config
        search_config = config.get_ldap_search_config()
        assert "default_scope" in search_config
        assert "size_limit" in search_config
        assert "time_limit" in search_config
        assert "page_size" in search_config

        # Test logging config
        logging_config = config.get_ldap_logging_config()
        assert "enable_debug" in logging_config
        assert "log_queries" in logging_config
        assert "structured_logging" in logging_config

        # Test performance config
        perf_config = config.get_ldap_performance_config()
        assert "enable_caching" in perf_config
        assert "cache_ttl" in perf_config

    def test_parameter_overrides(self) -> None:
        """Test applying LDAP parameter overrides."""
        config = FlextLDAPConfig(
            ldap_size_limit=100,
            ldap_time_limit=30,
            ldap_enable_caching=False,
        )

        # Apply overrides
        overrides: dict[str, object] = {
            "size_limit": 500,
            "time_limit": 60,
            "enable_caching": True,
            "cache_ttl": 300,
        }

        result = config.apply_ldap_overrides(overrides)
        assert result.is_success

        # Check overrides were applied
        assert config.ldap_size_limit == 500
        assert config.ldap_time_limit == 60
        assert config.ldap_enable_caching is True
        assert config.ldap_cache_ttl == 300

    def test_connection_config_update(self) -> None:
        """Test updating connection configuration."""
        config = FlextLDAPConfig()

        new_connection = FlextLDAPConnectionConfig(
            server="ldaps://new.example.com",
            port=636,
            use_ssl=True,
        )

        result = config.update_connection_config(new_connection)
        assert result.is_success

        # Check connection was updated
        assert config.ldap_default_connection is new_connection
        assert config.ldap_default_connection.server == "ldaps://new.example.com"
        assert config.ldap_default_connection.port == 636

    def test_validation_business_rules(self) -> None:
        """Test LDAP-specific business rule validation."""
        # Valid configuration
        valid_config = FlextLDAPConfig(
            ldap_size_limit=1000,
            ldap_time_limit=30,
            ldap_page_size=100,
            ldap_enable_caching=True,
            ldap_cache_ttl=300,
        )

        result = valid_config.validate_business_rules()
        assert result.is_success

        # Test business rules validation with valid configuration
        # The validation_business_rules method should handle edge cases
        valid_config_with_cache = FlextLDAPConfig(
            ldap_enable_caching=True,
            ldap_cache_ttl=300,  # Valid value
        )

        result = valid_config_with_cache.validate_business_rules()
        assert result.is_success

    def test_field_validation(self) -> None:
        """Test LDAP-specific field validation."""
        # Valid bind DN
        config = FlextLDAPConfig(ldap_bind_dn="cn=test,dc=example,dc=com")
        assert config.ldap_bind_dn == "cn=test,dc=example,dc=com"

        # Invalid bind DN - empty
        with pytest.raises(
            ValidationError, match="String should have at least 3 characters"
        ):
            FlextLDAPConfig(ldap_bind_dn="")

        # Invalid scope
        with pytest.raises(ValueError, match="Invalid LDAP scope"):
            FlextLDAPConfig(ldap_default_scope="invalid_scope")

    def test_model_validation_consistency(self) -> None:
        """Test cross-field validation consistency."""
        # Valid configuration
        config = FlextLDAPConfig(
            ldap_use_ssl=True,
            ldap_verify_certificates=True,
            ldap_enable_test_mode=False,
            environment="production",
        )
        assert config.ldap_use_ssl is True

        # Invalid configuration - test mode in production
        with pytest.raises(ValueError, match="Test mode should not be enabled"):
            FlextLDAPConfig.model_validate(
                {
                    "ldap_enable_test_mode": True,
                    "environment": "production",
                }
            )

    def test_singleton_persistence_across_imports(self) -> None:
        """Test that singleton persists across different import contexts."""
        # Get config from first context
        config1 = get_flext_ldap_config()

        # Simulate different import context by clearing and reloading
        clear_flext_ldap_config()

        # Get config from second context
        config2 = get_flext_ldap_config()

        # Should be different instances (fresh load)
        assert config1 is not config2

        # But both should be valid FlextLDAPConfig instances
        assert isinstance(config1, FlextLDAPConfig)
        assert isinstance(config2, FlextLDAPConfig)
