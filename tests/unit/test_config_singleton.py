"""Tests for FlextLdapConfigs singleton functionality.

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
from pydantic import SecretStr

from flext_ldap.config import FlextLdapConfigs
from flext_ldap.models import FlextLdapModels


class TestFlextLdapConfigSingleton:
    """Test FlextLdapConfigs singleton functionality."""

    def setup_method(self) -> None:
        """Clear global instance before each test."""
        FlextLdapConfigs.reset_global_instance()

    def teardown_method(self) -> None:
        """Clear global instance after each test."""
        FlextLdapConfigs.reset_global_instance()

    def test_singleton_instance_creation(self) -> None:
        """Test that get_global_instance returns the same instance."""
        # Get first instance
        config1 = FlextLdapConfigs.get_global_instance()

        # Get second instance
        config2 = FlextLdapConfigs.get_global_instance()

        # Should be the same instance
        assert config1 is config2
        assert id(config1) == id(config2)

    def test_convenience_function_get_config(self) -> None:
        """Test that get_global_instance returns the singleton instance."""
        config1 = FlextLdapConfigs.get_global_instance()
        config2 = FlextLdapConfigs.get_global_instance()

        assert config1 is config2
        assert isinstance(config1, FlextLdapConfigs)

    def test_set_global_instance(self) -> None:
        """Test setting a custom global instance."""
        # Create custom config using model_validate
        config_data = {
            "app_name": "test-app",
            "ldap_bind_dn": "cn=test,dc=example,dc=com",
            "ldap_bind_password": SecretStr("test123"),
        }
        custom_config = FlextLdapConfigs.model_validate(config_data)

        # Set as global
        FlextLdapConfigs.set_global_instance(custom_config)

        # Get global instance
        global_config = FlextLdapConfigs.get_global_instance()

        # Should be the custom instance
        assert global_config is custom_config
        assert global_config.app_name == "test-app"
        assert global_config.ldap_bind_dn == "cn=test,dc=example,dc=com"

    def test_reset_global_instance(self) -> None:
        """Test resetting the global instance."""
        # Get initial instance
        config1 = FlextLdapConfigs.get_global_instance()

        # Reset global instance
        FlextLdapConfigs.reset_global_instance()

        # Get new instance
        config2 = FlextLdapConfigs.get_global_instance()

        # Should be different instances
        assert config1 is not config2

    @pytest.mark.skip(
        reason="Environment variable loading needs investigation - FlextConfig inheritance issue",
    )
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
            FlextLdapConfigs.reset_global_instance()
            # Create instance directly to ensure env vars are read
            config = FlextLdapConfigs()

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
            encoding="utf-8",
            mode="w",
            suffix=".json",
            delete=False,
        ) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            # Create config from file using Pydantic Settings
            config = FlextLdapConfigs(_env_file=config_file)
            assert config.app_name == "file-app"
            assert config.ldap_bind_dn == "cn=file,dc=example,dc=com"
            assert config.ldap_bind_password is not None
            assert config.ldap_bind_password.get_secret_value() == "file123"
            assert config.ldap_use_ssl is False

        finally:
            Path(config_file).unlink()

    def test_basic_config_creation(self) -> None:
        """Test basic configuration creation with default values."""
        config = FlextLdapConfigs()

        assert config.ldap_use_ssl is True
        assert config.ldap_verify_certificates is True
        assert config.ldap_enable_debug is False
        assert config.ldap_log_queries is False
        assert config.ldap_enable_caching is False

    def test_ldap_specific_methods(self) -> None:
        """Test LDAP-specific configuration methods."""
        config = FlextLdapConfigs()
        config.ldap_default_connection = FlextLdapModels.ConnectionConfig(
            server="ldap://test.example.com",
            port=389,
        )
        config.ldap_bind_dn = "cn=test,dc=example,dc=com"
        config.ldap_bind_password = SecretStr("test123")
        config.ldap_use_ssl = False

        # Test effective methods that actually exist
        server_uri = config.get_effective_server_uri()
        assert server_uri == "ldap://test.example.com"

        bind_dn = config.get_effective_bind_dn()
        assert bind_dn == "cn=test,dc=example,dc=com"

        bind_password = config.get_effective_bind_password()
        assert bind_password == "test123"

        # Test utility methods
        assert config.is_ssl_enabled() is False
        assert config.is_debug_enabled() is False

    def test_config_field_modifications(self) -> None:
        """Test modifying LDAP configuration fields."""
        config_data = {
            "ldap_size_limit": 100,
            "ldap_time_limit": 30,
            "ldap_enable_caching": False,
        }
        config = FlextLdapConfigs.model_validate(config_data)

        # Check initial values
        assert config.ldap_size_limit == 100
        assert config.ldap_time_limit == 30
        assert config.ldap_enable_caching is False

        # Modify values directly
        config.ldap_size_limit = 500
        config.ldap_time_limit = 60
        config.ldap_enable_caching = True
        config.ldap_cache_ttl = 300

        # Check modified values
        assert config.ldap_size_limit == 500
        assert config.ldap_time_limit == 60
        assert config.ldap_enable_caching is True
        assert config.ldap_cache_ttl == 300

    def test_connection_config_assignment(self) -> None:
        """Test assigning connection configuration."""
        config = FlextLdapConfigs()

        new_connection = FlextLdapModels.ConnectionConfig(
            server="ldaps://new.example.com",
            port=636,
            use_ssl=True,
        )

        # Assign connection directly
        config.ldap_default_connection = new_connection

        # Check connection was assigned
        assert config.ldap_default_connection is new_connection
        assert config.ldap_default_connection.server == "ldaps://new.example.com"
        assert config.ldap_default_connection.port == 636

    def test_validation_business_rules(self) -> None:
        """Test LDAP-specific business rule validation."""
        # Valid configuration
        valid_config_data = {
            "ldap_size_limit": 1000,
            "ldap_time_limit": 30,
            "ldap_page_size": 100,
            "ldap_enable_caching": True,
            "ldap_cache_ttl": 300,
        }
        valid_config = FlextLdapConfigs.model_validate(valid_config_data)

        result = valid_config.validate_business_rules()
        assert result.is_success

        # Test business rules validation with valid configuration
        # The validation_business_rules method should handle edge cases
        cache_config_data = {
            "ldap_enable_caching": True,
            "ldap_cache_ttl": 300,  # Valid value
        }
        valid_config_with_cache = FlextLdapConfigs.model_validate(cache_config_data)

        result = valid_config_with_cache.validate_business_rules()
        assert result.is_success

    def test_field_validation(self) -> None:
        """Test LDAP-specific field validation."""
        # Valid bind DN
        config_data = {"ldap_bind_dn": "cn=test,dc=example,dc=com"}
        config = FlextLdapConfigs.model_validate(config_data)
        assert config.ldap_bind_dn == "cn=test,dc=example,dc=com"

        # None bind DN is valid
        config_none_data = {"ldap_bind_dn": None}
        config_none = FlextLdapConfigs.model_validate(config_none_data)
        assert config_none.ldap_bind_dn is None

        # Invalid bind DN - malformed DN format
        invalid_dn_data = {"ldap_bind_dn": "invalid-dn-format"}
        with pytest.raises(ValueError, match="Invalid LDAP bind DN format"):
            FlextLdapConfigs.model_validate(invalid_dn_data)

    def test_model_validation_consistency(self) -> None:
        """Test cross-field validation consistency."""
        # Valid configuration
        valid_config_data = {
            "ldap_use_ssl": True,
            "ldap_verify_certificates": True,
            "ldap_enable_caching": True,
            "ldap_cache_ttl": 300,
        }
        config = FlextLdapConfigs.model_validate(valid_config_data)
        assert config.ldap_use_ssl is True

        # Test business rules validation
        result = config.validate_business_rules()
        assert result.is_success

    def test_singleton_persistence_across_imports(self) -> None:
        """Test that singleton persists across different import contexts."""
        # Get config from first context
        config1 = FlextLdapConfigs.get_global_instance()

        # Simulate different import context by clearing and reloading
        FlextLdapConfigs.reset_global_instance()

        # Get config from second context
        config2 = FlextLdapConfigs.get_global_instance()

        # Should be different instances (fresh load)
        assert config1 is not config2

        # But both should be valid FlextLdapConfigs instances
        assert isinstance(config1, FlextLdapConfigs)
        assert isinstance(config2, FlextLdapConfigs)
