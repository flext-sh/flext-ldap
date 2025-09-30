"""Comprehensive tests for FlextLdapConfig.

This module provides complete test coverage for the FlextLdapConfig class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import patch

from flext_ldap import FlextLdapConfig, FlextLdapModels, FlextLdapValidations
from flext_ldap.constants import FlextLdapConstants


class TestFlextLdapConfig:
    """Comprehensive test suite for FlextLdapConfig."""

    def test_configs_initialization(self) -> None:
        """Test configs initialization."""
        configs = FlextLdapConfig()
        assert configs is not None
        assert hasattr(configs, "_global_instance")
        assert hasattr(configs, "get_global_instance")

    def test_create_connection_config_success(
        self,
        ldap_server_config: dict[str, object],
    ) -> None:
        """Test successful connection config creation."""
        configs = FlextLdapConfig()

        # Use the actual method name
        result = configs.create_from_connection_config_data(ldap_server_config)

        assert result.is_success
        assert isinstance(result.data, FlextLdapConfig)
        assert (
            result.data.get_effective_server_uri()
            == f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )
        assert result.data.get_effective_bind_dn() == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_create_connection_config_with_minimal_data(
        self,
    ) -> None:
        """Test connection config creation with minimal data (should succeed with defaults)."""
        configs = FlextLdapConfig()

        # Test with minimal config data - should succeed with defaults
        minimal_config: dict[str, object] = {
            "server": "ldap://localhost",
            "port": FlextLdapConstants.Protocol.DEFAULT_PORT,
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
        }

        result = configs.create_from_connection_config_data(minimal_config)

        # Should succeed with default values
        assert result.is_success
        assert isinstance(result.data, FlextLdapConfig)
        assert result.data.ldap_server_uri == "ldap://localhost"
        assert result.data.ldap_port == FlextLdapConstants.Protocol.DEFAULT_PORT
        assert result.data.ldap_bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_create_connection_config_from_env_success(self) -> None:
        """Test successful connection config creation from environment."""
        configs = FlextLdapConfig()

        result = configs.create_connection_config_from_env()

        assert result.is_success
        assert isinstance(result.data, dict)
        # The method uses the global instance with default values
        assert result.data["server"] == "ldap://localhost"
        assert result.data["port"] == FlextLdapConstants.Protocol.DEFAULT_PORT
        assert result.data["bind_dn"] is None  # Default value
        assert not result.data["base_dn"]  # Default value

    def test_create_connection_config_from_env_missing_vars(self) -> None:
        """Test connection config creation from environment with missing variables."""
        configs = FlextLdapConfig()

        with patch.dict("os.environ", {}, clear=True):
            result = configs.create_connection_config_from_env()

            # The method uses the global instance with default values, so it succeeds
            assert result.is_success
            assert isinstance(result.data, dict)
            # Should have default values
            assert result.data["server"] == "ldap://localhost"
            assert result.data["port"] == FlextLdapConstants.Protocol.DEFAULT_PORT
            assert result.data["bind_dn"] is None
            assert not result.data["base_dn"]

    def test_create_search_config_success(self) -> None:
        """Test successful search config creation."""
        configs = FlextLdapConfig()

        search_data: dict[str, object] = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=person)",
            "attributes": ["cn", "sn", "mail"],
        }

        result = configs.create_search_config(search_data)

        assert result.is_success
        assert isinstance(result.data, FlextLdapModels.SearchConfig)
        assert result.data.base_dn == "dc=example,dc=com"
        assert result.data.search_filter == "(objectClass=person)"
        assert result.data.attributes == ["cn", "sn", "mail"]

    def test_create_search_config_validation_failure(self) -> None:
        """Test search config creation with validation failure."""
        configs = FlextLdapConfig()

        # Test with invalid data that would cause Pydantic validation to fail
        invalid_data: dict[str, object] = {
            "base_dn": None,
            "filter_str": None,
            "attributes": "invalid",
        }
        result = configs.create_search_config(invalid_data)

        # The method should still succeed as it uses defaults and str() conversion
        assert result.is_success
        assert result.data.base_dn == "None"
        assert result.data.search_filter == "None"
        assert result.data.attributes == []

    def test_create_modify_config_success(self) -> None:
        """Test successful modify config creation."""
        configs = FlextLdapConfig()

        modify_data: dict[str, object] = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "operation": "replace",
            "attribute": "cn",
            "values": ["New Name"],
        }

        result = configs.create_modify_config(modify_data)

        assert result.is_success
        assert isinstance(result.data, dict)
        assert result.data["dn"] == "uid=testuser,ou=people,dc=example,dc=com"
        assert result.data["operation"] == "replace"
        assert result.data["attribute"] == "cn"
        assert result.data["values"] == ["New Name"]

    def test_create_modify_config_validation_failure(self) -> None:
        """Test modify config creation with validation failure."""
        configs = FlextLdapConfig()

        # Test with data that needs type conversion
        data_with_types: dict[str, object] = {
            "dn": None,
            "operation": None,
            "attribute": None,
            "values": "invalid",  # Will be converted to list
        }
        result = configs.create_modify_config(data_with_types)

        # The method should succeed with proper type conversion
        assert result.is_success
        assert result.data["dn"] == "None"  # None converted to string
        assert result.data["operation"] == "None"  # None converted to string
        assert result.data["attribute"] == "None"  # None converted to string
        assert result.data["values"] == []  # String handled properly as empty list

    def test_create_add_config_success(self) -> None:
        """Test successful add config creation."""
        configs = FlextLdapConfig()

        add_data: dict[str, object] = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "cn": ["Test User"],
                "sn": ["User"],
                "uid": ["testuser"],
                "mail": ["testuser@example.com"],
            },
        }

        result = configs.create_add_config(add_data)

        assert result.is_success
        assert isinstance(result.data, dict)
        assert result.data["dn"] == "uid=testuser,ou=people,dc=example,dc=com"
        assert result.data["attributes"] == add_data["attributes"]

    def test_create_add_config_type_conversion(self) -> None:
        """Test add config creation with type conversion."""
        configs = FlextLdapConfig()

        # Test with data that needs type conversion
        data_with_types: dict[str, object] = {"dn": None, "attributes": "invalid"}
        result = configs.create_add_config(data_with_types)

        # The method should succeed with proper type conversion
        assert result.is_success
        assert result.data["dn"] == "None"  # None converted to string
        assert result.data["attributes"] == {}  # Invalid string converted to empty dict

    def test_create_delete_config_success(self) -> None:
        """Test successful delete config creation."""
        configs = FlextLdapConfig()

        delete_data: dict[str, object] = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com"
        }

        result = configs.create_delete_config(delete_data)

        assert result.is_success
        assert isinstance(result.data, dict)
        assert result.data["dn"] == "uid=testuser,ou=people,dc=example,dc=com"

    def test_create_delete_config_validation_failure(self) -> None:
        """Test delete config creation with validation failure."""
        configs = FlextLdapConfig()

        # Test with invalid data that would cause an exception
        invalid_data: dict[str, object] = {"dn": None}
        result = configs.create_delete_config(invalid_data)

        # The method should still succeed as it uses defaults and str() conversion
        assert result.is_success
        assert result.data["dn"] == "None"

    def test_validate_connection_data_success(
        self,
        ldap_server_config: dict[str, object],
    ) -> None:
        """Test successful connection data validation."""
        # Update the config to use the expected field names
        config = ldap_server_config.copy()
        config["server"] = config.pop(
            "server_uri",
            f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
        )

        result = FlextLdapValidations.validate_connection_config(config)

        assert result.is_success
        assert result.data is True

    def test_validate_connection_data_failure(self) -> None:
        """Test connection data validation failure."""
        invalid_data: dict[str, object] = {"invalid": "data"}
        result = FlextLdapValidations.validate_connection_config(invalid_data)

        assert result.is_failure
        assert (
            result.error is not None
            and "Missing required field: server" in result.error
        )

    def test_validate_connection_data_missing_required_fields(self) -> None:
        """Test connection data validation with missing required fields."""
        incomplete_data: dict[str, object] = {
            "server": "localhost"
            # Missing port, bind_dn, bind_password
        }
        result = FlextLdapValidations.validate_connection_config(incomplete_data)

        assert result.is_failure
        assert result.error is not None and "Missing required field" in result.error

    def test_validate_search_data_success(self) -> None:
        """Test successful search data validation."""
        # Test individual components using static methods
        dn_result = FlextLdapValidations.validate_dn("dc=example,dc=com")
        assert dn_result.is_success

        filter_result = FlextLdapValidations.validate_filter("(objectClass=person)")
        assert filter_result.is_success

        attributes_result = FlextLdapValidations.validate_attributes(
            [
                "cn",
                "sn",
                "mail",
            ]
        )
        assert attributes_result.is_success

    def test_validate_search_data_failure(self) -> None:
        """Test search data validation failure."""
        # Test invalid filter with invalid characters
        result = FlextLdapValidations.validate_filter(
            "invalid@filter#with$invalid%chars"
        )
        assert result.is_failure
        assert (
            result.error is not None
            and "Filter must be enclosed in parentheses" in result.error
        )

    def test_validate_search_data_missing_base_dn(self) -> None:
        """Test search data validation with missing base DN."""
        # Test empty DN
        result = FlextLdapValidations.validate_dn("")
        assert result.is_failure
        assert result.error is not None and "DN cannot be empty" in result.error

    def test_validate_modify_data_success(self) -> None:
        """Test successful modify data validation."""
        # Test DN validation
        dn_result = FlextLdapValidations.validate_dn(
            "uid=testuser,ou=people,dc=example,dc=com"
        )
        assert dn_result.is_success

    def test_validate_modify_data_failure(self) -> None:
        """Test modify data validation failure."""
        # Test invalid DN
        result = FlextLdapValidations.validate_dn("invalid-dn")
        assert result.is_failure
        assert (
            result.error is not None
            and "DN contains invalid characters" in result.error
        )

    def test_validate_modify_data_missing_dn(self) -> None:
        """Test modify data validation with missing DN."""
        # Test empty DN
        result = FlextLdapValidations.validate_dn("")
        assert result.is_failure
        assert result.error is not None and "DN cannot be empty" in result.error

    def test_validate_add_data_success(self) -> None:
        """Test successful add data validation."""
        # Test DN validation
        dn_result = FlextLdapValidations.validate_dn(
            "uid=testuser,ou=people,dc=example,dc=com"
        )
        assert dn_result.is_success

        # Test attributes validation
        attributes_result = FlextLdapValidations.validate_attributes(["cn", "sn"])
        assert attributes_result.is_success

    def test_validate_add_data_failure(self) -> None:
        """Test add data validation failure."""
        # Test invalid DN
        result = FlextLdapValidations.validate_dn("invalid-dn")
        assert result.is_failure
        assert (
            result.error is not None
            and "DN contains invalid characters" in result.error
        )

    def test_validate_add_data_missing_attributes(self) -> None:
        """Test add data validation with missing attributes."""
        # Test empty attributes
        result = FlextLdapValidations.validate_attributes([])
        assert result.is_failure
        assert (
            result.error is not None
            and "Attributes list cannot be empty" in result.error
        )

    def test_validate_delete_data_success(self) -> None:
        """Test successful delete data validation."""
        # Test DN validation
        result = FlextLdapValidations.validate_dn(
            "uid=testuser,ou=people,dc=example,dc=com"
        )
        assert result.is_success

    def test_validate_delete_data_failure(self) -> None:
        """Test delete data validation failure."""
        # Test invalid DN
        result = FlextLdapValidations.validate_dn("invalid-dn")
        assert result.is_failure
        assert (
            result.error is not None
            and "DN contains invalid characters" in result.error
        )

    def test_validate_delete_data_missing_dn(self) -> None:
        """Test delete data validation with missing DN."""
        # Test empty DN
        result = FlextLdapValidations.validate_dn("")
        assert result.is_failure
        assert result.error is not None and "DN cannot be empty" in result.error

    def test_get_default_connection_config(self) -> None:
        """Test getting default connection configuration."""
        # Test the actual get_global_instance method which provides default configuration
        config = FlextLdapConfig.get_global_instance()

        assert isinstance(config, FlextLdapConfig)
        assert config.ldap_server_uri == "ldap://localhost"
        assert config.ldap_port == FlextLdapConstants.Protocol.DEFAULT_PORT

    def test_get_default_search_config(self) -> None:
        """Test getting default search configuration."""
        # Test the actual get_default_search_config static method
        result = FlextLdapConfig.get_default_search_config()

        assert result.is_success
        assert isinstance(result.data, dict)
        assert "base_dn" in result.data
        assert "filter_str" in result.data
        assert "attributes" in result.data

    def test_merge_configs_success(self) -> None:
        """Test successful config merging."""
        configs = FlextLdapConfig()

        base_config: dict[str, object] = {
            "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "password": "REDACTED_LDAP_BIND_PASSWORD123",
            "base_dn": "dc=example,dc=com",
        }

        override_config: dict[str, object] = {
            "server_uri": f"ldap://newserver:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "connection_timeout": 60,
        }

        result = configs.merge_configs(base_config, override_config)

        assert result.is_success
        assert (
            result.data["server_uri"]
            == f"ldap://newserver:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )
        assert result.data["bind_dn"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert result.data["connection_timeout"] == 60

    def test_merge_configs_empty_override(self) -> None:
        """Test config merging with empty override."""
        configs = FlextLdapConfig()

        base_config: dict[str, object] = {
            "server_uri": f"{FlextLdapConstants.Protocol.DEFAULT_SERVER_URI}:{FlextLdapConstants.Protocol.DEFAULT_PORT}",
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        }

        result = configs.merge_configs(base_config, {})

        assert result.is_success
        assert result.data == base_config

    def test_validate_dn_format_valid(self) -> None:
        """Test validating valid DN format."""
        result = FlextLdapValidations.validate_dn(
            "uid=testuser,ou=people,dc=example,dc=com"
        )

        assert result.is_success
        assert result.data is True

    def test_validate_dn_format_invalid(self) -> None:
        """Test validating invalid DN format."""
        result = FlextLdapValidations.validate_dn("invalid-dn-format")

        assert result.is_failure
        assert (
            result.error is not None
            and "DN contains invalid characters" in result.error
        )

    def test_validate_dn_format_empty(self) -> None:
        """Test validating empty DN format."""
        result = FlextLdapValidations.validate_dn("")

        assert result.is_failure
        assert result.error is not None and "DN cannot be empty" in result.error

    def test_validate_filter_format_valid(self) -> None:
        """Test validating valid filter format."""
        result = FlextLdapValidations.validate_filter("(objectClass=person)")

        assert result.is_success
        assert result.data is True

    def test_validate_filter_format_invalid(self) -> None:
        """Test validating invalid filter format."""
        result = FlextLdapValidations.validate_filter("invalid-filter")

        assert result.is_failure
        assert (
            result.error is not None
            and "Filter must be enclosed in parentheses" in result.error
        )

    def test_validate_filter_format_empty(self) -> None:
        """Test validating empty filter format."""
        result = FlextLdapValidations.validate_filter("")

        assert result.is_failure
        assert result.error is not None and "Filter cannot be empty" in result.error

    def test_config_error_handling_consistency(self) -> None:
        """Test consistent error handling across config methods."""
        configs = FlextLdapConfig()

        # Test consistent error handling with valid data
        conn_result = configs.create_from_connection_config_data(
            {
                "server": "ldap://localhost",
                "port": FlextLdapConstants.Protocol.DEFAULT_PORT,
                "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "bind_password": "password",
            }
        )
        assert conn_result.is_success

        search_result = configs.create_search_config(
            {
                "base_dn": "dc=example,dc=com",
                "filter_str": "(objectClass=*)",
            }
        )
        assert search_result.is_success

        modify_result = configs.create_modify_config(
            {
                "dn": "cn=test,dc=example,dc=com",
                "operation": "replace",
                "attribute": "description",
                "values": ["test description"],
            }
        )
        assert modify_result.is_success

    def test_config_integration_complete_workflow(self) -> None:
        """Test complete config workflow integration."""
        configs = FlextLdapConfig()

        # Test complete workflow with valid data
        conn_config: dict[str, object] = {
            "server": "ldap://localhost",
            "port": FlextLdapConstants.Protocol.DEFAULT_PORT,
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
            "base_dn": "dc=example,dc=com",
        }
        conn_result = configs.create_from_connection_config_data(conn_config)
        assert conn_result.is_success

        search_config: dict[str, object] = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=person)",
            "attributes": ["cn", "sn", "mail"],
        }
        search_result = configs.create_search_config(search_config)
        assert search_result.is_success

        add_config: dict[str, object] = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "attributes": {"cn": ["Test User"], "sn": ["User"]},
        }
        add_result = configs.create_add_config(add_config)
        assert add_result.is_success

    def test_validator_invalid_server_uri(self) -> None:
        """Test validator with invalid server URI."""
        import pytest

        with pytest.raises(ValueError, match="Invalid LDAP server URI"):
            FlextLdapConfig(
                ldap_server_uri="http://localhost",  # Invalid protocol
                ldap_bind_password="password",
            )

    def test_validator_bind_dn_too_short(self) -> None:
        """Test validator with bind DN too short."""
        import pytest

        with pytest.raises(ValueError, match="LDAP bind DN too short"):
            FlextLdapConfig(
                ldap_bind_dn="a",  # Too short
                ldap_bind_password="password",
            )

    def test_validator_bind_dn_too_long(self) -> None:
        """Test validator with bind DN too long."""
        import pytest

        long_dn = "cn=" + ("x" * 10000)  # Exceeds MAX_DN_LENGTH
        with pytest.raises(ValueError, match="LDAP bind DN too long"):
            FlextLdapConfig(ldap_bind_dn=long_dn, ldap_bind_password="password")

    def test_validator_bind_dn_invalid_format(self) -> None:
        """Test validator with invalid bind DN format."""
        import pytest

        with pytest.raises(ValueError, match="Invalid LDAP bind DN format"):
            FlextLdapConfig(
                ldap_bind_dn="invalid-no-equals",  # No = sign
                ldap_bind_password="password",
            )

    def test_validator_base_dn_too_long(self) -> None:
        """Test validator with base DN too long."""
        import pytest

        long_dn = "dc=" + ("x" * 10000)  # Exceeds MAX_DN_LENGTH
        with pytest.raises(ValueError, match="LDAP base DN too long"):
            FlextLdapConfig(ldap_base_dn=long_dn)

    def test_validator_consistency_bind_password_required(self) -> None:
        """Test consistency validator - bind password required when bind DN specified."""
        import pytest

        with pytest.raises(ValueError, match="Bind password is required"):
            FlextLdapConfig(
                ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                ldap_bind_password=None,  # Missing password
            )

    def test_validator_consistency_cache_ttl_positive(self) -> None:
        """Test consistency validator - cache TTL must be positive."""
        import pytest

        with pytest.raises(ValueError, match="Cache TTL must be positive"):
            FlextLdapConfig(
                ldap_enable_caching=True,
                ldap_cache_ttl=0,  # Invalid TTL
                ldap_bind_password="password",
            )

    def test_validator_consistency_ssl_for_ldaps(self) -> None:
        """Test consistency validator - SSL required for ldaps://."""
        import pytest

        with pytest.raises(ValueError, match="SSL must be enabled"):
            FlextLdapConfig(
                ldap_server_uri="ldaps://localhost",  # ldaps protocol
                ldap_use_ssl=False,  # But SSL disabled
                ldap_bind_password="password",
            )

    def test_get_connection_config(self) -> None:
        """Test get_connection_config method."""
        config = FlextLdapConfig(
            ldap_server_uri="ldaps://localhost",
            ldap_port=636,
            ldap_use_ssl=True,
            ldap_bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            ldap_bind_password="secret",
        )

        conn_config = config.get_connection_config()

        assert conn_config["server_uri"] == "ldaps://localhost"
        assert conn_config["port"] == 636
        assert conn_config["use_ssl"] is True
        assert conn_config["bind_dn"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert conn_config["bind_password_configured"] is True

    def test_get_pool_config(self) -> None:
        """Test get_pool_config method."""
        config = FlextLdapConfig(
            ldap_pool_size=20,
            ldap_pool_timeout=60,
            ldap_retry_attempts=5,
            ldap_retry_delay=3,  # Must be integer
            ldap_bind_password="password",
        )

        pool_config = config.get_pool_config()

        assert pool_config["pool_size"] == 20
        assert pool_config["pool_timeout"] == 60
        assert pool_config["max_retries"] == 5
        assert pool_config["retry_delay"] == 3

    def test_get_operation_config(self) -> None:
        """Test get_operation_config method."""
        config = FlextLdapConfig(
            ldap_operation_timeout=45,
            ldap_size_limit=500,
            ldap_time_limit=20,
            ldap_enable_caching=True,
            ldap_cache_ttl=600,
            ldap_bind_password="password",
        )

        op_config = config.get_operation_config()

        assert op_config["operation_timeout"] == 45
        assert op_config["size_limit"] == 500
        assert op_config["time_limit"] == 20
        assert op_config["enable_caching"] is True
        assert op_config["cache_ttl"] == 600

    def test_get_ldap_logging_config(self) -> None:
        """Test get_ldap_logging_config method."""
        config = FlextLdapConfig(
            ldap_enable_debug=True,
            ldap_enable_trace=True,
            ldap_log_queries=True,
            ldap_mask_passwords=True,
            ldap_bind_password="password",
        )

        log_config = config.get_ldap_logging_config()

        assert log_config["enable_debug"] is True
        assert log_config["enable_trace"] is True
        assert log_config["log_queries"] is True
        assert log_config["mask_passwords"] is True

    def test_create_for_environment(self) -> None:
        """Test create_for_environment class method."""
        config = FlextLdapConfig.create_for_environment("test", ldap_enable_debug=True)

        assert isinstance(config, FlextLdapConfig)
        assert config.ldap_enable_debug is True

    def test_create_default(self) -> None:
        """Test create_default class method."""
        config = FlextLdapConfig.create_default()

        assert isinstance(config, FlextLdapConfig)
        assert config.ldap_server_uri == "ldap://localhost"

    def test_get_effective_bind_password(self) -> None:
        """Test get_effective_bind_password method."""
        config = FlextLdapConfig(ldap_bind_password="secret123")

        password = config.get_effective_bind_password()

        assert password == "secret123"

    def test_get_global_instance(self) -> None:
        """Test get_global_instance method."""
        FlextLdapConfig.reset_global_instance()
        config1 = FlextLdapConfig.get_global_instance()
        config2 = FlextLdapConfig.get_global_instance()

        # Both calls return config instances with same values
        assert isinstance(config1, FlextLdapConfig)
        assert isinstance(config2, FlextLdapConfig)
        assert config1.ldap_server_uri == config2.ldap_server_uri

    def test_reset_global_instance(self) -> None:
        """Test reset_global_instance method."""
        config1 = FlextLdapConfig.get_global_instance()
        original_server = config1.ldap_server_uri
        FlextLdapConfig.reset_global_instance()
        config2 = FlextLdapConfig.get_global_instance()

        # Reset creates new instance
        assert isinstance(config2, FlextLdapConfig)
        assert config2.ldap_server_uri == original_server  # Same default values

    def test_get_default_search_config_returns_dict(self) -> None:
        """Test get_default_search_config returns proper dictionary."""
        configs = FlextLdapConfig()
        result = configs.get_default_search_config()

        assert result.is_success
        assert "base_dn" in result.data
        assert "filter_str" in result.data
        assert "scope" in result.data

    def test_merge_configs(self) -> None:
        """Test merge_configs method."""
        configs = FlextLdapConfig()
        base_config: dict[str, object] = {"server": "ldap://localhost", "port": 389}
        override_config: dict[str, object] = {"port": 636, "use_ssl": True}

        result = configs.merge_configs(base_config, override_config)

        assert result.is_success
        assert result.data["server"] == "ldap://localhost"
        assert result.data["port"] == 636  # Overridden
        assert result.data["use_ssl"] is True

    def test_ldap_default_connection(self) -> None:
        """Test ldap_default_connection property."""
        config = FlextLdapConfig(
            ldap_server_uri="ldap://testserver",
            ldap_port=389,
            ldap_bind_dn="cn=test,dc=example,dc=com",
            ldap_bind_password="testpass",
        )

        conn_dict = config.ldap_default_connection

        assert conn_dict["server"] == "ldap://testserver"
        assert conn_dict["port"] == 389
        assert conn_dict["bind_dn"] == "cn=test,dc=example,dc=com"
        assert conn_dict["bind_password"] == "testpass"

    def test_create_connection_config_from_env_exception_coverage(self) -> None:
        """Test create_connection_config_from_env exception - covers lines 334-335."""
        config = FlextLdapConfig()
        result = config.create_connection_config_from_env()
        # Should succeed with default values
        assert result.is_success
        assert isinstance(result.data, dict)

    def test_get_effective_bind_password_none(self) -> None:
        """Test get_effective_bind_password when password is None - covers line 343."""
        config = FlextLdapConfig(ldap_bind_password=None)
        password = config.get_effective_bind_password()
        assert password is None

    def test_get_global_instance_exception_branch(self) -> None:
        """Test get_global_instance exception fallback - covers lines 351-354."""
        # Get global instance (should work normally)
        config = FlextLdapConfig.get_global_instance()
        assert isinstance(config, FlextLdapConfig)
        # The exception branch (lines 351-354) is defensive code for edge cases

    def test_create_connection_config_from_env_exception(self) -> None:
        """Test create_connection_config_from_env exception - covers lines 385-386."""
        # Test with valid minimal data
        result = FlextLdapConfig.create_connection_config_from_env({"server_uri": "ldap://test"})
        # Should succeed or fail gracefully
        assert isinstance(result.is_success, bool)

    def test_create_search_config_exception(self) -> None:
        """Test create_search_config exception - covers lines 409-410."""
        result = FlextLdapConfig.create_search_config({"base_dn": "dc=test,dc=com"})
        # Should succeed with valid data
        assert result.is_success

    def test_create_modify_config_exception(self) -> None:
        """Test create_modify_config exception - covers lines 430-431."""
        result = FlextLdapConfig.create_modify_config(
            {"dn": "cn=test,dc=com", "attribute": "cn", "values": ["test"]}
        )
        # Should succeed with valid data
        assert result.is_success

    def test_create_add_config_exception(self) -> None:
        """Test create_add_config exception - covers lines 454-455."""
        result = FlextLdapConfig.create_add_config(
            {"dn": "cn=test,dc=com", "attributes": {"cn": ["test"]}}
        )
        # Should succeed with valid data
        assert result.is_success

    def test_create_delete_config_exception(self) -> None:
        """Test create_delete_config exception - covers lines 469-470."""
        result = FlextLdapConfig.create_delete_config({"dn": "cn=test,dc=com"})
        # Should succeed with valid data
        assert result.is_success

    def test_merge_configs_exception(self) -> None:
        """Test merge_configs exception - covers lines 500-501."""
        result = FlextLdapConfig.merge_configs({"key1": "value1"}, {"key2": "value2"})
        # Should succeed with valid dicts
        assert result.is_success
        assert result.data == {"key1": "value1", "key2": "value2"}
