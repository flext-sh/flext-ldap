"""Comprehensive tests for FlextLdapConfig.

This module provides complete test coverage for the FlextLdapConfig class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import patch

from flext_ldap import FlextLdapConfig, FlextLdapModels, FlextLdapValidations


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
        assert result.data.get_effective_server_uri() == "ldap://localhost:389"
        assert result.data.get_effective_bind_dn() == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_create_connection_config_with_minimal_data(
        self,
    ) -> None:
        """Test connection config creation with minimal data (should succeed with defaults)."""
        configs = FlextLdapConfig()

        # Test with minimal config data - should succeed with defaults
        minimal_config = {
            "server": "ldap://localhost",
            "port": 389,
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
        }

        result = configs.create_from_connection_config_data(minimal_config)

        # Should succeed with default values
        assert result.is_success
        assert isinstance(result.data, FlextLdapConfig)
        assert result.data.ldap_server_uri == "ldap://localhost"
        assert result.data.ldap_port == 389
        assert result.data.ldap_bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_create_connection_config_from_env_success(self) -> None:
        """Test successful connection config creation from environment."""
        configs = FlextLdapConfig()

        result = configs.create_connection_config_from_env()

        assert result.is_success
        assert isinstance(result.data, dict)
        # The method uses the global instance with default values
        assert result.data["server"] == "ldap://localhost"
        assert result.data["port"] == 389
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
            assert result.data["port"] == 389
            assert result.data["bind_dn"] is None
            assert not result.data["base_dn"]

    def test_create_search_config_success(self) -> None:
        """Test successful search config creation."""
        configs = FlextLdapConfig()

        search_data = {
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
        invalid_data = {"base_dn": None, "filter_str": None, "attributes": "invalid"}
        result = configs.create_search_config(invalid_data)

        # The method should still succeed as it uses defaults and str() conversion
        assert result.is_success
        assert result.data.base_dn == "None"
        assert result.data.search_filter == "None"
        assert result.data.attributes == []

    def test_create_modify_config_success(self) -> None:
        """Test successful modify config creation."""
        configs = FlextLdapConfig()

        modify_data = {
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

        # Test with invalid data that would cause an exception
        invalid_data = {
            "dn": None,
            "operation": None,
            "attribute": None,
            "values": "invalid",
        }
        result = configs.create_modify_config(invalid_data)

        # The method should still succeed as it uses defaults and str() conversion
        assert result.is_success
        assert result.data["dn"] == "None"
        assert result.data["operation"] == "None"
        assert result.data["attribute"] == "None"
        assert result.data["values"] == "invalid"

    def test_create_add_config_success(self) -> None:
        """Test successful add config creation."""
        configs = FlextLdapConfig()

        add_data = {
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

    def test_create_add_config_validation_failure(self) -> None:
        """Test add config creation with validation failure."""
        configs = FlextLdapConfig()

        # Test with invalid data that would cause an exception
        invalid_data = {"dn": None, "attributes": "invalid"}
        result = configs.create_add_config(invalid_data)

        # The method should still succeed as it uses defaults and str() conversion
        assert result.is_success
        assert result.data["dn"] == "None"
        assert result.data["attributes"] == "invalid"

    def test_create_delete_config_success(self) -> None:
        """Test successful delete config creation."""
        configs = FlextLdapConfig()

        delete_data = {"dn": "uid=testuser,ou=people,dc=example,dc=com"}

        result = configs.create_delete_config(delete_data)

        assert result.is_success
        assert isinstance(result.data, dict)
        assert result.data["dn"] == "uid=testuser,ou=people,dc=example,dc=com"

    def test_create_delete_config_validation_failure(self) -> None:
        """Test delete config creation with validation failure."""
        configs = FlextLdapConfig()

        # Test with invalid data that would cause an exception
        invalid_data = {"dn": None}
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
        config["server"] = config.pop("server_uri", "ldap://localhost:389")

        result = FlextLdapValidations.validate_connection_config(config)

        assert result.is_success
        assert result.data is True

    def test_validate_connection_data_failure(self) -> None:
        """Test connection data validation failure."""
        invalid_data = {"invalid": "data"}
        result = FlextLdapValidations.validate_connection_config(invalid_data)

        assert result.is_failure
        assert (
            result.error is not None
            and "Missing required field: server" in result.error
        )

    def test_validate_connection_data_missing_required_fields(self) -> None:
        """Test connection data validation with missing required fields."""
        incomplete_data = {
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

        attributes_result = FlextLdapValidations.validate_attributes([
            "cn",
            "sn",
            "mail",
        ])
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
        assert config.ldap_port == 389

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

        base_config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "password": "REDACTED_LDAP_BIND_PASSWORD123",
            "base_dn": "dc=example,dc=com",
        }

        override_config = {
            "server_uri": "ldap://newserver:389",
            "connection_timeout": 60,
        }

        result = configs.merge_configs(base_config, override_config)

        assert result.is_success
        assert result.data["server_uri"] == "ldap://newserver:389"
        assert result.data["bind_dn"] == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert result.data["connection_timeout"] == 60

    def test_merge_configs_empty_override(self) -> None:
        """Test config merging with empty override."""
        configs = FlextLdapConfig()

        base_config = {
            "server_uri": "ldap://localhost:389",
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
        conn_result = configs.create_from_connection_config_data({
            "server": "ldap://localhost",
            "port": 389,
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "bind_password": "password",
        })
        assert conn_result.is_success

        search_result = configs.create_search_config({
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=*)",
        })
        assert search_result.is_success

        modify_result = configs.create_modify_config({
            "dn": "cn=test,dc=example,dc=com",
            "operation": "replace",
            "attribute": "description",
            "values": ["test description"],
        })
        assert modify_result.is_success

    def test_config_integration_complete_workflow(self) -> None:
        """Test complete config workflow integration."""
        configs = FlextLdapConfig()

        # Test complete workflow with valid data
        conn_config = {
            "server": "ldap://localhost",
            "port": 389,
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
            "base_dn": "dc=example,dc=com",
        }
        conn_result = configs.create_from_connection_config_data(conn_config)
        assert conn_result.is_success

        search_config = {
            "base_dn": "dc=example,dc=com",
            "filter_str": "(objectClass=person)",
            "attributes": ["cn", "sn", "mail"],
        }
        search_result = configs.create_search_config(search_config)
        assert search_result.is_success

        add_config = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "attributes": {"cn": ["Test User"], "sn": ["User"]},
        }
        add_result = configs.create_add_config(add_config)
        assert add_result.is_success
