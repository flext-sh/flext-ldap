"""Comprehensive tests for FlextLdapConfig.

This module provides complete test coverage for the FlextLdapConfig class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import patch

from flext_core import FlextResult
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
        assert result.data.get_effective_bind_dn() == "cn=admin,dc=example,dc=com"

    def test_create_connection_config_with_minimal_data(
        self,
    ) -> None:
        """Test connection config creation with minimal data (should succeed with defaults)."""
        configs = FlextLdapConfig()

        # Test with minimal config data - should succeed with defaults
        minimal_config = {"server_uri": "ldap://localhost:389"}

        result = configs.create_from_connection_config_data(minimal_config)

        # Should succeed with default values
        assert result.is_success
        assert isinstance(result.data, FlextLdapConfig)
        assert result.data.ldap_default_connection is not None
        assert result.data.ldap_default_connection.server == "ldap://localhost:389"

    def test_create_connection_config_from_env_success(self) -> None:
        """Test successful connection config creation from environment."""
        configs = FlextLdapConfig()

        with (
            patch.dict(
                "os.environ",
                {
                    "LDAP_SERVER_URI": "ldap://localhost:389",
                    "LDAP_BIND_DN": "cn=admin,dc=example,dc=com",
                    "LDAP_BIND_PASSWORD": "admin123",
                    "LDAP_BASE_DN": "dc=example,dc=com",
                },
            ),
            patch.object(configs, "_validate_connection_data") as mock_validate,
        ):
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            result = configs.create_connection_config_from_env()

            assert result.is_success
            assert isinstance(result.data, FlextLdapModels.ConnectionConfig)
            assert result.data.server == "ldap://localhost:389"
            mock_validate.assert_called_once()

    def test_create_connection_config_from_env_missing_vars(self) -> None:
        """Test connection config creation from environment with missing variables."""
        configs = FlextLdapConfig()

        with patch.dict("os.environ", {}, clear=True):
            result = configs.create_connection_config_from_env()

            assert result.is_failure
            assert "Missing required environment variables" in result.error

    def test_create_search_config_success(self) -> None:
        """Test successful search config creation."""
        configs = FlextLdapConfig()

        search_data = {
            "base_dn": "dc=example,dc=com",
            "search_filter": "(objectClass=person)",
            "attributes": ["cn", "sn", "mail"],
            "scope": "subtree",
            "size_limit": 100,
            "time_limit": 30,
        }

        with patch.object(configs, "_validate_search_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            result = configs.create_search_config(search_data)

            assert result.is_success
            assert isinstance(result.data, FlextLdapModels.SearchConfig)
            assert result.data.base_dn == "dc=example,dc=com"
            assert result.data.search_filter == "(objectClass=person)"
            mock_validate.assert_called_once()

    def test_create_search_config_validation_failure(self) -> None:
        """Test search config creation with validation failure."""
        configs = FlextLdapConfig()

        with patch.object(configs, "_validate_search_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Validation failed"
            )

            invalid_data = {"invalid": "data"}
            result = configs.create_search_config(invalid_data)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_create_modify_config_success(self) -> None:
        """Test successful modify config creation."""
        configs = FlextLdapConfig()

        modify_data = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "changes": {
                "cn": [("MODIFY_REPLACE", ["New Name"])],
                "mail": [("MODIFY_ADD", ["newemail@example.com"])],
            },
        }

        with patch.object(configs, "_validate_modify_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            result = configs.create_modify_config(modify_data)

            assert result.is_success
            assert isinstance(result.data, FlextLdapModels.ModifyConfig)
            assert result.data.dn == "uid=testuser,ou=people,dc=example,dc=com"
            mock_validate.assert_called_once()

    def test_create_modify_config_validation_failure(self) -> None:
        """Test modify config creation with validation failure."""
        configs = FlextLdapConfig()

        with patch.object(configs, "_validate_modify_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Validation failed"
            )

            invalid_data = {"invalid": "data"}
            result = configs.create_modify_config(invalid_data)

            assert result.is_failure
            assert "Validation failed" in result.error

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

        with patch.object(configs, "_validate_add_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            result = configs.create_add_config(add_data)

            assert result.is_success
            assert isinstance(result.data, FlextLdapModels.AddConfig)
            assert result.data.dn == "uid=testuser,ou=people,dc=example,dc=com"
            mock_validate.assert_called_once()

    def test_create_add_config_validation_failure(self) -> None:
        """Test add config creation with validation failure."""
        configs = FlextLdapConfig()

        with patch.object(configs, "_validate_add_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Validation failed"
            )

            invalid_data = {"invalid": "data"}
            result = configs.create_add_config(invalid_data)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_create_delete_config_success(self) -> None:
        """Test successful delete config creation."""
        configs = FlextLdapConfig()

        delete_data = {"dn": "uid=testuser,ou=people,dc=example,dc=com"}

        with patch.object(configs, "_validate_delete_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            result = configs.create_delete_config(delete_data)

            assert result.is_success
            assert isinstance(result.data, FlextLdapModels.DeleteConfig)
            assert result.data.dn == "uid=testuser,ou=people,dc=example,dc=com"
            mock_validate.assert_called_once()

    def test_create_delete_config_validation_failure(self) -> None:
        """Test delete config creation with validation failure."""
        configs = FlextLdapConfig()

        with patch.object(configs, "_validate_delete_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Validation failed"
            )

            invalid_data = {"invalid": "data"}
            result = configs.create_delete_config(invalid_data)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_validate_connection_data_success(
        self,
        ldap_server_config: dict[str, object],
    ) -> None:
        """Test successful connection data validation."""
        configs = FlextLdapConfig()
        result = configs._validate_connection_data(ldap_server_config)

        assert result.is_success
        assert "valid" in result.data

    def test_validate_connection_data_failure(self) -> None:
        """Test connection data validation failure."""
        configs = FlextLdapConfig()

        invalid_data = {"invalid": "data"}
        result = configs._validate_connection_data(invalid_data)

        assert result.is_failure
        assert "Server URI is required for connection operations" in result.error

    def test_validate_connection_data_missing_required_fields(self) -> None:
        """Test connection data validation with missing required fields."""
        configs = FlextLdapConfig()

        incomplete_data = {
            "server_uri": "ldap://localhost:389"
            # Missing bind_dn, password, base_dn
        }
        result = configs._validate_connection_data(incomplete_data)

        assert result.is_failure
        assert "Missing required fields" in result.error

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
        assert "Filter contains invalid characters" in result.error

    def test_validate_search_data_missing_base_dn(self) -> None:
        """Test search data validation with missing base DN."""
        # Test empty DN
        result = FlextLdapValidations.validate_dn("")
        assert result.is_failure
        assert "DN cannot be empty" in result.error

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
        assert "DN contains invalid characters" in result.error

    def test_validate_modify_data_missing_dn(self) -> None:
        """Test modify data validation with missing DN."""
        # Test empty DN
        result = FlextLdapValidations.validate_dn("")
        assert result.is_failure
        assert "DN cannot be empty" in result.error

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
        assert "DN contains invalid characters" in result.error

    def test_validate_add_data_missing_attributes(self) -> None:
        """Test add data validation with missing attributes."""
        # Test empty attributes
        result = FlextLdapValidations.validate_attributes([])
        assert result.is_failure
        assert "Attributes list cannot be empty" in result.error

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
        assert "DN contains invalid characters" in result.error

    def test_validate_delete_data_missing_dn(self) -> None:
        """Test delete data validation with missing DN."""
        # Test empty DN
        result = FlextLdapValidations.validate_dn("")
        assert result.is_failure
        assert "DN cannot be empty" in result.error

    def test_get_default_connection_config(self) -> None:
        """Test getting default connection configuration."""
        configs = FlextLdapConfig()

        with patch.object(configs, "_create_connection_config") as mock_create:
            mock_config = FlextLdapModels.ConnectionConfig(
                server="localhost",
                port=389,
                use_ssl=False,
                bind_dn="cn=admin,dc=example,dc=com",
                bind_password="admin123",
                timeout=30,
            )
            mock_create.return_value = FlextResult[FlextLdapModels.ConnectionConfig].ok(
                mock_config
            )

            result = configs.get_default_connection_config()

            assert result.is_success
            assert isinstance(result.data, FlextLdapModels.ConnectionConfig)
            mock_create.assert_called_once()

    def test_get_default_search_config(self) -> None:
        """Test getting default search configuration."""
        configs = FlextLdapConfig()

        with patch.object(configs, "_create_search_config") as mock_create:
            mock_config = FlextLdapModels.SearchConfig(
                base_dn="dc=example,dc=com",
                search_filter="(objectClass=*)",
                attributes=["*"],
            )
            mock_create.return_value = FlextResult[FlextLdapModels.SearchConfig].ok(
                mock_config
            )

            result = configs.get_default_search_config()

            assert result.is_success
            assert isinstance(result.data, FlextLdapModels.SearchConfig)
            mock_create.assert_called_once()

    def test_merge_configs_success(self) -> None:
        """Test successful config merging."""
        configs = FlextLdapConfig()

        base_config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
            "password": "admin123",
            "base_dn": "dc=example,dc=com",
        }

        override_config = {
            "server_uri": "ldap://newserver:389",
            "connection_timeout": 60,
        }

        result = configs.merge_configs(base_config, override_config)

        assert result.is_success
        assert result.data["server_uri"] == "ldap://newserver:389"
        assert result.data["bind_dn"] == "cn=admin,dc=example,dc=com"
        assert result.data["connection_timeout"] == 60

    def test_merge_configs_empty_override(self) -> None:
        """Test config merging with empty override."""
        configs = FlextLdapConfig()

        base_config = {
            "server_uri": "ldap://localhost:389",
            "bind_dn": "cn=admin,dc=example,dc=com",
        }

        result = configs.merge_configs(base_config, {})

        assert result.is_success
        assert result.data == base_config

    def test_validate_dn_format_valid(self) -> None:
        """Test validating valid DN format."""
        configs = FlextLdapConfig()

        result = configs.validate_dn_format("uid=testuser,ou=people,dc=example,dc=com")

        assert result.is_success
        assert result.data is True

    def test_validate_dn_format_invalid(self) -> None:
        """Test validating invalid DN format."""
        configs = FlextLdapConfig()

        result = configs.validate_dn_format("invalid-dn-format")

        assert result.is_failure
        assert "Invalid DN format" in result.error

    def test_validate_dn_format_empty(self) -> None:
        """Test validating empty DN format."""
        configs = FlextLdapConfig()

        result = configs.validate_dn_format("")

        assert result.is_failure
        assert "DN cannot be empty" in result.error

    def test_validate_filter_format_valid(self) -> None:
        """Test validating valid filter format."""
        configs = FlextLdapConfig()

        result = configs.validate_filter_format("(objectClass=person)")

        assert result.is_success
        assert result.data is True

    def test_validate_filter_format_invalid(self) -> None:
        """Test validating invalid filter format."""
        configs = FlextLdapConfig()

        result = configs.validate_filter_format("invalid-filter")

        assert result.is_failure
        assert "Invalid filter format" in result.error

    def test_validate_filter_format_empty(self) -> None:
        """Test validating empty filter format."""
        configs = FlextLdapConfig()

        result = configs.validate_filter_format("")

        assert result.is_failure
        assert "Invalid filter format: empty filter" in result.error

    def test_config_error_handling_consistency(self) -> None:
        """Test consistent error handling across config methods."""
        configs = FlextLdapConfig()

        with (
            patch.object(configs, "_validate_connection_data") as mock_validate_conn,
            patch.object(configs, "_validate_search_data") as mock_validate_search,
            patch.object(configs, "_validate_modify_data") as mock_validate_modify,
        ):
            mock_validate_conn.return_value = FlextResult[dict[str, object]].fail(
                "Connection validation error"
            )
            mock_validate_search.return_value = FlextResult[dict[str, object]].fail(
                "Search validation error"
            )
            mock_validate_modify.return_value = FlextResult[dict[str, object]].fail(
                "Modify validation error"
            )

            # Test consistent error handling
            conn_result = configs.create_connection_config({"invalid": "data"})
            assert conn_result.is_failure
            assert "Connection validation error" in conn_result.error

            search_result = configs.create_search_config({"invalid": "data"})
            assert search_result.is_failure
            assert "Search validation error" in search_result.error

            modify_result = configs.create_modify_config({"invalid": "data"})
            assert modify_result.is_failure
            assert "Modify validation error" in modify_result.error

    def test_config_integration_complete_workflow(self) -> None:
        """Test complete config workflow integration."""
        configs = FlextLdapConfig()

        with (
            patch.object(configs, "_validate_connection_data") as mock_validate_conn,
            patch.object(configs, "_validate_search_data") as mock_validate_search,
            patch.object(configs, "_validate_add_data") as mock_validate_add,
        ):
            mock_validate_conn.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })
            mock_validate_search.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })
            mock_validate_add.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            # Test complete workflow
            conn_config = {
                "server_uri": "ldap://localhost:389",
                "bind_dn": "cn=admin,dc=example,dc=com",
                "password": "admin123",
                "base_dn": "dc=example,dc=com",
            }
            conn_result = configs.create_connection_config(conn_config)
            assert conn_result.is_success

            search_config = {
                "base_dn": "dc=example,dc=com",
                "search_filter": "(objectClass=person)",
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
