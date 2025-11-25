"""Unit tests for FlextLdapModels.

This module provides comprehensive testing of all LDAP domain models including
ConnectionConfig, SearchOptions, OperationResult, SyncStats, SearchResult, and
BatchOperations models. Uses advanced Python 3.13 features, factory patterns,
and generic helpers from flext_tests for efficient test data generation and
edge case coverage. All tests validate model behavior, computed properties,
and domain validation rules.

Tested modules: flext_ldap.models
Test scope: Domain model validation, computed properties, factory methods
Coverage target: 100% with parametrized edge cases

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest
from flext_ldif.models import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

from ..fixtures.constants import TestConstants
from ..helpers import ModelTestHelpers

pytestmark = pytest.mark.unit


class ModelTestScenario(StrEnum):
    """Test scenarios for model validation using Python 3.13 StrEnum."""

    DEFAULT = "default"
    CUSTOM = "custom"
    INVALID = "invalid"
    EDGE_CASE = "edge_case"


class ModelTestCategory(StrEnum):
    """Model test categories for flat parametrization."""

    CONNECTION_CONFIG = "connection_config"
    SEARCH_OPTIONS = "search_options"
    OPERATION_RESULT = "operation_result"
    SYNC_STATS = "sync_stats"
    SEARCH_RESULT = "search_result"
    BATCH_OPERATIONS = "batch_operations"


class SSLTLSScenario(StrEnum):
    """SSL/TLS validation scenarios for parametrized testing."""

    BOTH_ENABLED = "both_enabled"
    BOTH_DISABLED = "both_disabled"
    SSL_ONLY = "ssl_only"
    TLS_ONLY = "tls_only"


class TestFlextLdapModels:
    """Comprehensive tests for all FLEXT-LDAP domain models.

    Single class per module with flat test methods covering:
    - ConnectionConfig model with SSL/TLS validation (parametrized)
    - SearchOptions model with validation and normalization
    - OperationResult model with success/failure scenarios
    - SyncStats model with computed properties
    - SearchResult model with entry categorization
    - BatchOperations models with result aggregation

    Uses Python 3.13 StrEnum for test scenarios and parametrization.
    Uses static factory methods for efficient test data generation.
    """

    # Test constants
    _BASE_DN: ClassVar[str] = TestConstants.DEFAULT_BASE_DN
    _TEST_DN: ClassVar[str] = TestConstants.TEST_USER_DN
    _ADMIN_DN: ClassVar[str] = TestConstants.DEFAULT_BIND_DN

    # Explicit scenario tuples for parametrization
    _MODEL_SCENARIOS: ClassVar[tuple[ModelTestScenario, ...]] = (
        ModelTestScenario.DEFAULT,
        ModelTestScenario.CUSTOM,
        ModelTestScenario.INVALID,
        ModelTestScenario.EDGE_CASE,
    )

    # SSL/TLS test scenarios
    _SSL_TLS_SCENARIOS: ClassVar[tuple[SSLTLSScenario, ...]] = (
        SSLTLSScenario.BOTH_ENABLED,
        SSLTLSScenario.BOTH_DISABLED,
        SSLTLSScenario.SSL_ONLY,
        SSLTLSScenario.TLS_ONLY,
    )

    # Connection config test data by scenario
    _CONNECTION_CONFIG_DATA: ClassVar[dict[str, dict[str, object]]] = {
        "default": {
            "scenario": ModelTestScenario.DEFAULT,
            "expected_attrs": {
                "host": "ldap.example.com",
                "port": 389,
                "use_ssl": False,
                "use_tls": False,
                "bind_dn": None,
                "bind_password": None,
                "timeout": 30,
                "auto_bind": True,
                "auto_range": True,
            },
        },
        "custom": {
            "scenario": ModelTestScenario.CUSTOM,
            "expected_attrs": {
                "host": "secure.example.com",
                "port": 636,
                "use_ssl": True,
                "use_tls": False,
                "bind_dn": TestConstants.DEFAULT_BIND_DN,
                "bind_password": "secure_password",
                "timeout": 60,
                "auto_bind": False,
                "auto_range": False,
            },
        },
        "edge_case": {
            "scenario": ModelTestScenario.EDGE_CASE,
            "expected_attrs": {
                "host": "a",
                "port": 1,
                "use_ssl": False,
                "use_tls": False,
                "bind_dn": None,
                "bind_password": None,
                "timeout": 300,
                "auto_bind": False,
                "auto_range": False,
            },
        },
    }

    # Search options test data by scenario
    _SEARCH_OPTIONS_DATA: ClassVar[dict[str, dict[str, object]]] = {
        "default": {
            "scenario": ModelTestScenario.DEFAULT,
            "expected_attrs": {
                "base_dn": TestConstants.DEFAULT_BASE_DN,
                "filter_str": "(objectClass=*)",
                "scope": "SUBTREE",
                "attributes": None,
                "size_limit": 0,
                "time_limit": 0,
            },
        },
        "custom": {
            "scenario": ModelTestScenario.CUSTOM,
            "expected_attrs": {
                "base_dn": TestConstants.DEFAULT_BASE_DN,
                "filter_str": "(cn=test)",
                "scope": "ONELEVEL",
                "attributes": ["cn", "mail", "uid"],
                "size_limit": 100,
                "time_limit": 30,
            },
        },
        "edge_case": {
            "scenario": ModelTestScenario.EDGE_CASE,
            "expected_attrs": {
                "base_dn": TestConstants.DEFAULT_BASE_DN,
                "filter_str": "(objectClass=*)",
                "scope": "BASE",
                "attributes": [],
                "size_limit": 1000,
                "time_limit": 3600,
            },
        },
    }

    # Operation result test data by scenario
    _OPERATION_RESULT_DATA: ClassVar[dict[str, dict[str, object]]] = {
        "success": {
            "scenario": ModelTestScenario.DEFAULT,
            "expected_attrs": {
                "success": True,
                "operation_type": "add",
                "entries_affected": 1,
            },
        },
        "failure": {
            "scenario": ModelTestScenario.CUSTOM,
            "expected_attrs": {
                "success": False,
                "operation_type": "delete",
                "entries_affected": 0,
            },
        },
    }

    # Sync stats test data by scenario
    _SYNC_STATS_DATA: ClassVar[dict[str, dict[str, object]]] = {
        "default": {
            "scenario": ModelTestScenario.DEFAULT,
            "expected_attrs": {
                "added": 0,
                "skipped": 0,
                "failed": 0,
                "total": 0,
                "duration_seconds": 0.0,
            },
        },
        "custom": {
            "scenario": ModelTestScenario.CUSTOM,
            "expected_attrs": {
                "added": 5,
                "skipped": 2,
                "failed": 1,
                "total": 8,
                "duration_seconds": 1.5,
            },
        },
    }

    @staticmethod
    def _create_connection_config(
        scenario: ModelTestScenario = ModelTestScenario.DEFAULT,
        host: str | None = None,
        port: int | None = None,
        use_ssl: bool | None = None,
        use_tls: bool | None = None,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        timeout: int | None = None,
        auto_bind: bool | None = None,
        auto_range: bool | None = None,
    ) -> FlextLdapModels.ConnectionConfig:
        """Factory for ConnectionConfig instances with scenario-based defaults.

        Args:
            scenario: Test scenario type for default values
            host: Override host
            port: Override port
            use_ssl: Override use_ssl
            use_tls: Override use_tls
            bind_dn: Override bind_dn
            bind_password: Override bind_password
            timeout: Override timeout
            auto_bind: Override auto_bind
            auto_range: Override auto_range

        Returns:
            FlextLdapModels.ConnectionConfig instance

        """
        scenario_defaults: dict[
            ModelTestScenario, dict[str, str | int | bool | None]
        ] = {
            ModelTestScenario.DEFAULT: {
                "host": "ldap.example.com",
                "port": 389,
                "use_ssl": False,
                "use_tls": False,
                "bind_dn": None,
                "bind_password": None,
                "timeout": 30,
                "auto_bind": True,
                "auto_range": True,
            },
            ModelTestScenario.CUSTOM: {
                "host": "secure.example.com",
                "port": 636,
                "use_ssl": True,
                "use_tls": False,
                "bind_dn": TestConstants.DEFAULT_BIND_DN,
                "bind_password": "secure_password",
                "timeout": 60,
                "auto_bind": False,
                "auto_range": False,
            },
            ModelTestScenario.INVALID: {
                "host": "invalid.host.name",
                "port": 389,
                "use_ssl": True,
                "use_tls": True,
                "bind_dn": "invalid",
                "bind_password": "",
                "timeout": -1,
                "auto_bind": True,
                "auto_range": True,
            },
            ModelTestScenario.EDGE_CASE: {
                "host": "a",
                "port": 1,
                "use_ssl": False,
                "use_tls": False,
                "bind_dn": None,
                "bind_password": None,
                "timeout": 300,
                "auto_bind": False,
                "auto_range": False,
            },
        }

        defaults = scenario_defaults[scenario]
        default_host = defaults["host"]
        default_port = defaults["port"]
        default_use_ssl = defaults["use_ssl"]
        default_use_tls = defaults["use_tls"]
        default_bind_dn = defaults["bind_dn"]
        default_bind_password = defaults["bind_password"]
        default_timeout = defaults["timeout"]
        default_auto_bind = defaults["auto_bind"]
        default_auto_range = defaults["auto_range"]

        assert isinstance(default_host, str)
        assert isinstance(default_port, int)
        assert isinstance(default_use_ssl, bool)
        assert isinstance(default_use_tls, bool)
        assert isinstance(default_timeout, int)
        assert isinstance(default_auto_bind, bool)
        assert isinstance(default_auto_range, bool)

        return FlextLdapModels.ConnectionConfig(
            host=host if host is not None else default_host,
            port=port if port is not None else default_port,
            use_ssl=use_ssl if use_ssl is not None else default_use_ssl,
            use_tls=use_tls if use_tls is not None else default_use_tls,
            bind_dn=(bind_dn if isinstance(bind_dn, (str, type(None))) else None)
            if bind_dn is not None
            else (
                default_bind_dn
                if isinstance(default_bind_dn, (str, type(None)))
                else None
            ),
            bind_password=(
                bind_password if isinstance(bind_password, (str, type(None))) else None
            )
            if bind_password is not None
            else (
                default_bind_password
                if isinstance(default_bind_password, (str, type(None)))
                else None
            ),
            timeout=timeout if timeout is not None else default_timeout,
            auto_bind=auto_bind if auto_bind is not None else default_auto_bind,
            auto_range=auto_range if auto_range is not None else default_auto_range,
        )

    @staticmethod
    def _create_search_options(
        scenario: ModelTestScenario = ModelTestScenario.DEFAULT,
        base_dn: str | None = None,
        filter_str: str | None = None,
        scope: str | None = None,
        attributes: list[str] | None = None,
        size_limit: int | None = None,
        time_limit: int | None = None,
    ) -> FlextLdapModels.SearchOptions:
        """Factory for SearchOptions instances with scenario-based defaults.

        Args:
            scenario: Test scenario type for default values
            base_dn: Override base_dn
            filter_str: Override filter_str
            scope: Override scope
            attributes: Override attributes
            size_limit: Override size_limit
            time_limit: Override time_limit

        Returns:
            FlextLdapModels.SearchOptions instance

        """
        scenario_defaults: dict[
            ModelTestScenario, dict[str, str | list[str] | int | None]
        ] = {
            ModelTestScenario.DEFAULT: {
                "base_dn": TestConstants.DEFAULT_BASE_DN,
                "filter_str": "(objectClass=*)",
                "scope": "SUBTREE",
                "attributes": None,
                "size_limit": 0,
                "time_limit": 0,
            },
            ModelTestScenario.CUSTOM: {
                "base_dn": TestConstants.DEFAULT_BASE_DN,
                "filter_str": "(cn=test)",
                "scope": "ONELEVEL",
                "attributes": ["cn", "mail", "uid"],
                "size_limit": 100,
                "time_limit": 30,
            },
            ModelTestScenario.INVALID: {
                "base_dn": "invalid-dn-format",
                "filter_str": "invalid-filter",
                "scope": "INVALID_SCOPE",
                "attributes": ["invalid_attr"],
                "size_limit": -1,
                "time_limit": -1,
            },
            ModelTestScenario.EDGE_CASE: {
                "base_dn": TestConstants.DEFAULT_BASE_DN,
                "filter_str": "(objectClass=*)",
                "scope": "BASE",
                "attributes": [],
                "size_limit": 1000,
                "time_limit": 3600,
            },
        }

        defaults = scenario_defaults[scenario]
        default_base_dn = defaults["base_dn"]
        default_filter_str = defaults["filter_str"]
        default_scope = defaults["scope"]
        default_attributes = defaults["attributes"]
        default_size_limit = defaults["size_limit"]
        default_time_limit = defaults["time_limit"]

        assert isinstance(default_base_dn, str)
        assert isinstance(default_filter_str, str)
        assert isinstance(default_scope, str)
        assert isinstance(default_size_limit, int)
        assert isinstance(default_time_limit, int)

        # Validate scope is a valid Literal
        final_scope = scope if scope is not None else default_scope
        if final_scope == "BASE":
            scope_valid: FlextLdapConstants.LiteralTypes.SearchScope = "BASE"
        elif final_scope == "ONELEVEL":
            scope_valid = "ONELEVEL"
        elif final_scope == "SUBTREE":
            scope_valid = "SUBTREE"
        else:
            msg = f"Invalid scope: {final_scope}"
            raise ValueError(msg)

        # Type narrowing for attributes
        final_attributes = attributes if attributes is not None else default_attributes
        attributes_valid: list[str] | None = (
            final_attributes
            if isinstance(final_attributes, (list, type(None)))
            else None
        )

        return FlextLdapModels.SearchOptions(
            base_dn=base_dn if base_dn is not None else default_base_dn,
            filter_str=filter_str if filter_str is not None else default_filter_str,
            scope=scope_valid,
            attributes=attributes_valid,
            size_limit=size_limit if size_limit is not None else default_size_limit,
            time_limit=time_limit if time_limit is not None else default_time_limit,
        )

    @staticmethod
    def _create_ldif_entry(
        dn: str | None = None,
        cn: list[str] | None = None,
        object_class: list[str] | None = None,
        **attributes: list[str],
    ) -> FlextLdifModels.Entry:
        """Factory for LDIF Entry instances.

        Args:
            dn: Distinguished name (uses TEST_USER_DN if None)
            cn: Common name attribute
            object_class: Object class attribute
            **attributes: Additional entry attributes as key-value pairs

        Returns:
            FlextLdifModels.Entry instance

        """
        entry_dn = dn or TestConstants.TEST_USER_DN
        default_attrs: dict[str, list[str]] = {
            "cn": cn if cn is not None else ["test"],
            "objectClass": object_class
            if object_class is not None
            else ["top", "person"],
        }
        default_attrs.update(attributes)
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=entry_dn),
            attributes=FlextLdifModels.LdifAttributes(attributes=default_attrs),
        )

    @staticmethod
    def _create_operation_result(
        *,
        success: bool = True,
        operation_type: str = "add",
        message: str = "",
        entries_affected: int = 1,
        data: dict[str, str | int | float | bool | list[str]] | None = None,
    ) -> FlextLdapModels.OperationResult:
        """Factory for OperationResult instances.

        Args:
            success: Whether operation succeeded
            operation_type: Type of operation performed (must be valid Literal)
            message: Operation result message
            entries_affected: Number of entries affected
            data: Additional operation data

        Returns:
            FlextLdapModels.OperationResult instance

        """
        # Validate operation_type is a valid Literal value
        valid_operations: set[FlextLdapConstants.LiteralTypes.OperationType] = {
            "search",
            "add",
            "modify",
            "delete",
            "modify_dn",
            "compare",
            "bind",
            "unbind",
        }
        if operation_type not in valid_operations:
            msg = f"Invalid operation_type: {operation_type}"
            raise ValueError(msg)

        # After validation, operation_type is guaranteed to be a valid Literal
        # Mypy needs explicit type narrowing - use a type guard pattern
        if operation_type == "search":
            op_type: FlextLdapConstants.LiteralTypes.OperationType = "search"
        elif operation_type == "add":
            op_type = "add"
        elif operation_type == "modify":
            op_type = "modify"
        elif operation_type == "delete":
            op_type = "delete"
        elif operation_type == "modify_dn":
            op_type = "modify_dn"
        elif operation_type == "compare":
            op_type = "compare"
        elif operation_type == "bind":
            op_type = "bind"
        elif operation_type == "unbind":
            op_type = "unbind"
        else:
            msg = f"Invalid operation_type: {operation_type}"
            raise ValueError(msg)

        return FlextLdapModels.OperationResult(
            success=success,
            operation_type=op_type,
            message=message,
            entries_affected=entries_affected,
            data=data if data is not None else {},
        )

    @staticmethod
    def _create_sync_stats(
        added: int = 0,
        skipped: int = 0,
        failed: int = 0,
        total: int = 0,
        duration_seconds: float = 0.0,
    ) -> FlextLdapModels.SyncStats:
        """Factory for SyncStats instances.

        Args:
            added: Number of entries added
            skipped: Number of entries skipped
            failed: Number of entries failed
            total: Total number of entries
            duration_seconds: Duration in seconds

        Returns:
            FlextLdapModels.SyncStats instance

        """
        return FlextLdapModels.SyncStats(
            added=added,
            skipped=skipped,
            failed=failed,
            total=total,
            duration_seconds=duration_seconds,
        )

    @pytest.mark.parametrize("scenario_name", ["default", "custom", "edge_case"])
    def test_connection_config_creation_scenarios(self, scenario_name: str) -> None:
        """Test ConnectionConfig with various scenarios (parametrized).

        Covers TestConnectionConfig::test_connection_config_scenarios
        with dynamic parametrization using scenario names.
        """
        scenario_data = self._CONNECTION_CONFIG_DATA[scenario_name]
        scenario_value = scenario_data["scenario"]
        if isinstance(scenario_value, ModelTestScenario):
            scenario = scenario_value
        else:
            scenario = ModelTestScenario(str(scenario_value))
        expected_attrs = scenario_data["expected_attrs"]
        if not isinstance(expected_attrs, dict):
            msg = "expected_attrs must be a dict"
            raise TypeError(msg)

        def factory_wrapper(**kwargs: object) -> FlextLdapModels.ConnectionConfig:
            # Extract and validate kwargs for type safety
            host_val = kwargs.get("host")
            port_val = kwargs.get("port")
            use_ssl_val = kwargs.get("use_ssl")
            use_tls_val = kwargs.get("use_tls")
            bind_dn_val = kwargs.get("bind_dn")
            bind_password_val = kwargs.get("bind_password")
            timeout_val = kwargs.get("timeout")
            auto_bind_val = kwargs.get("auto_bind")
            auto_range_val = kwargs.get("auto_range")

            return self._create_connection_config(
                scenario=scenario,
                host=host_val if isinstance(host_val, str) else None,
                port=port_val if isinstance(port_val, int) else None,
                use_ssl=use_ssl_val if isinstance(use_ssl_val, bool) else None,
                use_tls=use_tls_val if isinstance(use_tls_val, bool) else None,
                bind_dn=bind_dn_val
                if isinstance(bind_dn_val, (str, type(None)))
                else None,
                bind_password=bind_password_val
                if isinstance(bind_password_val, (str, type(None)))
                else None,
                timeout=timeout_val if isinstance(timeout_val, int) else None,
                auto_bind=auto_bind_val if isinstance(auto_bind_val, bool) else None,
                auto_range=auto_range_val if isinstance(auto_range_val, bool) else None,
            )

        ModelTestHelpers.assert_model_creation_success(
            factory_wrapper,
            expected_attrs,
        )

    @pytest.mark.parametrize("ssl_tls_scenario", _SSL_TLS_SCENARIOS)
    def test_connection_config_ssl_tls_validation(self, ssl_tls_scenario: str) -> None:
        """Test ConnectionConfig SSL/TLS mutual exclusion validation (parametrized).

        Covers TestConnectionConfig::test_connection_config_ssl_tls_validation
        with parametrized SSL/TLS combinations.
        """
        scenario = SSLTLSScenario(ssl_tls_scenario)
        use_ssl_value = scenario in {
            SSLTLSScenario.BOTH_ENABLED,
            SSLTLSScenario.SSL_ONLY,
        }
        use_tls_value = scenario in {
            SSLTLSScenario.BOTH_ENABLED,
            SSLTLSScenario.TLS_ONLY,
        }
        expect_failure = scenario == SSLTLSScenario.BOTH_ENABLED

        if expect_failure:

            def factory_wrapper(**kwargs: object) -> FlextLdapModels.ConnectionConfig:
                use_ssl_val = kwargs.get("use_ssl", False)
                use_tls_val = kwargs.get("use_tls", False)
                if not isinstance(use_ssl_val, bool):
                    msg = "use_ssl must be a bool"
                    raise TypeError(msg)
                if not isinstance(use_tls_val, bool):
                    msg = "use_tls must be a bool"
                    raise TypeError(msg)
                return self._create_connection_config(
                    use_ssl=use_ssl_val, use_tls=use_tls_val
                )

            ModelTestHelpers.assert_model_validation_failure(
                factory_wrapper,
                ["mutually exclusive"],
                use_ssl=use_ssl_value,
                use_tls=use_tls_value,
            )
        else:
            config = self._create_connection_config(
                use_ssl=use_ssl_value, use_tls=use_tls_value
            )
            assert config.use_ssl == use_ssl_value
            assert config.use_tls == use_tls_value

    @pytest.mark.parametrize("scenario_name", ["default", "custom", "edge_case"])
    def test_search_options_creation_scenarios(self, scenario_name: str) -> None:
        """Test SearchOptions with various scenarios (parametrized).

        Covers TestSearchOptions::test_search_options_scenarios
        with dynamic parametrization using scenario names.
        """
        scenario_data = self._SEARCH_OPTIONS_DATA[scenario_name]
        scenario_value = scenario_data["scenario"]
        if isinstance(scenario_value, ModelTestScenario):
            scenario = scenario_value
        else:
            scenario = ModelTestScenario(str(scenario_value))
        expected_attrs = scenario_data["expected_attrs"]
        if not isinstance(expected_attrs, dict):
            msg = "expected_attrs must be a dict"
            raise TypeError(msg)

        def factory_wrapper(**kwargs: object) -> FlextLdapModels.SearchOptions:
            # Extract and validate kwargs for type safety
            base_dn_val = kwargs.get("base_dn")
            filter_str_val = kwargs.get("filter_str")
            scope_val = kwargs.get("scope")
            attributes_val = kwargs.get("attributes")
            size_limit_val = kwargs.get("size_limit")
            time_limit_val = kwargs.get("time_limit")

            return self._create_search_options(
                scenario=scenario,
                base_dn=base_dn_val if isinstance(base_dn_val, str) else None,
                filter_str=filter_str_val if isinstance(filter_str_val, str) else None,
                scope=scope_val if isinstance(scope_val, str) else None,
                attributes=attributes_val
                if isinstance(attributes_val, (list, type(None)))
                else None,
                size_limit=size_limit_val if isinstance(size_limit_val, int) else None,
                time_limit=time_limit_val if isinstance(time_limit_val, int) else None,
            )

        ModelTestHelpers.assert_model_creation_success(
            factory_wrapper,
            expected_attrs,
        )

    def test_search_options_invalid_base_dn_validation(self) -> None:
        """Test SearchOptions rejects malformed base DN.

        Covers TestSearchOptions::test_search_options_validates_invalid_base_dn
        """

        def factory_wrapper(**kwargs: object) -> FlextLdapModels.SearchOptions:
            # Extract and validate kwargs for type safety
            base_dn_val = kwargs.get("base_dn")
            filter_str_val = kwargs.get("filter_str")
            scope_val = kwargs.get("scope")
            attributes_val = kwargs.get("attributes")
            size_limit_val = kwargs.get("size_limit")
            time_limit_val = kwargs.get("time_limit")

            return self._create_search_options(
                scenario=ModelTestScenario.INVALID,
                base_dn=base_dn_val if isinstance(base_dn_val, str) else None,
                filter_str=filter_str_val if isinstance(filter_str_val, str) else None,
                scope=scope_val if isinstance(scope_val, str) else None,
                attributes=attributes_val
                if isinstance(attributes_val, (list, type(None)))
                else None,
                size_limit=size_limit_val if isinstance(size_limit_val, int) else None,
                time_limit=time_limit_val if isinstance(time_limit_val, int) else None,
            )

        ModelTestHelpers.assert_model_validation_failure(
            factory_wrapper,
            ["Invalid base_dn format"],
        )

    def test_search_options_normalized_with_explicit_scope(self) -> None:
        """Test SearchOptions.normalized preserves explicit scope.

        Covers TestSearchOptionsNormalized::test_normalized_with_explicit_scope
        """
        options = FlextLdapModels.SearchOptions.normalized(
            base_dn=TestConstants.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope="BASE",
        )

        assert options.base_dn == TestConstants.DEFAULT_BASE_DN
        assert options.filter_str == "(objectClass=*)"
        assert options.scope == "BASE"

    def test_search_options_normalized_default_scope(self) -> None:
        """Test SearchOptions.normalized applies default scope when omitted.

        Covers TestSearchOptionsNormalized::test_normalized_uses_default_scope_when_not_specified
        """
        options = FlextLdapModels.SearchOptions.normalized(
            base_dn=TestConstants.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
        )

        assert options.scope == "SUBTREE"

    def test_search_options_normalized_default_filter(self) -> None:
        """Test SearchOptions.normalized applies default filter when omitted.

        Covers TestSearchOptionsNormalized::test_normalized_uses_default_filter_when_not_specified
        """
        options = FlextLdapModels.SearchOptions.normalized(
            base_dn=TestConstants.DEFAULT_BASE_DN,
        )

        assert options.filter_str == "(objectClass=*)"

    @pytest.mark.parametrize("scenario_name", ["success", "failure"])
    def test_operation_result_scenarios(self, scenario_name: str) -> None:
        """Test OperationResult with various scenarios (parametrized).

        Covers TestOperationResult::test_operation_result_scenarios
        with dynamic parametrization using scenario names.
        """
        scenario_data = self._OPERATION_RESULT_DATA[scenario_name]
        expected_attrs = scenario_data["expected_attrs"]
        if not isinstance(expected_attrs, dict):
            msg = "expected_attrs must be a dict"
            raise TypeError(msg)

        success_val = expected_attrs.get("success", True)
        operation_type_val = expected_attrs.get("operation_type", "add")
        entries_affected_val = expected_attrs.get("entries_affected", 1)
        if not isinstance(success_val, bool):
            msg = "success must be a bool"
            raise TypeError(msg)
        if not isinstance(operation_type_val, str):
            msg = "operation_type must be a str"
            raise TypeError(msg)
        if not isinstance(entries_affected_val, int):
            msg = "entries_affected must be an int"
            raise TypeError(msg)

        result = self._create_operation_result(
            success=success_val,
            operation_type=operation_type_val,
            entries_affected=entries_affected_val,
        )
        for attr, expected_value in expected_attrs.items():
            assert getattr(result, attr) == expected_value

    @pytest.mark.parametrize("scenario_name", ["default", "custom"])
    def test_sync_stats_initialization_scenarios(self, scenario_name: str) -> None:
        """Test SyncStats initialization with various scenarios (parametrized).

        Covers TestSyncStats::test_sync_stats_initialization_scenarios
        with dynamic parametrization using scenario names.
        """
        scenario_data = self._SYNC_STATS_DATA[scenario_name]
        expected_attrs = scenario_data["expected_attrs"]
        if not isinstance(expected_attrs, dict):
            msg = "expected_attrs must be a dict"
            raise TypeError(msg)

        added_val = expected_attrs.get("added", 0)
        skipped_val = expected_attrs.get("skipped", 0)
        failed_val = expected_attrs.get("failed", 0)
        total_val = expected_attrs.get("total", 0)
        duration_val = expected_attrs.get("duration_seconds", 0.0)
        if not isinstance(added_val, int):
            msg = "added must be an int"
            raise TypeError(msg)
        if not isinstance(skipped_val, int):
            msg = "skipped must be an int"
            raise TypeError(msg)
        if not isinstance(failed_val, int):
            msg = "failed must be an int"
            raise TypeError(msg)
        if not isinstance(total_val, int):
            msg = "total must be an int"
            raise TypeError(msg)
        if not isinstance(duration_val, (int, float)):
            msg = "duration_seconds must be a number"
            raise TypeError(msg)

        stats = self._create_sync_stats(
            added=added_val,
            skipped=skipped_val,
            failed=failed_val,
            total=total_val,
            duration_seconds=float(duration_val),
        )
        for attr, expected_value in expected_attrs.items():
            assert getattr(stats, attr) == expected_value

    @pytest.mark.parametrize(
        ("factory_kwargs", "expected_success_rate"),
        [
            ({"added": 7, "skipped": 2, "failed": 1, "total": 10}, 0.9),
            ({"added": 10, "skipped": 0, "failed": 0, "total": 10}, 1.0),
            ({"added": 0, "skipped": 0, "failed": 5, "total": 5}, 0.0),
            ({"total": 0}, 0.0),  # Edge case: zero total
        ],
    )
    def test_sync_stats_success_rate_calculation(
        self,
        factory_kwargs: dict[str, object],
        expected_success_rate: float,
    ) -> None:
        """Test SyncStats success_rate computed property (parametrized).

        Covers TestSyncStats::test_sync_stats_success_rate_calculation
        with parametrized rate calculations.
        """
        added_val = factory_kwargs.get("added", 0)
        skipped_val = factory_kwargs.get("skipped", 0)
        failed_val = factory_kwargs.get("failed", 0)
        total_val = factory_kwargs.get("total", 0)
        duration_val = factory_kwargs.get("duration_seconds", 0.0)
        if not isinstance(added_val, int):
            msg = "added must be an int"
            raise TypeError(msg)
        if not isinstance(skipped_val, int):
            msg = "skipped must be an int"
            raise TypeError(msg)
        if not isinstance(failed_val, int):
            msg = "failed must be an int"
            raise TypeError(msg)
        if not isinstance(total_val, int):
            msg = "total must be an int"
            raise TypeError(msg)
        if not isinstance(duration_val, (int, float)):
            msg = "duration_seconds must be a number"
            raise TypeError(msg)

        stats = self._create_sync_stats(
            added=added_val,
            skipped=skipped_val,
            failed=failed_val,
            total=total_val,
            duration_seconds=float(duration_val),
        )
        success_rate = stats.success_rate
        if not isinstance(success_rate, (int, float)):
            msg = "success_rate must be a number"
            raise TypeError(msg)
        assert float(success_rate) == expected_success_rate

    def test_sync_stats_from_counters_factory_method(self) -> None:
        """Test SyncStats.from_counters class method.

        Covers TestSyncStats::test_sync_stats_from_counters_factory_method
        """
        stats = FlextLdapModels.SyncStats.from_counters(
            added=10,
            skipped=5,
            failed=2,
            duration_seconds=1.5,
        )

        expected_attrs = {
            "added": 10,
            "skipped": 5,
            "failed": 2,
            "total": 17,  # 10 + 5 + 2
            "duration_seconds": 1.5,
        }

        for attr, expected_value in expected_attrs.items():
            assert getattr(stats, attr) == expected_value

    def test_search_result_total_count_property(self) -> None:
        """Test SearchResult.total_count computed property.

        Covers TestSearchResult::test_search_result_total_count_property
        """
        entries = [
            self._create_ldif_entry("cn=user1,dc=example,dc=com"),
            self._create_ldif_entry("cn=user2,dc=example,dc=com"),
        ]

        search_result = FlextLdapModels.SearchResult(
            entries=entries,
            search_options=self._create_search_options(),
        )

        assert search_result.total_count == 2

    def test_search_result_by_objectclass_categorization(self) -> None:
        """Test SearchResult.by_objectclass with multiple categories.

        Covers TestSearchResult::test_search_result_by_objectclass_categorization
        """
        entries = [
            self._create_ldif_entry(
                "cn=user1,dc=example,dc=com", object_class=["person", "top"]
            ),
            self._create_ldif_entry(
                "cn=user2,dc=example,dc=com", object_class=["person", "top"]
            ),
            self._create_ldif_entry(
                "ou=org,dc=example,dc=com", object_class=["organizationalUnit"]
            ),
        ]

        search_result = FlextLdapModels.SearchResult(
            entries=entries,
            search_options=self._create_search_options(),
        )

        categories_obj = search_result.by_objectclass
        if not isinstance(categories_obj, dict):
            msg = "by_objectclass must return a dict"
            raise TypeError(msg)
        categories = categories_obj
        assert isinstance(categories, dict)
        assert "person" in categories
        assert "organizationalUnit" in categories
        assert len(categories["person"]) == 2
        assert len(categories["organizationalUnit"]) == 1

    def test_search_result_by_objectclass_missing_attribute(self) -> None:
        """Test SearchResult.by_objectclass with missing objectClass.

        Covers TestSearchResult::test_search_result_by_objectclass_handles_missing_objectclass
        """
        entry = self._create_ldif_entry()
        entry.attributes.attributes.pop("objectClass", None)

        search_result = FlextLdapModels.SearchResult(
            entries=[entry],
            search_options=self._create_search_options(),
        )

        categories_obj = search_result.by_objectclass
        if not isinstance(categories_obj, dict):
            msg = "by_objectclass must return a dict"
            raise TypeError(msg)
        categories = categories_obj
        assert "unknown" in categories
        assert len(categories["unknown"]) == 1

    def test_search_result_empty_entries_list(self) -> None:
        """Test SearchResult with empty entries collection.

        Covers TestSearchResult::test_search_result_empty_entries_list
        """
        search_result = FlextLdapModels.SearchResult(
            entries=[],
            search_options=self._create_search_options(),
        )

        assert search_result.entries == []
        assert len(search_result.entries) == 0

    def test_search_result_with_populated_entries(self) -> None:
        """Test SearchResult with actual entry data.

        Covers TestSearchResult::test_search_result_with_populated_entries
        """
        entries = [self._create_ldif_entry("cn=test1,dc=example,dc=com")]

        search_result = FlextLdapModels.SearchResult(
            entries=entries,
            search_options=self._create_search_options(),
        )

        assert len(search_result.entries) == 1
        assert search_result.entries[0].dn.value == "cn=test1,dc=example,dc=com"

    def test_search_result_by_objectclass_empty_result(self) -> None:
        """Test by_objectclass returns empty dict for no entries.

        Covers TestSearchResult::test_search_result_by_objectclass_empty_result
        """
        search_result = FlextLdapModels.SearchResult(
            entries=[],
            search_options=self._create_search_options(),
        )

        categories_obj = search_result.by_objectclass
        if not isinstance(categories_obj, dict):
            msg = "by_objectclass must return a dict"
            raise TypeError(msg)
        categories = categories_obj
        assert isinstance(categories, dict)
        assert len(categories) == 0

    def test_batch_upsert_result_basic_initialization(self) -> None:
        """Test BatchUpsertResult basic properties.

        Covers TestBatchOperations::test_batch_upsert_result_basic_initialization
        """
        result = FlextLdapModels.BatchUpsertResult(
            total_processed=10,
            successful=8,
            failed=2,
            results=[],
        )

        assert result.total_processed == 10
        assert result.successful == 8
        assert result.failed == 2
        assert result.results == []

    def test_batch_upsert_result_with_individual_results(self) -> None:
        """Test BatchUpsertResult with populated results list.

        Covers TestBatchOperations::test_batch_upsert_result_with_individual_results
        """
        individual_results = [
            FlextLdapModels.UpsertResult(
                success=True,
                dn="cn=test1,dc=example,dc=com",
                operation="add",
            ),
            FlextLdapModels.UpsertResult(
                success=False,
                dn="cn=test2,dc=example,dc=com",
                operation="modify",
                error="Entry not found",
            ),
        ]

        result = FlextLdapModels.BatchUpsertResult(
            total_processed=2,
            successful=1,
            failed=1,
            results=individual_results,
        )

        assert len(result.results) == 2
        assert result.results[0].success is True
        assert result.results[1].success is False
        assert result.results[1].error == "Entry not found"

    @pytest.mark.parametrize(("total_processed", "successful"), [(10, 7), (0, 0)])
    def test_batch_upsert_result_success_rate_calculation(
        self, total_processed: int, successful: int
    ) -> None:
        """Test BatchUpsertResult success_rate computed property (parametrized).

        Covers TestBatchOperations::test_batch_upsert_result_success_rate_calculation
        with parametrized success rate scenarios.
        """
        expected_rate = 0.0 if total_processed == 0 else successful / total_processed
        result = FlextLdapModels.BatchUpsertResult(
            total_processed=total_processed,
            successful=successful,
            failed=total_processed - successful,
            results=[],
        )
        assert result.success_rate == expected_rate

    def test_upsert_result_successful_case(self) -> None:
        """Test UpsertResult for successful operations.

        Covers TestBatchOperations::test_upsert_result_successful_case
        """
        result = FlextLdapModels.UpsertResult(
            success=True,
            dn="cn=test,dc=example,dc=com",
            operation="add",
        )

        assert result.success is True
        assert result.dn == "cn=test,dc=example,dc=com"
        assert result.operation == "add"
        assert result.error is None

    def test_upsert_result_failure_case(self) -> None:
        """Test UpsertResult for failed operations.

        Covers TestBatchOperations::test_upsert_result_failure_case
        """
        result = FlextLdapModels.UpsertResult(
            success=False,
            dn="cn=test,dc=example,dc=com",
            operation="modify",
            error="Entry not found",
        )

        assert result.success is False
        assert result.dn == "cn=test,dc=example,dc=com"
        assert result.operation == "modify"
        assert result.error == "Entry not found"
