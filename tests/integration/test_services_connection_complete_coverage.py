"""Complete coverage tests for FlextLdapConnection with real LDAP server.

Modules tested: FlextLdapConnection, FlextLdapConfig, FlextLdapModels
Scope: Complete connection coverage including service config options, overrides, and parser reuse scenarios

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, cast

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection

from ..fixtures.typing import GenericFieldsDict

pytestmark = pytest.mark.integration


class ConnectionTestType(StrEnum):
    """Enumeration of connection test types."""

    SERVICE_CONFIG_ALL_OPTIONS = "service_config_all_options"
    CONNECTION_CONFIG_OVERRIDES = "connection_config_overrides"
    PARSER_REUSE = "parser_reuse"


class TestFlextLdapConnectionCompleteCoverage:
    """Complete coverage tests for FlextLdapConnection."""

    # Test configurations as ClassVar for parameterized tests
    CONNECTION_TEST_CONFIGS: ClassVar[list[tuple[str, GenericFieldsDict]]] = [
        (
            "service_config_all_options",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": ConnectionTestType.SERVICE_CONFIG_ALL_OPTIONS,
                    "service_config": {
                        "use_ssl": False,
                        "use_tls": False,
                        "timeout": 30,
                        "auto_bind": True,
                        "auto_range": True,
                    },
                    "expect_success": True,
                },
            ),
        ),
        (
            "connection_config_overrides",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": ConnectionTestType.CONNECTION_CONFIG_OVERRIDES,
                    "service_config": {
                        "host": "wrong-host",
                        "port": 9999,
                    },
                    "connection_config_override": {
                        "use_ssl": False,
                    },
                    "expect_success": True,
                },
            ),
        ),
        (
            "parser_reuse",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": ConnectionTestType.PARSER_REUSE,
                    "parser_reuse": True,
                    "expect_success": None,  # Can be success or failure depending on server
                },
            ),
        ),
    ]

    class TestDataFactories:
        """Nested class for test data creation."""

        @staticmethod
        def create_service_config(
            base_config: GenericFieldsDict,
            container: GenericFieldsDict,
        ) -> FlextLdapConfig:
            """Create service config with container values."""
            # Build config with properly typed fields
            # GenericFieldsDict allows any keys via __extra_items__, use get with defaults
            host: str = str(container.get("host", "localhost"))
            port: int = int(str(container.get("port", 389)))
            bind_dn: str = str(container.get("bind_dn", ""))
            bind_password: str = str(container.get("password", ""))

            # Extract optional fields from base_config with proper types
            use_ssl_value = base_config.get("use_ssl", False)
            use_ssl: bool = bool(use_ssl_value) if use_ssl_value is not None else False

            use_tls_value = base_config.get("use_tls", False)
            use_tls: bool = bool(use_tls_value) if use_tls_value is not None else False

            timeout_value = base_config.get("timeout", 30)
            timeout: int = int(str(timeout_value)) if timeout_value is not None else 30

            auto_bind_value = base_config.get("auto_bind", True)
            auto_bind: bool = (
                bool(auto_bind_value) if auto_bind_value is not None else True
            )

            auto_range_value = base_config.get("auto_range", True)
            auto_range: bool = (
                bool(auto_range_value) if auto_range_value is not None else True
            )

            return FlextLdapConfig(
                host=host,
                port=port,
                bind_dn=bind_dn,
                bind_password=bind_password,
                use_ssl=use_ssl,
                use_tls=use_tls,
                timeout=timeout,
                auto_bind=auto_bind,
                auto_range=auto_range,
            )

        @staticmethod
        def create_connection_config(
            container: GenericFieldsDict,
            overrides: GenericFieldsDict | None = None,
        ) -> FlextLdapModels.ConnectionConfig:
            """Create connection config from container."""
            # Use get() for GenericFieldsDict to avoid mypy errors
            # Build config dict - GenericFieldsDict is TypedDict with total=False
            # Use dict literal and cast to GenericFieldsDict
            config_data: dict[str, object] = {
                "host": str(container.get("host", "localhost")),
                "port": int(str(container.get("port", 389))),
                "use_ssl": False,
                "use_tls": False,
                "bind_dn": str(container.get("bind_dn", "")),
                "bind_password": str(container.get("password", "")),
                "timeout": 30,
                "auto_bind": True,
                "auto_range": True,
            }
            if overrides:
                config_data.update(overrides)
            config_dict = cast("GenericFieldsDict", config_data)
            # Use .get() for GenericFieldsDict to avoid mypy errors
            return FlextLdapModels.ConnectionConfig(
                host=cast("str", config_dict.get("host", "localhost")),
                port=cast("int", config_dict.get("port", 389)),
                use_ssl=cast("bool", config_dict.get("use_ssl", False)),
                use_tls=cast("bool", config_dict.get("use_tls", False)),
                bind_dn=cast("str", config_dict.get("bind_dn", "")),
                bind_password=cast("str", config_dict.get("bind_password", "")),
                timeout=cast("int", config_dict.get("timeout", 30)),
                auto_bind=cast("bool", config_dict.get("auto_bind", True)),
                auto_range=cast("bool", config_dict.get("auto_range", True)),
            )

    class TestAssertions:
        """Nested class for test assertions."""

        @staticmethod
        def assert_connection_result(
            result: FlextResult[bool],
            config: GenericFieldsDict,
        ) -> None:
            """Assert connection result based on configuration."""
            if expected_success := config.get("expect_success"):
                assert result.is_success == expected_success, (
                    f"Expected success={expected_success}, got is_success={result.is_success}, "
                    f"error={result.error}"
                )
                # Validate actual content: if success expected, validate connection
                if expected_success and result.is_success:
                    connection_result = result.unwrap()
                    assert connection_result is True
                elif not expected_success and result.is_failure:
                    # Validate failure: error message should be present
                    error_msg = str(result.error) if result.error else ""
                    assert len(error_msg) > 0

            if config.get("parser_reuse"):
                # Parser reuse test - just check that method completes
                assert result is not None

    @pytest.mark.parametrize(("test_name", "config"), CONNECTION_TEST_CONFIGS)
    def test_connection_operations_parameterized(
        self,
        ldap_container: GenericFieldsDict,
        connection_config: FlextLdapModels.ConnectionConfig,
        test_name: str,
        config: GenericFieldsDict,
    ) -> None:
        """Test connection operations with different configurations."""
        if config.get("test_type") == ConnectionTestType.SERVICE_CONFIG_ALL_OPTIONS:
            # Test service config with all options
            service_config_dict_raw = config.get("service_config", {})
            # Cast to GenericFieldsDict for type compatibility
            service_config_dict = cast("GenericFieldsDict", service_config_dict_raw)
            service_config = self.TestDataFactories.create_service_config(
                service_config_dict,
                ldap_container,
            )
            connection = FlextLdapConnection(config=service_config)

            # Create ConnectionConfig from service config explicitly
            connection_config_to_use = FlextLdapModels.ConnectionConfig(
                host=service_config.host,
                port=service_config.port,
                use_ssl=service_config.use_ssl,
                use_tls=service_config.use_tls,
                bind_dn=service_config.bind_dn,
                bind_password=service_config.bind_password,
                timeout=service_config.timeout,
                auto_bind=service_config.auto_bind,
                auto_range=service_config.auto_range,
            )

        elif config.get("test_type") == ConnectionTestType.CONNECTION_CONFIG_OVERRIDES:
            # Test connection config overrides
            service_config_dict_raw = config.get("service_config", {})
            # Cast to GenericFieldsDict for type compatibility
            service_config_dict = cast("GenericFieldsDict", service_config_dict_raw)
            service_config = FlextLdapConfig(
                host=cast("str", service_config_dict.get("host", "")),
                port=cast("int", service_config_dict.get("port", 0)),
            )
            connection = FlextLdapConnection(config=service_config)

            overrides_raw = config.get("connection_config_override", {})
            # Cast to GenericFieldsDict for type compatibility
            overrides = cast("GenericFieldsDict | None", overrides_raw or None)
            connection_config_to_use = self.TestDataFactories.create_connection_config(
                ldap_container,
                overrides,
            )

        elif config.get("test_type") == ConnectionTestType.PARSER_REUSE:
            # Test parser reuse
            parser = FlextLdifParser()
            connection1 = FlextLdapConnection(parser=parser)
            connection2 = FlextLdapConnection(parser=parser)

            # Both should use same parser instance
            assert connection1._adapter._parser == parser
            assert connection2._adapter._parser == parser

            # Connect and disconnect
            result1 = connection1.connect(connection_config)
            if result1.is_success:
                connection1.disconnect()

            result2 = connection2.connect(connection_config)
            if result2.is_success:
                connection2.disconnect()

            # For parser reuse test, we're done - no further assertions needed
            return

        else:
            # Default case - use standard connection config
            connection = FlextLdapConnection()
            connection_config_to_use = connection_config

        # Connect and assert result
        result = connection.connect(connection_config_to_use)
        self.TestAssertions.assert_connection_result(result, config)

        # Disconnect if connection was successful
        if result.is_success:
            connection.disconnect()
