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

pytestmark = pytest.mark.integration


class ConnectionTestType(StrEnum):
    """Enumeration of connection test types."""

    SERVICE_CONFIG_ALL_OPTIONS = "service_config_all_options"
    CONNECTION_CONFIG_OVERRIDES = "connection_config_overrides"
    PARSER_REUSE = "parser_reuse"


class TestFlextLdapConnectionCompleteCoverage:
    """Complete coverage tests for FlextLdapConnection."""

    # Test configurations as ClassVar for parameterized tests
    CONNECTION_TEST_CONFIGS: ClassVar[list[tuple[str, dict[str, object]]]] = [
        (
            "service_config_all_options",
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
        (
            "connection_config_overrides",
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
        (
            "parser_reuse",
            {
                "test_type": ConnectionTestType.PARSER_REUSE,
                "parser_reuse": True,
                "expect_success": None,  # Can be success or failure depending on server
            },
        ),
    ]

    class TestDataFactories:
        """Nested class for test data creation."""

        @staticmethod
        def create_service_config(
            base_config: dict[str, object],
            container: dict[str, object],
        ) -> FlextLdapConfig:
            """Create service config with container values."""
            # Cast base_config to avoid type issues with **kwargs
            config_dict: dict[str, str | int | bool] = {
                "host": str(container["host"]),
                "port": int(str(container["port"])),
                "bind_dn": str(container["bind_dn"]),
                "bind_password": str(container["password"]),
            }
            # Merge with base_config, casting to expected types
            for key, value in base_config.items():
                if key in {"use_ssl", "use_tls", "auto_bind", "auto_range"}:
                    config_dict[key] = cast("bool", value)
                elif key == "timeout":
                    config_dict[key] = cast("int", value)
                else:
                    config_dict[key] = cast("str | int | bool", value)

            return FlextLdapConfig(**config_dict)

        @staticmethod
        def create_connection_config(
            container: dict[str, object],
            overrides: dict[str, object] | None = None,
        ) -> FlextLdapModels.ConnectionConfig:
            """Create connection config from container."""
            config_dict: dict[str, object] = {
                "host": str(container["host"]),
                "port": int(str(container["port"])),
                "use_ssl": False,
                "use_tls": False,
                "bind_dn": str(container["bind_dn"]),
                "bind_password": str(container["password"]),
                "timeout": 30,
                "auto_bind": True,
                "auto_range": True,
            }
            if overrides:
                config_dict.update(overrides)
            # Cast to expected types for ConnectionConfig constructor
            return FlextLdapModels.ConnectionConfig(
                host=cast("str", config_dict["host"]),
                port=cast("int", config_dict["port"]),
                use_ssl=cast("bool", config_dict["use_ssl"]),
                use_tls=cast("bool", config_dict["use_tls"]),
                bind_dn=cast("str", config_dict["bind_dn"]),
                bind_password=cast("str", config_dict["bind_password"]),
                timeout=cast("int", config_dict["timeout"]),
                auto_bind=cast("bool", config_dict["auto_bind"]),
                auto_range=cast("bool", config_dict["auto_range"]),
            )

    class TestAssertions:
        """Nested class for test assertions."""

        @staticmethod
        def assert_connection_result(
            result: FlextResult[bool],
            config: dict[str, object],
        ) -> None:
            """Assert connection result based on configuration."""
            if expected_success := config.get("expect_success"):
                assert result.is_success == expected_success

            if config.get("parser_reuse"):
                # Parser reuse test - just check that method completes
                assert result is not None

    @pytest.mark.parametrize(("test_name", "config"), CONNECTION_TEST_CONFIGS)
    def test_connection_operations_parameterized(
        self,
        ldap_container: dict[str, object],
        connection_config: FlextLdapModels.ConnectionConfig,
        test_name: str,
        config: dict[str, object],
    ) -> None:
        """Test connection operations with different configurations."""
        if config.get("test_type") == ConnectionTestType.SERVICE_CONFIG_ALL_OPTIONS:
            # Test service config with all options
            service_config_dict = cast(
                "dict[str, object]", config.get("service_config", {})
            )
            service_config = self.TestDataFactories.create_service_config(
                service_config_dict, ldap_container
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
            service_config_dict = cast(
                "dict[str, object]", config.get("service_config", {})
            )
            service_config = FlextLdapConfig(
                host=cast("str", service_config_dict.get("host", "")),
                port=cast("int", service_config_dict.get("port", 0)),
            )
            connection = FlextLdapConnection(config=service_config)

            overrides = cast(
                "dict[str, object]", config.get("connection_config_override", {})
            )
            connection_config_to_use = self.TestDataFactories.create_connection_config(
                ldap_container, overrides
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
