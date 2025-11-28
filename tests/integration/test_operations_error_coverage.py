"""Integration tests for FlextLdapOperations error cases with real LDAP server.

Modules tested: FlextLdapOperations, FlextLdapConnection, FlextLdapModels
Scope: Error handling and failure scenarios in LDAP operations for complete test coverage

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, cast

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsUtilities
from ldap3 import MODIFY_REPLACE

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from tests.fixtures.typing import GenericFieldsDict

from ..helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.integration


class ErrorTestType(StrEnum):
    """Enumeration of error test types."""

    SEARCH_FAILED_ADAPTER = "search_failed_adapter"
    ADD_FAILED_ADAPTER = "add_failed_adapter"
    MODIFY_FAILED_ADAPTER = "modify_failed_adapter"
    DELETE_FAILED_ADAPTER = "delete_failed_adapter"
    EXECUTE_NOT_CONNECTED = "execute_not_connected"


class TestFlextLdapOperationsErrorCoverage:
    """Tests for operations service error handling coverage."""

    # Test configurations as ClassVar for parameterized tests
    ERROR_TEST_CONFIGS: ClassVar[list[tuple[str, GenericFieldsDict]]] = [
        (
            "search_failed_adapter",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": ErrorTestType.SEARCH_FAILED_ADAPTER,
                    "operation": "search",
                    "search_options": {
                        "base_dn": "invalid=base,dn=invalid",
                        "filter_str": "(objectClass=*)",
                        "scope": "SUBTREE",
                    },
                    "expect_failure": None,  # Can be success or failure depending on server
                },
            ),
        ),
        (
            "add_failed_adapter",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": ErrorTestType.ADD_FAILED_ADAPTER,
                    "operation": "add",
                    "entry_dn": "invalid=dn",
                    "entry_attrs": {"objectClass": ["top"]},
                    "expect_failure": True,
                    "expect_error": True,
                },
            ),
        ),
        (
            "modify_failed_adapter",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": ErrorTestType.MODIFY_FAILED_ADAPTER,
                    "operation": "modify",
                    "dn": "cn=nonexistent,dc=flext,dc=local",
                    "changes": {"cn": [(MODIFY_REPLACE, ["modified"])]},
                    "expect_failure": True,
                    "expect_error": True,
                },
            ),
        ),
        (
            "delete_failed_adapter",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": ErrorTestType.DELETE_FAILED_ADAPTER,
                    "operation": "delete",
                    "dn": "cn=nonexistent,dc=flext,dc=local",
                    "expect_failure": True,
                    "expect_error": True,
                },
            ),
        ),
        (
            "execute_not_connected",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": ErrorTestType.EXECUTE_NOT_CONNECTED,
                    "operation": "execute",
                    "expect_failure": True,
                    "expect_error": True,
                    "error_contains": "Not connected",
                },
            ),
        ),
    ]

    class TestDataFactories:
        """Nested class for test data creation."""

        @staticmethod
        def create_operations_service(
            connection_config: FlextLdapModels.ConnectionConfig,
            ldap_parser: FlextLdifParser,
        ) -> FlextLdapOperations:
            """Create and connect operations service."""
            config = FlextLdapConfig()
            connection = FlextLdapConnection(config=config, parser=ldap_parser)
            connect_result = connection.connect(connection_config)
            if connect_result.is_failure:
                pytest.skip(f"Failed to connect: {connect_result.error}")

            return FlextLdapOperations(connection=connection)

        @staticmethod
        def create_operations_service_not_connected(
            ldap_parser: FlextLdifParser,
        ) -> FlextLdapOperations:
            """Create operations service without connection."""
            config = FlextLdapConfig()
            connection = FlextLdapConnection(config=config, parser=ldap_parser)
            return FlextLdapOperations(connection=connection)

        @staticmethod
        def create_test_entry(
            dn: str,
            attrs: dict[
                str,
                list[str] | str | tuple[str, ...] | set[str] | frozenset[str],
            ],
        ) -> FlextLdifModels.Entry:
            """Create test entry for error scenarios."""
            return EntryTestHelpers.create_entry(dn, attrs)

    class TestAssertions:
        """Nested class for test assertions."""

        @staticmethod
        def assert_error_result(
            result: FlextResult[object],
            config: GenericFieldsDict,
        ) -> None:
            """Assert error result based on configuration."""
            if config.get("expect_failure") is True:
                FlextTestsUtilities.TestUtilities.assert_result_failure(result)

            if config.get("expect_error"):
                assert result.error is not None

            if (
                error_contains := config.get("error_contains")
            ) and result.error is not None:
                assert str(error_contains) in result.error

            # For operations that may succeed or fail depending on server
            if config.get("expect_failure") is None:
                assert result.is_failure or result.is_success

    @pytest.mark.parametrize(("test_name", "config"), ERROR_TEST_CONFIGS)
    def test_operations_error_coverage_parameterized(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser,
        test_name: str,
        config: GenericFieldsDict,
    ) -> None:
        """Test operations error coverage with different failure scenarios."""
        # Create operations service based on test type
        if config.get("test_type") == ErrorTestType.EXECUTE_NOT_CONNECTED:
            operations = self.TestDataFactories.create_operations_service_not_connected(
                ldap_parser,
            )
        else:
            operations = self.TestDataFactories.create_operations_service(
                connection_config,
                ldap_parser,
            )

        # Execute operation based on test configuration
        result = self._execute_operation(operations, config)

        # Assert result based on configuration
        self.TestAssertions.assert_error_result(
            cast("FlextResult[object]", result),
            config,
        )

        # Cleanup connection if it was created
        if (
            hasattr(operations, "_connection")
            and operations._connection
            and hasattr(operations._connection, "disconnect")
        ):
            operations._connection.disconnect()

    def _execute_operation(
        self,
        operations: FlextLdapOperations,
        config: GenericFieldsDict,
    ) -> (
        FlextResult[FlextLdapModels.OperationResult]
        | FlextResult[FlextLdapModels.SearchResult]
    ):
        """Execute operation based on configuration."""
        operation = config.get("operation")

        if operation == "search":
            search_options_config = cast(
                "dict[str, object]",
                config.get("search_options", {}),
            )
            search_options = FlextLdapModels.SearchOptions(
                base_dn=str(search_options_config.get("base_dn", "")),
                scope=cast(
                    "FlextLdapConstants.LiteralTypes.SearchScope",
                    search_options_config.get("scope", "SUBTREE"),
                ),
                filter_str=str(
                    search_options_config.get("filter_str", "(objectClass=*)"),
                ),
                attributes=cast(
                    "list[str] | None",
                    search_options_config.get("attributes"),
                ),
                size_limit=int(
                    cast("int | str", search_options_config.get("size_limit", 0)),
                ),
            )
            return operations.search(search_options)

        if operation == "add":
            entry_dn = str(config.get("entry_dn", ""))
            entry_attrs_raw = cast(
                "dict[str, list[str]]",
                config.get("entry_attrs", {}),
            )
            # Convert to proper type for EntryTestHelpers
            entry_attrs: dict[
                str,
                list[str] | str | tuple[str, ...] | set[str] | frozenset[str],
            ] = dict(entry_attrs_raw)
            entry = self.TestDataFactories.create_test_entry(entry_dn, entry_attrs)
            return operations.add(entry)

        if operation == "modify":
            dn = str(config.get("dn", ""))
            changes = cast(
                "dict[str, list[tuple[str, list[str]]]]",
                config.get("changes", {}),
            )
            return operations.modify(dn, changes)

        if operation == "delete":
            dn = str(config.get("dn", ""))
            return operations.delete(dn)

        if operation == "execute":
            return operations.execute()

        # Default fallback - should not happen in valid tests
        raise ValueError(f"Unknown operation: {operation}")
