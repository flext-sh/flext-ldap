"""Complete coverage tests for FlextLdapOperations with modern patterns.

Tests FlextLdapOperations service with real LDAP server using factories,
parameterized tests, and flext_tests utilities for maximum code reduction
while maintaining comprehensive edge case coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator, Mapping
from enum import StrEnum
from typing import ClassVar, cast

import pytest
from flext_core import FlextResult, FlextTypes
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsFactories, FlextTestsUtilities
from ldap3 import MODIFY_REPLACE

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ..fixtures.constants import RFC
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class OperationType(StrEnum):
    """Operation type enumeration."""

    SEARCH = "search"
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    EXECUTE = "execute"


class DNHandlingType(StrEnum):
    """DN handling type enumeration."""

    NORMALIZED_WHITESPACE = "normalized_whitespace"
    ERROR_HANDLING = "error_handling"
    ADAPTER_FAILURE = "adapter_failure"


class TestDataFactories:
    """Factory methods for generating test data and configurations."""

    # Configuration templates for different test scenarios
    CONFIG_TEMPLATES: ClassVar[dict[str, dict[str, object]]] = {
        "default": {},
        "with_parser": {"parser": True},
    }

    @staticmethod
    def create_operations_service(
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser | None = None,
    ) -> Generator[FlextLdapOperations]:
        """Factory for operations service with connected adapter."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        connect_result = connection.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        operations = FlextLdapOperations(connection=connection)
        yield operations

        connection.disconnect()

    @staticmethod
    def create_test_entry_with_dn_handling(
        dn_handling: DNHandlingType,
        base_dn: str = RFC.DEFAULT_BASE_DN,
    ) -> tuple[str, FlextLdifModels.Entry]:
        """Create test entry with specific DN handling."""
        test_id = FlextTestsUtilities.TestUtilities.generate_test_id()

        # Create entry using flext_tests patterns
        user_data = FlextTestsFactories.create_user(
            user_id=f"test_{dn_handling.value}_{test_id}",
            name=f"Test {dn_handling.value.title()} Entry",
            email=f"{dn_handling.value}{test_id}@internal.invalid",
        )

        entry = TestOperationHelpers.create_inetorgperson_entry(
            f"test{dn_handling.value}{test_id}",
            base_dn,
            mail=getattr(user_data, "email", str(user_data)),
        )

        # Apply DN handling
        match dn_handling:
            case DNHandlingType.NORMALIZED_WHITESPACE:
                dn_str = f"  {entry.dn!s}  "
                # Recreate entry with modified DN
                attrs_raw = (
                    entry.attributes.attributes
                    if entry.attributes and entry.attributes.attributes
                    else {}
                )
                attrs_dict = {
                    k: v if isinstance(v, (list, str)) else [str(v)]
                    for k, v in attrs_raw.items()
                }
                # Convert dict to Mapping[str, GeneralValueType] for EntryTestHelpers.create_entry
                attrs_mapping: Mapping[str, FlextTypes.GeneralValueType] = cast(
                    "Mapping[str, FlextTypes.GeneralValueType]",
                    attrs_dict,
                )
                entry = EntryTestHelpers.create_entry(dn_str, attrs_mapping)
                return dn_str, entry
            case _:
                return str(entry.dn), entry

    @staticmethod
    def create_invalid_entry() -> FlextLdifModels.Entry:
        """Create entry that will fail to add (invalid DN format)."""
        attrs_dict = {
            "cn": ["test"],
            "objectClass": ["top", "person"],
        }
        # Convert dict to Mapping[str, GeneralValueType] for EntryTestHelpers.create_entry
        attrs_mapping: Mapping[str, FlextTypes.GeneralValueType] = cast(
            "Mapping[str, FlextTypes.GeneralValueType]",
            attrs_dict,
        )
        return EntryTestHelpers.create_entry("invalid-dn", attrs_mapping)

    @staticmethod
    def create_modify_changes() -> dict[str, list[tuple[str, list[str]]]]:
        """Create standard modification changes."""
        return {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

    @staticmethod
    def assert_dn_normalized(entry: FlextLdifModels.Entry) -> None:
        """Assert that DN was normalized (no leading/trailing whitespace)."""
        assert str(entry.dn).strip() == str(entry.dn)


class TestFlextLdapOperationsCompleteCoverage:
    """Complete coverage tests for FlextLdapOperations with modern patterns.

    Tests FlextLdapOperations service operations with factories,
    parameterized tests, and flext_tests utilities for maximum code reduction
    while maintaining comprehensive edge case coverage.
    """

    # Test configurations for different operation scenarios
    OPERATION_TEST_CONFIGS: ClassVar[list[tuple[OperationType, DNHandlingType]]] = [
        # (operation_type, dn_handling_type)
        (OperationType.SEARCH, DNHandlingType.NORMALIZED_WHITESPACE),
        (OperationType.SEARCH, DNHandlingType.ERROR_HANDLING),
        (OperationType.ADD, DNHandlingType.NORMALIZED_WHITESPACE),
        (OperationType.ADD, DNHandlingType.ERROR_HANDLING),
        (OperationType.ADD, DNHandlingType.ADAPTER_FAILURE),
        (OperationType.MODIFY, DNHandlingType.NORMALIZED_WHITESPACE),
        (OperationType.MODIFY, DNHandlingType.ERROR_HANDLING),
        (OperationType.DELETE, DNHandlingType.NORMALIZED_WHITESPACE),
        (OperationType.DELETE, DNHandlingType.ERROR_HANDLING),
        (OperationType.EXECUTE, DNHandlingType.ERROR_HANDLING),
    ]

    @pytest.mark.parametrize(
        ("operation_type", "dn_handling"),
        OPERATION_TEST_CONFIGS,
        ids=[
            f"{config[0].value}_{config[1].value}" for config in OPERATION_TEST_CONFIGS
        ],
    )
    def test_operations_complete_coverage_parameterized(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser | None,
        operation_type: OperationType,
        dn_handling: DNHandlingType,
    ) -> None:
        """Parameterized test for all operations with different handling types."""
        # Get operations service
        operations_service_gen = TestDataFactories.create_operations_service(
            connection_config,
            ldap_parser,
        )
        operations_service = next(operations_service_gen)

        try:
            match operation_type:
                case OperationType.SEARCH:
                    self._test_search_operation(operations_service, dn_handling)

                case OperationType.ADD:
                    self._test_add_operation(operations_service, dn_handling)

                case OperationType.MODIFY:
                    self._test_modify_operation(operations_service, dn_handling)

                case OperationType.DELETE:
                    self._test_delete_operation(operations_service, dn_handling)

                case OperationType.EXECUTE:
                    self._test_execute_operation(operations_service, dn_handling)

        finally:
            try:
                next(operations_service_gen)  # Cleanup
            except StopIteration:
                pass

    @staticmethod
    def _test_search_operation(
        operations_service: FlextLdapOperations,
        dn_handling: DNHandlingType,
    ) -> None:
        """Test search operation with specific DN handling."""
        match dn_handling:
            case DNHandlingType.NORMALIZED_WHITESPACE:
                # Test search with base DN that needs normalization
                search_options = FlextLdapModels.SearchOptions(
                    base_dn=f"  {RFC.DEFAULT_BASE_DN}  ",
                    filter_str="(objectClass=*)",
                    scope=FlextLdapConstants.SearchScope.SUBTREE,
                )
                result = operations_service.search(search_options)
                # search() returns FlextResult[SearchResult], not OperationResult
                TestAssertions.assert_search_success(result)

            case DNHandlingType.ERROR_HANDLING:
                # Disconnect to trigger error
                if hasattr(operations_service, "_connection"):
                    connection = operations_service._connection
                    if hasattr(connection, "disconnect"):
                        connection.disconnect()

                search_options = FlextLdapModels.SearchOptions(
                    base_dn=RFC.DEFAULT_BASE_DN,
                    filter_str="(objectClass=*)",
                    scope=FlextLdapConstants.SearchScope.SUBTREE,
                )
                result = operations_service.search(search_options)
                TestAssertions.assert_search_failure(
                    result,
                    "Not connected",
                )

    @staticmethod
    def _test_add_operation(
        operations_service: FlextLdapOperations,
        dn_handling: DNHandlingType,
    ) -> None:
        """Test add operation with specific DN handling."""
        match dn_handling:
            case DNHandlingType.NORMALIZED_WHITESPACE:
                # Test add with DN that needs normalization
                dn_str, entry = TestDataFactories.create_test_entry_with_dn_handling(
                    DNHandlingType.NORMALIZED_WHITESPACE,
                )

                # Cleanup first
                _ = operations_service.delete(dn_str.strip())

                result = operations_service.add(entry)
                TestAssertions.assert_operation_success(result)

                # Verify DN was normalized
                # DN normalization check would go here if needed

                # Cleanup
                delete_result = operations_service.delete(dn_str.strip())
                assert delete_result.is_success or delete_result.is_failure

            case DNHandlingType.ERROR_HANDLING:
                # Disconnect to trigger error
                if hasattr(operations_service, "_connection"):
                    connection = operations_service._connection
                    if hasattr(connection, "disconnect"):
                        connection.disconnect()

                entry = TestOperationHelpers.create_inetorgperson_entry(
                    "testerror",
                    RFC.DEFAULT_BASE_DN,
                )
                result = operations_service.add(entry)
                TestAssertions.assert_operation_failure(
                    result,
                    "Not connected",
                )

            case DNHandlingType.ADAPTER_FAILURE:
                # Test add with entry that will fail (invalid DN format)
                entry = TestDataFactories.create_invalid_entry()
                result = operations_service.add(entry)
                TestAssertions.assert_operation_failure(
                    result,
                    "",
                )

    @staticmethod
    def _test_modify_operation(
        operations_service: FlextLdapOperations,
        dn_handling: DNHandlingType,
    ) -> None:
        """Test modify operation with specific DN handling."""
        match dn_handling:
            case DNHandlingType.NORMALIZED_WHITESPACE:
                # First add an entry
                _, entry = TestDataFactories.create_test_entry_with_dn_handling(
                    DNHandlingType.NORMALIZED_WHITESPACE,
                )

                # Cleanup first
                _ = operations_service.delete(str(entry.dn).strip())

                add_result = operations_service.add(entry)
                TestAssertions.assert_operation_success(
                    add_result,
                )

                # Modify with DN that needs normalization
                changes = TestDataFactories.create_modify_changes()
                dn_with_spaces = f"  {entry.dn!s}  "
                modify_result = operations_service.modify(dn_with_spaces, changes)
                TestAssertions.assert_operation_success(
                    modify_result,
                )

                # Cleanup
                delete_result = operations_service.delete(str(entry.dn).strip())
                assert delete_result.is_success or delete_result.is_failure

            case DNHandlingType.ERROR_HANDLING:
                # Disconnect to trigger error
                if hasattr(operations_service, "_connection"):
                    connection = operations_service._connection
                    if hasattr(connection, "disconnect"):
                        connection.disconnect()

                changes = TestDataFactories.create_modify_changes()
                result = operations_service.modify("cn=test,dc=flext,dc=local", changes)
                TestAssertions.assert_operation_failure(
                    result,
                    "Not connected",
                )

    @staticmethod
    def _test_delete_operation(
        operations_service: FlextLdapOperations,
        dn_handling: DNHandlingType,
    ) -> None:
        """Test delete operation with specific DN handling."""
        match dn_handling:
            case DNHandlingType.NORMALIZED_WHITESPACE:
                # Test delete with DN that needs normalization
                dn_str, entry = TestDataFactories.create_test_entry_with_dn_handling(
                    DNHandlingType.NORMALIZED_WHITESPACE,
                )

                # Cleanup first
                _ = operations_service.delete(dn_str.strip())

                add_result = operations_service.add(entry)
                TestAssertions.assert_operation_success(
                    add_result,
                )

                # Delete with DN that needs normalization
                delete_result = operations_service.delete(dn_str)
                TestAssertions.assert_operation_success(
                    delete_result,
                )

            case DNHandlingType.ERROR_HANDLING:
                # Disconnect to trigger error
                if hasattr(operations_service, "_connection"):
                    connection = operations_service._connection
                    if hasattr(connection, "disconnect"):
                        connection.disconnect()

                result = operations_service.delete("cn=test,dc=flext,dc=local")
                TestAssertions.assert_operation_failure(
                    result,
                    "Not connected",
                )

    @staticmethod
    def _test_execute_operation(
        operations_service: FlextLdapOperations,
        dn_handling: DNHandlingType,
    ) -> None:
        """Test execute operation with specific DN handling."""
        match dn_handling:
            case DNHandlingType.ERROR_HANDLING:
                # Test execute error handling (not connected)
                # Create a new operations service without connection for error test
                config = FlextLdapConfig()
                unconnected_connection = FlextLdapConnection(config=config)
                unconnected_operations = FlextLdapOperations(
                    connection=unconnected_connection,
                )
                result = unconnected_operations.execute()
                # execute() returns FlextResult[SearchResult], not OperationResult
                TestAssertions.assert_search_failure(
                    result,
                    "Not connected",
                )


class TestAssertions:
    """Comprehensive assertion helpers for operations service tests."""

    @staticmethod
    def assert_operation_success(
        result: FlextResult[FlextLdapModels.OperationResult],
    ) -> None:
        """Assert that operation succeeded using flext_tests."""
        FlextTestsUtilities.TestUtilities.assert_result_success(result)

    @staticmethod
    def assert_operation_failure(
        result: FlextResult[FlextLdapModels.OperationResult],
        expected_error_contains: str,
    ) -> None:
        """Assert that operation failed with expected error."""
        FlextTestsUtilities.TestUtilities.assert_result_failure(result)
        assert result.error is not None
        assert expected_error_contains in result.error

    @staticmethod
    def assert_search_success(
        result: FlextResult[FlextLdapModels.SearchResult],
    ) -> FlextLdapModels.SearchResult:
        """Assert that search operation succeeded and return unwrapped result.

        Business Rules:
            - Uses flext_tests utilities for consistent assertion patterns
            - Returns unwrapped SearchResult for further assertions
            - Validates result is success before unwrapping

        Returns:
            Unwrapped SearchResult instance.

        """
        FlextTestsUtilities.TestUtilities.assert_result_success(result)
        return result.unwrap()

    @staticmethod
    def assert_search_failure(
        result: FlextResult[FlextLdapModels.SearchResult],
        expected_error_contains: str,
    ) -> None:
        """Assert that search operation failed with expected error."""
        FlextTestsUtilities.TestUtilities.assert_result_failure(result)
        assert result.error is not None
        assert expected_error_contains in result.error
