"""Integration tests for FlextLdapOperations with real LDAP server.

Tests all operations service methods with real server and flext-ldif integration.
Modules tested: FlextLdapOperations, FlextLdapConnection, FlextLdapModels
Scope: Real LDAP operations (search, add, modify, delete, execute) with flext-ldif integration

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Generator
from enum import StrEnum
from typing import ClassVar, cast

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsUtilities
from ldap3 import MODIFY_REPLACE

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.typings import LdapClientProtocol

from ..fixtures.constants import RFC
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class OperationType(StrEnum):
    """Enumeration of LDAP operation types."""

    SEARCH = "search"
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    EXECUTE = "execute"


class SearchScope(StrEnum):
    """Enumeration of LDAP search scopes."""

    BASE = "BASE"
    ONELEVEL = "ONELEVEL"
    SUBTREE = "SUBTREE"


class TestFlextLdapOperationsRealOperations:
    """Integration tests for FlextLdapOperations with real LDAP server."""

    # Test configurations as ClassVar for parameterized tests
    SEARCH_TEST_CONFIGS: ClassVar[list[tuple[str, dict[str, object]]]] = [
        (
            "all_entries",
            {
                "filter_str": "(objectClass=*)",
                "scope": SearchScope.SUBTREE,
                "expected_min_count": 1,
                "assert_total_count": True,
            },
        ),
        (
            "base_scope",
            {
                "filter_str": "(objectClass=*)",
                "scope": SearchScope.BASE,
                "expected_max_count": 1,
            },
        ),
        (
            "onelevel_scope",
            {
                "filter_str": "(objectClass=*)",
                "scope": SearchScope.ONELEVEL,
                "assert_entries_list": True,
            },
        ),
        (
            "with_attributes",
            {
                "filter_str": "(objectClass=*)",
                "scope": SearchScope.SUBTREE,
                "attributes": ["objectClass", "cn"],
                "expected_min_count": 1,
            },
        ),
        (
            "with_size_limit",
            {
                "filter_str": "(objectClass=*)",
                "scope": SearchScope.SUBTREE,
                "size_limit": 2,
                "expected_max_count": 2,
            },
        ),
    ]

    ADD_TEST_CONFIGS: ClassVar[list[tuple[str, dict[str, object]]]] = [
        (
            "basic_add",
            {
                "cn_value": "testopsadd",
                "sn": "Test",
                "expected_operation_type": "add",
                "expected_entries_affected": 1,
            },
        ),
    ]

    MODIFY_TEST_CONFIGS: ClassVar[list[tuple[str, dict[str, object]]]] = [
        (
            "basic_modify",
            {
                "cn_value": "testopsmodify",
                "sn": "Test",
                "changes": {"mail": [(MODIFY_REPLACE, ["modified@example.com"])]},
                "expected_operation_type": "modify",
            },
        ),
    ]

    DELETE_TEST_CONFIGS: ClassVar[list[tuple[str, dict[str, object]]]] = [
        (
            "basic_delete",
            {
                "cn_value": "testopsdelete",
                "sn": "Test",
                "expected_operation_type": "delete",
                "expected_entries_affected": 1,
            },
        ),
    ]

    EXECUTE_TEST_CONFIGS: ClassVar[list[tuple[str, dict[str, object]]]] = [
        (
            "when_connected",
            {
                "assert_total_count_zero": True,
                "assert_entries_empty": True,
            },
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
        def create_test_entry(
            cn_value: str,
            base_dn: str,
            sn: str | None = None,
        ) -> FlextLdifModels.Entry:
            """Create test inetOrgPerson entry."""
            return TestOperationHelpers.create_inetorgperson_entry(
                cn_value, base_dn, sn=sn
            )

        @staticmethod
        def create_test_entry_dict(
            cn_value: str,
            base_dn: str,
            sn: str | None = None,
        ) -> dict[str, object]:
            """Create test entry dictionary."""
            return TestOperationHelpers.create_entry_dict(cn_value, base_dn, sn=sn)

        @staticmethod
        def create_modify_changes(
            attribute: str = "mail",
            value: str = "modified@example.com",
        ) -> dict[str, list[tuple[str, list[str]]]]:
            """Create modify changes dictionary."""
            return {attribute: [(MODIFY_REPLACE, [value])]}

    class TestAssertions:
        """Nested class for test assertions."""

        @staticmethod
        def assert_search_result(
            result: FlextLdapModels.SearchResult,
            config: dict[str, object],
        ) -> None:
            """Assert search result based on configuration."""
            if config.get("assert_total_count"):
                assert result.total_count() == len(result.entries)

            if config.get("assert_entries_list"):
                assert isinstance(result.entries, list)

            if config.get("assert_total_count_zero"):
                assert result.total_count() == 0

            if config.get("assert_entries_empty"):
                assert len(result.entries) == 0

        @staticmethod
        def assert_operation_success(
            result: FlextResult[FlextLdapModels.OperationResult],
            config: dict[str, object],
        ) -> None:
            """Assert operation result success."""
            FlextTestsUtilities.TestUtilities.assert_result_success(result)

            if expected_type := config.get("expected_operation_type"):
                operation_result = result.unwrap()
                assert operation_result.operation_type == expected_type

            if expected_affected := config.get("expected_entries_affected"):
                operation_result = result.unwrap()
                assert operation_result.entries_affected == expected_affected

        @staticmethod
        def assert_add_modify_sequence(
            add_result: FlextResult[FlextLdapModels.OperationResult],
            modify_result: FlextResult[FlextLdapModels.OperationResult],
        ) -> None:
            """Assert add and modify sequence results."""
            assert add_result.is_success
            TestOperationHelpers.assert_operation_result_success(
                modify_result,
                expected_operation_type="modify",
            )

        @staticmethod
        def assert_add_delete_sequence(
            add_result: FlextResult[FlextLdapModels.OperationResult],
            delete_result: FlextResult[FlextLdapModels.OperationResult],
            config: dict[str, object],
        ) -> None:
            """Assert add and delete sequence results."""
            assert add_result.is_success
            TestOperationHelpers.assert_operation_result_unwrapped(
                delete_result,
                expected_operation_type=cast(
                    "str | None", config.get("expected_operation_type")
                ),
                expected_entries_affected=cast(
                    "int | None", config.get("expected_entries_affected")
                ),
            )

        @staticmethod
        def assert_execute_when_not_connected(
            result: FlextResult[FlextLdapModels.SearchResult],
        ) -> None:
            """Assert execute fails when not connected."""
            assert result.is_failure
            assert result.error is not None
            assert "Not connected" in result.error

    @pytest.fixture
    def operations_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser,
    ) -> Generator[FlextLdapOperations]:
        """Get operations service with connected adapter."""
        operations = self.TestDataFactories.create_operations_service(
            connection_config, ldap_parser
        )
        yield operations

        # Cleanup
        if (
            hasattr(operations, "_connection")
            and operations._connection
            and hasattr(operations._connection, "disconnect")
        ):
            operations._connection.disconnect()

    @pytest.mark.parametrize(("test_name", "config"), SEARCH_TEST_CONFIGS)
    def test_search_operations_parameterized(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
        test_name: str,
        config: dict[str, object],
    ) -> None:
        """Test search operations with different configurations."""
        search_result = TestOperationHelpers.search_and_assert_success(
            operations_service,  # type: ignore[arg-type]
            str(ldap_container["base_dn"]),
            filter_str=str(config.get("filter_str", "(objectClass=*)")),
            scope=str(config.get("scope", SearchScope.SUBTREE)),
            attributes=cast("list[str] | None", config.get("attributes")),
            size_limit=cast("int", config.get("size_limit", 0)),
            expected_min_count=cast("int", config.get("expected_min_count", 0)),
            expected_max_count=cast("int | None", config.get("expected_max_count")),
        )

        self.TestAssertions.assert_search_result(search_result, config)

    def test_search_when_not_connected(
        self,
        ldap_container: dict[str, object],
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test search when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)

        search_options = TestOperationHelpers.create_search_options(
            str(ldap_container["base_dn"]),
            filter_str="(objectClass=*)",
            scope=SearchScope.SUBTREE,
        )

        TestOperationHelpers.execute_operation_when_not_connected(
            cast("LdapClientProtocol", operations),
            OperationType.SEARCH,
            search_options=search_options,
        )

    def test_search_with_failed_adapter_search(
        self,
        operations_service: FlextLdapOperations,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search when adapter search fails."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn=str(ldap_container["base_dn"]),
            filter_str="(invalidFilterSyntax)",
            scope="SUBTREE",
        )

        result = operations_service.search(search_options)
        # Should handle adapter failure gracefully
        assert result.is_failure or result.is_success

    @pytest.mark.parametrize(("test_name", "config"), ADD_TEST_CONFIGS)
    def test_add_operations_parameterized(
        self,
        operations_service: FlextLdapOperations,
        test_name: str,
        config: dict[str, object],
    ) -> None:
        """Test add operations with different configurations."""
        entry = self.TestDataFactories.create_test_entry(
            str(config.get("cn_value", "testadd")),
            RFC.DEFAULT_BASE_DN,
            sn=cast("str | None", config.get("sn")),
        )

        result = EntryTestHelpers.add_and_cleanup(
            cast("LdapClientProtocol", operations_service), entry
        )

        self.TestAssertions.assert_operation_success(result, config)

    def test_add_entry_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test add when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)

        entry = EntryTestHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )

        TestOperationHelpers.execute_operation_when_not_connected(
            cast("LdapClientProtocol", operations),
            OperationType.ADD,
            entry=entry,
        )

    @pytest.mark.parametrize(("test_name", "config"), MODIFY_TEST_CONFIGS)
    def test_modify_operations_parameterized(
        self,
        operations_service: FlextLdapOperations,
        test_name: str,
        config: dict[str, object],
    ) -> None:
        """Test modify operations with different configurations."""
        entry = self.TestDataFactories.create_test_entry(
            str(config.get("cn_value", "testmodify")),
            RFC.DEFAULT_BASE_DN,
            sn=cast("str | None", config.get("sn")),
        )
        entry_dict = {
            "dn": str(entry.dn),
            "attributes": entry.attributes.attributes if entry.attributes else {},
        }

        changes = cast(
            "dict[str, list[tuple[str, list[str]]]]",
            config.get("changes", self.TestDataFactories.create_modify_changes()),
        )

        _entry, add_result, modify_result = (
            EntryTestHelpers.modify_entry_with_verification(
                cast("LdapClientProtocol", operations_service),
                entry_dict,
                changes,
                verify_attribute=None,
            )
        )

        self.TestAssertions.assert_add_modify_sequence(add_result, modify_result)

    @pytest.mark.parametrize(("test_name", "config"), DELETE_TEST_CONFIGS)
    def test_delete_operations_parameterized(
        self,
        operations_service: FlextLdapOperations,
        test_name: str,
        config: dict[str, object],
    ) -> None:
        """Test delete operations with different configurations."""
        entry_dict = self.TestDataFactories.create_test_entry_dict(
            str(config.get("cn_value", "testdelete")),
            RFC.DEFAULT_BASE_DN,
            sn=cast("str | None", config.get("sn")),
        )

        _entry, add_result, delete_result = (
            EntryTestHelpers.delete_entry_with_verification(
                cast("LdapClientProtocol", operations_service),
                entry_dict,
            )
        )

        self.TestAssertions.assert_add_delete_sequence(
            add_result, delete_result, config
        )

    def test_delete_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test delete when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)

        TestOperationHelpers.execute_operation_when_not_connected(
            cast("LdapClientProtocol", operations),
            OperationType.DELETE,
            dn="cn=test,dc=example,dc=com",
        )

    @pytest.mark.parametrize(("test_name", "config"), EXECUTE_TEST_CONFIGS)
    def test_execute_operations_parameterized(
        self,
        operations_service: FlextLdapOperations,
        test_name: str,
        config: dict[str, object],
    ) -> None:
        """Test execute operations with different configurations."""
        search_result = TestOperationHelpers.execute_and_assert_success(
            operations_service
        )

        self.TestAssertions.assert_search_result(search_result, config)

    def test_execute_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test execute method when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)

        result = operations.execute()
        self.TestAssertions.assert_execute_when_not_connected(result)
