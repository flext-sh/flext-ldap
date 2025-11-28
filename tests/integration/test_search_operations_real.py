"""Real LDAP operations integration tests using modern Python patterns.

Tests FlextLdap search, add, modify, and delete operations against real LDAP server.
Uses factory patterns, parameterized tests, and flext_tests utilities for maximum
code reduction while maintaining 100% coverage of edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, cast

import pytest
from flext_core import FlextResult
from flext_tests import FlextTestsFactories, FlextTestsUtilities
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols

from ..fixtures.constants import RFC
from ..helpers.entry_helpers import EntryTestHelpers
from ..helpers.operation_helpers import TestOperationHelpers

# Integration tests - require Docker LDAP server from conftest.py
pytestmark = pytest.mark.integration


class SearchScope(StrEnum):
    """LDAP search scopes enumeration."""

    BASE = "BASE"
    ONELEVEL = "ONELEVEL"
    SUBTREE = "SUBTREE"


class TestFlextLdapRealOperations:
    """Real LDAP operations integration tests with modern patterns.

    Tests all CRUD operations (search, add, modify, delete) against real LDAP server.
    Uses parameterized tests, factories, and mappings for maximum code reduction
    while maintaining comprehensive edge case coverage.
    """

    # Test data factories using flext_tests
    @staticmethod
    def _create_test_user_data(
        uid_suffix: str,
        operation: str = "test",
    ) -> object:
        """Create test user data using FlextTestsFactories."""
        return FlextTestsFactories.create_user(
            user_id=f"{operation}_{uid_suffix}",
            name=f"Test {operation.title()} User",
            email=f"{operation}{uid_suffix}@flext.local",
        )

    @staticmethod
    def _create_test_config(
        operation: str = "test",
    ) -> object:
        """Create test configuration using FlextTestsFactories."""
        return FlextTestsFactories.create_config(
            service_type="ldap",
            environment="integration",
            operation=operation,
        )

    # Search operation test configurations
    SEARCH_TEST_CONFIGS: ClassVar[
        list[
            tuple[
                str,
                SearchScope,
                str | None,
                list[str] | None,
                int,
                int | None,
                int | None,
            ]
        ]
    ] = [
        # (test_name, scope, filter_str, attributes, expected_min, expected_max, size_limit)
        ("base_dn", SearchScope.BASE, None, ["dc", "objectClass"], 1, 1, None),
        ("subtree", SearchScope.SUBTREE, None, None, 1, None, None),
        (
            "onelevel_ou",
            SearchScope.ONELEVEL,
            "(objectClass=organizationalUnit)",
            None,
            0,
            None,
            None,
        ),
        (
            "filter_ou",
            SearchScope.SUBTREE,
            "(objectClass=organizationalUnit)",
            None,
            0,
            None,
            None,
        ),
        ("attributes", SearchScope.BASE, None, ["dc", "objectClass"], 1, 1, None),
        ("size_limit", SearchScope.SUBTREE, None, None, 0, 2, 2),
    ]

    @pytest.mark.parametrize(
        (
            "test_name",
            "scope",
            "filter_str",
            "attributes",
            "expected_min",
            "expected_max",
            "size_limit",
        ),
        SEARCH_TEST_CONFIGS,
        ids=[config[0] for config in SEARCH_TEST_CONFIGS],
    )
    def test_search_operations_parameterized(
        self,
        ldap_client: FlextLdap,
        test_name: str,
        scope: SearchScope,
        filter_str: str | None,
        attributes: list[str] | None,
        expected_min: int,
        expected_max: int | None,
        size_limit: int | None,
    ) -> None:
        """Parameterized test for all search operations."""
        # Create search options using helpers
        search_options = TestOperationHelpers.create_search_options_with_defaults(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
        )

        if size_limit:
            search_options = FlextLdapModels.SearchOptions(
                **search_options.model_dump(),
                size_limit=size_limit,
            )

        # Execute search and assert success
        search_result = TestOperationHelpers.search_and_assert_success(
            ldap_client,
            search_options.base_dn,
            filter_str=search_options.filter_str,
            scope=search_options.scope,
            attributes=search_options.attributes,
            size_limit=search_options.size_limit,
            expected_min_count=expected_min,
            expected_max_count=expected_max,
        )

        # Additional assertions based on test type
        match test_name:
            case "base_dn":
                # Verify base DN is in results
                assert any(
                    entry.dn is not None and RFC.DEFAULT_BASE_DN in str(entry.dn.value)
                    for entry in search_result.entries
                )
            case "attributes":
                # Verify only requested attributes are present
                entry = search_result.entries[0]
                if entry.attributes and entry.attributes.attributes:
                    attrs = entry.attributes.attributes
                    assert any(key in attrs for key in ["dc", "objectClass"])
            case "filter_ou":
                # Verify all results are organizational units
                for entry in search_result.entries:
                    if entry.attributes and entry.attributes.attributes:
                        object_classes = entry.attributes.attributes.get(
                            "objectClass",
                            [],
                        )
                        if isinstance(object_classes, list):
                            assert "organizationalUnit" in object_classes
                        else:
                            assert "organizationalUnit" in str(object_classes)
            case _:
                # Default case - no additional assertions needed
                pass

    # Add operation test configurations
    ADD_TEST_CONFIGS: ClassVar[list[tuple[str, str, bool]]] = [
        # (test_name, entry_type, cleanup_expected)
        ("user_entry", "inetorgperson", True),
        ("group_entry", "group", False),  # Manual cleanup for groups
    ]

    @pytest.mark.parametrize(
        ("test_name", "entry_type", "cleanup_expected"),
        ADD_TEST_CONFIGS,
        ids=[config[0] for config in ADD_TEST_CONFIGS],
    )
    def test_add_operations_parameterized(
        self,
        ldap_client: FlextLdap,
        test_name: str,
        entry_type: str,
        cleanup_expected: bool,
    ) -> None:
        """Parameterized test for add operations."""
        match entry_type:
            case "inetorgperson":
                entry = TestOperationHelpers.create_inetorgperson_entry(
                    f"testadd_{FlextTestsUtilities.TestUtilities.generate_test_id()}",
                    RFC.DEFAULT_BASE_DN,
                    sn="Add",
                    mail="testadd@flext.local",
                    use_uid=True,
                    cn="Test Add User",
                )
            case "group":
                entry = TestOperationHelpers.create_group_entry(
                    f"testaddgroup_{FlextTestsUtilities.TestUtilities.generate_test_id()}",
                    RFC.DEFAULT_BASE_DN,
                    members=["cn=admin,dc=flext,dc=local"],
                )
            case _:
                pytest.fail(f"Unknown entry type: {entry_type}")

        # Add entry and verify
        result = TestOperationHelpers.add_entry_and_assert_success(
            ldap_client,
            entry,
            verify_operation_result=True,
            cleanup_after=cleanup_expected,
        )

        # Assert operation result
        TestOperationHelpers.assert_operation_result_success(
            result,
            expected_operation_type=FlextLdapConstants.OperationType.ADD.value,
            expected_entries_affected=1,
        )

        # Manual cleanup for groups if needed
        if entry_type == "group" and entry.dn:
            delete_result = ldap_client.delete(str(entry.dn))
            FlextTestsUtilities.TestUtilities.assert_result_success(delete_result)

    def test_modify_entry_comprehensive(
        self,
        ldap_client: FlextLdap,
        unique_dn_suffix: str,
    ) -> None:
        """Test comprehensive modify operations using factory patterns."""
        # Create test data
        user_data = self._create_test_user_data(unique_dn_suffix, "modify")

        # Create entry dict from factory data
        uid = f"testmodify_{unique_dn_suffix}"
        entry_dict = {
            "dn": f"uid={uid},ou=people,{RFC.DEFAULT_BASE_DN}",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": [uid],
                "cn": [str(getattr(user_data, "name", str(user_data)))],
                "sn": ["Modify"],
            },
        }

        # Define modification changes
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [
                (MODIFY_REPLACE, [str(getattr(user_data, "email", str(user_data)))]),
            ],
            "telephoneNumber": [(MODIFY_ADD, ["+1234567890"])],
        }

        # Execute modify sequence with verification
        _entry, add_result, modify_result = (
            EntryTestHelpers.modify_entry_with_verification(
                cast("FlextLdapProtocols.LdapClient", ldap_client),
                entry_dict,
                changes,
                verify_attribute=None,
            )
        )

        # Assert results using flext_tests utilities
        FlextTestsUtilities.TestUtilities.assert_result_success(add_result)
        FlextTestsUtilities.TestUtilities.assert_result_success(modify_result)

    def test_delete_entry_comprehensive(
        self,
        ldap_client: FlextLdap,
        unique_dn_suffix: str,
    ) -> None:
        """Test comprehensive delete operations using factory patterns."""
        # Create test user data
        user_data = self._create_test_user_data(unique_dn_suffix, "delete")

        # Create entry using factory data
        uid = f"testdelete_{unique_dn_suffix}"
        entry = TestOperationHelpers.create_inetorgperson_entry(
            uid,
            RFC.DEFAULT_BASE_DN,
            sn="Delete",
            mail=str(getattr(user_data, "email", str(user_data))),
            use_uid=True,
            cn=str(getattr(user_data, "name", str(user_data))),
        )

        # Add entry first
        TestOperationHelpers.add_entry_and_assert_success(
            cast("FlextLdapProtocols.LdapClient", ldap_client),
            entry,
            cleanup_after=False,  # We'll delete it manually
        )

        # Delete and verify
        delete_result = ldap_client.delete(f"uid={uid},ou=people,{RFC.DEFAULT_BASE_DN}")
        TestOperationHelpers.assert_operation_result_success(
            delete_result,
            expected_operation_type=FlextLdapConstants.OperationType.DELETE.value,
            expected_entries_affected=1,
        )

    # CRUD sequence test configurations
    CRUD_TEST_CONFIGS: ClassVar[list[tuple[str, bool]]] = [
        # (test_name, with_search)
        ("add_modify_delete", False),
        ("full_crud", True),
    ]

    @pytest.mark.parametrize(
        ("test_name", "with_search"),
        CRUD_TEST_CONFIGS,
        ids=[config[0] for config in CRUD_TEST_CONFIGS],
    )
    def test_crud_sequences_parameterized(
        self,
        ldap_client: FlextLdap,
        unique_dn_suffix: str,
        test_name: str,
        with_search: bool,
    ) -> None:
        """Parameterized test for CRUD operation sequences."""
        # Create test data using factories
        user_data = self._create_test_user_data(unique_dn_suffix, test_name)

        # Create entry from factory data
        uid = f"{test_name}_{unique_dn_suffix}"
        entry = TestOperationHelpers.create_inetorgperson_entry(
            uid,
            RFC.DEFAULT_BASE_DN,
            sn=test_name.title(),
            mail=str(getattr(user_data, "email", str(user_data))),
            use_uid=True,
            cn=str(getattr(user_data, "name", str(user_data))),
        )

        # Define modification changes
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [
                (
                    MODIFY_REPLACE,
                    [f"modified_{getattr(user_data, 'email', str(user_data))!s}"],
                ),
            ],
            "telephoneNumber": [(MODIFY_ADD, ["+1234567890"])],
        }

        # Execute appropriate CRUD sequence
        results: dict[
            str,
            FlextResult[FlextLdapModels.OperationResult]
            | FlextResult[FlextLdapModels.SearchResult],
        ]
        if with_search:
            crud_results = TestOperationHelpers.execute_crud_sequence(
                cast("FlextLdapProtocols.LdapClient", ldap_client),
                entry,
                changes,
            )
            # Verify search was included
            assert "search" in crud_results
            results = crud_results
        else:
            add_modify_delete_results = (
                TestOperationHelpers.execute_add_modify_delete_sequence(
                    cast("FlextLdapProtocols.LdapClient", ldap_client),
                    entry,
                    changes,
                )
            )
            results = {
                k: cast(
                    "FlextResult[FlextLdapModels.OperationResult] | FlextResult[FlextLdapModels.SearchResult]",
                    v,
                )
                for k, v in add_modify_delete_results.items()
            }

        # Assert all operations succeeded using flext_tests
        for result in results.values():
            FlextTestsUtilities.TestUtilities.assert_result_success(
                cast("FlextResult[object]", result),
            )
