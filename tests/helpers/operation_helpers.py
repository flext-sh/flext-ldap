"""Helper methods for LDAP operation testing to reduce code duplication.

This module provides LDAP-specific helpers that extend flext_tests utilities.
Uses FlextRuntime, FlextTestsUtilities for maximum code reuse.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal

import pytest
from flext_core import FlextResult, FlextRuntime
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsUtilities

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.typings import LdapClientProtocol

from ..fixtures.constants import RFC
from .entry_helpers import EntryTestHelpers

# Union type for LDAP clients - accepts FlextLdap and protocol-compliant clients
LdapClientType = FlextLdap | LdapClientProtocol

# Union type for LDAP operations only (no connect method) - for FlextLdapOperations and similar
LdapOperationsType = FlextLdap | FlextLdapOperations | LdapClientProtocol

# Valid search scopes for validation
_VALID_SCOPES: frozenset[str] = frozenset({"BASE", "ONELEVEL", "SUBTREE"})
SearchScopeType = Literal["BASE", "ONELEVEL", "SUBTREE"]


def _validate_scope(scope: str) -> SearchScopeType:
    """Validate and return a typed search scope.

    Args:
        scope: Scope string to validate

    Returns:
        Validated scope as Literal type

    Raises:
        ValueError: If scope is not valid

    """
    if scope not in _VALID_SCOPES:
        msg = f"Invalid scope: {scope}. Must be one of {_VALID_SCOPES}"
        raise ValueError(msg)
    scope_map: dict[str, SearchScopeType] = {
        "BASE": "BASE",
        "ONELEVEL": "ONELEVEL",
        "SUBTREE": "SUBTREE",
    }
    return scope_map[scope]


class TestOperationHelpers:
    """Helper methods for LDAP operation testing to reduce duplication."""

    @staticmethod
    def assert_result_failure[T](
        result: FlextResult[T],
        *,
        expected_error: str | None = None,
    ) -> None:
        """Assert result is failure, common pattern.

        Uses centralized FlextTestsUtilities for consistency.

        Args:
            result: FlextResult to check
            expected_error: Optional expected error substring

        """
        FlextTestsUtilities.TestUtilities.assert_result_failure(result)
        if expected_error:
            # FlextResult.error can be None, so we need to check
            error_msg = result.error
            assert error_msg is not None, "Expected error message but got None"
            assert expected_error in error_msg, (
                f"Expected error containing '{expected_error}', got: {error_msg}"
            )

    @staticmethod
    def get_error_message[T](result: FlextResult[T]) -> str:
        """Get error message from result, raising if None.

        Args:
            result: FlextResult to get error from

        Returns:
            str: Error message (guaranteed non-None)

        Raises:
            AssertionError: If result is success or error is None

        """
        assert result.is_failure, "Expected failure result"
        error_msg = result.error
        assert error_msg is not None, "Expected error message but got None"
        return error_msg

    @staticmethod
    def assert_result_success[T](
        result: FlextResult[T],
        *,
        error_message: str | None = None,
    ) -> None:
        """Assert result is success, common pattern.

        Uses centralized FlextTestsUtilities for consistency.

        Args:
            result: FlextResult to check
            error_message: Optional custom error message

        """
        FlextTestsUtilities.TestUtilities.assert_result_success(result)
        # Custom error message handling if needed
        if error_message and not result.is_success:
            pytest.fail(f"{error_message}: {result.error}")

    @staticmethod
    def assert_result_success_and_unwrap[T](
        result: FlextResult[T],
        *,
        error_message: str | None = None,
    ) -> T:
        """Assert result is success and unwrap it.

        Args:
            result: FlextResult to unwrap
            error_message: Optional custom error message

        Returns:
            Unwrapped result value

        """
        TestOperationHelpers.assert_result_success(result, error_message=error_message)
        return result.unwrap()

    @staticmethod
    def unwrap_and_assert_not_none[T](
        result: FlextResult[T],
        *,
        error_message: str | None = None,
    ) -> T:
        """Unwrap result and assert it's not None.

        Args:
            result: FlextResult to unwrap
            error_message: Optional custom error message

        Returns:
            Unwrapped result value (guaranteed not None)

        """
        value = TestOperationHelpers.assert_result_success_and_unwrap(
            result,
            error_message=error_message,
        )
        assert value is not None, "Unwrapped value is None"
        return value

    @staticmethod
    def unwrap_sync_stats[T](
        result: FlextResult[T],
    ) -> T:
        """Unwrap sync service stats result.

        Args:
            result: Sync service result (accepts any FlextResult type)

        Returns:
            Unwrapped stats of type T

        """
        return TestOperationHelpers.assert_result_success_and_unwrap(result)

    @staticmethod
    def connect_with_skip_on_failure(
        client: LdapClientType,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Connect client and skip test on failure.

        Args:
            client: LDAP client implementing LdapClientProtocol
            connection_config: Connection configuration

        """
        connect_result = client.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

    @staticmethod
    def connect_and_assert_success(
        client: LdapClientType,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Connect client and assert success.

        Args:
            client: LDAP client implementing LdapClientProtocol
            connection_config: Connection configuration

        """
        connect_result = client.connect(connection_config)
        TestOperationHelpers.assert_result_success(
            connect_result,
            error_message="Connection failed",
        )

    @staticmethod
    def search_and_assert_success(
        client: LdapOperationsType,
        base_dn: str,
        *,
        filter_str: str = "(objectClass=*)",
        expected_min_count: int = 0,
        expected_max_count: int | None = None,
        scope: str = "SUBTREE",
        attributes: list[str] | None = None,
        size_limit: int = 0,
    ) -> FlextLdapModels.SearchResult:
        """Search and assert success.

        Args:
            client: LDAP client with search method
            base_dn: Base DN for search
            filter_str: LDAP filter string
            expected_min_count: Minimum number of entries expected
            expected_max_count: Maximum number of entries expected (optional)
            scope: Search scope
            attributes: Attributes to retrieve
            size_limit: Maximum number of entries to return

        Returns:
            SearchResult

        """
        search_options = FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=_validate_scope(scope),
            attributes=attributes,
            size_limit=size_limit,
        )

        search_result = client.search(search_options)
        TestOperationHelpers.assert_result_success(
            search_result,
            error_message="Search failed",
        )

        result = search_result.unwrap()
        assert len(result.entries) >= expected_min_count, (
            f"Expected at least {expected_min_count} entries, got {len(result.entries)}"
        )
        if expected_max_count is not None:
            assert len(result.entries) <= expected_max_count, (
                f"Expected at most {expected_max_count} entries, "
                f"got {len(result.entries)}"
            )
        return result

    @staticmethod
    def execute_and_assert_success(
        client: LdapClientType,
    ) -> FlextLdapModels.SearchResult:
        """Execute client and assert success.

        Args:
            client: LDAP client with execute method

        Returns:
            SearchResult

        """
        result: FlextResult[FlextLdapModels.SearchResult] = client.execute()
        return TestOperationHelpers.assert_result_success_and_unwrap(
            result,
            error_message="Execute failed",
        )

    @staticmethod
    def create_search_options(
        base_dn: str,
        *,
        filter_str: str = "(objectClass=*)",
        scope: str = "SUBTREE",
        attributes: list[str] | None = None,
    ) -> FlextLdapModels.SearchOptions:
        """Create SearchOptions with common defaults.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope
            attributes: Attributes to retrieve

        Returns:
            SearchOptions instance

        """
        return FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=_validate_scope(scope),
            attributes=attributes,
        )

    @staticmethod
    def create_inetorgperson_entry(
        cn_value: str,
        base_dn: str,
        *,
        sn: str | None = None,
        mail: str | None = None,
        use_uid: bool = False,
        additional_attrs: dict[str, object] | None = None,
        **extra_attributes: object,
    ) -> FlextLdifModels.Entry:
        """Create inetOrgPerson entry - COMMON PATTERN.

        Replaces repetitive inetOrgPerson entry creation across tests.
        Supports both cn-based and uid-based DNs.

        Args:
            cn_value: Common name value (or uid if use_uid=True)
            base_dn: Base DN for entry
            sn: Optional surname
            mail: Optional email
            use_uid: If True, creates uid-based DN (uid={cn_value},ou=people,{base_dn})
                     If False, creates cn-based DN (cn={cn_value},{base_dn})
            additional_attrs: Optional dictionary of additional attributes to merge
            **extra_attributes: Additional attributes as individual kwargs

        Returns:
            FlextLdifModels.Entry with inetOrgPerson objectClass

        Example:
            # CN-based entry
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testuser", "dc=example,dc=com", sn="User"
            )
            # UID-based entry
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testuser", "dc=example,dc=com", sn="User", use_uid=True
            )
            # With additional attributes
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testuser", "dc=example,dc=com",
                additional_attrs={"mail": ["test@example.com"]}
            )

        """
        if use_uid:
            dn = f"uid={cn_value},ou=people,{base_dn}"
            entry_attributes: dict[str, list[str]] = {
                "objectClass": [
                    "top",
                    "person",
                    "organizationalPerson",
                    "inetOrgPerson",
                ],
                "uid": [cn_value],
            }
            if sn:
                entry_attributes["sn"] = [sn]
        else:
            dn = f"cn={cn_value},{base_dn}"
            entry_attributes_cn: dict[str, list[str]] = {
                "cn": [cn_value],
                "objectClass": ["top", "person", "inetOrgPerson"],
                "sn": [sn or cn_value],
            }
            entry_attributes = entry_attributes_cn

        if mail:
            entry_attributes["mail"] = [mail]

        # Merge additional_attrs if provided
        if additional_attrs:
            for key, value in additional_attrs.items():
                if FlextRuntime.is_list_like(value):
                    entry_attributes[key] = [str(v) for v in value]
                else:
                    entry_attributes[key] = [str(value)]

        # Process individual extra attributes - convert dict[str, object] to dict[str, list[str]]
        extra_attrs_typed: dict[str, list[str]] = {
            key: (
                [str(item) for item in value]
                if FlextRuntime.is_list_like(value)
                else [str(value)]
            )
            for key, value in extra_attributes.items()
            if value is not None
        }
        entry_attributes.update(extra_attrs_typed)

        # entry_attributes is dict[str, list[str]] which is compatible with create_entry's type
        return EntryTestHelpers.create_entry(dn, entry_attributes)

    @staticmethod
    def create_group_entry(
        cn: str,
        base_dn: str,
        *,
        members: list[str] | None = None,
        **kwargs: object,
    ) -> FlextLdifModels.Entry:
        """Create group entry.

        Args:
            cn: Common name
            base_dn: Base DN
            members: List of member DNs
            **kwargs: Additional attributes

        Returns:
            Entry instance

        """
        dn = f"cn={cn},ou=groups,{base_dn}"
        attributes: dict[str, list[str]] = {
            "objectClass": ["top", "groupOfNames"],
            "cn": [cn],
        }

        if members:
            attributes["member"] = members

        for key, value in kwargs.items():
            if FlextRuntime.is_list_like(value):
                attributes[key] = [str(item) for item in value]
            else:
                attributes[key] = [str(value)]

        # attributes is dict[str, list[str]] which is compatible with create_entry's type
        return EntryTestHelpers.create_entry(dn, attributes)

    @staticmethod
    def create_entry_dict(
        cn_value: str,
        base_dn: str,
        *,
        sn: str | None = None,
        mail: str | None = None,
        **extra_attributes: object,
    ) -> dict[str, object]:
        """Create entry dictionary - COMMON PATTERN.

        Replaces repetitive entry dict creation across tests.

        Args:
            cn_value: Common name value
            base_dn: Base DN for entry
            sn: Optional surname
            mail: Optional email
            **extra_attributes: Additional attributes

        Returns:
            Dictionary with 'dn' and 'attributes' keys

        Example:
            entry_dict = TestOperationHelpers.create_entry_dict(
                "testuser", "dc=example,dc=com", sn="User"
            )

        """
        dn = f"cn={cn_value},{base_dn}"
        attributes: dict[str, list[str]] = {
            "cn": [cn_value],
            "objectClass": ["top", "person", "inetOrgPerson"],
            "sn": [sn or cn_value],
        }
        if mail:
            attributes["mail"] = [mail]
        for key, value in extra_attributes.items():
            if FlextRuntime.is_list_like(value):
                attributes[key] = [str(v) for v in value]
            else:
                attributes[key] = [str(value)]
        return {"dn": dn, "attributes": attributes}

    @staticmethod
    def add_entry_and_assert_success(
        client: LdapClientType,
        entry: FlextLdifModels.Entry,
        *,
        verify_operation_result: bool = False,
        cleanup_after: bool = True,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add entry and assert success.

        Args:
            client: LDAP client with add method
            entry: Entry to add
            verify_operation_result: Whether to verify operation result details
            cleanup_after: Whether to cleanup after add (default: True)

        Returns:
            OperationResult

        """
        # Cleanup before
        if entry.dn:
            EntryTestHelpers.cleanup_entry(client, str(entry.dn))

        result = client.add(entry)
        TestOperationHelpers.assert_result_success(
            result,
            error_message="Add operation failed",
        )

        if verify_operation_result:
            operation_result = result.unwrap()
            assert operation_result.success is True
            assert operation_result.entries_affected == 1

        # Cleanup after if requested
        if cleanup_after and entry.dn:
            EntryTestHelpers.cleanup_after_test(client, str(entry.dn))

        return result

    @staticmethod
    def add_then_delete_and_assert(
        client: LdapClientType,
        entry: FlextLdifModels.Entry,
    ) -> tuple[
        FlextResult[FlextLdapModels.OperationResult],
        FlextResult[FlextLdapModels.OperationResult],
    ]:
        """Add entry then delete and assert both succeed.

        Args:
            client: LDAP client with add and delete methods
            entry: Entry to add and delete

        Returns:
            Tuple of (add_result, delete_result)

        """
        add_result = TestOperationHelpers.add_entry_and_assert_success(
            client,
            entry,
            cleanup_after=False,
        )

        if not hasattr(client, "delete"):
            error_msg = "Client does not have delete method"
            raise AttributeError(error_msg)

        dn_str = str(entry.dn) if entry.dn else ""
        delete_result = client.delete(dn_str)
        TestOperationHelpers.assert_result_success(
            delete_result,
            error_message="Delete operation failed",
        )

        return (add_result, delete_result)

    @staticmethod
    def assert_operation_result_success(
        result: FlextResult[FlextLdapModels.OperationResult],
        *,
        expected_operation_type: str | None = None,
        expected_entries_affected: int = 1,
    ) -> FlextLdapModels.OperationResult:
        """Assert operation result is successful.

        Args:
            result: Operation result to check
            expected_operation_type: Expected operation type
            expected_entries_affected: Expected number of entries affected

        Returns:
            OperationResult

        """
        operation_result = TestOperationHelpers.assert_result_success_and_unwrap(
            result,
            error_message="Operation failed",
        )

        assert operation_result.success is True
        assert operation_result.entries_affected == expected_entries_affected

        if expected_operation_type:
            assert operation_result.operation_type == expected_operation_type

        return operation_result

    @staticmethod
    def execute_add_modify_delete_sequence(
        client: LdapClientType,
        entry: FlextLdifModels.Entry,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_delete: bool = True,
    ) -> dict[str, FlextResult[FlextLdapModels.OperationResult]]:
        """Execute add, modify, delete sequence.

        Args:
            client: LDAP client with add, modify, delete methods
            entry: Entry to add
            changes: Modification changes
            verify_delete: Whether to verify delete succeeded

        Returns:
            Dictionary with add, modify, delete results

        """
        # Add (don't cleanup after since we'll modify and delete)
        add_result = TestOperationHelpers.add_entry_and_assert_success(
            client,
            entry,
            cleanup_after=False,
        )

        # Modify
        if not hasattr(client, "modify"):
            error_msg = "Client does not have modify method"
            raise AttributeError(error_msg)

        dn_str = str(entry.dn) if entry.dn else ""
        modify_result = client.modify(dn_str, changes)
        TestOperationHelpers.assert_result_success(
            modify_result,
            error_message="Modify operation failed",
        )

        # Delete
        if not hasattr(client, "delete"):
            error_msg = "Client does not have delete method"
            raise AttributeError(error_msg)

        delete_result = client.delete(dn_str)
        if verify_delete:
            TestOperationHelpers.assert_result_success(
                delete_result,
                error_message="Delete operation failed",
            )

        return {
            "add": add_result,
            "modify": modify_result,
            "delete": delete_result,
        }

    @staticmethod
    def execute_crud_sequence(
        client: LdapClientType,
        entry: FlextLdifModels.Entry,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> dict[
        str,
        FlextResult[FlextLdapModels.OperationResult]
        | FlextResult[FlextLdapModels.SearchResult],
    ]:
        """Execute complete CRUD sequence (add, search, modify, delete).

        Args:
            client: LDAP client with add, modify, delete, search methods
            entry: Entry to add
            changes: Modification changes

        Returns:
            Dictionary with add, search, modify, delete results

        """
        # Add (don't cleanup after since we'll modify and delete)
        add_result = TestOperationHelpers.add_entry_and_assert_success(
            client,
            entry,
            cleanup_after=False,
        )

        # Search to verify entry was added
        search_result: FlextResult[FlextLdapModels.SearchResult] | None = None
        if hasattr(client, "search") and entry.dn:
            dn_str = str(entry.dn)
            # All clients now use SearchOptions - unified API
            search_options = FlextLdapModels.SearchOptions(
                base_dn=dn_str,
                filter_str="(objectClass=*)",
                scope="BASE",
            )
            search_result = client.search(search_options)

        # Modify
        if not hasattr(client, "modify"):
            error_msg = "Client does not have modify method"
            raise AttributeError(error_msg)

        dn_str = str(entry.dn) if entry.dn else ""
        modify_result = client.modify(dn_str, changes)
        TestOperationHelpers.assert_result_success(
            modify_result,
            error_message="Modify operation failed",
        )

        # Delete
        if not hasattr(client, "delete"):
            error_msg = "Client does not have delete method"
            raise AttributeError(error_msg)

        delete_result = client.delete(dn_str)
        TestOperationHelpers.assert_result_success(
            delete_result,
            error_message="Delete operation failed",
        )

        results: dict[
            str,
            FlextResult[FlextLdapModels.OperationResult]
            | FlextResult[FlextLdapModels.SearchResult],
        ] = {
            "add": add_result,
            "modify": modify_result,
            "delete": delete_result,
        }

        if search_result is not None:
            results["search"] = search_result

        return results

    @staticmethod
    def execute_operation_when_not_connected(
        client: LdapClientType,
        operation: str,
        **kwargs: object,
    ) -> None:
        """Execute operation when not connected and assert failure.

        Args:
            client: LDAP client
            operation: Operation name (search, add, modify, delete)
            **kwargs: Operation-specific arguments

        """
        expected_error = "Not connected"

        if operation == "search":
            if "search_options" not in kwargs:
                error_msg = "search_options required for search operation"
                raise ValueError(error_msg)
            search_options = kwargs["search_options"]
            if not isinstance(search_options, FlextLdapModels.SearchOptions):
                error_msg = "search_options must be FlextLdapModels.SearchOptions"
                raise TypeError(error_msg)
            TestOperationHelpers.assert_result_failure(
                client.search(search_options), expected_error=expected_error
            )
        elif operation == "add":
            if "entry" not in kwargs:
                error_msg = "entry required for add operation"
                raise ValueError(error_msg)
            entry = kwargs["entry"]
            if not isinstance(entry, FlextLdifModels.Entry):
                error_msg = "entry must be FlextLdifModels.Entry"
                raise TypeError(error_msg)
            TestOperationHelpers.assert_result_failure(
                client.add(entry), expected_error=expected_error
            )
        elif operation == "modify":
            if "dn" not in kwargs or "changes" not in kwargs:
                error_msg = "dn and changes required for modify operation"
                raise ValueError(error_msg)
            dn = kwargs["dn"]
            changes = kwargs["changes"]
            if not isinstance(dn, (str, FlextLdifModels.DistinguishedName)):
                error_msg = "dn must be str or FlextLdifModels.DistinguishedName"
                raise TypeError(error_msg)
            # Protocol requires exact dict type - use isinstance for type narrowing
            if not isinstance(changes, dict):
                error_msg = "changes must be dict"
                raise TypeError(error_msg)
            TestOperationHelpers.assert_result_failure(
                client.modify(dn, changes), expected_error=expected_error
            )
        elif operation == "delete":
            if "dn" not in kwargs:
                error_msg = "dn required for delete operation"
                raise ValueError(error_msg)
            dn = kwargs["dn"]
            if not isinstance(dn, (str, FlextLdifModels.DistinguishedName)):
                error_msg = "dn must be str or FlextLdifModels.DistinguishedName"
                raise TypeError(error_msg)
            TestOperationHelpers.assert_result_failure(
                client.delete(dn), expected_error=expected_error
            )
        else:
            error_msg = f"Unknown operation: {operation}"
            raise ValueError(error_msg)

    @staticmethod
    def assert_operation_result_unwrapped(
        result: FlextResult[FlextLdapModels.OperationResult],
        *,
        expected_operation_type: str | None = None,
        expected_entries_affected: int | None = None,
    ) -> FlextLdapModels.OperationResult:
        """Assert operation result and return unwrapped.

        Alias for assert_operation_result_success.

        Args:
            result: Operation result to assert
            expected_operation_type: Optional expected operation type
            expected_entries_affected: Optional expected entries affected count

        Returns:
            Unwrapped OperationResult

        """
        if expected_entries_affected is None:
            expected_entries_affected = 1

        return TestOperationHelpers.assert_operation_result_success(
            result,
            expected_operation_type=expected_operation_type,
            expected_entries_affected=expected_entries_affected,
        )

    @staticmethod
    def create_search_options_with_defaults(
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        scope: str | None = None,
        attributes: list[str] | None = None,
    ) -> FlextLdapModels.SearchOptions:
        """Create SearchOptions using constants - COMMON PATTERN.

        Uses RFC constants by default. Replaces repetitive SearchOptions creation.

        Args:
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            attributes: Attributes to retrieve (default: RFC.DEFAULT_ATTRIBUTES as list)

        Returns:
            FlextLdapModels.SearchOptions

        """
        if base_dn is None:
            base_dn = RFC.DEFAULT_BASE_DN
        if filter_str is None:
            filter_str = RFC.DEFAULT_FILTER
        if scope is None:
            scope = RFC.DEFAULT_SCOPE
        if attributes is None:
            attributes = list(RFC.DEFAULT_ATTRIBUTES)

        return FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=_validate_scope(scope),
            attributes=attributes,
        )
