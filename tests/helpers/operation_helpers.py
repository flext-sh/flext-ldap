"""Helper methods for LDAP operation testing to reduce code duplication.

This module provides LDAP-specific helpers that extend flext_tests utilities.
Uses FlextRuntime, FlextTestsUtilities for maximum code reuse.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

import pytest
from flext_core import FlextResult, FlextRuntime
from flext_core.protocols import FlextProtocols as p
from flext_core.typings import FlextTypes as t
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsUtilities

from flext_ldap import FlextLdap
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities as u

from ..fixtures.constants import RFC
from ..fixtures.typing import GenericFieldsDict
from .test_helpers import FlextLdapTestHelpers

# Union type for LDAP clients - accepts FlextLdap and protocol-compliant clients
LdapClientType = FlextLdap | FlextLdapProtocols.LdapService.LdapClientProtocol

# Union type for LDAP operations only (no connect method) - for FlextLdapOperations and similar
LdapOperationsType = (
    FlextLdap | FlextLdapOperations | FlextLdapProtocols.LdapService.LdapClientProtocol
)

# Valid search scopes for validation - reuse production StrEnum

_VALID_SCOPES: frozenset[str] = frozenset({
    FlextLdapConstants.SearchScope.BASE.value,
    FlextLdapConstants.SearchScope.ONELEVEL.value,
    FlextLdapConstants.SearchScope.SUBTREE.value,
})
# Reuse production Literal type
SearchScopeType = FlextLdapConstants.LiteralTypes.SearchScopeLiteral


def _validate_scope(
    scope: str | FlextLdapConstants.SearchScope,
) -> FlextLdapConstants.SearchScope:
    """Validate and return a SearchScope StrEnum.

    Uses u.Enum.parse for unified enum parsing.

    Args:
        scope: Scope string or StrEnum to validate

    Returns:
        Validated scope as SearchScope StrEnum

    Raises:
        ValueError: If scope is not valid

    """
    # If already a StrEnum, return it
    if isinstance(scope, FlextLdapConstants.SearchScope):
        return scope

    # Use u.Enum.parse for unified enum parsing
    parse_result = u.Enum.parse(
        FlextLdapConstants.SearchScope,
        scope,
    )
    if parse_result.is_success:
        return parse_result.value

    # If parsing failed, raise ValueError with helpful message
    msg = f"Invalid scope: {scope}. Must be one of {_VALID_SCOPES}"
    raise ValueError(msg)


class TestOperationHelpers:
    """Helper methods for LDAP operation testing to reduce duplication."""

    @staticmethod
    def _ensure_entry_has_dn(entry: FlextLdifModels.Entry) -> None:
        """Ensure entry has DN for protocol compatibility.

        Args:
            entry: Entry to validate

        Raises:
            ValueError: If entry.dn is None

        """
        if entry.dn is None:
            error_msg = "Entry must have a DN to add"
            raise ValueError(error_msg)

    @staticmethod
    def _ensure_entry_has_attributes(entry: FlextLdifModels.Entry) -> None:
        """Ensure entry has attributes for protocol compatibility.

        Args:
            entry: Entry to validate

        Raises:
            ValueError: If entry.attributes is None

        """
        if entry.attributes is None:
            error_msg = "Entry must have attributes to add"
            raise ValueError(error_msg)

    @staticmethod
    def _ensure_entry_protocol_compatible(entry: FlextLdifModels.Entry) -> None:
        """Ensure entry is compatible with EntryProtocol.

        Args:
            entry: Entry to validate

        Raises:
            ValueError: If entry.dn or entry.attributes is None

        """
        TestOperationHelpers._ensure_entry_has_dn(entry)
        TestOperationHelpers._ensure_entry_has_attributes(entry)

    @staticmethod
    def _get_entry_for_protocol(
        entry: FlextLdifModels.Entry,
    ) -> FlextLdapProtocols.LdapEntry.EntryProtocol:
        """Get entry compatible with EntryProtocol after validation.

        Args:
            entry: Entry that has been validated via _ensure_entry_protocol_compatible

        Returns:
            Entry compatible with EntryProtocol

        """
        # After _ensure_entry_protocol_compatible, entry.dn and entry.attributes are guaranteed non-None
        # Entry is structurally compatible with EntryProtocol
        # Use cast to satisfy type checker while maintaining runtime compatibility
        return cast("FlextLdapProtocols.LdapEntry.EntryProtocol", entry)

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
            client: LDAP client implementing FlextLdapProtocols.LdapService.LdapClientProtocol
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
            client: LDAP client implementing FlextLdapProtocols.LdapService.LdapClientProtocol
            connection_config: Connection configuration

        """
        connect_result = client.connect(connection_config)
        # Type narrowing: ensure we have FlextResult, not just ResultProtocol
        if isinstance(connect_result, FlextResult):
            TestOperationHelpers.assert_result_success(
                connect_result,
                error_message="Connection failed",
            )
        # Convert protocol result to FlextResult if needed
        elif connect_result.is_success:
            TestOperationHelpers.assert_result_success(
                FlextResult[bool].ok(connect_result.unwrap()),
                error_message="Connection failed",
            )
        else:
            TestOperationHelpers.assert_result_success(
                FlextResult[bool].fail(str(connect_result.error)),
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
        scope: str = FlextLdapConstants.SearchScope.SUBTREE.value,
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
        validated_scope = _validate_scope(scope)
        search_options = FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=validated_scope.value,  # Convert StrEnum to str for SearchOptions
            attributes=attributes,
            size_limit=size_limit,
        )

        # SearchOptions is structurally compatible with SearchOptionsProtocol
        search_result_raw = client.search(search_options)
        search_result: FlextResult[FlextLdapModels.SearchResult] = (
            FlextLdapTestHelpers._ensure_flext_result(search_result_raw)
        )
        TestOperationHelpers.assert_result_success(
            search_result,
            error_message="Search failed",
        )
        result = search_result.unwrap()
        # SearchResult.unwrap() always returns SearchResult model, no conversion needed
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
        execute_result_raw = client.execute()
        execute_result: FlextResult[FlextLdapModels.SearchResult] = (
            FlextLdapTestHelpers._ensure_flext_result(execute_result_raw)
        )
        return TestOperationHelpers.assert_result_success_and_unwrap(
            execute_result,
            error_message="Execute failed",
        )

    @staticmethod
    def create_search_options(
        base_dn: str,
        *,
        filter_str: str = "(objectClass=*)",
        scope: str = FlextLdapConstants.SearchScope.SUBTREE.value,
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
            scope=_validate_scope(scope).value,  # Convert StrEnum to str
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
        additional_attrs: GenericFieldsDict | None = None,
        **extra_attributes: t.GeneralValueType,
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

            def process_additional_attr(
                key: str, value: object
            ) -> tuple[str, list[str]]:
                """Process additional attribute value."""
                value_typed: t.GeneralValueType = cast("t.GeneralValueType", value)
                if FlextRuntime.is_list_like(value_typed):
                    return (key, [str(v) for v in value_typed])
                return (key, [str(value_typed)])

            processed_attrs = u.process(
                additional_attrs,
                processor=process_additional_attr,
                on_error="skip",
            )
            if processed_attrs.is_success:
                entry_attributes.update(
                    dict(cast("list[tuple[str, list[str]]]", processed_attrs.value))
                )

        # Process individual extra attributes - convert dict[str, object] to dict[str, list[str]]
        def process_extra_attr(
            key: str, extra_value: object
        ) -> tuple[str, list[str]] | None:
            """Process extra attribute value."""
            if extra_value is None:
                return None
            # Type narrowing: cast object to GeneralValueType for FlextRuntime methods
            extra_value_typed: t.GeneralValueType = cast(
                "t.GeneralValueType", extra_value
            )
            if FlextRuntime.is_list_like(extra_value_typed):
                return (key, [str(v) for v in extra_value_typed])
            return (key, [str(extra_value_typed)])

        processed_extra = u.process(
            extra_attributes,
            processor=process_extra_attr,
            on_error="skip",
        )
        extra_attrs_typed = dict(
            cast(
                "list[tuple[str, list[str]]]",
                processed_extra.value if processed_extra.is_success else [],
            )
        )
        entry_attributes.update(extra_attrs_typed)

        # entry_attributes is dict[str, list[str]] which is compatible with create_entry's type
        return FlextLdapTestHelpers.create_entry(dn, entry_attributes)

    @staticmethod
    def create_group_entry(
        cn: str,
        base_dn: str,
        *,
        members: list[str] | None = None,
        **kwargs: t.GeneralValueType,
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

        def process_kwarg(key: str, value: object) -> tuple[str, list[str]]:
            """Process kwargs attribute value."""
            value_typed: t.GeneralValueType = cast("t.GeneralValueType", value)
            if FlextRuntime.is_list_like(value_typed):
                return (key, [str(item) for item in value_typed])
            return (key, [str(value_typed)])

        processed_kwargs = u.process(
            kwargs,
            processor=process_kwarg,
            on_error="skip",
        )
        if processed_kwargs.is_success:
            attributes.update(
                dict(cast("list[tuple[str, list[str]]]", processed_kwargs.value))
            )

        # attributes is dict[str, list[str]] which is compatible with create_entry's type
        return FlextLdapTestHelpers.create_entry(dn, attributes)

    @staticmethod
    def create_entry_dict(
        cn_value: str,
        base_dn: str,
        *,
        sn: str | None = None,
        mail: str | None = None,
        **extra_attributes: t.GeneralValueType,
    ) -> GenericFieldsDict:
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

        def process_extra_attr_value(key: str, value: object) -> tuple[str, list[str]]:
            """Process extra attribute value."""
            value_typed: t.GeneralValueType = cast("t.GeneralValueType", value)
            if FlextRuntime.is_list_like(value_typed):
                return (key, [str(v) for v in value_typed])
            return (key, [str(value_typed)])

        processed_extra_attrs = u.process(
            extra_attributes,
            processor=process_extra_attr_value,
            on_error="skip",
        )
        if processed_extra_attrs.is_success:
            attributes.update(
                dict(cast("list[tuple[str, list[str]]]", processed_extra_attrs.value))
            )
        # TypedDict with total=False allows extra keys via __extra_items__
        # Return dict[str, object] for flexible test data
        return {
            "dn": dn,
            "attributes": attributes,
        }

    @staticmethod
    def add_entry_and_assert_success(
        client: LdapOperationsType,
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
            FlextLdapTestHelpers.cleanup_entry(client, str(entry.dn))

        # Ensure entry.dn is not None for protocol compatibility
        TestOperationHelpers._ensure_entry_has_dn(entry)
        # Type narrowing: client is LdapOperationsType
        # FlextLdap and FlextLdapOperations accept Entry directly
        # Protocol clients accept EntryProtocol (Entry is structurally compatible)
        if isinstance(client, (FlextLdap, FlextLdapOperations)):
            add_result_raw = client.add(entry)
        else:
            # For protocol clients, Entry is structurally compatible with EntryProtocol
            # entry.dn is guaranteed to be not None by _ensure_entry_has_dn
            # Type narrowing: Entry with non-None dn satisfies EntryProtocol
            # Use cast to satisfy type checker while maintaining runtime compatibility
            entry_for_protocol = cast(
                "FlextLdapProtocols.LdapEntry.EntryProtocol",
                entry,
            )
            add_result_raw = client.add(entry_for_protocol)  # type: ignore[assignment]  # Protocol result is compatible with FlextResult
        result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(add_result_raw)
        )
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
            FlextLdapTestHelpers.cleanup_after_test(client, str(entry.dn))

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
        delete_result_raw = client.delete(dn_str)
        delete_result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(delete_result_raw)
        )
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
        modify_result_raw = client.modify(dn_str, changes)
        modify_result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(modify_result_raw)
        )
        TestOperationHelpers.assert_result_success(
            modify_result,
            error_message="Modify operation failed",
        )

        # Delete
        if not hasattr(client, "delete"):
            error_msg = "Client does not have delete method"
            raise AttributeError(error_msg)

        delete_result_raw = client.delete(dn_str)
        delete_result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(delete_result_raw)
        )
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
        search_result_optional: FlextResult[FlextLdapModels.SearchResult] | None = None
        if hasattr(client, "search") and entry.dn:
            dn_str = str(entry.dn)
            # All clients now use SearchOptions - unified API
            search_options = FlextLdapModels.SearchOptions(
                base_dn=dn_str,
                filter_str="(objectClass=*)",
                scope=FlextLdapConstants.SearchScope.BASE.value,  # Convert StrEnum to str
            )
            # SearchOptions is structurally compatible with SearchOptionsProtocol
            # Protocol expects settable attributes, but SearchOptions is frozen (read-only)
            # Runtime compatibility is guaranteed via structural typing
            search_result_raw = client.search(search_options)
            search_result_optional = FlextLdapTestHelpers._ensure_flext_result(
                search_result_raw,
            )

        # Modify
        if not hasattr(client, "modify"):
            error_msg = "Client does not have modify method"
            raise AttributeError(error_msg)

        dn_str = str(entry.dn) if entry.dn else ""
        modify_result_raw = client.modify(dn_str, changes)
        modify_result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(modify_result_raw)
        )
        TestOperationHelpers.assert_result_success(
            modify_result,
            error_message="Modify operation failed",
        )

        # Delete
        if not hasattr(client, "delete"):
            error_msg = "Client does not have delete method"
            raise AttributeError(error_msg)

        delete_result_raw = client.delete(dn_str)
        delete_result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(delete_result_raw)
        )
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

        if search_result_optional is not None:
            results["search"] = search_result_optional

        return results

    @staticmethod
    def _execute_search_when_not_connected(
        client: LdapClientType,
        search_options: FlextLdapModels.SearchOptions,
        expected_error: str,
    ) -> None:
        """Execute search operation when not connected and assert failure."""
        # SearchOptions is structurally compatible with SearchOptionsProtocol
        search_result_raw = client.search(search_options)
        search_result: FlextResult[FlextLdapModels.SearchResult] = (
            FlextLdapTestHelpers._ensure_flext_result(search_result_raw)
        )
        TestOperationHelpers.assert_result_failure(
            search_result,
            expected_error=expected_error,
        )

    @staticmethod
    def _execute_add_when_not_connected(
        client: LdapClientType,
        entry: FlextLdifModels.Entry,
        expected_error: str,
    ) -> None:
        """Execute add operation when not connected and assert failure."""
        TestOperationHelpers._ensure_entry_protocol_compatible(entry)
        # Use Entry directly for FlextLdap/FlextLdapOperations, EntryProtocol for protocol clients
        # Result may be FlextResult or ResultProtocol depending on client type
        # Use object type to accept both FlextResult and ResultProtocol variants
        if isinstance(client, (FlextLdap, FlextLdapOperations)):
            add_result_raw: object = client.add(entry)
        else:
            entry_protocol = TestOperationHelpers._get_entry_for_protocol(entry)
            add_result_raw = client.add(entry_protocol)
        # Convert protocol result to FlextResult if needed
        add_result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(
                cast(
                    "FlextResult[FlextLdapModels.OperationResult] | p.ResultProtocol[FlextLdapModels.OperationResult] | p.ResultProtocol[object]",
                    add_result_raw,
                ),
            )
        )
        TestOperationHelpers.assert_result_failure(
            add_result,
            expected_error=expected_error,
        )

    @staticmethod
    def _convert_changes_to_modify_format(
        changes: dict[str, t.GeneralValueType],
    ) -> FlextLdapTypes.Ldap.ModifyChanges:
        """Convert dict changes to ModifyChanges format."""

        def process_change(
            key: str, value_raw: object
        ) -> tuple[str, list[tuple[str, list[str]]] | None] | None:
            """Process change value."""
            if value_raw is None:
                return None
            value: t.GeneralValueType = cast("t.GeneralValueType", value_raw)
            if isinstance(value, list) and all(
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], str)
                and isinstance(item[1], list)
                and all(isinstance(v, str) for v in item[1])
                for item in value
            ):
                typed_value: list[tuple[str, list[str]]] = []
                for tup_item in value:
                    if isinstance(tup_item, tuple) and len(tup_item) == 2:
                        tup_0: str = str(tup_item[0])
                        tup_1: object = tup_item[1]
                        if isinstance(tup_1, (list, tuple)):
                            tup_1_list: list[str] = [str(v) for v in tup_1]
                        else:
                            tup_1_list = [str(tup_1)]
                        typed_value.append((tup_0, tup_1_list))
                return (key, typed_value)
            if isinstance(value, (list, tuple)):
                value_list: list[str] = [str(v) for v in value]
                return (key, [("MODIFY_REPLACE", value_list)])
            return (key, [("MODIFY_REPLACE", [str(value)])])

        processed_changes = u.process(
            changes,
            processor=process_change,
            on_error="skip",
        )
        modify_changes: FlextLdapTypes.Ldap.ModifyChanges = dict(
            cast(
                "list[tuple[str, list[tuple[str, list[str]]] | None]]",
                processed_changes.value if processed_changes.is_success else [],
            )
        )
        return modify_changes

    @staticmethod
    def _execute_modify_when_not_connected(
        client: LdapClientType,
        dn: str,
        changes: dict[str, t.GeneralValueType],
        expected_error: str,
    ) -> None:
        """Execute modify operation when not connected and assert failure."""
        modify_changes = TestOperationHelpers._convert_changes_to_modify_format(changes)
        modify_result_raw = client.modify(dn, modify_changes)
        modify_result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(modify_result_raw)
        )
        TestOperationHelpers.assert_result_failure(
            modify_result,
            expected_error=expected_error,
        )

    @staticmethod
    def _execute_delete_when_not_connected(
        client: LdapClientType,
        dn: str,
        expected_error: str,
    ) -> None:
        """Execute delete operation when not connected and assert failure."""
        delete_result_raw = client.delete(dn)
        delete_result: FlextResult[FlextLdapModels.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(delete_result_raw)
        )
        TestOperationHelpers.assert_result_failure(
            delete_result,
            expected_error=expected_error,
        )

    @staticmethod
    def execute_operation_when_not_connected(
        client: LdapClientType,
        operation: str,
        **kwargs: t.GeneralValueType,
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
            search_options_raw = kwargs["search_options"]
            if not isinstance(search_options_raw, FlextLdapModels.SearchOptions):
                error_msg = "search_options must be FlextLdapModels.SearchOptions"
                raise TypeError(error_msg)
            # Type narrowing: search_options_raw is SearchOptions after isinstance check
            TestOperationHelpers._execute_search_when_not_connected(
                client,
                search_options_raw,
                expected_error,
            )
        elif operation == "add":
            if "entry" not in kwargs:
                error_msg = "entry required for add operation"
                raise ValueError(error_msg)
            entry_raw = kwargs["entry"]
            if not isinstance(entry_raw, FlextLdifModels.Entry):
                error_msg = "entry must be FlextLdifModels.Entry"
                raise TypeError(error_msg)
            # Type narrowing: entry_raw is Entry after isinstance check
            TestOperationHelpers._execute_add_when_not_connected(
                client,
                entry_raw,
                expected_error,
            )
        elif operation == "modify":
            if "dn" not in kwargs or "changes" not in kwargs:
                error_msg = "dn and changes required for modify operation"
                raise ValueError(error_msg)
            dn = kwargs["dn"]
            changes = kwargs["changes"]
            # DistinguishedName is a type alias for str, so we only need to check for str
            if not isinstance(dn, str):
                error_msg = "dn must be str"
                raise TypeError(error_msg)
            if not isinstance(changes, dict):
                error_msg = "changes must be dict"
                raise TypeError(error_msg)
            # Type narrowing: dn is str (DistinguishedName is a type alias for str)
            modify_dn_str: str = dn
            TestOperationHelpers._execute_modify_when_not_connected(
                client,
                modify_dn_str,
                changes,
                expected_error,
            )
        elif operation == "delete":
            if "dn" not in kwargs:
                error_msg = "dn required for delete operation"
                raise ValueError(error_msg)
            delete_dn = kwargs["dn"]
            # DistinguishedName is a type alias for str, so we only need to check for str
            if not isinstance(delete_dn, str):
                error_msg = "dn must be str"
                raise TypeError(error_msg)
            # Type narrowing: delete_dn is str
            delete_dn_str: str = delete_dn
            TestOperationHelpers._execute_delete_when_not_connected(
                client,
                delete_dn_str,
                expected_error,
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
            scope=_validate_scope(scope).value,  # Convert StrEnum to str
            attributes=attributes,
        )
