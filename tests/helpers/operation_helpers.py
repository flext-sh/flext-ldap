"""Helper methods for LDAP operation testing to reduce code duplication.

This module provides LDAP-specific helpers that extend flext_tests utilities.
Uses FlextRuntime, FlextTestsUtilities for maximum code reuse.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TypeAlias, TypeVar

import pytest
from flext_tests import u

from flext_ldap import (
    FlextLdap,
    FlextLdapModels,
    FlextLdapOperations,
    p,
    r,
)

from .. import constants as c_mod
from ..typings import GenericFieldsDict, t

LDAP_MODIFY_ADD: int = 0
LDAP_MODIFY_DELETE: int = 1
LDAP_MODIFY_REPLACE: int = 2
c = c_mod.c
m = FlextLdapModels
T = TypeVar("T")
OperationResultType: TypeAlias = r[FlextLdapModels.Ldap.OperationResult]
SearchResultType: TypeAlias = r[FlextLdapModels.Ldap.SearchResult]
LdapEntry: TypeAlias = FlextLdapModels.Ldif.Entry
LdapClientType = FlextLdap | p.Ldap.LdapClient
LdapOperationsType = FlextLdap | FlextLdapOperations | p.Ldap.LdapClient
_VALID_SCOPES: frozenset[str] = frozenset({
    c.Ldap.SearchScope.BASE.value,
    c.Ldap.SearchScope.ONELEVEL.value,
    c.Ldap.SearchScope.SUBTREE.value,
})
SearchScopeType = c.Ldap.SearchScope


class _LdapEntryProtocolAdapter:
    dn: str | p.Ldap.DN | None
    attributes: Mapping[str, Sequence[str]] | p.Ldap.Attributes | None
    metadata: t.ConfigMap | None

    def __init__(
        self,
        dn: str,
        attributes: Mapping[str, Sequence[str]],
        *,
        metadata: t.ConfigMap | None = None,
    ) -> None:
        self.dn = dn
        self.attributes = attributes
        self.metadata = metadata


def _ldap_entry_to_protocol_adapter(entry: LdapEntry) -> p.Ldap.LdapEntry:
    dn_str = str(entry.dn) if entry.dn is not None else ""
    attrs: Mapping[str, Sequence[str]] = (
        entry.attributes.attributes
        if entry.attributes is not None and hasattr(entry.attributes, "attributes")
        else {}
    )
    return _LdapEntryProtocolAdapter(dn=dn_str, attributes=attrs)


def _validate_scope(scope: str | c.Ldap.SearchScope) -> c.Ldap.SearchScope:
    """Validate and return a SearchScope StrEnum.

    Uses u.parse for unified enum parsing via test utilities.

    Args:
        scope: Scope string or StrEnum to validate

    Returns:
        Validated scope as SearchScope StrEnum

    Raises:
        ValueError: If scope is not valid

    """
    if isinstance(scope, c.Ldap.SearchScope):
        return scope
    parse_result = u.parse(c.Ldap.SearchScope, scope)
    if parse_result.is_success:
        return parse_result.value
    msg = f"Invalid scope: {scope}. Must be one of {_VALID_SCOPES}"
    raise ValueError(msg)


class TestsFlextLdapOperationHelpers:
    """Helper methods for LDAP operation testing to reduce code duplication.

    Architecture: Single class per module following FLEXT patterns.
    Uses flext_tests utilities and protocols for maximum code reuse.
    All methods are static for easy use in tests.
    """

    @staticmethod
    def _ensure_flext_result(result: r[T] | object) -> r[T]:
        """Ensure result is r, converting from protocol if needed.

        Args:
            result: Result that may be r or protocol result

        Returns:
            r[T] instance

        """
        if isinstance(result, r):
            return result
        assert isinstance(result, r), f"Expected r[T], got {type(result)}"
        return result

    @staticmethod
    def _assert_result_success(
        result: r[T], error_msg: str = "Operation failed"
    ) -> r[T]:
        """Assert result is success and return it.

        Args:
            result: Result to check
            error_msg: Error message if failure

        Returns:
            Result if success

        Raises:
            AssertionError: If result is failure

        """
        if not result.is_success:
            raise AssertionError(error_msg)
        return result

    @staticmethod
    def _ensure_entry_has_dn(entry: LdapEntry) -> None:
        """Ensure entry has DN for protocol compatibility.

        Args:
            entry: LdapEntry to validate

        Raises:
            ValueError: If entry.dn is None

        """
        if not hasattr(entry, "dn") or entry.dn is None:
            error_msg = "Entry must have a DN to add"
            raise ValueError(error_msg)

    @staticmethod
    def _ensure_entry_has_attributes(entry: LdapEntry) -> None:
        """Ensure entry has attributes for protocol compatibility.

        Args:
            entry: LdapEntry to validate

        Raises:
            ValueError: If entry.attributes is None

        """
        if not hasattr(entry, "attributes") or entry.attributes is None:
            error_msg = "Entry must have attributes to add"
            raise ValueError(error_msg)

    @staticmethod
    def _ensure_entry_protocol_compatible(entry: LdapEntry) -> None:
        """Ensure entry is compatible with Entry.

        Args:
            entry: LdapEntry to validate

        Raises:
            ValueError: If entry.dn or entry.attributes is None

        """
        TestsFlextLdapOperationHelpers._ensure_entry_has_dn(entry)
        TestsFlextLdapOperationHelpers._ensure_entry_has_attributes(entry)

    @staticmethod
    def _validate_search_options_type(
        search_options_raw: Mapping[str, str | int | bool] | None,
    ) -> m.Ldap.SearchOptions:
        """Validate and return SearchOptions type.

        Args:
            search_options_raw: Raw search options to validate

        Returns:
            Validated SearchOptions instance

        Raises:
            TypeError: If search_options_raw is not SearchOptions

        """
        if not isinstance(search_options_raw, m.Ldap.SearchOptions):
            error_msg = "search_options must be m.Ldap.SearchOptions"
            raise TypeError(error_msg)
        return search_options_raw

    @staticmethod
    def _get_entry_for_protocol(entry: LdapEntry) -> LdapEntry:
        """Get entry compatible with LdapEntry after validation.

        Args:
            entry: LdapEntry that has been validated via _ensure_entry_protocol_compatible

        Returns:
            Entry (m.Ldif.Entry) compatible with LdapEntry

        """
        if not (hasattr(entry, "dn") and hasattr(entry, "attributes")):
            raise TypeError(f"Entry must have dn and attributes, got {type(entry)}")
        return entry

    @staticmethod
    def connect_with_skip_on_failure(
        client: LdapClientType, connection_config: m.Ldap.ConnectionConfig
    ) -> None:
        """Connect client and skip test on failure.

        Args:
            client: LDAP client implementing p.Ldap.LdapClient
            connection_config: Connection configuration

        """
        connect_result = client.connect(connection_config)
        if connect_result.is_failure:
            pytest.fail(
                f"Failed to connect: {connect_result.error}. This test requires a running LDAP container."
            )

    @staticmethod
    def connect_and_assert_success(
        client: LdapClientType, connection_config: m.Ldap.ConnectionConfig
    ) -> None:
        """Connect client and assert success.

        Args:
            client: LDAP client implementing p.Ldap.LdapClient
            connection_config: Connection configuration

        """
        connect_result = client.connect(connection_config)
        if isinstance(connect_result, r):
            u.Tests.Result.assert_result_success(connect_result)
        elif connect_result.is_success:
            u.Tests.Result.assert_result_success(r[bool].ok(connect_result.value))
        else:
            result_as_r = r[bool].fail(str(connect_result.error))
            u.Tests.Result.assert_result_success(result_as_r)

    @staticmethod
    def search_and_assert_success(
        client: LdapOperationsType,
        base_dn: str,
        *,
        filter_str: str = "(objectClass=*)",
        expected_min_count: int = 0,
        expected_max_count: int | None = None,
        scope: str = c.Ldap.SearchScope.SUBTREE.value,
        attributes: list[str] | None = None,
        size_limit: int = 0,
    ) -> m.Ldap.SearchResult:
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
        search_options = m.Ldap.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=validated_scope.value,
            attributes=attributes,
            size_limit=size_limit,
        )
        if isinstance(client, (FlextLdap, FlextLdapOperations)):
            search_result_raw: r[m.Ldap.SearchResult] | r[p.Ldap.SearchResult] = (
                client.search(search_options)
            )
        else:
            if not hasattr(search_options, "base_dn"):
                raise TypeError(
                    f"SearchOptions must have base_dn, got {type(search_options)}"
                )
            search_result_protocol = client.search(search_options)
            search_result_raw = search_result_protocol
        if not isinstance(search_result_raw, r):
            search_result_raw = TestsFlextLdapOperationHelpers._ensure_flext_result(
                search_result_raw
            )
        assert search_result_raw.is_success, "Search failed"
        result_untyped = search_result_raw.value
        if not isinstance(result_untyped, m.Ldap.SearchResult):
            raise TypeError(f"Expected m.Ldap.SearchResult, got {type(result_untyped)}")
        result: m.Ldap.SearchResult = result_untyped
        assert len(result.entries) >= expected_min_count, (
            f"Expected at least {expected_min_count} entries, got {len(result.entries)}"
        )
        if expected_max_count is not None:
            assert len(result.entries) <= expected_max_count, (
                f"Expected at most {expected_max_count} entries, got {len(result.entries)}"
            )
        return result

    @staticmethod
    def execute_and_assert_success(client: LdapClientType) -> m.Ldap.SearchResult:
        """Execute client and assert success.

        Args:
            client: LDAP client with execute method

        Returns:
            SearchResult

        """
        execute_result_raw = client.execute()
        execute_result_typed: SearchResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(execute_result_raw)
        )
        assert execute_result_typed.is_success
        return execute_result_typed.value

    @staticmethod
    def create_search_options(
        base_dn: str,
        *,
        filter_str: str = "(objectClass=*)",
        scope: str = c.Ldap.SearchScope.SUBTREE.value,
        attributes: list[str] | None = None,
    ) -> m.Ldap.SearchOptions:
        """Create SearchOptions with common defaults.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope
            attributes: Attributes to retrieve

        Returns:
            SearchOptions instance

        """
        return m.Ldap.SearchOptions(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=_validate_scope(scope).value,
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
        **extra_attributes: t.Scalar,
    ) -> FlextLdapModels.Ldif.Entry:
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
            m.Ldif.Entry with inetOrgPerson objectClass

        Example:
            # CN-based entry
            entry = TestsFlextLdapOperationHelpers.create_inetorgperson_entry(
                "testuser", "dc=example,dc=com", sn="User"
            )
            # UID-based entry
            entry = TestsFlextLdapOperationHelpers.create_inetorgperson_entry(
                "testuser", "dc=example,dc=com", sn="User", use_uid=True
            )
            # With additional attributes
            entry = TestsFlextLdapOperationHelpers.create_inetorgperson_entry(
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
        if "cn" in extra_attributes:
            cn_extra = extra_attributes.pop("cn")
            if isinstance(cn_extra, list):
                entry_attributes["cn"] = [str(v) for v in cn_extra]
            else:
                entry_attributes["cn"] = [str(cn_extra)]
        if additional_attrs:
            normalized_additional: dict[str, list[str]] = {}
            for key, value in additional_attrs.items():
                if isinstance(value, list):
                    normalized_additional[key] = [str(v) for v in value]
                else:
                    normalized_additional[key] = [str(value)]
            entry_attributes.update(normalized_additional)
        if extra_attributes:
            normalized_extra: dict[str, list[str]] = {}
            for key, value in extra_attributes.items():
                if isinstance(value, list):
                    normalized_extra[key] = [str(v) for v in value]
                else:
                    normalized_extra[key] = [str(value)]
            entry_attributes.update(normalized_extra)
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(attributes=entry_attributes),
        )

    @staticmethod
    def create_group_entry(
        cn: str,
        base_dn: str,
        *,
        members: list[str] | None = None,
        **kwargs: t.Scalar,
    ) -> FlextLdapModels.Ldif.Entry:
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
        normalized_kwargs: dict[str, list[str]] = {}
        for key, value in kwargs.items():
            if isinstance(value, list):
                normalized_kwargs[key] = [str(v) for v in value]
            else:
                normalized_kwargs[key] = [str(value)]
        attributes.update(normalized_kwargs)
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn), attributes=m.Ldif.Attributes(attributes=attributes)
        )

    @staticmethod
    def create_entry_dict(
        cn_value: str,
        base_dn: str,
        *,
        sn: str | None = None,
        mail: str | None = None,
        **extra_attributes: t.Scalar,
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
            entry_dict = TestsFlextLdapOperationHelpers.create_entry_dict(
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
        normalized_extra_attrs: dict[str, list[str]] = {}
        for key, value in extra_attributes.items():
            if isinstance(value, list):
                normalized_extra_attrs[key] = [str(v) for v in value]
            else:
                normalized_extra_attrs[key] = [str(value)]
        attributes.update(normalized_extra_attrs)
        result: GenericFieldsDict = {"dn": dn, "attributes": attributes}
        return result

    @staticmethod
    def add_entry_and_assert_success(
        client: LdapOperationsType,
        entry: LdapEntry,
        *,
        verify_operation_result: bool = False,
        cleanup_after: bool = True,
    ) -> OperationResultType:
        """Add entry and assert success.

        Args:
            client: LDAP client with add method
            entry: LdapEntry to add
            verify_operation_result: Whether to verify operation result details
            cleanup_after: Whether to cleanup after add (default: True)

        Returns:
            OperationResult

        """
        if entry.dn and hasattr(client, "delete"):
            client.delete(str(entry.dn))
        TestsFlextLdapOperationHelpers._ensure_entry_has_dn(entry)
        if isinstance(client, (FlextLdap, FlextLdapOperations)):
            add_result_raw = client.add(entry)
        else:
            entry_for_protocol = _ldap_entry_to_protocol_adapter(entry)
            add_result_raw_protocol = client.add(entry_for_protocol)
            add_result_raw = TestsFlextLdapOperationHelpers._ensure_flext_result(
                add_result_raw_protocol
            )
        add_result_typed: OperationResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(add_result_raw)
        )
        result: OperationResultType = (
            TestsFlextLdapOperationHelpers._assert_result_success(
                add_result_typed, error_msg="Add operation failed"
            )
        )
        if verify_operation_result:
            operation_result = result.value
            assert operation_result.is_success is True
            assert operation_result.entries_affected == 1
        if cleanup_after and entry.dn and hasattr(client, "delete"):
            client.delete(str(entry.dn))
        return result

    @staticmethod
    def add_then_delete_and_assert(
        client: LdapClientType, entry: LdapEntry
    ) -> tuple[OperationResultType, OperationResultType]:
        """Add entry then delete and assert both succeed.

        Args:
            client: LDAP client with add and delete methods
            entry: LdapEntry to add and delete

        Returns:
            Tuple of (add_result, delete_result)

        """
        add_result = TestsFlextLdapOperationHelpers.add_entry_and_assert_success(
            client, entry, cleanup_after=False
        )
        if not hasattr(client, "delete"):
            error_msg = "Client does not have delete method"
            raise AttributeError(error_msg)
        dn_str = str(entry.dn) if entry.dn else ""
        delete_result_raw = client.delete(dn_str)
        delete_result: OperationResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(delete_result_raw)
        )
        u.Tests.Result.assert_result_success(delete_result)
        return (add_result, delete_result)

    @staticmethod
    def assert_operation_result_success(
        result: OperationResultType,
        *,
        expected_operation_type: str | None = None,
        expected_entries_affected: int = 1,
    ) -> m.Ldap.OperationResult:
        """Assert operation result is successful.

        Args:
            result: Operation result to check
            expected_operation_type: Expected operation type
            expected_entries_affected: Expected number of entries affected

        Returns:
            OperationResult

        """
        assert result.is_success
        operation_result: m.Ldap.OperationResult = result.value
        assert operation_result.is_success is True
        assert operation_result.entries_affected == expected_entries_affected
        if expected_operation_type:
            assert operation_result.operation_type == expected_operation_type
        return operation_result

    @staticmethod
    def execute_add_modify_delete_sequence(
        client: LdapClientType,
        entry: LdapEntry,
        changes: Mapping[str, list[tuple[str, list[str]]]],
        *,
        verify_delete: bool = True,
    ) -> dict[str, OperationResultType]:
        """Execute add, modify, delete sequence.

        Args:
            client: LDAP client with add, modify, delete methods
            entry: LdapEntry to add
            changes: Modification changes
            verify_delete: Whether to verify delete succeeded

        Returns:
            Dictionary with add, modify, delete results

        """
        add_result = TestsFlextLdapOperationHelpers.add_entry_and_assert_success(
            client, entry, cleanup_after=False
        )
        if not hasattr(client, "modify"):
            error_msg = "Client does not have modify method"
            raise AttributeError(error_msg)
        dn_str = str(entry.dn) if entry.dn else ""
        modify_changes = (
            TestsFlextLdapOperationHelpers._convert_changes_to_modify_format(changes)
        )
        modify_result_raw = client.modify(dn_str, modify_changes)
        modify_result_typed: OperationResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(modify_result_raw)
        )
        modify_result: OperationResultType = (
            TestsFlextLdapOperationHelpers._assert_result_success(
                modify_result_typed, error_msg="Modify operation failed"
            )
        )
        if not hasattr(client, "delete"):
            error_msg = "Client does not have delete method"
            raise AttributeError(error_msg)
        delete_result_raw = client.delete(dn_str)
        delete_result: OperationResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(delete_result_raw)
        )
        if verify_delete:
            TestsFlextLdapOperationHelpers._assert_result_success(
                delete_result, error_msg="Delete operation failed"
            )
        return {"add": add_result, "modify": modify_result, "delete": delete_result}

    @staticmethod
    def execute_crud_sequence(
        client: LdapClientType,
        entry: LdapEntry,
        changes: Mapping[str, list[tuple[str, list[str]]]],
    ) -> dict[str, OperationResultType | SearchResultType]:
        """Execute complete CRUD sequence (add, search, modify, delete).

        Args:
            client: LDAP client with add, modify, delete, search methods
            entry: LdapEntry to add
            changes: Modification changes

        Returns:
            Dictionary with add, search, modify, delete results

        """
        add_result = TestsFlextLdapOperationHelpers.add_entry_and_assert_success(
            client, entry, cleanup_after=False
        )
        search_result_optional: SearchResultType | None = None
        if hasattr(client, "search") and entry.dn:
            dn_str = str(entry.dn)
            search_options = TestsFlextLdapOperationHelpers.create_search_options(
                dn_str,
                filter_str=c.RFC.DEFAULT_FILTER,
                scope=c.Ldap.SearchScope.BASE.value,
            )
            if isinstance(client, (FlextLdap, FlextLdapOperations)):
                search_result_raw = client.search(search_options)
            else:
                search_result_protocol = client.search(search_options)
                search_result_raw = TestsFlextLdapOperationHelpers._ensure_flext_result(
                    search_result_protocol
                )
            search_result_optional = (
                TestsFlextLdapOperationHelpers._ensure_flext_result(search_result_raw)
            )
        if not hasattr(client, "modify"):
            error_msg = "Client does not have modify method"
            raise AttributeError(error_msg)
        dn_str = str(entry.dn) if entry.dn else ""
        modify_changes = (
            TestsFlextLdapOperationHelpers._convert_changes_to_modify_format(changes)
        )
        modify_result_raw = client.modify(dn_str, modify_changes)
        modify_result_typed: OperationResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(modify_result_raw)
        )
        modify_result: OperationResultType = (
            TestsFlextLdapOperationHelpers._assert_result_success(
                modify_result_typed, error_msg="Modify operation failed"
            )
        )
        if not hasattr(client, "delete"):
            error_msg = "Client does not have delete method"
            raise AttributeError(error_msg)
        delete_result_raw = client.delete(dn_str)
        delete_result_typed: OperationResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(delete_result_raw)
        )
        delete_result: OperationResultType = (
            TestsFlextLdapOperationHelpers._assert_result_success(
                delete_result_typed, error_msg="Delete operation failed"
            )
        )
        results: dict[str, OperationResultType | SearchResultType] = {
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
        search_options: m.Ldap.SearchOptions,
        expected_error: str,
    ) -> None:
        """Execute search operation when not connected and assert failure."""
        if isinstance(client, (FlextLdap, FlextLdapOperations)):
            search_result_raw = client.search(search_options)
        else:
            search_result_protocol = client.search(search_options)
            search_result_raw = TestsFlextLdapOperationHelpers._ensure_flext_result(
                search_result_protocol
            )
        search_result: SearchResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(search_result_raw)
        )
        u.Tests.Result.assert_result_failure_with_error(
            search_result, expected_error=expected_error
        )

    @staticmethod
    def _execute_add_when_not_connected(
        client: LdapClientType, entry: LdapEntry, expected_error: str
    ) -> None:
        """Execute add operation when not connected and assert failure."""
        TestsFlextLdapOperationHelpers._ensure_entry_protocol_compatible(entry)
        add_result_raw: r[m.Ldap.Entry] | None
        if isinstance(client, (FlextLdap, FlextLdapOperations)):
            add_result_raw = client.add(entry)
        else:
            entry_for_protocol = _ldap_entry_to_protocol_adapter(entry)
            add_result_raw = client.add(entry_for_protocol)
        add_result_typed: r[p.Ldap.OperationResult] = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(add_result_raw)
        )
        u.Tests.Result.assert_result_failure_with_error(
            add_result_typed, expected_error=expected_error
        )

    @staticmethod
    def _convert_changes_to_modify_format(
        changes: Mapping[str, object | list[tuple[str | int, list[str]]]],
    ) -> t.Ldap.Operation.Changes:
        """Convert dict changes to ldap3 format (int operation codes)."""
        op_str_to_int: dict[str, int] = {
            "MODIFY_ADD": LDAP_MODIFY_ADD,
            "MODIFY_DELETE": LDAP_MODIFY_DELETE,
            "MODIFY_REPLACE": LDAP_MODIFY_REPLACE,
        }
        result: dict[str, list[tuple[int, list[str]]]] = {}
        for key, value_raw in changes.items():
            if value_raw is None:
                continue
            if isinstance(value_raw, (str, int, float, bool, list, dict, type(None))):
                value = value_raw
            else:
                value = str(value_raw)
            ops_list: list[tuple[int, list[str]]] = []
            if isinstance(value, list) and all(
                isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], (str, int))
                and isinstance(item[1], list)
                and all(isinstance(v, str) for v in item[1])
                for item in value
            ):
                for tup_item in value:
                    if isinstance(tup_item, tuple) and len(tup_item) == 2:
                        op_raw, vals = (tup_item[0], tup_item[1])
                        op_int = (
                            op_str_to_int.get(str(op_raw).upper(), LDAP_MODIFY_REPLACE)
                            if isinstance(op_raw, str)
                            else int(op_raw)
                            if isinstance(op_raw, int)
                            else LDAP_MODIFY_REPLACE
                        )
                        op_val: int = (
                            op_int if op_int is not None else LDAP_MODIFY_REPLACE
                        )
                        vals_list: list[str] = (
                            [str(v) for v in vals]
                            if isinstance(vals, (list, tuple))
                            else [str(vals)]
                        )
                        ops_list.append((op_val, vals_list))
            elif isinstance(value, (list, tuple)):
                value_list = [str(v) for v in value]
                ops_list.append((LDAP_MODIFY_REPLACE, value_list))
            else:
                ops_list.append((LDAP_MODIFY_REPLACE, [str(value)]))
            if ops_list:
                result[key] = ops_list
        return result

    @staticmethod
    def _execute_modify_when_not_connected(
        client: LdapClientType,
        dn: str,
        changes: Mapping[str, object],
        expected_error: str,
    ) -> None:
        """Execute modify operation when not connected and assert failure."""
        modify_changes = (
            TestsFlextLdapOperationHelpers._convert_changes_to_modify_format(changes)
        )
        modify_result_raw = client.modify(dn, modify_changes)
        modify_result: OperationResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(modify_result_raw)
        )
        u.Tests.Result.assert_result_failure_with_error(
            modify_result, expected_error=expected_error
        )

    @staticmethod
    def _execute_delete_when_not_connected(
        client: LdapClientType, dn: str, expected_error: str
    ) -> None:
        """Execute delete operation when not connected and assert failure."""
        delete_result_raw = client.delete(dn)
        delete_result: OperationResultType = (
            TestsFlextLdapOperationHelpers._ensure_flext_result(delete_result_raw)
        )
        u.Tests.Result.assert_result_failure_with_error(
            delete_result, expected_error=expected_error
        )

    @staticmethod
    def execute_operation_when_not_connected(
        client: LdapClientType, operation: str, **kwargs: t.Scalar
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
            search_options_validated = (
                TestsFlextLdapOperationHelpers._validate_search_options_type(
                    search_options_raw
                )
            )
            TestsFlextLdapOperationHelpers._execute_search_when_not_connected(
                client, search_options_validated, expected_error
            )
        elif operation == "add":
            if "entry" not in kwargs:
                error_msg = "entry required for add operation"
                raise ValueError(error_msg)
            entry_raw = kwargs["entry"]
            if not isinstance(entry_raw, m.Ldif.Entry):
                error_msg = "entry must be m.Ldif.Entry (LdapEntry)"
                raise TypeError(error_msg)
            entry_validated: LdapEntry = entry_raw
            TestsFlextLdapOperationHelpers._execute_add_when_not_connected(
                client, entry_validated, expected_error
            )
        elif operation == "modify":
            if "dn" not in kwargs or "changes" not in kwargs:
                error_msg = "dn and changes required for modify operation"
                raise ValueError(error_msg)
            dn = kwargs["dn"]
            changes = kwargs["changes"]
            if not isinstance(dn, str):
                error_msg = "dn must be str"
                raise TypeError(error_msg)
            if not isinstance(changes, dict):
                error_msg = "changes must be dict"
                raise TypeError(error_msg)
            modify_dn_str: str = dn
            TestsFlextLdapOperationHelpers._execute_modify_when_not_connected(
                client, modify_dn_str, changes, expected_error
            )
        elif operation == "delete":
            if "dn" not in kwargs:
                error_msg = "dn required for delete operation"
                raise ValueError(error_msg)
            delete_dn = kwargs["dn"]
            if not isinstance(delete_dn, str):
                error_msg = "dn must be str"
                raise TypeError(error_msg)
            delete_dn_str: str = delete_dn
            TestsFlextLdapOperationHelpers._execute_delete_when_not_connected(
                client, delete_dn_str, expected_error
            )
        else:
            error_msg = f"Unknown operation: {operation}"
            raise ValueError(error_msg)

    @staticmethod
    def assert_operation_result_unwrapped(
        result: OperationResultType,
        *,
        expected_operation_type: str | None = None,
        expected_entries_affected: int | None = None,
    ) -> m.Ldap.OperationResult:
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
        return TestsFlextLdapOperationHelpers.assert_operation_result_success(
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
    ) -> m.Ldap.SearchOptions:
        """Create SearchOptions using constants - COMMON PATTERN.

        Uses RFC constants by default. Replaces repetitive SearchOptions creation.

        Args:
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            attributes: Attributes to retrieve (default: RFC.DEFAULT_ATTRIBUTES as list)

        Returns:
            m.Ldap.SearchOptions

        """
        if base_dn is None:
            base_dn = str(c.RFC.DEFAULT_BASE_DN) if c.RFC.DEFAULT_BASE_DN else ""
        if filter_str is None:
            filter_str = (
                str(c.RFC.DEFAULT_FILTER) if c.RFC.DEFAULT_FILTER else "(objectClass=*)"
            )
        if scope is None:
            scope = c.Ldap.SearchScope.SUBTREE.value
        if attributes is None:
            attributes = list(c.RFC.DEFAULT_ATTRIBUTES)
        return m.Ldap.SearchOptions(
            base_dn=str(base_dn),
            filter_str=str(filter_str),
            scope=_validate_scope(scope).value,
            attributes=attributes,
        )
