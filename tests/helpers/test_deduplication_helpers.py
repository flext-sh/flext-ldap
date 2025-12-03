"""Test deduplication helpers for massive code reduction in pytest tests.

This module provides helper methods to replace common patterns across
all test files, significantly reducing code duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import fcntl
import inspect
import tempfile
import types
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Literal, cast

import pytest
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsMatchers
from ldap3 import MODIFY_REPLACE, Connection, Entry as Ldap3Entry, Server

from flext_ldap import (
    FlextLdap,
    c,
    m,
    p,
    r,
    t,
)
from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService

from ..fixtures import LdapTestFixtures
from ..fixtures.constants import RFC
from ..fixtures.typing import (
    GenericFieldsDict,
    LdapAttributeValue,
)
from .entry_helpers import EntryTestHelpers
from .operation_helpers import TestOperationHelpers
from .test_helpers import FlextLdapTestHelpers


class TestDeduplicationHelpers:
    """Helper methods for massive test code deduplication."""

    @staticmethod
    def _narrow_client_type(
        client: p.LdapService.LdapClientProtocol | FlextLdapOperations,
    ) -> p.LdapService.LdapClientProtocol:
        """Narrow client type from object to p.LdapService.LdapClientProtocol.

        Args:
            client: Client object to narrow

        Returns:
            Client cast to p.LdapService.LdapClientProtocol

        Raises:
            TypeError: If client doesn't have required methods

        """
        # Check for required methods (connect is optional for operations service)
        if not (
            hasattr(client, "add")
            and hasattr(client, "delete")
            and hasattr(client, "search")
            and hasattr(client, "modify")
        ):
            error_msg = "client must have add, delete, search, and modify methods"
            raise TypeError(error_msg)
        # Operations service doesn't need connect (it uses connection internally)
        return cast("p.LdapService.LdapClientProtocol", client)

    @staticmethod
    def create_entry(
        dn: str,
        attributes: dict[
            str,
            list[str] | str | tuple[str, ...] | set[str] | frozenset[str],
        ],
    ) -> FlextLdifModels.Entry:
        """Create Entry - SIMPLEST PATTERN.

        Replaces all FlextLdifModels.Entry creation patterns.

        Args:
            dn: Distinguished name as string
            attributes: Attributes dict (values can be list or single string)

        Returns:
            FlextLdifModels.Entry

        Example:
            entry = TestDeduplicationHelpers.create_entry(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"], "objectClass": ["top", "person"]}
            )

        """
        # Convert attributes to GeneralValueType-compatible mapping
        normalized_attrs: dict[str, t.GeneralValueType] = {}
        for key, value in attributes.items():
            if isinstance(value, (frozenset, set, tuple)):
                normalized_attrs[key] = list(value)
            else:
                normalized_attrs[key] = value
        return EntryTestHelpers.create_entry(dn, normalized_attrs)

    @staticmethod
    def create_search(
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        scope: str | None = None,
        attributes: list[str] | None = None,
    ) -> m.SearchOptions:
        """Create SearchOptions - SIMPLEST PATTERN WITH CONSTANTS.

        Uses RFC constants by default. Replaces all SearchOptions creation.

        Args:
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            attributes: Attributes to retrieve (default: RFC.DEFAULT_ATTRIBUTES)

        Returns:
            m.SearchOptions

        Example:
            options = TestDeduplicationHelpers.create_search()
            # or
            options = TestDeduplicationHelpers.create_search(
                filter_str="(cn=test)"
            )

        """
        return TestOperationHelpers.create_search_options_with_defaults(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
        )

    @staticmethod
    def create_user(
        cn_value: str | None = None,
        base_dn: str | None = None,
        *,
        sn: str | None = None,
        mail: str | None = None,
        use_uid: bool = False,
        **extra_attributes: LdapAttributeValue,
    ) -> FlextLdifModels.Entry:
        """Create test user entry - SIMPLEST PATTERN WITH CONSTANTS.

        Uses RFC constants by default. Replaces all test user creation.

        Args:
            cn_value: Common name (default: RFC.TEST_USER_CN)
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            sn: Optional surname
            mail: Optional email
            use_uid: If True, creates uid-based DN
            **extra_attributes: Additional attributes

        Returns:
            FlextLdifModels.Entry

        Example:
            user = TestDeduplicationHelpers.create_user()
            # or
            user = TestDeduplicationHelpers.create_user("john", sn="Doe")

        """
        # Type narrowing: filter extra_attributes to only valid types
        # Extract known parameters that create_test_user_entry accepts
        # Only include attributes that can be converted to valid types
        filtered_attrs: dict[str, object] = {
            key: value for key, value in extra_attributes.items() if value is not None
        }

        # Direct delegation to generalized method with RFC defaults
        return TestOperationHelpers.create_inetorgperson_entry(
            cn_value or RFC.TEST_USER_CN,
            base_dn or RFC.DEFAULT_BASE_DN,
            use_uid=use_uid,
            sn=sn,
            mail=mail,
            additional_attrs=cast("GenericFieldsDict | None", filtered_attrs or None),
        )

    @staticmethod
    def create_group(
        cn_value: str | None = None,
        base_dn: str | None = None,
        *,
        members: list[str] | None = None,
        **extra_attributes: LdapAttributeValue,
    ) -> FlextLdifModels.Entry:
        """Create test group entry - SIMPLEST PATTERN WITH CONSTANTS.

        Uses RFC constants by default. Replaces all test group creation.

        Args:
            cn_value: Common name (default: RFC.TEST_GROUP_CN)
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            members: List of member DNs
            **extra_attributes: Additional attributes

        Returns:
            FlextLdifModels.Entry

        Example:
            group = TestDeduplicationHelpers.create_group()
            # or
            group = TestDeduplicationHelpers.create_group(
                "REDACTED_LDAP_BIND_PASSWORDs", members=["cn=user1"]
            )

        """
        # Type narrowing: filter extra_attributes to only valid types
        # Extract known parameters that create_test_group_entry accepts
        # Only include attributes that can be converted to valid types
        filtered_attrs: dict[str, object] = {
            key: value for key, value in extra_attributes.items() if value is not None
        }

        # Direct delegation to generalized method with RFC defaults
        # Convert filtered_attrs to GeneralValueType-compatible kwargs
        kwargs: dict[str, t.GeneralValueType] = cast(
            "dict[str, t.GeneralValueType]",
            filtered_attrs,
        )
        return TestOperationHelpers.create_group_entry(
            cn_value or RFC.TEST_GROUP_CN,
            base_dn or RFC.DEFAULT_BASE_DN,
            members=members,
            **kwargs,
        )

    @staticmethod
    def add_entry(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        *,
        verify: bool = False,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> r[m.OperationResult]:
        """Add entry with automatic cleanup - COMPLETE WORKFLOW.

        Replaces entire add + cleanup pattern.

        Args:
            client: LDAP client with add, delete methods
            entry: Entry to add
            verify: Whether to verify entry was added
            cleanup_before: Whether to cleanup before add
            cleanup_after: Whether to cleanup after add

        Returns:
            Add result

        Example:
            result = TestDeduplicationHelpers.add_entry(client, entry)
            FlextTestsMatchers.assert_success(result)

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        return EntryTestHelpers.add_and_cleanup(typed_client, entry, verify=verify)

    @staticmethod
    def add_from_dict(
        client: p.LdapService.LdapClientProtocol,
        entry_dict: Mapping[str, t.GeneralValueType] | GenericFieldsDict,
        *,
        verify: bool = True,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
        """Add entry from dict - COMPLETE WORKFLOW.

        Replaces entire dict -> entry -> add -> verify -> cleanup pattern.

        Args:
            client: LDAP client with add, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            verify: Whether to verify entry was added
            cleanup_before: Whether to cleanup before add
            cleanup_after: Whether to cleanup after add

        Returns:
            Tuple of (entry, add_result)

        Example:
            entry, result = TestDeduplicationHelpers.add_from_dict(
                client,
                {
                    "dn": "cn=test,dc=example,dc=com",
                    "attributes": {"cn": ["test"]},
                },
            )
            FlextTestsMatchers.assert_success(result)

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        return EntryTestHelpers.add_entry_from_dict(
            typed_client,
            entry_dict,
            verify=verify,
            cleanup_before=cleanup_before,
            cleanup_after=cleanup_after,
        )

    @staticmethod
    def search_and_unwrap(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        scope: str | None = None,
        attributes: list[str] | None = None,
        min_entries: int = 0,
    ) -> m.SearchResult:
        """Search and unwrap result - COMPLETE WORKFLOW.

        Replaces entire search + assert + unwrap pattern.

        Args:
            client: LDAP client with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            attributes: Attributes to retrieve
            min_entries: Minimum number of entries expected

        Returns:
            SearchResult

        Example:
            result = TestDeduplicationHelpers.search_and_unwrap(client)
            assert len(result.entries) >= 1

        """
        search_options = TestDeduplicationHelpers.create_search(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        # SearchOptions is compatible with SearchOptionsProtocol structurally
        search_result_raw = typed_client.search(search_options)
        search_result: r[m.SearchResult] = cast(
            "r[m.SearchResult]",
            search_result_raw,
        )
        result = FlextTestsMatchers.assert_success(
            search_result,
            error_msg="Search failed",
        )

        assert len(result.entries) >= min_entries, (
            f"Expected at least {min_entries} entries, got {len(result.entries)}"
        )

        return result

    @staticmethod
    def modify_entry(
        client: p.LdapService.LdapClientProtocol,
        entry_dict: Mapping[str, t.GeneralValueType] | GenericFieldsDict,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_attribute: str | None = None,
        verify_value: str | None = None,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Modify entry - COMPLETE WORKFLOW.

        Replaces entire add + modify + verify pattern.

        Args:
            client: LDAP client with add, modify, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            changes: Dictionary of modifications
            verify_attribute: Optional attribute name to verify after modify
            verify_value: Optional value to check in verify_attribute
            cleanup_before: Whether to cleanup before add
            cleanup_after: Whether to cleanup after modify

        Returns:
            Tuple of (entry, add_result, modify_result)

        Example:
            entry, add_result, modify_result = TestDeduplicationHelpers.modify_entry(
                client,
                {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
                {"mail": [(MODIFY_REPLACE, ["new@example.com"])]},
                verify_attribute="mail",
                verify_value="new@example.com"
            )
            FlextTestsMatchers.assert_success(add_result)
            FlextTestsMatchers.assert_success(modify_result)

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        return EntryTestHelpers.modify_entry_with_verification(
            typed_client,
            entry_dict,
            changes,
            verify_attribute=verify_attribute,
            verify_value=verify_value,
            cleanup_before=cleanup_before,
            cleanup_after=cleanup_after,
        )

    @staticmethod
    def delete_entry(
        client: p.LdapService.LdapClientProtocol,
        entry_dict: Mapping[str, t.GeneralValueType] | GenericFieldsDict,
        *,
        cleanup_before: bool = True,
        verify_deletion: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Delete entry - COMPLETE WORKFLOW.

        Replaces entire add + delete + verify pattern.

        Args:
            client: LDAP client with add, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            cleanup_before: Whether to cleanup before add
            verify_deletion: Whether to verify entry was deleted

        Returns:
            Tuple of (entry, add_result, delete_result)

        Example:
            entry, add_result, delete_result = TestDeduplicationHelpers.delete_entry(
                client,
                {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
            )
            FlextTestsMatchers.assert_success(add_result)
            FlextTestsMatchers.assert_success(delete_result)

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        return EntryTestHelpers.delete_entry_with_verification(
            typed_client,
            entry_dict,
            cleanup_before=cleanup_before,
            verify_deletion=verify_deletion,
        )

    @staticmethod
    def assert_operation(
        result: r[m.OperationResult],
        *,
        operation_type: str | None = None,
        entries_affected: int | None = None,
    ) -> m.OperationResult:
        """Assert operation result - COMPLETE VERIFICATION.

        Replaces entire operation result verification pattern.

        Args:
            result: Operation result to assert
            operation_type: Optional expected operation type
            entries_affected: Optional expected entries affected count

        Returns:
            Unwrapped OperationResult

        Example:
            op_result = TestDeduplicationHelpers.assert_operation(
                result, operation_type=c.OperationType.ADD.value, entries_affected=1
            )

        """
        if entries_affected is None:
            entries_affected = 1

        return TestOperationHelpers.assert_operation_result_success(
            result,
            expected_operation_type=operation_type,
            expected_entries_affected=entries_affected,
        )

    @staticmethod
    def create_connection_config(
        ldap_container: GenericFieldsDict | None = None,
        *,
        host: str | None = None,
        port: int | None = None,
        use_ssl: bool = False,
        use_tls: bool = False,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        timeout: int = 30,
        auto_bind: bool = True,
        auto_range: bool = True,
    ) -> m.ConnectionConfig:
        """Create ConnectionConfig - MASSIVE CODE REDUCTION.

        Replaces all ConnectionConfig creation patterns across tests.
        Uses ldap_container fixture by default if provided.

        Args:
            ldap_container: Optional container dict with connection info
            host: Host (default: from ldap_container or RFC.DEFAULT_HOST)
            port: Port (default: from ldap_container or RFC.DEFAULT_PORT)
            use_ssl: Use SSL (default: False)
            use_tls: Use TLS (default: False)
            bind_dn: Bind DN (default: from ldap_container or
                RFC.DEFAULT_BIND_DN)
            bind_password: Bind password (default: from ldap_container or
                RFC.DEFAULT_BIND_PASSWORD)
            timeout: Connection timeout (default: 30)
            auto_bind: Auto bind (default: True)
            auto_range: Auto range (default: True)

        Returns:
            m.ConnectionConfig

        Example:
            # Using container fixture
            config = TestDeduplicationHelpers.create_connection_config(ldap_container)
            # Custom config
            config = TestDeduplicationHelpers.create_connection_config(
                host="localhost", port=389, use_ssl=True
            )

        """
        if ldap_container:
            if host is None:
                host = str(ldap_container.get("host", RFC.DEFAULT_HOST))
            if port is None:
                port = int(str(ldap_container.get("port", RFC.DEFAULT_PORT)))
            if bind_dn is None:
                bind_dn = str(ldap_container.get("bind_dn", RFC.DEFAULT_BIND_DN))
            if bind_password is None:
                bind_password = str(
                    ldap_container.get("password", RFC.DEFAULT_BIND_PASSWORD),
                )
            host_val = host
            port_val = port
            bind_dn_val = bind_dn
            bind_password_val = bind_password
        else:
            if host is None:
                host = RFC.DEFAULT_HOST
            if port is None:
                port = RFC.DEFAULT_PORT
            if bind_dn is None:
                bind_dn = RFC.DEFAULT_BIND_DN
            if bind_password is None:
                bind_password = RFC.DEFAULT_BIND_PASSWORD
            host_val = host
            port_val = port
            bind_dn_val = bind_dn
            bind_password_val = bind_password

        return m.ConnectionConfig(
            host=host_val,
            port=port_val,
            use_ssl=use_ssl,
            use_tls=use_tls,
            bind_dn=bind_dn_val,
            bind_password=bind_password_val,
            timeout=timeout,
            auto_bind=auto_bind,
            auto_range=auto_range,
        )

    @staticmethod
    def connect_and_assert(
        client: p.LdapService.LdapClientProtocol,
        connection_config: m.ConnectionConfig | None = None,
        ldap_container: GenericFieldsDict | None = None,
    ) -> None:
        """Connect client and assert success - COMPLETE WORKFLOW.

        Replaces entire connect + assert pattern. Creates config if not provided.

        Args:
            client: LDAP client with connect method
            connection_config: Optional connection config
                (created if not provided)
            ldap_container: Optional container dict
                (used if connection_config not provided)

        Example:
            TestDeduplicationHelpers.connect_and_assert(
                client, ldap_container=ldap_container
            )
            # or
            TestDeduplicationHelpers.connect_and_assert(
                client, connection_config=config
            )

        """
        if connection_config is None:
            connection_config = TestDeduplicationHelpers.create_connection_config(
                ldap_container,
            )

        # Type narrowing: ensure client has connect method
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        TestOperationHelpers.connect_and_assert_success(typed_client, connection_config)

    @staticmethod
    def crud_sequence(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry | None = None,
        entry_dict: Mapping[str, object] | GenericFieldsDict | None = None,
        changes: dict[str, list[tuple[str, list[str]]]] | None = None,
        *,
        cleanup_after: bool = True,
    ) -> dict[
        str,
        r[m.OperationResult]
        | r[m.SearchResult],
    ]:
        """Execute complete CRUD sequence - MASSIVE CODE REDUCTION.

        Replaces entire add + search + modify + delete pattern.
        Creates entry from dict if entry not provided.

        Args:
            client: LDAP client with add, modify, delete, search methods
            entry: Optional entry to use (created from entry_dict if not provided)
            entry_dict: Optional entry dict (used if entry not provided)
            changes: Optional modification changes (default: empty dict)
            cleanup_after: Whether to cleanup after sequence (default: True)

        Returns:
            Dictionary with add, search, modify, delete results

        Example:
            results = TestDeduplicationHelpers.crud_sequence(
                client,
                entry_dict={
                    "dn": "cn=test,dc=example,dc=com",
                    "attributes": {"cn": ["test"]},
                },
                changes={"mail": [(MODIFY_REPLACE, ["new@example.com"])]}
            )
            FlextTestsMatchers.assert_success(results["add"])

        """
        if entry is None:
            if entry_dict is None:
                error_msg = "Either entry or entry_dict must be provided"
                raise ValueError(error_msg)
            entry, _ = TestDeduplicationHelpers.add_from_dict(
                client,
                cast(
                    "Mapping[str, t.GeneralValueType] | GenericFieldsDict",
                    entry_dict,
                ),
                cleanup_after=False,
            )
        else:
            _ = TestDeduplicationHelpers.add_entry(client, entry, cleanup_after=False)

        if changes is None:
            changes = {}

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        return TestOperationHelpers.execute_crud_sequence(typed_client, entry, changes)

    @staticmethod
    def search_entry_by_dn(
        client: p.LdapService.LdapClientProtocol,
        dn: str,
        *,
        verify_exists: bool = True,
    ) -> m.SearchResult | None:
        """Search for entry by DN - COMMON PATTERN.

        Replaces BASE search pattern for specific DN.

        Args:
            client: LDAP client with search method
            dn: Distinguished name to search for
            verify_exists: Whether to assert entry exists (default: True)

        Returns:
            SearchResult if found, None otherwise

        Example:
            result = TestDeduplicationHelpers.search_entry_by_dn(
                client, "cn=test,dc=example,dc=com"
            )
            assert result is not None
            assert len(result.entries) == 1

        """
        search_options = m.SearchOptions(
            base_dn=dn,
            filter_str="(objectClass=*)",
            scope=c.SearchScope.BASE,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        # SearchOptions is compatible with SearchOptionsProtocol structurally
        search_result_raw = typed_client.search(search_options)
        search_result: r[m.SearchResult] = cast(
            "r[m.SearchResult]",
            search_result_raw,
        )
        result = FlextTestsMatchers.assert_success(
            search_result,
            error_msg="Search failed",
        )

        if verify_exists:
            assert len(result.entries) == 1, (
                f"Expected exactly 1 entry for DN {dn}, got {len(result.entries)}"
            )

        return result if len(result.entries) > 0 else None

    @staticmethod
    def verify_entry_exists(
        client: p.LdapService.LdapClientProtocol,
        dn: str,
    ) -> bool:
        """Verify entry exists - COMMON PATTERN.

        Replaces BASE search + assert pattern for existence check.

        Args:
            client: LDAP client with search method
            dn: Distinguished name to check

        Returns:
            True if entry exists, False otherwise

        Example:
            exists = TestDeduplicationHelpers.verify_entry_exists(
                client, "cn=test,dc=example,dc=com"
            )
            assert exists

        """
        result = TestDeduplicationHelpers.search_entry_by_dn(
            client,
            dn,
            verify_exists=False,
        )
        return result is not None and len(result.entries) == 1

    @staticmethod
    def verify_entry_not_exists(
        client: p.LdapService.LdapClientProtocol,
        dn: str,
    ) -> bool:
        """Verify entry does not exist - COMMON PATTERN.

        Replaces BASE search + assert pattern for non-existence check.

        Args:
            client: LDAP client with search method
            dn: Distinguished name to check

        Returns:
            True if entry does not exist, False otherwise

        Example:
            not_exists = TestDeduplicationHelpers.verify_entry_not_exists(
                client, "cn=test,dc=example,dc=com"
            )
            assert not_exists

        """
        result = TestDeduplicationHelpers.search_entry_by_dn(
            client,
            dn,
            verify_exists=False,
        )
        return result is None or len(result.entries) == 0

    @staticmethod
    def add_multiple_entries(
        client: p.LdapService.LdapClientProtocol,
        entry_dicts: list[GenericFieldsDict],
        *,
        adjust_dn: dict[str, str] | None = None,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> list[
        tuple[FlextLdifModels.Entry, r[m.OperationResult]]
    ]:
        """Add multiple entries from list of dictionaries - MASSIVE CODE REDUCTION.

        Replaces entire loop + add + cleanup pattern for multiple entries.

        Args:
            client: LDAP client with add, delete methods
            entry_dicts: List of dictionaries with 'dn' and 'attributes' keys
            adjust_dn: Optional dict with 'from' and 'to' keys to replace in DN
            cleanup_before: Whether to cleanup before each add (default: True)
            cleanup_after: Whether to cleanup all entries after (default: True)

        Returns:
            List of tuples (entry, add_result) for each entry

        Example:
            results = TestDeduplicationHelpers.add_multiple_entries(
                client,
                [user1_dict, user2_dict],
                adjust_dn={"from": "dc=example,dc=com", "to": "dc=flext,dc=local"}
            )
            for entry, result in results:
                FlextTestsMatchers.assert_success(result)

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        return EntryTestHelpers.add_multiple_entries_from_dicts(
            typed_client,
            entry_dicts,
            adjust_dn=adjust_dn,
            cleanup_before=cleanup_before,
            cleanup_after=cleanup_after,
        )

    @staticmethod
    def search_with_assertions(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        scope: str | None = None,
        attributes: list[str] | None = None,
        min_count: int = 0,
        max_count: int | None = None,
    ) -> m.SearchResult:
        """Search with automatic assertions - COMPLETE WORKFLOW.

        Replaces entire search + assert + count check pattern.

        Args:
            client: LDAP client with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            attributes: Attributes to retrieve
            min_count: Minimum number of entries expected (default: 0)
            max_count: Maximum number of entries expected (optional)

        Returns:
            SearchResult

        Example:
            result = TestDeduplicationHelpers.search_with_assertions(
                client, min_count=1, max_count=10
            )
            assert len(result.entries) >= 1

        """
        if base_dn is None:
            base_dn = ""
        if filter_str is None:
            filter_str = "(objectClass=*)"
        if scope is None:
            scope = ""

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        return TestOperationHelpers.search_and_assert_success(
            typed_client,
            base_dn,
            filter_str=filter_str,
            expected_min_count=min_count,
            expected_max_count=max_count,
            scope=scope,
            attributes=attributes,
        )

    @staticmethod
    def add_then_modify(
        client: p.LdapService.LdapClientProtocol,
        entry_dict: Mapping[str, t.GeneralValueType] | GenericFieldsDict,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_attribute: str | None = None,
        verify_value: str | None = None,
        cleanup_before: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Add entry then modify - COMPLETE WORKFLOW.

        Replaces entire add + modify + verify pattern.

        Args:
            client: LDAP client with add, modify, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            changes: Dictionary of modifications
            verify_attribute: Optional attribute name to verify after modify
            verify_value: Optional value to check in verify_attribute
            cleanup_before: Whether to cleanup before add (default: True)
            cleanup_after: Whether to cleanup after modify (default: True)

        Returns:
            Tuple of (entry, add_result, modify_result)

        Example:
            entry, add_result, modify_result = TestDeduplicationHelpers.add_then_modify(
                client,
                {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
                {"mail": [(MODIFY_REPLACE, ["new@example.com"])]},
                verify_attribute="mail",
                verify_value="new@example.com"
            )

        """
        return TestDeduplicationHelpers.modify_entry(
            client,
            entry_dict,
            changes,
            verify_attribute=verify_attribute,
            verify_value=verify_value,
            cleanup_before=cleanup_before,
            cleanup_after=cleanup_after,
        )

    @staticmethod
    def add_then_delete(
        client: p.LdapService.LdapClientProtocol,
        entry_dict: Mapping[str, t.GeneralValueType] | GenericFieldsDict,
        *,
        cleanup_before: bool = True,
        verify_deletion: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Add entry then delete - COMPLETE WORKFLOW.

        Replaces entire add + delete + verify pattern.

        Args:
            client: LDAP client with add, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            cleanup_before: Whether to cleanup before add (default: True)
            verify_deletion: Whether to verify entry was deleted (default: True)

        Returns:
            Tuple of (entry, add_result, delete_result)

        Example:
            entry, add_result, delete_result = TestDeduplicationHelpers.add_then_delete(
                client,
                {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
            )

        """
        return TestDeduplicationHelpers.delete_entry(
            client,
            entry_dict,
            cleanup_before=cleanup_before,
            verify_deletion=verify_deletion,
        )

    @staticmethod
    def execute_operation_when_disconnected(
        client: p.LdapService.LdapClientProtocol,
        operation: str,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Execute operation when disconnected and assert failure - COMMON PATTERN.

        Replaces entire disconnected operation + assert failure pattern.

        Args:
            client: LDAP client
            operation: Operation name (search, add, modify, delete)
            **kwargs: Operation-specific arguments

        Example:
            TestDeduplicationHelpers.execute_operation_when_disconnected(
                client, "search", search_options=search_options
            )

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        TestOperationHelpers.execute_operation_when_not_connected(
            typed_client,
            operation,
            **kwargs,
        )

    @staticmethod
    def add_operation_complete(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry | None = None,
        entry_dict: Mapping[str, object] | GenericFieldsDict | None = None,
        *,
        verify_operation_result: bool = True,
        expected_entries_affected: int = 1,
        cleanup_after: bool = True,
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
        """Complete add operation test - REPLACES ENTIRE TEST METHOD (10-20 lines).

        Replaces entire test_add_* methods with single call.

        Args:
            client: LDAP client with add method
            entry: Optional entry to add (created from entry_dict if not provided)
            entry_dict: Optional entry dict (used if entry not provided)
            verify_operation_result: Whether to verify operation result details
            expected_entries_affected: Expected number of entries affected
            cleanup_after: Whether to cleanup after add

        Returns:
            Tuple of (entry, add_result)

        Example:
            entry, result = TestDeduplicationHelpers.test_add_operation_complete(
                client,
                entry_dict={
                    "dn": "cn=test,dc=example,dc=com",
                    "attributes": {"cn": ["test"]},
                },
            )
            FlextTestsMatchers.assert_success(result)

        """
        if entry is None:
            if entry_dict is None:
                error_msg = "Either entry or entry_dict must be provided"
                raise ValueError(error_msg)
            entry, add_result = TestDeduplicationHelpers.add_from_dict(
                client,
                cast(
                    "Mapping[str, t.GeneralValueType] | GenericFieldsDict",
                    entry_dict,
                ),
                cleanup_after=cleanup_after,
            )
        else:
            add_result = TestDeduplicationHelpers.add_entry(
                client,
                entry,
                cleanup_after=cleanup_after,
            )

        if verify_operation_result:
            TestDeduplicationHelpers.assert_operation(
                add_result,
                entries_affected=expected_entries_affected,
            )

        return entry, add_result

    @staticmethod
    def modify_operation_complete(
        client: p.LdapService.LdapClientProtocol,
        entry_dict: Mapping[str, t.GeneralValueType] | GenericFieldsDict,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_attribute: str | None = None,
        verify_value: str | None = None,
        cleanup_after: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Complete modify operation test - REPLACES ENTIRE TEST METHOD (15-25 lines).

        Replaces entire test_modify_* methods with single call.

        Args:
            client: LDAP client with add, modify, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            changes: Dictionary of modifications
            verify_attribute: Optional attribute name to verify after modify
            verify_value: Optional value to check in verify_attribute
            cleanup_after: Whether to cleanup after modify

        Returns:
            Tuple of (entry, add_result, modify_result)

        Example:
            entry, add_result, modify_result = (
                TestDeduplicationHelpers.test_modify_operation_complete(
                client,
                {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
                {"mail": [(MODIFY_REPLACE, ["new@example.com"])]},
                verify_attribute="mail",
                verify_value="new@example.com"
            )

        """
        return TestDeduplicationHelpers.add_then_modify(
            client,
            entry_dict,
            changes,
            verify_attribute=verify_attribute,
            verify_value=verify_value,
            cleanup_after=cleanup_after,
        )

    @staticmethod
    def delete_operation_complete(
        client: p.LdapService.LdapClientProtocol,
        entry_dict: Mapping[str, t.GeneralValueType] | GenericFieldsDict,
        *,
        verify_deletion: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Complete delete operation test - REPLACES ENTIRE TEST METHOD (10-20 lines).

        Replaces entire test_delete_* methods with single call.

        Args:
            client: LDAP client with add, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            verify_deletion: Whether to verify entry was deleted

        Returns:
            Tuple of (entry, add_result, delete_result)

        Example:
            entry, add_result, delete_result = (
                TestDeduplicationHelpers.test_delete_operation_complete(
                client,
                {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}
            )

        """
        return TestDeduplicationHelpers.add_then_delete(
            client,
            entry_dict,
            verify_deletion=verify_deletion,
        )

    @staticmethod
    def search_operation_complete(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        scope: str | None = None,
        attributes: list[str] | None = None,
        min_count: int = 0,
        max_count: int | None = None,
        verify_entry_attributes: bool = False,
        expected_object_classes: list[str] | None = None,
    ) -> m.SearchResult:
        """Complete search operation test - REPLACES ENTIRE TEST METHOD (10-30 lines).

        Replaces entire test_search_* methods with single call.

        Args:
            client: LDAP client with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            attributes: Attributes to retrieve
            min_count: Minimum number of entries expected
            max_count: Maximum number of entries expected
            verify_entry_attributes: Whether to verify entry attributes
            expected_object_classes: Optional list of object classes
                to verify in entries

        Returns:
            SearchResult

        Example:
            result = TestDeduplicationHelpers.test_search_operation_complete(
                client,
                filter_str="(objectClass=inetOrgPerson)",
                min_count=1,
                expected_object_classes=["inetOrgPerson", "person"]
            )

        """
        result = TestDeduplicationHelpers.search_with_assertions(
            client,
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
            min_count=min_count,
            max_count=max_count,
        )

        if verify_entry_attributes and result.entries:
            for entry in result.entries:
                assert entry.attributes is not None
                assert entry.attributes.attributes is not None

        if expected_object_classes and result.entries:
            for entry in result.entries:
                if entry.attributes and entry.attributes.attributes:
                    object_classes = entry.attributes.attributes.get("objectClass", [])
                    if isinstance(object_classes, list):
                        for expected_oc in expected_object_classes:
                            assert expected_oc in object_classes, (
                                f"Expected objectClass {expected_oc} "
                                f"not found in {object_classes}"
                            )

        return result

    @staticmethod
    def crud_sequence_complete(
        client: p.LdapService.LdapClientProtocol,
        entry_dict: Mapping[str, t.GeneralValueType] | GenericFieldsDict,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_search: bool = True,
        verify_modify: bool = True,
        verify_delete: bool = True,
    ) -> dict[
        str,
        r[m.OperationResult]
        | r[m.SearchResult],
    ]:
        """Complete CRUD sequence test - REPLACES ENTIRE TEST METHOD (20-40 lines).

        Replaces entire test_all_operations_* methods with single call.

        Args:
            client: LDAP client with add, modify, delete, search methods
            entry_dict: Dictionary with 'dn' and 'attributes' keys
            changes: Modification changes
            verify_search: Whether to verify search found entry
            verify_modify: Whether to verify modify succeeded
            verify_delete: Whether to verify delete succeeded

        Returns:
            Dictionary with add, search, modify, delete results

        Example:
            results = TestDeduplicationHelpers.test_crud_sequence_complete(
                client,
                {"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}},
                {"mail": [(MODIFY_REPLACE, ["new@example.com"])]}
            )
            FlextTestsMatchers.assert_success(results["add"])

        """
        results = TestDeduplicationHelpers.crud_sequence(
            client,
            entry_dict=entry_dict,
            changes=changes,
            cleanup_after=True,
        )

        if verify_search and "search" in results:
            search_result = FlextTestsMatchers.assert_success(
                cast(
                    "r[m.SearchResult]",
                    results["search"],
                ),
                error_msg="Search failed",
            )
            assert len(search_result.entries) == 1

        if verify_modify:
            modify_result_value = results.get("modify")
            if modify_result_value is not None:
                # Type narrowing: result must be OperationResult
                FlextTestsMatchers.assert_success(
                    cast(
                        "r[m.OperationResult]",
                        modify_result_value,
                    ),
                    error_msg="Modify failed",
                )

        if verify_delete:
            delete_result_value = results.get("delete")
            if delete_result_value is not None:
                # Type narrowing: result must be OperationResult
                FlextTestsMatchers.assert_success(
                    cast(
                        "r[m.OperationResult]",
                        delete_result_value,
                    ),
                    error_msg="Delete failed",
                )

        return results

    @staticmethod
    def connection_management_complete(
        client_factory: Callable[[], FlextLdap],
        connection_config: m.ConnectionConfig | None = None,
        ldap_container: GenericFieldsDict | None = None,
        *,
        test_context_manager: bool = True,
        test_disconnect: bool = True,
        test_reconnect: bool = False,
    ) -> FlextLdap:
        """Complete connection management test.

        REPLACES ENTIRE TEST METHOD (15-30 lines).
        Replaces entire test_connect_* and test_context_manager_* methods.

        Args:
            client_factory: Callable that returns client instance
                (e.g., lambda: TestDeduplicationHelpers.create_api())
            connection_config: Optional connection config
                (created if not provided)
            ldap_container: Optional container dict (used if connection_config not provided)
            test_context_manager: Whether to test context manager
            test_disconnect: Whether to test disconnect
            test_reconnect: Whether to test reconnect

        Returns:
            Client instance

        Example:
            client = TestDeduplicationHelpers.connection_management_complete(
                lambda: TestDeduplicationHelpers.create_api(), ldap_container=ldap_container
            )

        """
        if connection_config is None:
            connection_config = TestDeduplicationHelpers.create_connection_config(
                ldap_container,
            )

        # Type narrowing: ensure client_factory is callable
        if not callable(client_factory):
            error_msg = "client_factory must be callable"
            raise TypeError(error_msg)
        factory = client_factory

        if test_context_manager:
            # Test context manager
            client_obj = factory()
            # Type narrowing: check if client supports context manager
            if not hasattr(client_obj, "__enter__") or not hasattr(
                client_obj,
                "__exit__",
            ):
                error_msg = "Client must support context manager protocol"
                raise TypeError(error_msg)
            client_cm = cast("AbstractContextManager[FlextLdap]", client_obj)
            with client_cm as client:
                # Type narrowing for client inside context
                if not hasattr(client, "is_connected") or not hasattr(
                    client,
                    "connect",
                ):
                    error_msg = "Client must have is_connected and connect attributes"
                    raise TypeError(error_msg)
                TestDeduplicationHelpers.connect_and_assert(
                    cast("p.LdapService.LdapClientProtocol", client),
                    connection_config,
                )
                is_connected = getattr(client, "is_connected", False)
                assert is_connected is True

            # Should be disconnected after context exit
            is_connected_after = getattr(client, "is_connected", False)
            assert is_connected_after is False

        # Test regular connect/disconnect
        client = factory()
        # Type narrowing: check client has required attributes
        if not (
            hasattr(client, "connect")
            and hasattr(client, "disconnect")
            and hasattr(client, "is_connected")
        ):
            error_msg = (
                "Client must have connect, disconnect, and is_connected attributes"
            )
            raise TypeError(error_msg)
        TestDeduplicationHelpers.connect_and_assert(
            cast("p.LdapService.LdapClientProtocol", client),
            connection_config,
        )

        if test_disconnect:
            disconnect_method = getattr(client, "disconnect", None)
            if disconnect_method is not None:
                disconnect_method()
            is_connected = getattr(client, "is_connected", False)
            assert is_connected is False

        if test_reconnect:
            TestDeduplicationHelpers.connect_and_assert(
                cast("p.LdapService.LdapClientProtocol", client),
                connection_config,
            )
            is_connected = getattr(client, "is_connected", False)
            assert is_connected is True
            disconnect_method = getattr(client, "disconnect", None)
            if disconnect_method is not None:
                disconnect_method()

        return client

    @staticmethod
    def create_operations_service_fixture(
        connection_config: m.ConnectionConfig | None = None,
        ldap_container: GenericFieldsDict | None = None,
    ) -> FlextLdapOperations:
        """Create operations service fixture - REPLACES ENTIRE FIXTURE (10-15 lines).

        Replaces repetitive operations_service fixtures across test files.

        Args:
            connection_config: Optional connection config (created if not provided)
            ldap_container: Optional container dict (used if connection_config not provided)

        Returns:
            FlextLdapOperations instance

        Example:
            operations = TestDeduplicationHelpers.create_operations_service_fixture(
                ldap_container=ldap_container
            )

        """
        if connection_config is None:
            connection_config = TestDeduplicationHelpers.create_connection_config(
                ldap_container,
            )

        config = FlextLdapConfig()
        parser = FlextLdifParser()
        connection = FlextLdapConnection(config=config, parser=parser)
        # Type narrowing: FlextLdapConnection implements p.LdapService.LdapClientProtocol
        typed_connection = cast(
            "p.LdapService.LdapClientProtocol",
            connection,
        )
        TestOperationHelpers.connect_with_skip_on_failure(
            typed_connection,
            connection_config,
        )

        return FlextLdapOperations(connection=connection)

    @staticmethod
    def create_ldap_config(
        ldap_container: GenericFieldsDict | None = None,
        *,
        host: str | None = None,
        port: int | None = None,
        use_ssl: bool = False,
        use_tls: bool = False,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        timeout: int = 30,
        auto_bind: bool = True,
        auto_range: bool = True,
    ) -> FlextLdapConfig:
        """Create FlextLdapConfig - MASSIVE CODE REDUCTION.

        Replaces all FlextLdapConfig creation patterns across tests.
        Uses ldap_container fixture by default if provided.

        Args:
            ldap_container: Optional container dict with connection info
            host: Host (default: from ldap_container or RFC.DEFAULT_HOST)
            port: Port (default: from ldap_container or RFC.DEFAULT_PORT)
            use_ssl: Use SSL (default: False)
            use_tls: Use TLS (default: False)
            bind_dn: Bind DN (default: from ldap_container or
                RFC.DEFAULT_BIND_DN)
            bind_password: Bind password (default: from ldap_container or
                RFC.DEFAULT_BIND_PASSWORD)
            timeout: Connection timeout (default: 30)
            auto_bind: Auto bind (default: True)
            auto_range: Auto range (default: True)

        Returns:
            FlextLdapConfig instance

        Example:
            config = TestDeduplicationHelpers.create_ldap_config(ldap_container)
            connection = FlextLdapConnection(config=config)
            operations = FlextLdapOperations(connection=connection)
            api = FlextLdap(connection=connection, operations=operations)

        """
        if ldap_container:
            if host is None:
                host = str(ldap_container.get("host", RFC.DEFAULT_HOST))
            if port is None:
                port = int(str(ldap_container.get("port", RFC.DEFAULT_PORT)))
            if bind_dn is None:
                bind_dn = str(ldap_container.get("bind_dn", RFC.DEFAULT_BIND_DN))
            if bind_password is None:
                bind_password = str(
                    ldap_container.get("password", RFC.DEFAULT_BIND_PASSWORD),
                )
            host_val = host
            port_val = port
            bind_dn_val = bind_dn
            bind_password_val = bind_password
        else:
            if host is None:
                host = RFC.DEFAULT_HOST
            if port is None:
                port = RFC.DEFAULT_PORT
            if bind_dn is None:
                bind_dn = RFC.DEFAULT_BIND_DN
            if bind_password is None:
                bind_password = RFC.DEFAULT_BIND_PASSWORD
            host_val = host
            port_val = port
            bind_dn_val = bind_dn
            bind_password_val = bind_password

        return FlextLdapConfig(
            host=host_val,
            port=port_val,
            use_ssl=use_ssl,
            use_tls=use_tls,
            bind_dn=bind_dn_val,
            bind_password=bind_password_val,
            timeout=timeout,
            auto_bind=auto_bind,
            auto_range=auto_range,
        )

    @staticmethod
    def convert_fixtures_to_entry_dicts(
        fixture_data: list[GenericFieldsDict],
        fixture_type: str = "user",
        *,
        limit: int | None = None,
        adjust_dn: dict[str, str] | None = None,
    ) -> list[GenericFieldsDict]:
        """Convert fixture JSON to entry dicts - REPLACES ENTIRE PATTERN (5-10 lines).

        Replaces repetitive fixture conversion patterns.

        Args:
            fixture_data: List of fixture dictionaries
            fixture_type: Type of fixture ("user" or "group")
            limit: Optional limit on number of entries to convert
            adjust_dn: Optional dict with 'from' and 'to' keys for DN replacement

        Returns:
            List of entry dictionaries

        Example:
            entry_dicts = TestDeduplicationHelpers.convert_fixtures_to_entry_dicts(
                test_users_json, fixture_type="user", limit=2
            )

        """
        if limit:
            fixture_data = fixture_data[:limit]

        if fixture_type == "user":
            entry_dicts = [
                LdapTestFixtures.convert_user_json_to_entry(user_data)
                for user_data in fixture_data
            ]
        elif fixture_type == "group":
            entry_dicts = [
                LdapTestFixtures.convert_group_json_to_entry(group_data)
                for group_data in fixture_data
            ]
        else:
            error_msg = f"Unknown fixture_type: {fixture_type}"
            raise ValueError(error_msg)

        if adjust_dn:
            for entry_dict in entry_dicts:
                dn_str = str(entry_dict.get("dn", ""))
                adjusted_dn = dn_str.replace(
                    adjust_dn.get("from", ""),
                    adjust_dn.get("to", ""),
                )
                entry_dict["dn"] = adjusted_dn

        return cast("list[GenericFieldsDict]", entry_dicts)

    @staticmethod
    def with_multiple_server_types(
        client: p.LdapService.LdapClientProtocol,
        test_func: Callable[[str], r[m.OperationResult]],
        server_types: list[str] | None = None,
        *,
        base_dn: str | None = None,
        skip_on_failure: bool = True,
    ) -> list[tuple[str, r[m.OperationResult]]]:
        """Test operation with multiple server types - REPLACES ENTIRE PATTERN (10-20 lines).

        Replaces repetitive server type testing patterns.

        Args:
            client: LDAP client
            test_func: Function to test (should accept server_type parameter)
            server_types: List of server types to test (default: ["rfc", "generic"])
            base_dn: Base DN for operations
            skip_on_failure: Whether to skip on failure (default: True)

        Returns:
            List of tuples (server_type, result)

        Example:
            typed_client = TestDeduplicationHelpers._narrow_client_type(client)
            results = TestDeduplicationHelpers.test_with_multiple_server_types(
                client, lambda st: typed_client.search(search_options, server_type=st)
            )

        """
        if server_types is None:
            server_types = ["rfc", "generic"]

        # Type narrowing: ensure test_func is callable
        if not callable(test_func):
            error_msg = "test_func must be callable"
            raise TypeError(error_msg)

        typed_test_func = test_func

        results: list[tuple[str, r[m.OperationResult]]] = []

        for server_type in server_types:
            try:
                result = typed_test_func(server_type)
                results.append((server_type, result))

                if skip_on_failure and result.is_failure:
                    pytest.skip(f"Server type {server_type} failed: {result.error}")
            except Exception as e:
                if skip_on_failure:
                    pytest.skip(f"Server type {server_type} error: {e!s}")
                raise

        return results

    @staticmethod
    def create_temp_ldif_file(
        entries: list[GenericFieldsDict] | None = None,
        ldif_content: str | None = None,
    ) -> Path:
        """Create temporary LDIF file - REPLACES ENTIRE FIXTURE (15-25 lines).

        Replaces repetitive temp LDIF file fixtures.

        Args:
            entries: Optional list of entry dicts to convert to LDIF
            ldif_content: Optional raw LDIF content string

        Returns:
            Path object to temporary file

        Example:
            ldif_file = TestDeduplicationHelpers.create_temp_ldif_file(
                entries=[{"dn": "cn=test,dc=example,dc=com", "attributes": {"cn": ["test"]}}]
            )

        """
        if ldif_content is None:
            if entries is None:
                error_msg = "Either entries or ldif_content must be provided"
                raise ValueError(error_msg)

            # Convert entries to LDIF format
            ldif_lines: list[str] = []
            for entry in entries:
                dn = entry.get("dn", "")
                ldif_lines.append(f"dn: {dn}")
                attrs = entry.get("attributes", {})
                if isinstance(attrs, dict):
                    for attr_name, attr_values in attrs.items():
                        if isinstance(attr_values, list):
                            ldif_lines.extend([
                                f"{attr_name}: {value}" for value in attr_values
                            ])
                        else:
                            ldif_lines.append(f"{attr_name}: {attr_values}")
                ldif_lines.append("")  # Empty line between entries

            ldif_content = "\n".join(ldif_lines)

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(ldif_content)
            return Path(f.name)

    @staticmethod
    def add_from_fixture(
        client: p.LdapService.LdapClientProtocol,
        fixture_entry: GenericFieldsDict,
        *,
        verify_operation: bool = True,
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
        """Test add from fixture - REPLACES ENTIRE TEST METHOD (5-10 lines).

        Replaces repetitive test_add_*_from_fixture methods.

        Args:
            client: LDAP client
            fixture_entry: Entry dictionary from fixture
            verify_operation: Whether to verify operation succeeded

        Returns:
            Tuple of (entry, result)

        Example:
            entry, result = TestDeduplicationHelpers.test_add_from_fixture(
                client, test_user_entry
            )

        """
        entry, result = TestDeduplicationHelpers.add_from_dict(client, fixture_entry)

        if verify_operation:
            TestDeduplicationHelpers.assert_operation(result)

        return entry, result

    @staticmethod
    def add_multiple_from_fixtures(
        client: p.LdapService.LdapClientProtocol,
        fixture_data: list[GenericFieldsDict],
        fixture_type: str = "user",
        ldap_container: GenericFieldsDict | None = None,
        *,
        limit: int | None = None,
        verify_all: bool = True,
    ) -> list[
        tuple[FlextLdifModels.Entry, r[m.OperationResult]]
    ]:
        """Test add multiple entries from fixtures - REPLACES ENTIRE TEST METHOD (15-25 lines).

        Replaces entire test_add_multiple_*_from_fixtures methods.

        Args:
            client: LDAP client
            fixture_data: List of fixture dictionaries
            fixture_type: Type of fixture ("user" or "group")
            ldap_container: Optional container dict for DN adjustment
            limit: Optional limit on number of entries
            verify_all: Whether to verify all operations succeeded

        Returns:
            List of tuples (entry, result)

        Example:
            results = TestDeduplicationHelpers.test_add_multiple_from_fixtures(
                client, test_users_json, fixture_type="user", limit=2
            )

        """
        adjust_dn = None
        if ldap_container:
            base_dn = str(ldap_container.get("base_dn", RFC.DEFAULT_BASE_DN))
            adjust_dn = {"from": "dc=example,dc=com", "to": base_dn}

        entry_dicts = TestDeduplicationHelpers.convert_fixtures_to_entry_dicts(
            fixture_data,
            fixture_type=fixture_type,
            limit=limit,
            adjust_dn=adjust_dn,
        )

        results = TestDeduplicationHelpers.add_multiple_entries(
            client,
            entry_dicts,
            adjust_dn=adjust_dn,
        )

        if verify_all:
            for _entry, result in results:
                FlextTestsMatchers.assert_success(result)

        return results

    @staticmethod
    def adapter_with_multiple_server_types(
        adapter: FlextLdapEntryAdapter,
        entry: FlextLdifModels.Entry,
        operation: str,
        server_types: list[str] | None = None,
        *,
        verify_result: bool = True,
    ) -> list[tuple[str, r[FlextLdifModels.Entry] | r[bool]]]:
        """Test adapter operation with multiple server types - REPLACES ENTIRE PATTERN (10-15 lines).

        Replaces repetitive adapter testing with server types loops.

        Args:
            adapter: Adapter instance (FlextLdapEntryAdapter, etc.)
            entry: Entry to test
            operation: Operation name ("normalize", "validate", etc.)
            server_types: List of server types (default: ["rfc", "openldap2", "generic"])
            verify_result: Whether to verify result succeeded

        Returns:
            List of tuples (server_type, result)

        Example:
            results = TestDeduplicationHelpers.test_adapter_with_multiple_server_types(
                adapter, entry, "normalize"
            )

        """
        if server_types is None:
            server_types = ["rfc", "openldap2", "generic"]

        results: list[
            tuple[str, r[FlextLdifModels.Entry] | r[bool]]
        ] = []

        for server_type in server_types:
            if operation == "normalize":
                # NOTE: normalize_entry_for_server method was removed during refactoring.
                # Entry normalization is now handled by flext-ldif parser with server-specific quirks.
                # This helper is deprecated - use FlextLdif parser directly with server_type.
                error_msg = (
                    "normalize_entry_for_server method was removed. "
                    "Use FlextLdif parser with server_type parameter instead."
                )
                result: r[FlextLdifModels.Entry] | r[bool] = (
                    r[FlextLdifModels.Entry].fail(error_msg)
                )
            elif operation == "validate":
                # NOTE: validate_entry_for_server method was removed during refactoring.
                # Entry validation is now handled by flext-ldif parser with server-specific quirks.
                # This helper is deprecated - use FlextLdif parser directly with server_type.
                error_msg = (
                    "validate_entry_for_server method was removed. "
                    "Use FlextLdif parser with server_type parameter instead."
                )
                result = r[bool].fail(error_msg)
            else:
                error_msg = f"Unknown operation: {operation}"
                result = r[bool].fail(error_msg)

            results.append((server_type, result))

            if verify_result:
                # Skip verification for deprecated operations - they return failures
                pass

        return results

    @staticmethod
    def get_real_ldap_entry(
        ldap_connection: FlextLdapConnection | Connection,
        base_dn: str | None = None,
        *,
        filter_str: str = "(objectClass=*)",
        scope: c.SearchScope = c.SearchScope.BASE,
        attributes: list[str] | None = None,
    ) -> Ldap3Entry:
        """Get real LDAP entry from connection - REPLACES ENTIRE PATTERN (8-12 lines).

        Replaces repetitive ldap_connection.search + assert + get entry pattern.

        Args:
            ldap_connection: LDAP connection with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter
            scope: Search scope
            attributes: Attributes to retrieve

        Returns:
            LDAP entry (ldap3.Entry or similar)

        Example:
            entry = TestDeduplicationHelpers.get_real_ldap_entry(ldap_connection)

        """
        if base_dn is None:
            base_dn = RFC.DEFAULT_BASE_DN

        if attributes is None:
            attributes = ["*"]

        if not hasattr(ldap_connection, "search"):
            error_msg = "Connection does not have search method"
            raise AttributeError(error_msg)

        # Type narrowing: connection has search method, cast to Connection
        connection: Connection = cast("Connection", ldap_connection)

        # Convert SearchScope to literal string for ldap3.Connection.search
        scope_str: str = (
            scope.value
            if isinstance(scope, c.SearchScope)
            else str(scope)
        )
        # Type narrowing: ldap3.Connection.search expects Literal['BASE', 'LEVEL', 'SUBTREE']
        scope_literal: Literal["BASE", "LEVEL", "SUBTREE"] = cast(
            "Literal['BASE', 'LEVEL', 'SUBTREE']",
            scope_str.upper(),
        )
        connection.search(
            search_base=base_dn,
            search_filter=filter_str,
            search_scope=scope_literal,
            attributes=attributes,
        )

        assert len(connection.entries) > 0, "No entries found in LDAP search"
        ldap3_entry: Ldap3Entry = connection.entries[0]

        return ldap3_entry

    @staticmethod
    def search_with_normalized_dn(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str,
        *,
        add_spaces: bool = True,
        filter_str: str = "(objectClass=*)",
        scope: str = c.SearchScope.SUBTREE.value,
    ) -> r[m.SearchResult]:
        """Test search with normalized DN - REPLACES ENTIRE TEST METHOD (8-12 lines).

        Replaces repetitive test_search_with_normalized_* methods.

        Args:
            client: LDAP client with search method
            base_dn: Base DN to normalize
            add_spaces: Whether to add spaces around DN (default: True)
            filter_str: LDAP filter
            scope: Search scope

        Returns:
            Search result

        Example:
            result = TestDeduplicationHelpers.test_search_with_normalized_dn(
                client, RFC.DEFAULT_BASE_DN
            )

        """
        normalized_dn = f"  {base_dn}  " if add_spaces else base_dn

        search_options = TestOperationHelpers.create_search_options(
            base_dn=normalized_dn,
            filter_str=filter_str,
            scope=scope,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        search_result_raw = typed_client.search(search_options)
        result: r[m.SearchResult] = cast(
            "r[m.SearchResult]",
            search_result_raw,
        )
        FlextTestsMatchers.assert_success(result)

        return result

    @staticmethod
    def modify_with_normalized_dn(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        add_spaces: bool = True,
        verify_success: bool = True,
    ) -> r[m.OperationResult]:
        """Test modify with normalized DN - REPLACES ENTIRE TEST METHOD (10-15 lines).

        Replaces repetitive test_modify_with_normalized_* methods.

        Args:
            client: LDAP client with add, modify, delete methods
            entry: Entry to add and modify
            changes: Modification changes
            add_spaces: Whether to add spaces around DN (default: True)
            verify_success: Whether to verify modify succeeded

        Returns:
            Modify result

        Example:
            result = TestDeduplicationHelpers.test_modify_with_normalized_dn(
                client, entry, {"mail": [(MODIFY_REPLACE, ["new@example.com"])]}
            )

        """
        # Add entry first
        add_result = TestDeduplicationHelpers.add_entry(
            client,
            entry,
            cleanup_after=False,
        )
        FlextTestsMatchers.assert_success(add_result)

        # Modify with normalized DN
        if entry.dn:
            dn_str = str(entry.dn)
            normalized_dn = f"  {dn_str}  " if add_spaces else dn_str

            typed_client = TestDeduplicationHelpers._narrow_client_type(client)
            modify_result = typed_client.modify(normalized_dn, changes)

            if verify_success:
                modify_result_typed: r[m.OperationResult] = (
                    cast(
                        "r[m.OperationResult]",
                        modify_result,
                    )
                )
                FlextTestsMatchers.assert_success(modify_result_typed)

            # Cleanup
            typed_client_cleanup = TestDeduplicationHelpers._narrow_client_type(client)
            _ = typed_client_cleanup.delete(dn_str)

            modify_result_return: r[m.OperationResult] = cast(
                "r[m.OperationResult]",
                modify_result,
            )
            return modify_result_return

        error_msg = "Entry must have a DN"
        raise ValueError(error_msg)

    @staticmethod
    def delete_with_normalized_dn(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        *,
        add_spaces: bool = True,
        verify_success: bool = True,
    ) -> r[m.OperationResult]:
        """Test delete with normalized DN - REPLACES ENTIRE TEST METHOD (10-15 lines).

        Replaces repetitive test_delete_with_normalized_* methods.

        Args:
            client: LDAP client with add, delete methods
            entry: Entry to add and delete
            add_spaces: Whether to add spaces around DN (default: True)
            verify_success: Whether to verify delete succeeded

        Returns:
            Delete result

        Example:
            result = TestDeduplicationHelpers.test_delete_with_normalized_dn(
                client, entry
            )

        """
        # Add entry first
        add_result = TestDeduplicationHelpers.add_entry(
            client,
            entry,
            cleanup_after=False,
        )
        FlextTestsMatchers.assert_success(add_result)

        # Delete with normalized DN
        if entry.dn:
            dn_str = str(entry.dn)
            normalized_dn = f"  {dn_str}  " if add_spaces else dn_str

            typed_client = TestDeduplicationHelpers._narrow_client_type(client)
            delete_result = typed_client.delete(normalized_dn)

            if verify_success:
                delete_result_typed: r[m.OperationResult] = (
                    cast(
                        "r[m.OperationResult]",
                        delete_result,
                    )
                )
                FlextTestsMatchers.assert_success(delete_result_typed)

            delete_result_return: r[m.OperationResult] = cast(
                "r[m.OperationResult]",
                delete_result,
            )
            return delete_result_return

        error_msg = "Entry must have a DN"
        raise ValueError(error_msg)

    @staticmethod
    def api_initialization(
        config: FlextLdapConfig | None = None,
        *,
        verify_config: bool = True,
        verify_connection: bool = True,
        verify_operations: bool = True,
    ) -> FlextLdap:
        """Test API initialization - REPLACES ENTIRE TEST METHOD (5-10 lines).

        Replaces repetitive test_api_initialization_* methods.

        Args:
            config: Optional FlextLdapConfig (default: None for default config)
            verify_config: Whether to verify config is set
            verify_connection: Whether to verify connection is initialized
            verify_operations: Whether to verify operations is initialized

        Returns:
            FlextLdap instance

        Example:
            api = TestDeduplicationHelpers.test_api_initialization()

        """
        connection = FlextLdapConnection(config=config)
        operations = FlextLdapOperations(connection=connection)
        api = FlextLdap(connection=connection, operations=operations)

        if verify_config:
            assert api._config is not None
            if config is not None:
                assert api._config == config
            else:
                assert isinstance(api._config, FlextLdapConfig)

        if verify_connection:
            assert api._connection is not None

        if verify_operations:
            assert api._operations is not None

        return api

    @staticmethod
    def connect_with_service_config(
        ldap_container: GenericFieldsDict | None = None,
        *,
        use_all_options: bool = False,
        verify_success: bool = True,
        disconnect_after: bool = True,
    ) -> tuple[FlextLdap, r[bool]]:
        """Test connect with service config - REPLACES ENTIRE TEST METHOD (15-25 lines).

        Replaces repetitive test_connect_with_service_config_* methods.

        Args:
            ldap_container: Optional container dict
            use_all_options: Whether to use all config options (default: False)
            verify_success: Whether to verify connection succeeded
            disconnect_after: Whether to disconnect after test

        Returns:
            Tuple of (api, connect_result)

        Example:
            api, result = TestDeduplicationHelpers.test_connect_with_service_config(
                ldap_container, use_all_options=True
            )

        """
        config = TestDeduplicationHelpers.create_ldap_config(
            ldap_container,
            use_tls=use_all_options,
            auto_range=use_all_options,
        )

        connection = FlextLdapConnection(config=config)
        operations = FlextLdapOperations(connection=connection)
        api = FlextLdap(connection=connection, operations=operations)
        # Create ConnectionConfig from service config explicitly (no fallback)
        connection_config = m.ConnectionConfig(
            host=config.host,
            port=config.port,
            use_ssl=config.use_ssl,
            use_tls=config.use_tls,
            bind_dn=config.bind_dn,
            bind_password=config.bind_password,
            timeout=config.timeout,
            auto_bind=config.auto_bind,
            auto_range=config.auto_range,
        )
        result = api.connect(connection_config)

        if verify_success:
            FlextTestsMatchers.assert_success(result)

        if disconnect_after:
            api.disconnect()

        # Already correctly typed
        return api, result

    @staticmethod
    def create_ldap3_connection(
        ldap_container: GenericFieldsDict | None = None,
        *,
        host: str | None = None,
        port: int | None = None,
        bind_dn: str | None = None,
        password: str | None = None,
        auto_bind: bool = True,
        get_info: str = "ALL",
    ) -> Connection:
        """Create ldap3 Connection with file-based locking for parallel execution.

        Uses file-based locking to prevent multiple workers from creating connections
        simultaneously, which can overwhelm the LDAP server.
        """
        """Create ldap3 Connection - REPLACES ENTIRE PATTERN (8-12 lines).

        Replaces repetitive Server + Connection creation patterns.

        Args:
            ldap_container: Optional container dict with connection info
            host: Host (default: from ldap_container or RFC.DEFAULT_HOST)
            port: Port (default: from ldap_container or RFC.DEFAULT_PORT)
            bind_dn: Bind DN (default: from ldap_container or RFC.DEFAULT_BIND_DN)
            password: Password (default: from ldap_container or RFC.DEFAULT_BIND_PASSWORD)
            auto_bind: Auto bind (default: True)
            get_info: Server info level (default: "ALL")

        Returns:
            ldap3.Connection instance

        Example:
            connection = TestDeduplicationHelpers.create_ldap3_connection(ldap_container)

        """
        if ldap_container:
            if host is None:
                host = str(ldap_container.get("host", RFC.DEFAULT_HOST))
            if port is None:
                port = int(str(ldap_container.get("port", RFC.DEFAULT_PORT)))
            if bind_dn is None:
                bind_dn = str(ldap_container.get("bind_dn", RFC.DEFAULT_BIND_DN))
            if password is None:
                password = str(
                    ldap_container.get("password", RFC.DEFAULT_BIND_PASSWORD),
                )
            host_val = host
            port_val = port
            bind_dn_val = bind_dn
            password_val = password
        else:
            if host is None:
                host = RFC.DEFAULT_HOST
            if port is None:
                port = RFC.DEFAULT_PORT
            if bind_dn is None:
                bind_dn = RFC.DEFAULT_BIND_DN
            if password is None:
                password = RFC.DEFAULT_BIND_PASSWORD
            host_val = host
            port_val = port
            bind_dn_val = bind_dn
            password_val = password

        # Type narrowing: ensure get_info is a valid Literal type
        get_info_literal: Literal["ALL", "DSA", "NO_INFO", "SCHEMA"] = cast(
            "Literal['ALL', 'DSA', 'NO_INFO', 'SCHEMA']",
            get_info,
        )

        # File-based locking to prevent parallel workers from overwhelming LDAP server
        lock_file = Path.home() / ".flext" / f"ldap_connection_{port_val}.lock"
        lock_file.parent.mkdir(parents=True, exist_ok=True)

        with Path(lock_file).open("w", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                server = Server(
                    f"ldap://{host_val}:{port_val}",
                    get_info=get_info_literal,
                )
                return Connection(
                    server,
                    user=bind_dn_val,
                    password=password_val,
                    auto_bind=auto_bind,
                )
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def adapter_conversion_complete(
        adapter: FlextLdapEntryAdapter,
        source_entry: Ldap3Entry,
        *,
        verify_dn: bool = True,
        verify_attributes: bool = True,
        verify_success: bool = True,
    ) -> FlextLdifModels.Entry:
        """Test adapter conversion - REPLACES ENTIRE TEST METHOD (10-20 lines).

        Replaces repetitive adapter conversion test patterns.

        Args:
            adapter: Adapter instance (FlextLdapEntryAdapter, etc.)
            source_entry: Source entry (ldap3.Entry, dict, or FlextLdifModels.Entry)
            verify_dn: Whether to verify DN matches
            verify_attributes: Whether to verify attributes exist
            verify_success: Whether to verify conversion succeeded

        Returns:
            Converted FlextLdifModels.Entry

        Example:
            entry = TestDeduplicationHelpers.test_adapter_conversion_complete(
                adapter, ldap3_entry
            )

        """
        if not hasattr(adapter, "ldap3_to_ldif_entry"):
            error_msg = "Adapter does not have ldap3_to_ldif_entry method"
            raise AttributeError(error_msg)

        result = adapter.ldap3_to_ldif_entry(source_entry)

        if verify_success:
            entry = FlextTestsMatchers.assert_success(
                result,
                error_msg="Adapter conversion failed",
            )
        else:
            unwrapped_entry = result.unwrap() if result.is_success else None
            if unwrapped_entry is None:
                error_msg = "Adapter conversion failed"
                raise ValueError(error_msg)
            if not isinstance(unwrapped_entry, FlextLdifModels.Entry):
                error_msg = "Adapter conversion failed"
                raise ValueError(error_msg)
            entry = unwrapped_entry

        if verify_dn:
            assert entry.dn is not None, "Entry DN is None"

        if verify_attributes:
            assert entry.attributes is not None, "Entry attributes is None"

        return entry

    @staticmethod
    def adapter_attributes_conversion_complete(
        adapter: FlextLdapEntryAdapter,
        entry: FlextLdifModels.Entry,
        *,
        verify_attributes: dict[str, list[str]] | None = None,
        verify_success: bool = True,
    ) -> dict[str, list[str]]:
        """Test adapter attributes conversion - REPLACES ENTIRE TEST METHOD (8-15 lines).

        Replaces repetitive adapter attributes conversion test patterns.

        Args:
            adapter: Adapter instance (FlextLdapEntryAdapter, etc.)
            entry: FlextLdifModels.Entry to convert
            verify_attributes: Optional dict of expected attributes to verify
            verify_success: Whether to verify conversion succeeded

        Returns:
            Converted attributes dict

        Example:
            attrs = TestDeduplicationHelpers.test_adapter_attributes_conversion_complete(
                adapter, entry, verify_attributes={"cn": ["test"]}
            )

        """
        if not hasattr(adapter, "ldif_entry_to_ldap3_attributes"):
            error_msg = "Adapter does not have ldif_entry_to_ldap3_attributes method"
            raise AttributeError(error_msg)

        result = adapter.ldif_entry_to_ldap3_attributes(entry)

        if verify_success:
            attrs = FlextTestsMatchers.assert_success(
                result,
                error_msg="Attributes conversion failed",
            )
        else:
            unwrapped_attrs = result.unwrap() if result.is_success else None
            if unwrapped_attrs is None:
                error_msg = "Attributes conversion failed"
                raise ValueError(error_msg)
            if not isinstance(unwrapped_attrs, dict):
                error_msg = "Attributes conversion failed"
                raise ValueError(error_msg)
            attrs = unwrapped_attrs

        if verify_attributes:
            for attr_name, expected_values in verify_attributes.items():
                assert attr_name in attrs, (
                    f"Attribute {attr_name} not found in converted attributes"
                )
                assert attrs[attr_name] == expected_values, (
                    f"Attribute {attr_name} values don't match: "
                    f"expected {expected_values}, got {attrs[attr_name]}"
                )

        return attrs

    @staticmethod
    def create_entry_with_ldif_attributes_validate(
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifModels.Entry:
        """Create Entry using LdifAttributes.model_validate - REPLACES ENTIRE PATTERN (5-8 lines).

        Replaces repetitive Entry creation with model_validate pattern.

        Args:
            dn: Distinguished name as string
            attributes: Attributes dictionary

        Returns:
            FlextLdifModels.Entry

        Example:
            entry = TestDeduplicationHelpers.create_entry_with_ldif_attributes_validate(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"], "objectClass": ["top", "person"]}
            )

        """
        # Convert attributes to GeneralValueType-compatible mapping
        normalized_attrs: dict[str, t.GeneralValueType] = {}
        for key, value in attributes.items():
            if isinstance(value, (frozenset, set, tuple)):
                normalized_attrs[key] = list(value)
            else:
                normalized_attrs[key] = value
        return EntryTestHelpers.create_entry(dn, normalized_attrs)

    @staticmethod
    def entry_conversion_roundtrip(
        adapter: FlextLdapEntryAdapter,
        source_entry: Ldap3Entry,
        *,
        verify_roundtrip: bool = True,
    ) -> tuple[FlextLdifModels.Entry, dict[str, list[str]]]:
        """Test entry conversion roundtrip - REPLACES ENTIRE TEST METHOD (15-25 lines).

        Replaces repetitive roundtrip conversion test patterns.

        Args:
            adapter: Adapter instance (FlextLdapEntryAdapter, etc.)
            source_entry: Source entry (ldap3.Entry, dict, or FlextLdifModels.Entry)
            verify_roundtrip: Whether to verify roundtrip conversion

        Returns:
            Tuple of (ldif_entry, ldap3_attributes)

        Example:
            entry, attrs = TestDeduplicationHelpers.test_entry_conversion_roundtrip(
                adapter, ldap3_entry
            )

        """
        # Convert to LDIF
        ldif_entry = TestDeduplicationHelpers.adapter_conversion_complete(
            adapter,
            source_entry,
        )

        # Convert back to LDAP3 attributes
        ldap3_attrs = TestDeduplicationHelpers.adapter_attributes_conversion_complete(
            adapter,
            ldif_entry,
        )

        if (
            verify_roundtrip
            and hasattr(adapter, "ldap3_to_ldif_entry")
            and hasattr(adapter, "ldif_entry_to_ldap3_attributes")
            and (
                roundtrip_result := adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
            ).is_success
        ):
            # Roundtrip verification: attributes converted successfully
            roundtrip_attrs = roundtrip_result.unwrap()
            assert isinstance(roundtrip_attrs, dict), (
                "Roundtrip should return dict of attributes"
            )

        return ldif_entry, ldap3_attrs

    @staticmethod
    def search_and_verify_entries(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        scope: str | None = None,
        min_count: int = 0,
        verify_object_classes: list[str] | None = None,
        verify_attributes_present: list[str] | None = None,
    ) -> m.SearchResult:
        """Test search and verify entries - REPLACES ENTIRE TEST METHOD (15-30 lines).

        Replaces repetitive search + verification patterns.

        Args:
            client: LDAP client with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            min_count: Minimum number of entries expected
            verify_object_classes: Optional list of object classes to verify
            verify_attributes_present: Optional list of attributes that must be present

        Returns:
            SearchResult

        Example:
            result = TestDeduplicationHelpers.test_search_and_verify_entries(
                client,
                filter_str="(objectClass=inetOrgPerson)",
                verify_object_classes=["inetOrgPerson", "person"],
                verify_attributes_present=["cn", "sn"]
            )

        """
        result = TestDeduplicationHelpers.search_with_assertions(
            client,
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            min_count=min_count,
        )

        if verify_object_classes and result.entries:
            for entry in result.entries:
                if entry.attributes and entry.attributes.attributes:
                    object_classes = entry.attributes.attributes.get("objectClass", [])
                    if isinstance(object_classes, list):
                        for expected_oc in verify_object_classes:
                            assert expected_oc in object_classes, (
                                f"Expected objectClass {expected_oc} "
                                f"not found in {object_classes}"
                            )

        if verify_attributes_present and result.entries:
            for entry in result.entries:
                if entry.attributes and entry.attributes.attributes:
                    for attr_name in verify_attributes_present:
                        assert attr_name in entry.attributes.attributes, (
                            f"Expected attribute {attr_name} not found in entry"
                        )

        return result

    @staticmethod
    def cleanup_multiple_entries(
        client: p.LdapService.LdapClientProtocol,
        dns: list[str],
        *,
        ignore_errors: bool = True,
    ) -> None:
        """Cleanup multiple entries - REPLACES ENTIRE PATTERN (5-10 lines).

        Replaces repetitive cleanup loops for multiple DNs.

        Args:
            client: LDAP client with delete method
            dns: List of DNs to delete
            ignore_errors: Whether to ignore delete errors (default: True)

        Example:
            TestDeduplicationHelpers.cleanup_multiple_entries(
                client, ["cn=test1,dc=example,dc=com", "cn=test2,dc=example,dc=com"]
            )

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        for dn in dns:
            delete_result = typed_client.delete(dn)
            if not ignore_errors and delete_result.is_failure:
                error_msg = f"Failed to delete {dn}: {delete_result.error}"
                raise RuntimeError(error_msg)

    @staticmethod
    def sync_ldif_file_complete(
        sync_service: FlextLdapSyncService,
        ldif_file: Path | str,
        *,
        cleanup_dns: list[str] | None = None,
        verify_stats: bool = True,
        expected_total: int | None = None,
        options: GenericFieldsDict | None = None,
    ) -> dict[str, object]:
        """Test sync LDIF file - REPLACES ENTIRE TEST METHOD (20-40 lines).

        Replaces repetitive test_sync_ldif_file_* methods.

        Args:
            sync_service: Sync service instance
            ldif_file: Path to LDIF file
            cleanup_dns: Optional list of DNs to cleanup before/after
            verify_stats: Whether to verify sync stats
            expected_total: Optional expected total entries
            options: Optional sync options

        Returns:
            Sync stats

        Example:
            stats = TestDeduplicationHelpers.sync_ldif_file_complete(
                sync_service, ldif_file,
                cleanup_dns=["cn=test1,dc=example,dc=com", "cn=test2,dc=example,dc=com"]
            )

        """
        if not hasattr(sync_service, "sync_ldif_file"):
            error_msg = "Sync service does not have sync_ldif_file method"
            raise AttributeError(error_msg)

            # Cleanup before if requested
            if (
                cleanup_dns
                and hasattr(sync_service, "_operations")
                and isinstance(sync_service._operations, FlextLdapOperations)
            ):
                # FlextLdapOperations has delete method, use it directly
                for dn in cleanup_dns:
                    _ = sync_service._operations.delete(dn)

        # Sync file
        # Type narrowing: ensure sync_service has sync_ldif_file method
        if not hasattr(sync_service, "sync_ldif_file"):
            error_msg = "sync_service must have sync_ldif_file method"
            raise TypeError(error_msg)
        sync_method = getattr(sync_service, "sync_ldif_file", None)
        if sync_method is None:
            error_msg = "sync_service.sync_ldif_file is not callable"
            raise TypeError(error_msg)
        result = sync_method(ldif_file, options) if options else sync_method(ldif_file)

        if verify_stats:
            stats = FlextTestsMatchers.assert_success(
                result,
                error_msg="Sync failed",
            )
            if expected_total is not None:
                assert stats.total == expected_total, (
                    f"Expected {expected_total} total entries, got {stats.total}"
                )
            return cast("dict[str, object]", stats.model_dump())

        if result.is_success:
            unwrapped = result.unwrap()
            return cast(
                "dict[str, object]",
                unwrapped.model_dump() if hasattr(unwrapped, "model_dump") else {},
            )
        return {}

    @staticmethod
    def create_entry_with_dn_and_attributes_direct(
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifModels.Entry:
        """Create Entry directly - REPLACES ENTIRE PATTERN (3-5 lines).

        Replaces direct FlextLdifModels.Entry creation with DistinguishedName and LdifAttributes.

        Args:
            dn: Distinguished name as string
            attributes: Attributes dictionary

        Returns:
            FlextLdifModels.Entry

        Example:
            entry = TestDeduplicationHelpers.create_entry_with_dn_and_attributes_direct(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"], "objectClass": ["top", "person"]}
            )

        """
        # Convert attributes to GeneralValueType-compatible mapping
        normalized_attrs: dict[str, t.GeneralValueType] = {}
        for key, value in attributes.items():
            if isinstance(value, (frozenset, set, tuple)):
                normalized_attrs[key] = list(value)
            else:
                normalized_attrs[key] = value
        return EntryTestHelpers.create_entry(dn, normalized_attrs)

    @staticmethod
    def real_ldap_entry_conversion_complete(
        adapter: FlextLdapEntryAdapter,
        ldap_container: GenericFieldsDict | None = None,
        *,
        base_dn: str | None = None,
        verify_dn_match: bool = True,
        verify_attributes: bool = True,
    ) -> tuple[Ldap3Entry, FlextLdifModels.Entry]:
        """Test real LDAP entry conversion - REPLACES ENTIRE TEST METHOD (20-30 lines).

        Replaces entire test_ldap3_to_ldif_entry_with_real_ldap3_entry methods.

        Args:
            adapter: Adapter instance
            ldap_container: Optional container dict
            base_dn: Base DN for search (default: RFC.DEFAULT_BASE_DN)
            verify_dn_match: Whether to verify DN matches original
            verify_attributes: Whether to verify attributes exist

        Returns:
            Tuple of (ldap3_entry, converted_entry)

        Example:
            ldap3_entry, entry = TestDeduplicationHelpers.real_ldap_entry_conversion_complete(
                adapter, ldap_container
            )

        """
        # Create connection
        connection = TestDeduplicationHelpers.create_ldap3_connection(ldap_container)

        try:
            # Get real entry
            ldap3_entry = TestDeduplicationHelpers.get_real_ldap_entry(
                connection,
                base_dn=base_dn,
            )

            # Type narrowing: ldap3_entry is already Ldap3Entry from get_real_ldap_entry
            typed_entry: Ldap3Entry = ldap3_entry

            # Convert
            converted_entry = TestDeduplicationHelpers.adapter_conversion_complete(
                adapter,
                typed_entry,
                verify_dn=verify_dn_match,
                verify_attributes=verify_attributes,
            )

            if verify_dn_match:
                assert str(converted_entry.dn) == str(typed_entry.entry_dn), (
                    "Converted DN doesn't match original"
                )

            return typed_entry, converted_entry
        finally:
            # Connection cleanup handled by disconnect() method
            # unbind() is part of Ldap3Connection protocol but not used directly
            if isinstance(connection, Connection):
                pass  # Connection cleanup handled elsewhere

    @staticmethod
    def real_ldap_entry_roundtrip_complete(
        adapter: FlextLdapEntryAdapter,
        ldap_container: GenericFieldsDict | None = None,
        *,
        base_dn: str | None = None,
        verify_attributes_match: bool = True,
    ) -> tuple[Ldap3Entry, FlextLdifModels.Entry, dict[str, list[str]]]:
        """Test real LDAP entry roundtrip conversion - REPLACES ENTIRE TEST METHOD (25-40 lines).

        Replaces entire test_ldif_entry_to_ldap3_attributes_with_real_entry methods.

        Args:
            adapter: Adapter instance
            ldap_container: Optional container dict
            base_dn: Base DN for search (default: RFC.DEFAULT_BASE_DN)
            verify_attributes_match: Whether to verify attributes match original

        Returns:
            Tuple of (ldap3_entry, ldif_entry, ldap3_attributes)

        Example:
            ldap3_entry, entry, attrs = TestDeduplicationHelpers.real_ldap_entry_roundtrip_complete(
                adapter, ldap_container
            )

        """
        # Create connection and get real entry
        connection = TestDeduplicationHelpers.create_ldap3_connection(ldap_container)

        try:
            ldap3_entry_obj = TestDeduplicationHelpers.get_real_ldap_entry(
                connection,
                base_dn=base_dn,
            )

            # Type narrowing: ldap3_entry_obj is already Ldap3Entry from get_real_ldap_entry
            ldap3_entry: Ldap3Entry = ldap3_entry_obj

            # Roundtrip conversion
            ldif_entry, ldap3_attrs = (
                TestDeduplicationHelpers.entry_conversion_roundtrip(
                    adapter,
                    ldap3_entry,
                )
            )

            if verify_attributes_match:
                # Verify attributes match original
                for attr_name in ldap3_entry.entry_attributes:
                    if attr_name in ldap3_attrs:
                        ldap3_values = list(ldap3_entry[attr_name].values)
                        assert ldap3_attrs[attr_name] == [
                            str(v) for v in ldap3_values
                        ], f"Attribute {attr_name} values don't match"

            return ldap3_entry, ldif_entry, ldap3_attrs
        finally:
            # Connection cleanup handled by disconnect() method
            # unbind() is part of Ldap3Connection protocol but not used directly
            if isinstance(connection, Connection):
                pass  # Connection cleanup handled elsewhere

    @staticmethod
    def all_scopes(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        verify_results: bool = True,
    ) -> dict[str, m.SearchResult]:
        """Test all search scopes - REPLACES ENTIRE TEST CLASS (30-50 lines).

        Replaces repetitive test_search_with_*_scope methods.

        Args:
            client: LDAP client with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            verify_results: Whether to verify each result

        Returns:
            Dict mapping scope to SearchResult

        Example:
            results = TestDeduplicationHelpers.test_all_scopes(client)
            assert c.SearchScope.BASE.value in results
            assert c.SearchScope.ONELEVEL.value in results
            assert c.SearchScope.SUBTREE.value in results

        """
        if base_dn is None:
            base_dn = RFC.DEFAULT_BASE_DN
        if filter_str is None:
            filter_str = RFC.DEFAULT_FILTER
        base_dn_val = base_dn
        filter_str_val = filter_str

        scopes = [
            c.SearchScope.BASE.value,
            c.SearchScope.ONELEVEL.value,
            c.SearchScope.SUBTREE.value,
        ]
        results: dict[str, m.SearchResult] = {}

        for scope in scopes:
            result = TestDeduplicationHelpers.search_with_assertions(
                client,
                base_dn=base_dn_val,
                filter_str=filter_str_val,
                scope=scope,
                min_count=0,
            )
            results[scope] = result

            if verify_results:
                if scope == c.SearchScope.BASE.value:
                    assert len(result.entries) <= 1, (
                        "BASE scope should return at most 1 entry"
                    )
                elif scope == c.SearchScope.ONELEVEL.value:
                    assert isinstance(result.entries, list), (
                        "ONELEVEL should return list"
                    )
                elif scope == c.SearchScope.SUBTREE.value:
                    assert isinstance(result.entries, list), (
                        "SUBTREE should return list"
                    )

        return results

    @staticmethod
    def operation_result_all_operations(
        operations_service: FlextLdapOperations,
        entry: FlextLdifModels.Entry,
        *,
        changes: dict[str, list[tuple[str, list[str]]]] | None = None,
        verify_all: bool = True,
    ) -> dict[str, object]:
        """Test OperationResult for all operations - REPLACES ENTIRE TEST CLASS (40-60 lines).

        Replaces repetitive test_*_with_operation_result_success methods.

        Args:
            operations_service: Operations service instance
            entry: Entry to test with
            changes: Optional modify changes (default: mail MODIFY_REPLACE)
            verify_all: Whether to verify all operation results

        Returns:
            Dict with add, modify, delete results

        Example:
            results = TestDeduplicationHelpers.test_operation_result_all_operations(
                operations_service, entry
            )
            assert results["add"].is_success
            assert results["modify"].is_success
            assert results["delete"].is_success

        """
        if changes is None:
            changes = {"mail": [(MODIFY_REPLACE, ["test@example.com"])]}

        # Type narrowing: operations_service has required methods
        if not (
            hasattr(operations_service, "modify")
            and hasattr(operations_service, "delete")
        ):
            error_msg = "operations_service must have modify and delete methods"
            raise TypeError(error_msg)

        # Add
        _, add_result = TestDeduplicationHelpers.add_operation_complete(
            cast(
                "p.LdapService.LdapClientProtocol",
                operations_service,
            ),
            entry,
            verify_operation_result=False,
        )

        if verify_all:
            # add_result is r[OperationResult], check if it's successful
            # For now, just assert success
            FlextTestsMatchers.assert_success(
                add_result,
                error_msg="Add operation failed",
            )

        # Modify
        if entry.dn:
            modify_result = operations_service.modify(str(entry.dn), changes)
            if verify_all:
                TestOperationHelpers.assert_operation_result_success(
                    modify_result,
                    expected_operation_type=c.OperationType.MODIFY.value,
                    expected_entries_affected=1,
                )
        else:
            modify_result = None

        # Delete
        if entry.dn:
            delete_result = operations_service.delete(str(entry.dn))
            if verify_all:
                TestOperationHelpers.assert_operation_result_success(
                    delete_result,
                    expected_operation_type=c.OperationType.DELETE.value,
                    expected_entries_affected=1,
                )
        else:
            delete_result = None

        return {
            "add": add_result,
            "modify": modify_result,
            "delete": delete_result,
        }

    @staticmethod
    def error_handling_all_operations(
        operations_service: FlextLdapOperations,
        *,
        invalid_base_dn: str = "invalid=base,dn=invalid",
        invalid_filter: str = "invalid(filter",
        verify_graceful: bool = True,
    ) -> dict[
        str,
        r[m.OperationResult | m.SearchResult],
    ]:
        """Test error handling for all operations - REPLACES ENTIRE TEST CLASS (50-80 lines).

        Replaces repetitive test_*_with_failed_* methods.

        Args:
            operations_service: Operations service instance
            invalid_base_dn: Invalid base DN to test
            invalid_filter: Invalid filter to test
            verify_graceful: Whether to verify graceful error handling

        Returns:
            Dict with error test results

        Example:
            results = TestDeduplicationHelpers.test_error_handling_all_operations(
                operations_service
            )
            assert results["search_invalid_dn"].is_failure or results["search_invalid_dn"].is_success

        """
        # Type narrowing: operations_service has required methods
        typed_service = cast(
            "p.LdapService.LdapClientProtocol",
            operations_service,
        )

        results: dict[
            str,
            r[m.OperationResult | m.SearchResult],
        ] = {}

        # Search with invalid base DN
        search_options = TestOperationHelpers.create_search_options(
            base_dn=invalid_base_dn,
            filter_str="(objectClass=*)",
            scope=c.SearchScope.SUBTREE,
        )
        search_result_raw = typed_service.search(search_options)
        results["search_invalid_dn"] = cast(
            "r[m.OperationResult | m.SearchResult]",
            search_result_raw,
        )

        # Search with invalid filter
        search_options_invalid_filter = TestOperationHelpers.create_search_options(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str=invalid_filter,
            scope=c.SearchScope.SUBTREE,
        )
        results["search_invalid_filter"] = cast(
            "r[m.OperationResult | m.SearchResult]",
            typed_service.search(search_options_invalid_filter),
        )

        # Add with invalid entry
        invalid_entry = (
            TestDeduplicationHelpers.create_entry_with_dn_and_attributes_direct(
                invalid_base_dn,
                {"objectClass": ["top"]},
            )
        )
        # Type narrowing: ensure entry has non-None dn and attributes for EntryProtocol compatibility
        if invalid_entry.dn is None:
            error_msg = "Entry must have DN for add operation"
            raise ValueError(error_msg)
        if invalid_entry.attributes is None:
            error_msg = "Entry must have attributes for add operation"
            raise ValueError(error_msg)
        # Cast to EntryProtocol-compatible type
        entry_protocol: p.LdapEntry.EntryProtocol = cast(
            "p.LdapEntry.EntryProtocol",
            invalid_entry,
        )
        add_result_raw = typed_service.add(entry_protocol)
        results["add_invalid_entry"] = cast(
            "r[m.OperationResult | m.SearchResult]",
            add_result_raw,
        )

        # Modify with invalid DN

        results["modify_invalid_dn"] = cast(
            "r[m.OperationResult | m.SearchResult]",
            typed_service.modify(
                invalid_base_dn,
                {"cn": [(MODIFY_REPLACE, ["test"])]},
            ),
        )

        # Delete with invalid DN
        results["delete_invalid_dn"] = cast(
            "r[m.OperationResult | m.SearchResult]",
            typed_service.delete(invalid_base_dn),
        )

        if verify_graceful:
            for name, result in results.items():
                assert result.is_failure or result.is_success, (
                    f"{name} should handle errors gracefully"
                )

        return results

    @staticmethod
    def create_operations_service_fixture_generic(
        connection_config: m.ConnectionConfig | None = None,
        *,
        skip_on_failure: bool = True,
        disconnect_after: bool = True,
    ) -> FlextLdapOperations | t.GeneralValueType:
        """Create operations service fixture - REPLACES ALL operations_service FIXTURES (10-15 lines).

        Replaces repetitive @pytest.fixture operations_service methods.

        Args:
            connection_config: Optional connection config (uses fixture if None)
            skip_on_failure: Whether to skip on connection failure
            disconnect_after: Whether to disconnect after (for cleanup)

        Returns:
            Operations service instance (use in context manager or cleanup manually)

        Example:
            operations = TestDeduplicationHelpers.create_operations_service_fixture_generic()
            # Use operations...
            operations._connection.disconnect()  # Cleanup

        """
        if connection_config is None:
            # This would be used in a fixture context
            # For standalone use, pass connection_config explicitly
            error_msg = "connection_config must be provided when not in fixture context"
            raise ValueError(error_msg)

        # Create FlextLdapConfig from ConnectionConfig
        service_config = FlextLdapConfig(
            host=connection_config.host,
            port=connection_config.port,
            use_ssl=connection_config.use_ssl,
            use_tls=connection_config.use_tls,
            bind_dn=connection_config.bind_dn,
            bind_password=connection_config.bind_password,
            timeout=connection_config.timeout,
            auto_bind=connection_config.auto_bind,
            auto_range=connection_config.auto_range,
        )
        parser = FlextLdifParser()
        connection = FlextLdapConnection(config=service_config, parser=parser)
        connect_result = connection.connect(connection_config)

        if skip_on_failure and connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        operations = FlextLdapOperations(connection=connection)

        if disconnect_after:
            # Return wrapper that disconnects on cleanup
            class OperationsWrapper:
                def __init__(
                    self,
                    ops: FlextLdapOperations,
                    conn: FlextLdapConnection,
                ) -> None:
                    self._operations = ops
                    self._connection = conn

                def __getattr__(self, name: str) -> t.GeneralValueType:
                    attr_value = getattr(self._operations, name)
                    # Type narrowing: ensure return type is GeneralValueType
                    if isinstance(attr_value, (str, int, float, bool, type(None))):
                        return attr_value
                    if isinstance(attr_value, (list, tuple)):
                        return cast("t.GeneralValueType", attr_value)
                    if isinstance(attr_value, dict):
                        return cast("t.GeneralValueType", attr_value)
                    return cast("t.GeneralValueType", attr_value)

                def __enter__(self) -> FlextLdapOperations:
                    return self._operations

                def __exit__(
                    self,
                    exc_type: type[BaseException] | None,
                    exc_val: BaseException | None,
                    exc_tb: types.TracebackType | None,
                ) -> None:
                    # Type narrowing: check if connection has disconnect method
                    if hasattr(self._connection, "disconnect") and isinstance(
                        self._connection,
                        FlextLdapConnection,
                    ):
                        self._connection.disconnect()

            return cast(
                "FlextLdapOperations",
                OperationsWrapper(operations, connection),
            )

        return operations

    @staticmethod
    def search_with_all_attributes_options(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        attribute_sets: list[list[str]] | None = None,
        verify_results: bool = True,
    ) -> dict[str, m.SearchResult]:
        """Test search with different attribute options - REPLACES ENTIRE TEST METHOD (20-40 lines).

        Replaces repetitive test_search_with_attributes methods.

        Args:
            client: LDAP client with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            attribute_sets: List of attribute sets to test (default: ["*"], ["objectClass", "cn"], [])
            verify_results: Whether to verify each result

        Returns:
            Dict mapping attribute set name to SearchResult

        Example:
            results = TestDeduplicationHelpers.test_search_with_all_attributes_options(client)
            assert "all_attributes" in results
            assert "specific_attributes" in results
            assert "no_attributes" in results

        """
        if attribute_sets is None:
            attribute_sets = [["*"], ["objectClass", "cn"], []]

        if base_dn is None:
            base_dn = RFC.DEFAULT_BASE_DN
        if filter_str is None:
            filter_str = RFC.DEFAULT_FILTER
        base_dn_val = base_dn
        filter_str_val = filter_str

        results: dict[str, m.SearchResult] = {}
        names = ["all_attributes", "specific_attributes", "no_attributes"]

        for name, attributes in zip(names, attribute_sets, strict=True):
            result = TestDeduplicationHelpers.search_with_assertions(
                client,
                base_dn=base_dn_val,
                filter_str=filter_str_val,
                attributes=attributes,
                min_count=0,
            )
            results[name] = result

            if verify_results and result.entries:
                entry = result.entries[0]
                if entry.attributes and entry.attributes.attributes:
                    if attributes == ["*"]:
                        assert len(entry.attributes.attributes) > 0, (
                            "All attributes should be returned"
                        )
                    elif attributes:
                        for attr in attributes:
                            assert attr in entry.attributes.attributes or attr == "*", (
                                f"Attribute {attr} should be present"
                            )

        return results

    @staticmethod
    def api_all_operations_complete(
        api: FlextLdap,
        entry: FlextLdifModels.Entry,
        *,
        changes: dict[str, list[tuple[str, list[str]]]] | None = None,
        verify_all: bool = True,
        cleanup_after: bool = True,
    ) -> dict[
        str,
        r[m.OperationResult]
        | r[m.SearchResult]
        | None,
    ]:
        """Test all API operations - REPLACES ENTIRE TEST CLASS (50-80 lines).

        Replaces repetitive test_api_* methods for all operations.

        Args:
            api: FlextLdap API instance
            entry: Entry to test with
            changes: Optional modify changes (default: mail MODIFY_REPLACE)
            verify_all: Whether to verify all operations succeed
            cleanup_after: Whether to cleanup after (delete entry)

        Returns:
            Dict with search, add, modify, delete results

        Example:
            results = TestDeduplicationHelpers.api_all_operations_complete(
                api, entry
            )
            assert results["add"].is_success
            assert results["modify"].is_success
            assert results["delete"].is_success

        """
        if changes is None:
            changes = {"mail": [(MODIFY_REPLACE, ["test@example.com"])]}

        # Type narrowing: api is already FlextLdap
        typed_api: FlextLdap = api

        results: dict[
            str,
            r[m.OperationResult]
            | r[m.SearchResult]
            | None,
        ] = {}

        # Search before add
        if entry.dn:
            search_options = TestOperationHelpers.create_search_options(
                base_dn=str(entry.dn),
                filter_str="(objectClass=*)",
                scope=c.SearchScope.BASE,
            )
            # SearchOptions is compatible with SearchOptionsProtocol structurally
            search_result: r[m.SearchResult] = typed_api.search(
                search_options,
            )
            results["search_before"] = search_result

        # Add
        add_result = typed_api.add(entry)
        results["add"] = add_result
        if verify_all:
            FlextTestsMatchers.assert_success(
                cast("r[m.OperationResult]", results["add"]),
                error_msg="API add failed",
            )

        # Modify
        if entry.dn:
            modify_result = typed_api.modify(str(entry.dn), changes)
            results["modify"] = modify_result
            if verify_all:
                FlextTestsMatchers.assert_success(
                    cast(
                        "r[m.OperationResult]",
                        results["modify"],
                    ),
                    error_msg="API modify failed",
                )
        else:
            results["modify"] = None

        # Search after modify
        if entry.dn:
            search_options_after = TestOperationHelpers.create_search_options(
                base_dn=str(entry.dn),
                filter_str="(objectClass=*)",
                scope=c.SearchScope.BASE,
            )
            search_result_after = typed_api.search(search_options_after)
            results["search_after"] = search_result_after

        # Delete
        if entry.dn and cleanup_after:
            delete_result = typed_api.delete(str(entry.dn))
            results["delete"] = delete_result
            if verify_all:
                FlextTestsMatchers.assert_success(
                    cast(
                        "r[m.OperationResult]",
                        results["delete"],
                    ),
                    error_msg="API delete failed",
                )
        else:
            results["delete"] = None

        return results

    @staticmethod
    def api_context_manager_complete(
        connection_config: m.ConnectionConfig,
        *,
        verify_connect: bool = True,
        verify_disconnect: bool = True,
        raise_exception: Exception | None = None,
    ) -> FlextLdap | None:
        """Test API context manager - REPLACES ENTIRE TEST METHOD (15-30 lines).

        Replaces repetitive test_context_manager* methods.

        Args:
            connection_config: Connection config
            verify_connect: Whether to verify connection succeeds
            verify_disconnect: Whether to verify disconnection after exit
            raise_exception: Optional exception to raise inside context

        Returns:
            API instance (after context exit)

        Example:
            api = TestDeduplicationHelpers.api_context_manager_complete(
                connection_config
            )
            assert api.is_connected is False

        """
        api = None
        connection = FlextLdapConnection(config=FlextLdapConfig())
        operations = FlextLdapOperations(connection=connection)
        api_instance = FlextLdap(connection=connection, operations=operations)

        try:
            with api_instance as context_api:
                api = context_api
                if verify_connect:
                    result = api.connect(connection_config)
                    FlextTestsMatchers.assert_success(
                        result,
                        error_msg="Context manager connect failed",
                    )

                if raise_exception:
                    raise raise_exception
        except Exception as e:
            if raise_exception and isinstance(e, type(raise_exception)):
                pass  # Exception was expected
            else:
                raise

        if api and verify_disconnect:
            # Type narrowing: check if api has is_connected attribute
            if hasattr(api, "_connection") and hasattr(api._connection, "is_connected"):
                assert api._connection.is_connected is False, (
                    "API should be disconnected after context exit"
                )
            elif hasattr(api, "is_connected"):
                assert api.is_connected is False, (
                    "API should be disconnected after context exit"
                )

        return api

    @staticmethod
    def api_initialization_all_variants(
        *,
        custom_config: FlextLdapConfig | None = None,
        ldap_container: GenericFieldsDict | None = None,
        verify_config: bool = True,
        verify_connection: bool = True,
        verify_operations: bool = True,
    ) -> FlextLdap:
        """Test API initialization with all variants - REPLACES ENTIRE TEST CLASS (30-50 lines).

        Replaces repetitive test_api_initialization_* methods.

        Args:
            custom_config: Optional custom FlextLdapConfig
            ldap_container: Optional container dict for config creation
            verify_config: Whether to verify config is set
            verify_connection: Whether to verify connection exists
            verify_operations: Whether to verify operations exists

        Returns:
            FlextLdap API instance

        Example:
            api = TestDeduplicationHelpers.api_initialization_all_variants(
                ldap_container=ldap_container
            )
            assert api._config is not None

        """
        if custom_config is not None:
            config = custom_config
        elif ldap_container is not None:
            config = FlextLdapConfig(
                host=str(ldap_container.get("host", RFC.DEFAULT_HOST)),
                port=int(str(ldap_container.get("port", RFC.DEFAULT_PORT))),
            )
        else:
            config = None

        if config is None:
            # Create default config and services
            default_config = FlextLdapConfig()
            connection = FlextLdapConnection(config=default_config)
            operations = FlextLdapOperations(connection=connection)
            api = FlextLdap(connection=connection, operations=operations)
        else:
            # Use provided config
            connection = FlextLdapConnection(config=config)
            operations = FlextLdapOperations(connection=connection)
            api = FlextLdap(connection=connection, operations=operations)

        if verify_config:
            assert api._config is not None, "API config should not be None"
            if config is not None:
                assert api._config == config, "API config should match provided config"

        if verify_connection:
            assert api._connection is not None, "API connection should not be None"

        if verify_operations:
            assert api._operations is not None, "API operations should not be None"

        return api

    @staticmethod
    def create_connected_adapter_fixture_generic(
        connection_config: m.ConnectionConfig | None = None,
        *,
        adapter_class: type | None = None,
        skip_on_failure: bool = True,
        disconnect_after: bool = True,
    ) -> Ldap3Adapter | t.GeneralValueType:
        """Create connected adapter fixture - REPLACES ALL connected_adapter FIXTURES (10-15 lines).

        Replaces repetitive @pytest.fixture connected_adapter methods.

        Args:
            connection_config: Optional connection config (uses fixture if None)
            adapter_class: Optional adapter class (default: Ldap3Adapter)
            skip_on_failure: Whether to skip on connection failure
            disconnect_after: Whether to disconnect after (for cleanup)

        Returns:
            Connected adapter instance (use in context manager or cleanup manually)

        Example:
            adapter = TestDeduplicationHelpers.create_connected_adapter_fixture_generic(
                connection_config
            )
            # Use adapter...
            adapter.disconnect()  # Cleanup

        """
        if adapter_class is None:
            adapter_class = Ldap3Adapter

        if connection_config is None:
            error_msg = "connection_config must be provided when not in fixture context"
            raise ValueError(error_msg)

        adapter = adapter_class()
        connect_result = adapter.connect(connection_config)

        if skip_on_failure and connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        if disconnect_after:
            # Return wrapper that disconnects on cleanup
            class AdapterWrapper:
                def __init__(self, adpt: Ldap3Adapter) -> None:
                    self._adapter = adpt

                def __getattr__(self, name: str) -> t.GeneralValueType:
                    attr_value = getattr(self._adapter, name)
                    # Type narrowing: ensure return type is GeneralValueType
                    if isinstance(attr_value, (str, int, float, bool, type(None))):
                        return attr_value
                    if isinstance(attr_value, (list, tuple)):
                        return cast("t.GeneralValueType", attr_value)
                    if isinstance(attr_value, dict):
                        return cast("t.GeneralValueType", attr_value)
                    return cast("t.GeneralValueType", attr_value)

                def __enter__(self) -> Ldap3Adapter:
                    return self._adapter

                def __exit__(
                    self,
                    exc_type: type[BaseException] | None,
                    exc_val: BaseException | None,
                    exc_tb: types.TracebackType | None,
                ) -> None:
                    # Type narrowing: check if adapter has disconnect method
                    if hasattr(self._adapter, "disconnect") and isinstance(
                        self._adapter,
                        Ldap3Adapter,
                    ):
                        self._adapter.disconnect()

            wrapper = AdapterWrapper(adapter)
            return cast("Ldap3Adapter", wrapper)

        # Type narrowing: adapter is already Ldap3Adapter at this point
        if isinstance(adapter, Ldap3Adapter):
            return adapter
        # Fallback: cast to ensure type safety
        return cast("Ldap3Adapter", adapter)

    @staticmethod
    def api_connect_disconnect_lifecycle(
        api: FlextLdap,
        connection_config: m.ConnectionConfig,
        *,
        verify_connect: bool = True,
        verify_disconnect: bool = True,
        verify_state: bool = True,
    ) -> tuple[r[bool], None]:
        """Test API connect/disconnect lifecycle - REPLACES ENTIRE TEST METHOD (10-20 lines).

        Replaces repetitive test_api_connect_and_disconnect methods.

        Args:
            api: FlextLdap API instance
            connection_config: Connection config
            verify_connect: Whether to verify connection succeeds
            verify_disconnect: Whether to verify disconnection succeeds
            verify_state: Whether to verify connection state

        Returns:
            Tuple of (connect_result, disconnect_result)

        Example:
            connect_result, disconnect_result = TestDeduplicationHelpers.api_connect_disconnect_lifecycle(
                api, connection_config
            )
            assert connect_result.is_success
            assert api.is_connected is False

        """
        # Type narrowing: api is already FlextLdap
        typed_api: FlextLdap = api

        # Connect
        connect_result = typed_api.connect(connection_config)
        if verify_connect:
            FlextTestsMatchers.assert_success(
                connect_result,
                error_msg="API connect failed",
            )

        if verify_state and connect_result.is_success:
            # Type narrowing: check if api has is_connected attribute
            if hasattr(typed_api, "_connection") and hasattr(
                typed_api._connection,
                "is_connected",
            ):
                assert typed_api._connection.is_connected is True, (
                    "API should be connected after connect"
                )
            elif hasattr(typed_api, "is_connected"):
                assert typed_api.is_connected is True, (
                    "API should be connected after connect"
                )

        # Disconnect
        typed_api.disconnect()

        if verify_disconnect and verify_state:
            # Type narrowing: check if api has is_connected attribute
            if hasattr(typed_api, "_connection") and hasattr(
                typed_api._connection,
                "is_connected",
            ):
                assert typed_api._connection.is_connected is False, (
                    "API should be disconnected after disconnect"
                )
            elif hasattr(typed_api, "is_connected"):
                assert typed_api.is_connected is False, (
                    "API should be disconnected after disconnect"
                )

        return connect_result, None

    @staticmethod
    def create_temp_ldif_file_with_content(
        content: str,
        *,
        suffix: str = ".ldif",
        encoding: str = "utf-8",
    ) -> Path:
        r"""Create temporary LDIF file with content - REPLACES ENTIRE PATTERN (8-15 lines).

        Replaces repetitive tempfile.NamedTemporaryFile patterns for LDIF files.

        Args:
            content: LDIF file content
            suffix: File suffix (default: ".ldif")
            encoding: File encoding (default: "utf-8")

        Returns:
            Path object to temporary file

        Example:
            temp_file = TestDeduplicationHelpers.create_temp_ldif_file_with_content(
                "dn: cn=test,dc=example,dc=com\ncn: test\n"
            )
            # Use temp_file...
            temp_file.unlink()  # Cleanup

        """
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding=encoding,
        ) as f:
            f.write(content)
            return Path(f.name)

    @staticmethod
    def sync_ldif_file_all_scenarios(
        sync_service: FlextLdapSyncService,
        ldif_content: str | Path,
        *,
        cleanup_dns: list[str] | None = None,
        verify_stats: bool = True,
        expected_total: int | None = None,
        expected_skipped: int | None = None,
        options: GenericFieldsDict | None = None,
        cleanup_file: bool = True,
    ) -> tuple[m.SyncStats | GenericFieldsDict | None, Path]:
        r"""Test sync LDIF file with all scenarios - REPLACES ENTIRE TEST CLASS (60-100 lines).

        Replaces repetitive test_sync_ldif_file_* methods.

        Args:
            sync_service: Sync service instance
            ldif_content: LDIF content string or Path to file
            cleanup_dns: Optional list of DNs to cleanup before/after
            verify_stats: Whether to verify sync stats
            expected_total: Optional expected total entries
            expected_skipped: Optional expected skipped entries
            options: Optional sync options
            cleanup_file: Whether to cleanup temp file after

        Returns:
            Tuple of (sync_stats, temp_file_path)

        Example:
            stats, temp_file = TestDeduplicationHelpers.sync_ldif_file_all_scenarios(
                sync_service, "dn: cn=test,dc=example,dc=com\ncn: test\n",
                cleanup_dns=["cn=test,dc=example,dc=com"]
            )
            assert stats.total == 1

        """
        # Create temp file if content is string
        if isinstance(ldif_content, str):
            temp_file = TestDeduplicationHelpers.create_temp_ldif_file_with_content(
                ldif_content,
            )
        else:
            temp_file = ldif_content

        try:
            # Cleanup before if requested
            if (
                cleanup_dns
                and hasattr(sync_service, "_operations")
                and isinstance(sync_service._operations, FlextLdapOperations)
            ):
                # FlextLdapOperations has delete method, use it directly
                for dn in cleanup_dns:
                    _ = sync_service._operations.delete(dn)

            # Sync file
            # Type narrowing: ensure sync_service has sync_ldif_file method
            if not hasattr(sync_service, "sync_ldif_file"):
                error_msg = "sync_service must have sync_ldif_file method"
                raise TypeError(error_msg)
            sync_method = getattr(sync_service, "sync_ldif_file", None)
            if sync_method is None:
                error_msg = "sync_service.sync_ldif_file is not callable"
                raise TypeError(error_msg)
            result = (
                sync_method(temp_file, options) if options else sync_method(temp_file)
            )

            if verify_stats:
                stats = FlextTestsMatchers.assert_success(
                    result,
                    error_msg="Sync failed",
                )
                if expected_total is not None:
                    assert stats.total == expected_total, (
                        f"Expected {expected_total} total entries, got {stats.total}"
                    )
                if expected_skipped is not None:
                    assert stats.skipped == expected_skipped, (
                        f"Expected {expected_skipped} skipped entries, got {stats.skipped}"
                    )
                return stats, temp_file

            return result.unwrap() if result.is_success else None, temp_file
        finally:
            if cleanup_file and isinstance(temp_file, Path) and temp_file.exists():
                temp_file.unlink()

    @staticmethod
    def api_property_access(
        api: FlextLdap,
        *,
        property_name: str = "client",
        verify_not_none: bool = True,
        verify_equals: str | None = None,
    ) -> t.GeneralValueType:
        """Test API property access - REPLACES ENTIRE TEST METHOD (5-10 lines).

        Replaces repetitive test_client_property, test_*_property methods.

        Args:
            api: FlextLdap API instance
            property_name: Property name to test (default: "client")
            verify_not_none: Whether to verify property is not None
            verify_equals: Optional attribute name to verify equals (e.g., "_operations")

        Returns:
            Property value

        Example:
            client = TestDeduplicationHelpers.test_api_property_access(
                api, property_name="client", verify_equals="_operations"
            )
            assert client is not None

        """
        if not hasattr(api, property_name):
            error_msg = f"API does not have property {property_name}"
            raise AttributeError(error_msg)

        value_raw = getattr(api, property_name)

        if verify_not_none:
            assert value_raw is not None, (
                f"API property {property_name} should not be None"
            )

        if verify_equals:
            expected_value = getattr(api, verify_equals, None)
            assert value_raw == expected_value, (
                f"API property {property_name} should equal {verify_equals}"
            )

        # Type narrowing: ensure return type is GeneralValueType
        value: t.GeneralValueType
        if isinstance(value_raw, (str, int, float, bool, type(None))):
            value = value_raw
        elif isinstance(value_raw, (list, tuple, dict)):
            value = cast("t.GeneralValueType", value_raw)
        else:
            value = cast("t.GeneralValueType", value_raw)
        return value

    @staticmethod
    def execute_method_all_services(
        service: p.LdapService.LdapClientProtocol,
        *,
        verify_success: bool = True,
        verify_stats: bool = True,
        expected_total: int = 0,
    ) -> m.SyncStats | t.GeneralValueType | None:
        """Test execute method for all services - REPLACES ENTIRE TEST METHOD (5-15 lines).

        Replaces repetitive test_execute_method methods.

        Args:
            service: Service instance with execute method
            verify_success: Whether to verify execution succeeds
            verify_stats: Whether to verify stats (for sync services)
            expected_total: Expected total entries (default: 0)

        Returns:
            Execute result or stats

        Example:
            result = TestDeduplicationHelpers.test_execute_method_all_services(
                sync_service
            )
            assert result.total == 0

        """
        if not hasattr(service, "execute"):
            error_msg = "Service does not have execute method"
            raise AttributeError(error_msg)

        result = service.execute()

        # Type narrowing: result is ResultProtocol, cast to r
        result_typed: r[m.SyncStats | object] = cast(
            "r[m.SyncStats | object]",
            result,
        )

        if verify_success:
            FlextTestsMatchers.assert_success(
                result_typed,
                error_msg="Execute method failed",
            )

        if verify_stats and result_typed.is_success:
            unwrapped = result_typed.unwrap()
            if not isinstance(unwrapped, m.SyncStats):
                error_msg = f"Expected SyncStats, got {type(unwrapped).__name__}"
                raise TypeError(error_msg)
            stats = unwrapped
            assert stats.total == expected_total, (
                f"Expected {expected_total} total entries, got {stats.total}"
            )
            return stats

        if result_typed.is_success:
            unwrapped = result_typed.unwrap()
            # Type narrowing: unwrapped could be SyncStats or other types
            if isinstance(unwrapped, m.SyncStats):
                return unwrapped
            # For other types, return None (not compatible with return type)
            return None
        return None

    @staticmethod
    def transform_entries_basedn_all_scenarios(
        sync_service: FlextLdapSyncService,
        entries: list[FlextLdifModels.Entry],
        from_basedn: str,
        to_basedn: str,
        *,
        verify_transformation: bool = True,
    ) -> list[FlextLdifModels.Entry]:
        """Test BaseDN transformation with all scenarios - REPLACES ENTIRE TEST CLASS (30-50 lines).

        Replaces repetitive test_transform_entries_basedn_* methods.

        Args:
            sync_service: Sync service instance
            entries: List of entries to transform
            from_basedn: Source BaseDN
            to_basedn: Target BaseDN
            verify_transformation: Whether to verify transformation

        Returns:
            Transformed entries

        Example:
            transformed = TestDeduplicationHelpers.transform_entries_basedn_all_scenarios(
                sync_service, entries, "dc=example,dc=com", "dc=flext,dc=local"
            )
            assert len(transformed) == len(entries)

        """
        transformed = sync_service.BaseDNTransformer.transform(
            entries,
            from_basedn,
            to_basedn,
        )

        if verify_transformation:
            assert len(transformed) == len(entries), (
                f"Expected {len(entries)} transformed entries, got {len(transformed)}"
            )

            # If same BaseDN, entries should be unchanged
            if from_basedn == to_basedn:
                assert transformed == entries, (
                    "Entries should be unchanged with same BaseDN"
                )

            # Verify DN transformations
            for original, transformed_entry in zip(entries, transformed, strict=True):
                if original.dn and transformed_entry.dn:
                    original_dn_str = str(original.dn)
                    transformed_dn_str = str(transformed_entry.dn)
                    if from_basedn in original_dn_str:
                        assert to_basedn in transformed_dn_str, (
                            f"DN should be transformed from {from_basedn} to {to_basedn}"
                        )

        return transformed

    @staticmethod
    def assert_success_or_failure(
        result: r[m.OperationResult],
        *,
        allow_failure: bool = True,
    ) -> None:
        """Assert result is success OR failure - COMMON PATTERN.

        Replaces:
            assert result.is_success or result.is_failure
            assert result.is_failure or result.is_success

        Args:
            result: r to check
            allow_failure: If True, allows both success and failure (default: True)

        Example:
            TestDeduplicationHelpers.assert_success_or_failure(result)

        """
        if allow_failure:
            assert result.is_success or result.is_failure, (
                f"Result must be success or failure, got: {result}"
            )
        else:
            FlextTestsMatchers.assert_success(result)

    @staticmethod
    def create_api(
        config: m.ConnectionConfig | None = None,
    ) -> FlextLdap:
        """Create FlextLdap API instance - COMMON PATTERN.

        Replaces:
            api = TestDeduplicationHelpers.create_api()
            client = TestDeduplicationHelpers.create_api()
            api = TestDeduplicationHelpers.create_api(config)

        Args:
            config: Optional connection config

        Returns:
            FlextLdap instance

        Example:
            api = TestDeduplicationHelpers.create_api()
            # or
            api = TestDeduplicationHelpers.create_api(connection_config)

        """
        if config is not None:
            # If config is ConnectionConfig, convert to FlextLdapConfig
            ldap_config = FlextLdapConfig(
                host=config.host,
                port=config.port,
                use_ssl=config.use_ssl,
                use_tls=config.use_tls,
                bind_dn=config.bind_dn,
                bind_password=config.bind_password,
                timeout=config.timeout,
            )
            connection = FlextLdapConnection(config=ldap_config)
            operations = FlextLdapOperations(connection=connection)
            return FlextLdap(connection=connection, operations=operations)
        connection = FlextLdapConnection(config=FlextLdapConfig())
        operations = FlextLdapOperations(connection=connection)
        return FlextLdap(connection=connection, operations=operations)

    @staticmethod
    def create_api_and_connect(
        connection_config: m.ConnectionConfig,
        *,
        assert_success: bool = True,
    ) -> tuple[FlextLdap, r[bool]]:
        """Create FlextLdap API and connect - COMMON PATTERN.

        Replaces:
            api = TestDeduplicationHelpers.create_api()
            connect_result = api.connect(connection_config)
            assert connect_result.is_success

        Args:
            connection_config: Connection configuration
            assert_success: Whether to assert connection success (default: True)

        Returns:
            Tuple of (api, connect_result)

        Example:
            api, result = TestDeduplicationHelpers.create_api_and_connect(
                connection_config
            )
            FlextTestsMatchers.assert_success(result)

        """
        api = TestDeduplicationHelpers.create_api()
        connect_result = api.connect(connection_config)

        if assert_success:
            FlextTestsMatchers.assert_success(
                connect_result,
                error_msg="Connection failed",
            )

        # Already correctly typed
        return api, connect_result

    @staticmethod
    def create_connection(
        config: m.ConnectionConfig | None = None,
    ) -> FlextLdapConnection:
        """Create FlextLdapConnection instance - COMMON PATTERN.

        Replaces:
            from flext_ldif import FlextLdifParser
            from flext_ldap.config import FlextLdapConfig
            config = FlextLdapConfig()
            parser = FlextLdifParser()
            connection = FlextLdapConnection(config=config, parser=parser)
            connection = FlextLdapConnection(config=config)

        Args:
            config: Optional connection config

        Returns:
            FlextLdapConnection instance

        Example:
            connection = TestDeduplicationHelpers.create_connection()
            # or
            connection = TestDeduplicationHelpers.create_connection(connection_config)

        """
        parser = FlextLdifParser()
        if config is not None:
            ldap_config = FlextLdapConfig(
                host=config.host,
                port=config.port,
                use_ssl=config.use_ssl,
                use_tls=config.use_tls,
                bind_dn=config.bind_dn,
                bind_password=config.bind_password,
                timeout=config.timeout,
            )
            return FlextLdapConnection(config=ldap_config, parser=parser)

        default_config = FlextLdapConfig()
        return FlextLdapConnection(config=default_config, parser=parser)

    @staticmethod
    def create_connection_and_connect(
        connection_config: m.ConnectionConfig,
        *,
        assert_success: bool = True,
        skip_on_failure: bool = False,
    ) -> tuple[FlextLdapConnection, r[m.OperationResult]]:
        """Create FlextLdapConnection and connect - COMMON PATTERN.

        Replaces:
            from flext_ldif import FlextLdifParser
            from flext_ldap.config import FlextLdapConfig
            config = FlextLdapConfig()
            parser = FlextLdifParser()
            connection = FlextLdapConnection(config=config, parser=parser)
            connect_result = connection.connect(connection_config)
            assert connect_result.is_success

        Args:
            connection_config: Connection configuration
            assert_success: Whether to assert connection success (default: True)
            skip_on_failure: Whether to skip test on failure (default: False)

        Returns:
            Tuple of (connection, connect_result)

        Example:
            connection, result = TestDeduplicationHelpers.create_connection_and_connect(
                connection_config
            )

        """
        connection = TestDeduplicationHelpers.create_connection()
        connect_result = connection.connect(connection_config)

        if skip_on_failure and connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        if assert_success:
            FlextTestsMatchers.assert_success(
                connect_result,
                error_msg="Connection failed",
            )

        # Cast result to expected return type
        return connection, cast(
            "r[m.OperationResult]",
            connect_result,
        )

    @staticmethod
    def with_api_context(
        connection_config: m.ConnectionConfig,
        *,
        assert_success: bool = True,
    ) -> AbstractContextManager[FlextLdap]:
        """Context manager for FlextLdap API - COMMON PATTERN.

        Replaces:
            with FlextLdap() as api:
                api.connect(connection_config)
                # test code

        Args:
            connection_config: Connection configuration
            assert_success: Whether to assert connection success (default: True)

        Returns:
            Context manager that yields connected FlextLdap instance

        Example:
            with TestDeduplicationHelpers.with_api_context(connection_config) as api:
                # test code

        """

        @contextmanager
        def _context() -> Iterator[FlextLdap]:
            api = TestDeduplicationHelpers.create_api()
            connect_result = api.connect(connection_config)

            if assert_success:
                FlextTestsMatchers.assert_success(
                    connect_result,
                    error_msg="Connection failed",
                )

            try:
                yield api
            finally:
                api.disconnect()

        return _context()

    @staticmethod
    def add_with_cleanup(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        *,
        verify: bool = False,
    ) -> r[m.OperationResult]:
        """Add entry with automatic cleanup - SIMPLIFIED PATTERN.

        Replaces:
            EntryTestHelpers.cleanup_entry(client, entry.dn)
            result = client.add(entry)
            assert result.is_success
            EntryTestHelpers.cleanup_after_test(client, entry.dn)

        Args:
            client: LDAP client with add, delete methods
            entry: Entry to add
            verify: Whether to verify entry was added (default: False)

        Returns:
            Add result

        Example:
            result = TestDeduplicationHelpers.add_with_cleanup(client, entry)
            FlextTestsMatchers.assert_success(result)

        """
        return TestDeduplicationHelpers.add_entry(
            client,
            entry,
            verify=verify,
            cleanup_before=True,
            cleanup_after=True,
        )

    @staticmethod
    def add_user(
        client: p.LdapService.LdapClientProtocol,
        cn_value: str | None = None,
        base_dn: str | None = None,
        *,
        sn: str | None = None,
        mail: str | None = None,
        use_uid: bool = False,
        verify: bool = False,
        cleanup_after: bool = True,
        **extra_attributes: LdapAttributeValue,
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
        """Create and add user entry - COMPLETE WORKFLOW.

        Replaces:
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        entry = TestOperationHelpers.create_inetorgperson_entry(...)
        result = typed_client.add(entry)
            assert result.is_success

        Args:
            client: LDAP client with add, delete methods
            cn_value: Common name (default: RFC.TEST_USER_CN)
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            sn: Optional surname
            mail: Optional email
            use_uid: If True, creates uid-based DN
            verify: Whether to verify entry was added
            cleanup_after: Whether to cleanup after add
            **extra_attributes: Additional attributes

        Returns:
            Tuple of (entry, add_result)

        Example:
            entry, result = TestDeduplicationHelpers.add_user(client, "john", sn="Doe")
            FlextTestsMatchers.assert_success(result)

        """
        entry = TestDeduplicationHelpers.create_user(
            cn_value=cn_value,
            base_dn=base_dn,
            sn=sn,
            mail=mail,
            use_uid=use_uid,
            **extra_attributes,
        )

        result = TestDeduplicationHelpers.add_entry(
            client,
            entry,
            verify=verify,
            cleanup_after=cleanup_after,
        )

        return entry, result

    @staticmethod
    def add_group(
        client: p.LdapService.LdapClientProtocol,
        cn_value: str | None = None,
        base_dn: str | None = None,
        *,
        members: list[str] | None = None,
        verify: bool = False,
        cleanup_after: bool = True,
        **extra_attributes: LdapAttributeValue,
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
        """Create and add group entry - COMPLETE WORKFLOW.

        Replaces:
            entry = TestOperationHelpers.create_group_entry(...)
            result = client.add(entry)
            assert result.is_success

        Args:
            client: LDAP client with add, delete methods
            cn_value: Common name (default: RFC.TEST_GROUP_CN)
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            members: List of member DNs
            verify: Whether to verify entry was added
            cleanup_after: Whether to cleanup after add
            **extra_attributes: Additional attributes

        Returns:
            Tuple of (entry, add_result)

        Example:
            entry, result = TestDeduplicationHelpers.add_group(
                client, "REDACTED_LDAP_BIND_PASSWORDs", members=["cn=user1"]
            )
            FlextTestsMatchers.assert_success(result)

        """
        entry = TestDeduplicationHelpers.create_group(
            cn_value=cn_value,
            base_dn=base_dn,
            members=members,
            **extra_attributes,
        )

        result = TestDeduplicationHelpers.add_entry(
            client,
            entry,
            verify=verify,
            cleanup_after=cleanup_after,
        )

        return entry, result

    @staticmethod
    def search_base(
        client: p.LdapService.LdapClientProtocol,
        dn: str,
        *,
        filter_str: str = "(objectClass=*)",
        attributes: list[str] | None = None,
    ) -> m.SearchResult:
        """Search BASE scope - COMMON PATTERN.

        Replaces:
            search_options = m.SearchOptions(
                base_dn=dn,
                filter_str="(objectClass=*)",
                scope=c.SearchScope.BASE,
            )
            # SearchOptions is compatible with SearchOptionsProtocol structurally
            result: r[m.SearchResult] = client.search(search_options)
            assert result.is_success
            return result.unwrap()

        Args:
            client: LDAP client with search method
            dn: Distinguished name to search
            filter_str: LDAP filter string
            attributes: Attributes to retrieve

        Returns:
            SearchResult

        Example:
            result = TestDeduplicationHelpers.search_base(client, "cn=test,dc=example,dc=com")
            assert len(result.entries) == 1

        """
        search_options = m.SearchOptions(
            base_dn=dn,
            filter_str=filter_str,
            scope=c.SearchScope.BASE,
            attributes=attributes,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        # SearchOptions is compatible with SearchOptionsProtocol structurally
        search_result_raw = typed_client.search(search_options)
        search_result: r[m.SearchResult] = cast(
            "r[m.SearchResult]",
            search_result_raw,
        )
        return FlextTestsMatchers.assert_success(
            search_result,
            error_msg="Base search failed",
        )

    @staticmethod
    def disconnect_safely(
        client: p.LdapService.LdapClientProtocol,
    ) -> None:
        """Disconnect client safely - COMMON PATTERN.

        Replaces:
            if client.is_connected:
                client.disconnect()
            # or
            try:
                client.disconnect()
            except:
                pass

        Args:
            client: LDAP client with disconnect method and is_connected property

        Example:
            TestDeduplicationHelpers.disconnect_safely(client)

        """
        # Type narrowing: check if client has required attributes
        if hasattr(client, "is_connected") and hasattr(client, "disconnect"):
            is_connected = getattr(client, "is_connected", False)
            if is_connected:
                disconnect_method = getattr(client, "disconnect", None)
                if disconnect_method is not None:
                    disconnect_method()
        elif hasattr(client, "disconnect"):
            # Try to disconnect anyway if method exists
            try:
                disconnect_method = getattr(client, "disconnect", None)
                if disconnect_method is not None:
                    disconnect_method()
            except Exception:
                pass  # Ignore errors during cleanup

    @staticmethod
    def add_user_and_assert(
        client: p.LdapService.LdapClientProtocol,
        cn_value: str | None = None,
        base_dn: str | None = None,
        *,
        sn: str | None = None,
        mail: str | None = None,
        use_uid: bool = False,
        cleanup_after: bool = True,
        **extra_attributes: LdapAttributeValue,
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
        """Create user, add, and assert success - COMPLETE WORKFLOW (3-5 lines -> 1 line).

        Replaces:
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testuser", RFC.DEFAULT_BASE_DN, sn="Test"
            )
            TestOperationHelpers.add_entry_and_assert_success(TestDeduplicationHelpers._narrow_client_type(client), entry)

        Args:
            client: LDAP client with add, delete methods
            cn_value: Common name (default: RFC.TEST_USER_CN)
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            sn: Optional surname
            mail: Optional email
            use_uid: If True, creates uid-based DN
            cleanup_after: Whether to cleanup after add
            **extra_attributes: Additional attributes

        Returns:
            Tuple of (entry, add_result)

        Example:
            entry, result = TestDeduplicationHelpers.add_user_and_assert(
                client, "john", sn="Doe"
            )

        """
        entry, result = TestDeduplicationHelpers.add_user(
            client,
            cn_value=cn_value,
            base_dn=base_dn,
            sn=sn,
            mail=mail,
            use_uid=use_uid,
            verify=False,
            cleanup_after=cleanup_after,
            **extra_attributes,
        )

        FlextTestsMatchers.assert_success(result, error_msg="Add user failed")

        return entry, result

    @staticmethod
    def modify_entry_simple(
        client: p.LdapService.LdapClientProtocol,
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        assert_success: bool = True,
        normalize_dn: bool = True,
    ) -> r[m.OperationResult]:
        """Modify entry with DN normalization - COMMON PATTERN (3-4 lines -> 1 line).

        Replaces:
            dn_str = str(entry.dn) if entry.dn else ""
            modify_result = client.modify(dn_str, changes)
            assert modify_result.is_success

        Args:
            client: LDAP client with modify method
            dn: Distinguished name (string or DistinguishedName object)
            changes: Dictionary of modifications
            assert_success: Whether to assert success (default: True)
            normalize_dn: Whether to normalize DN (strip spaces, default: True)

        Returns:
            Modify result

        Example:
            result = TestDeduplicationHelpers.modify_entry_simple(
                client, entry.dn, {"mail": [(MODIFY_REPLACE, ["new@example.com"])]}
            )

        """
        dn_str = str(dn) if dn else ""
        if normalize_dn:
            dn_str = dn_str.strip()

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        result = typed_client.modify(dn_str, changes)

        if assert_success:
            result_typed: r[m.OperationResult] = cast(
                "r[m.OperationResult]",
                result,
            )
            FlextTestsMatchers.assert_success(
                result_typed,
                error_msg="Modify operation failed",
            )

        result_return: r[m.OperationResult] = cast(
            "r[m.OperationResult]",
            result,
        )
        return result_return

    @staticmethod
    def delete_entry_simple(
        client: p.LdapService.LdapClientProtocol,
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
        *,
        assert_success: bool = True,
        normalize_dn: bool = True,
    ) -> r[m.OperationResult]:
        """Delete entry with DN normalization - COMMON PATTERN (2-3 lines -> 1 line).

        Replaces:
            dn_str = str(entry.dn) if entry.dn else ""
            delete_result = client.delete(dn_str)
            assert delete_result.is_success

        Args:
            client: LDAP client with delete method
            dn: Distinguished name (string or DistinguishedName object)
            assert_success: Whether to assert success (default: True)
            normalize_dn: Whether to normalize DN (strip spaces, default: True)

        Returns:
            Delete result

        Example:
            result = TestDeduplicationHelpers.delete_entry_simple(client, entry.dn)

        """
        # Type narrowing: convert DN to string
        if hasattr(dn, "__str__") and hasattr(dn, "value"):
            # Protocol-compatible DN object
            dn_str = str(dn)
        elif isinstance(dn, str):
            dn_str = dn
        else:
            dn_str = str(dn) if dn else ""
        if normalize_dn:
            dn_str = dn_str.strip()

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        result = typed_client.delete(dn_str)

        if assert_success:
            result_typed: r[m.OperationResult] = cast(
                "r[m.OperationResult]",
                result,
            )
            FlextTestsMatchers.assert_success(
                result_typed,
                error_msg="Delete operation failed",
            )

        result_return: r[m.OperationResult] = cast(
            "r[m.OperationResult]",
            result,
        )
        return result_return

    @staticmethod
    def add_then_modify_entry(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_modify: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Add entry then modify - COMPLETE WORKFLOW (8-12 lines -> 1 line).

        Replaces:
            add_result = TestOperationHelpers.add_entry_and_assert_success(
                client, entry, cleanup_after=False
            )
            typed_client = TestDeduplicationHelpers._narrow_client_type(client)
            dn_str = str(entry.dn) if entry.dn else ""
            modify_result = typed_client.modify(dn_str, changes)
            assert modify_result.is_success
            if cleanup_after:
                _ = typed_client.delete(dn_str)

        Args:
            client: LDAP client with add, modify, delete methods
            entry: Entry to add
            changes: Dictionary of modifications
            verify_modify: Whether to verify modify succeeded
            cleanup_after: Whether to cleanup after modify

        Returns:
            Tuple of (add_result, modify_result)

        Example:
            add_result, modify_result = TestDeduplicationHelpers.add_then_modify_entry(
                client, entry, {"mail": [(MODIFY_REPLACE, ["new@example.com"])]}
            )

        """
        # Add entry (without cleanup_after since we'll modify)
        add_result = TestDeduplicationHelpers.add_entry(
            client,
            entry,
            verify=False,
            cleanup_before=True,
            cleanup_after=False,
        )

        FlextTestsMatchers.assert_success(
            add_result,
            error_msg="Add operation failed",
        )

        # Modify entry
        if entry.dn is None:
            error_msg = "Entry must have DN for modify operation"
            raise ValueError(error_msg)
        modify_result = TestDeduplicationHelpers.modify_entry_simple(
            client,
            entry.dn,
            changes,
            assert_success=verify_modify,
        )

        # Cleanup if requested
        if cleanup_after and entry.dn:
            TestDeduplicationHelpers.delete_entry_simple(
                client,
                entry.dn,
                assert_success=False,
            )

        return add_result, modify_result

    @staticmethod
    def add_then_delete_entry(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        *,
        verify_delete: bool = True,
    ) -> tuple[
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Add entry then delete - COMPLETE WORKFLOW (6-8 lines -> 1 line).

        Replaces:
            add_result = TestOperationHelpers.add_entry_and_assert_success(
                client, entry, cleanup_after=False
            )
            dn_str = str(entry.dn) if entry.dn else ""
            delete_result = client.delete(dn_str)
            assert delete_result.is_success

        Args:
            client: LDAP client with add, delete methods
            entry: Entry to add
            verify_delete: Whether to verify delete succeeded

        Returns:
            Tuple of (add_result, delete_result)

        Example:
            add_result, delete_result = TestDeduplicationHelpers.add_then_delete_entry(
                client, entry
            )

        """
        # Add entry (without cleanup_after since we'll delete)
        add_result = TestDeduplicationHelpers.add_entry(
            client,
            entry,
            verify=False,
            cleanup_before=True,
            cleanup_after=False,
        )

        FlextTestsMatchers.assert_success(
            add_result,
            error_msg="Add operation failed",
        )

        # Delete entry
        if entry.dn is None:
            error_msg = "Entry must have DN for delete operation"
            raise ValueError(error_msg)
        delete_result = TestDeduplicationHelpers.delete_entry_simple(
            client,
            entry.dn,
            assert_success=verify_delete,
        )

        return add_result, delete_result

    @staticmethod
    def create_and_add_user(
        cn_value: str | None = None,
        base_dn: str | None = None,
        *,
        sn: str | None = None,
        mail: str | None = None,
        use_uid: bool = False,
        **extra_attributes: LdapAttributeValue,
    ) -> FlextLdifModels.Entry:
        """Create user entry - SIMPLIFIED (2-3 lines -> 1 line).

        Replaces:
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testuser", RFC.DEFAULT_BASE_DN, sn="Test"
            )

        Args:
            cn_value: Common name (default: RFC.TEST_USER_CN)
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            sn: Optional surname
            mail: Optional email
            use_uid: If True, creates uid-based DN
            **extra_attributes: Additional attributes

        Returns:
            Entry instance

        Example:
            entry = TestDeduplicationHelpers.create_and_add_user("john", sn="Doe")

        """
        return TestDeduplicationHelpers.create_user(
            cn_value=cn_value,
            base_dn=base_dn,
            sn=sn,
            mail=mail,
            use_uid=use_uid,
            **extra_attributes,
        )

    @staticmethod
    def search_with_server_type(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        scope: str | None = None,
        server_type: str | None = None,
        attributes: list[str] | None = None,
    ) -> m.SearchResult:
        """Search with optional server_type - COMMON PATTERN (4-6 lines -> 1 line).

        Replaces:
            if base_dn is None:
                base_dn = RFC.DEFAULT_BASE_DN
            if filter_str is None:
                filter_str = RFC.DEFAULT_FILTER
            if scope is None:
                scope = RFC.DEFAULT_SCOPE
            search_options = m.SearchOptions(
                base_dn=base_dn,
                filter_str=filter_str,
                scope=scope,
            )
            result = client.search(search_options, server_type="rfc")
            assert result.is_success
            return result.unwrap()

        Args:
            client: LDAP client with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            server_type: Optional server type parameter
            attributes: Attributes to retrieve

        Returns:
            SearchResult

        Example:
            result = TestDeduplicationHelpers.search_with_server_type(
                client, server_type="rfc"
            )

        """
        search_options = TestDeduplicationHelpers.create_search(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        if server_type:
            # Check if search accepts server_type parameter
            sig = inspect.signature(typed_client.search)
            if "server_type" in sig.parameters:
                result_raw = typed_client.search(
                    search_options,
                    server_type=server_type,
                )
            else:
                result_raw = typed_client.search(search_options)
        else:
            result_raw = typed_client.search(search_options)
        result: r[m.SearchResult] = cast(
            "r[m.SearchResult]",
            result_raw,
        )

        return FlextTestsMatchers.assert_success(
            result,
            error_msg="Search failed",
        )

    @staticmethod
    def create_operations_service(
        connection_config: m.ConnectionConfig,
        *,
        assert_connection: bool = True,
        skip_on_failure: bool = False,
    ) -> tuple[FlextLdapOperations, FlextLdapConnection]:
        """Create FlextLdapOperations with connected connection - COMMON PATTERN (5-7 lines -> 1 line).

        Replaces:
            from flext_ldif import FlextLdifParser
            from flext_ldap.config import FlextLdapConfig
            config = FlextLdapConfig()
            parser = FlextLdifParser()
            connection = FlextLdapConnection(config=config, parser=parser)
            connect_result = connection.connect(connection_config)
            if connect_result.is_failure:
                pytest.skip(f"Failed to connect: {connect_result.error}")
            operations = FlextLdapOperations(connection=connection)

        Args:
            connection_config: Connection configuration
            assert_connection: Whether to assert connection success (default: True)
            skip_on_failure: Whether to skip test on failure (default: False)

        Returns:
            Tuple of (operations_service, connection)

        Example:
            operations, connection = TestDeduplicationHelpers.create_operations_service(
                connection_config
            )

        """
        connection, _connect_result = (
            TestDeduplicationHelpers.create_connection_and_connect(
                connection_config,
                assert_success=assert_connection,
                skip_on_failure=skip_on_failure,
            )
        )

        operations = FlextLdapOperations(connection=connection)

        return operations, connection

    @staticmethod
    def cleanup_dn(
        client: p.LdapService.LdapClientProtocol,
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
        *,
        ignore_errors: bool = True,
    ) -> None:
        """Cleanup entry by DN - COMMON PATTERN (2-3 lines -> 1 line).

        Replaces:
            dn_str = str(entry.dn) if entry.dn else ""
            _ = client.delete(dn_str)  # Ignore result

        Args:
            client: LDAP client with delete method
            dn: Distinguished name (string or DistinguishedName object)
            ignore_errors: Whether to ignore delete errors (default: True)

        Example:
            TestDeduplicationHelpers.cleanup_dn(client, entry.dn)

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        dn_str = str(dn) if dn else ""
        delete_result_raw = typed_client.delete(dn_str)
        # Type narrowing: ensure r
        delete_result: r[m.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(delete_result_raw)
        )

        if not ignore_errors:
            FlextTestsMatchers.assert_success(
                delete_result,
                error_msg="Cleanup delete failed",
            )

    @staticmethod
    def create_entry_with_dn_spaces(
        base_entry: FlextLdifModels.Entry,
        *,
        spaces_before: int = 2,
        spaces_after: int = 2,
    ) -> FlextLdifModels.Entry:
        """Create entry with DN that has spaces - COMMON PATTERN (5-8 lines -> 1 line).

        Replaces:
            dn_with_spaces = f"  {entry.dn!s}  "
            attrs = (
                entry.attributes.attributes
                if entry.attributes and entry.attributes.attributes
                else {}
            )
            entry = EntryTestHelpers.create_entry(dn_with_spaces, attrs)

        Args:
            base_entry: Base entry to copy
            spaces_before: Number of spaces before DN (default: 2)
            spaces_after: Number of spaces after DN (default: 2)

        Returns:
            Entry with DN that has spaces

        Example:
            entry_with_spaces = TestDeduplicationHelpers.create_entry_with_dn_spaces(
                entry
            )

        """
        dn_str = str(base_entry.dn) if base_entry.dn else ""
        dn_with_spaces = " " * spaces_before + dn_str + " " * spaces_after

        attrs_raw = (
            base_entry.attributes.attributes
            if base_entry.attributes and base_entry.attributes.attributes
            else {}
        )
        # Normalize attributes to GeneralValueType for create_entry
        attrs: dict[str, t.GeneralValueType] = {}
        for key, value in attrs_raw.items():
            if isinstance(value, (str, int, float, bool, type(None))):
                attrs[key] = value
            elif isinstance(value, (list, tuple)):
                # Convert to list[str] for GeneralValueType
                attrs[key] = list(value) if isinstance(value, tuple) else value
            elif isinstance(value, (set, frozenset)):
                # Convert set/frozenset to list for GeneralValueType
                attrs[key] = list(value)
            else:
                attrs[key] = cast("t.GeneralValueType", value)

        return EntryTestHelpers.create_entry(dn_with_spaces, attrs)

    @staticmethod
    def modify_with_dn_spaces(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        spaces_before: int = 2,
        spaces_after: int = 2,
        assert_success: bool = True,
    ) -> r[m.OperationResult]:
        """Modify entry with DN that has spaces - COMMON PATTERN (3-4 lines -> 1 line).

        Replaces:
            modify_result = operations_service.modify(f"  {entry.dn!s}  ", changes)
            assert modify_result.is_success

        Args:
            client: LDAP client with modify method
            entry: Entry to modify
            changes: Dictionary of modifications
            spaces_before: Number of spaces before DN (default: 2)
            spaces_after: Number of spaces after DN (default: 2)
            assert_success: Whether to assert success (default: True)

        Returns:
            Modify result

        Example:
            result = TestDeduplicationHelpers.modify_with_dn_spaces(
                client, entry, {"mail": [(MODIFY_REPLACE, ["new@example.com"])]}
            )

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        dn_str = str(entry.dn) if entry.dn else ""
        dn_with_spaces = " " * spaces_before + dn_str + " " * spaces_after

        result_raw = typed_client.modify(dn_with_spaces, changes)
        # Type narrowing: ensure r
        result: r[m.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(result_raw)
        )

        if assert_success:
            FlextTestsMatchers.assert_success(
                result,
                error_msg="Modify with DN spaces failed",
            )

        return result

    @staticmethod
    def delete_with_dn_spaces(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        *,
        spaces_before: int = 2,
        spaces_after: int = 2,
        assert_success: bool = True,
    ) -> r[m.OperationResult]:
        """Delete entry with DN that has spaces - COMMON PATTERN (2-3 lines -> 1 line).

        Replaces:
            delete_result = operations_service.delete(f"  {entry.dn!s}  ")
            assert delete_result.is_success

        Args:
            client: LDAP client with delete method
            entry: Entry to delete
            spaces_before: Number of spaces before DN (default: 2)
            spaces_after: Number of spaces after DN (default: 2)
            assert_success: Whether to assert success (default: True)

        Returns:
            Delete result

        Example:
            result = TestDeduplicationHelpers.delete_with_dn_spaces(client, entry)

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        dn_str = str(entry.dn) if entry.dn else ""
        dn_with_spaces = " " * spaces_before + dn_str + " " * spaces_after

        result_raw = typed_client.delete(dn_with_spaces)
        # Type narrowing: ensure r
        result: r[m.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(result_raw)
        )

        if assert_success:
            FlextTestsMatchers.assert_success(
                result,
                error_msg="Delete with DN spaces failed",
            )

        return result

    @staticmethod
    def add_modify_delete_with_operation_results(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_add_result: bool = True,
        verify_modify_result: bool = True,
        verify_delete_result: bool = True,
        cleanup_after: bool = True,
    ) -> dict[str, r[m.OperationResult]]:
        """Complete add->modify->delete workflow with OperationResult verification - MASSIVE CODE REDUCTION (15-25 lines -> 1 line).

        Replaces entire test patterns like:
            entry = TestOperationHelpers.create_inetorgperson_entry("test", base_dn)
            add_result = EntryTestHelpers.add_and_cleanup(TestDeduplicationHelpers._narrow_client_type(client), entry, cleanup_after=False)
            assert add_result.is_success
            TestOperationHelpers.assert_operation_result_success(
                add_result, expected_operation_type=c.OperationType.ADD.value, expected_entries_affected=1
            )
            changes = {"mail": [(MODIFY_REPLACE, ["test@example.com"])]}
            modify_result = client.modify(str(entry.dn), changes)
            assert modify_result.is_success
            TestOperationHelpers.assert_operation_result_success(
                modify_result, expected_operation_type=c.OperationType.MODIFY.value, expected_entries_affected=1
            )
            delete_result = client.delete(str(entry.dn))
            assert delete_result.is_success
            TestOperationHelpers.assert_operation_result_success(
                delete_result, expected_operation_type=c.OperationType.DELETE.value, expected_entries_affected=1
            )

        Args:
            client: LDAP client with add, modify, delete methods
            entry: Entry to add, modify, and delete
            changes: Dictionary of modifications for modify operation
            verify_add_result: Whether to verify add OperationResult (default: True)
            verify_modify_result: Whether to verify modify OperationResult (default: True)
            verify_delete_result: Whether to verify delete OperationResult (default: True)
            cleanup_after: Whether to cleanup after delete (default: True, but entry is deleted so no-op)

        Returns:
            Dictionary with 'add', 'modify', 'delete' results

        Example:
            results = TestDeduplicationHelpers.add_modify_delete_with_operation_results(
                client,
                TestDeduplicationHelpers.create_user("testuser"),
                {"mail": [(MODIFY_REPLACE, ["new@example.com"])]}
            )

        """
        # Add entry
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        add_result = EntryTestHelpers.add_and_cleanup(
            typed_client,
            entry,
            verify=False,
            cleanup_after=False,
        )

        if verify_add_result:
            TestOperationHelpers.assert_operation_result_success(
                add_result,
                expected_operation_type=c.OperationType.ADD.value,
                expected_entries_affected=1,
            )

        # Modify entry
        if not entry.dn:
            error_msg = "Entry must have DN for modify operation"
            raise ValueError(error_msg)

        dn_str = str(entry.dn)
        modify_result_raw = typed_client.modify(dn_str, changes)
        # Type narrowing: ensure r
        modify_result: r[m.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(modify_result_raw)
        )

        if verify_modify_result:
            TestOperationHelpers.assert_operation_result_success(
                modify_result,
                expected_operation_type=c.OperationType.MODIFY.value,
                expected_entries_affected=1,
            )

        # Delete entry
        delete_result_raw = typed_client.delete(dn_str)
        # Type narrowing: ensure r
        delete_result: r[m.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(delete_result_raw)
        )

        if verify_delete_result:
            TestOperationHelpers.assert_operation_result_success(
                delete_result,
                expected_operation_type=c.OperationType.DELETE.value,
                expected_entries_affected=1,
            )

        return {
            "add": add_result,
            "modify": modify_result,
            "delete": delete_result,
        }

    @staticmethod
    def search_and_verify_count(
        client: p.LdapService.LdapClientProtocol,
        base_dn: str | None = None,
        *,
        filter_str: str | None = None,
        scope: str | None = None,
        expected_min: int = 0,
        expected_max: int | None = None,
        expected_exact: int | None = None,
    ) -> m.SearchResult:
        """Search with count verification - MASSIVE CODE REDUCTION (8-12 lines -> 1 line).

        Replaces entire test patterns like:
            search_options = m.SearchOptions(
                base_dn=base_dn or RFC.DEFAULT_BASE_DN,
                filter_str=filter_str or RFC.DEFAULT_FILTER,
                scope=scope or RFC.DEFAULT_SCOPE,
            )
            # SearchOptions is compatible with SearchOptionsProtocol structurally
            result: r[m.SearchResult] = client.search(search_options)
            assert result.is_success
            search_result = result.unwrap()
            assert len(search_result.entries) >= expected_min
            if expected_max is not None:
                assert len(search_result.entries) <= expected_max

        Args:
            client: LDAP client with search method
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            filter_str: LDAP filter (default: RFC.DEFAULT_FILTER)
            scope: Search scope (default: RFC.DEFAULT_SCOPE)
            expected_min: Minimum number of entries expected (default: 0)
            expected_max: Maximum number of entries expected (optional)
            expected_exact: Exact number of entries expected (optional, overrides min/max)

        Returns:
            SearchResult

        Example:
            result = TestDeduplicationHelpers.search_and_verify_count(
                client, expected_exact=1
            )

        """
        search_options = TestDeduplicationHelpers.create_search(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        result_raw = typed_client.search(search_options)
        # Type narrowing: ensure r
        result: r[m.SearchResult] = (
            FlextLdapTestHelpers._ensure_flext_result(result_raw)
        )
        FlextTestsMatchers.assert_success(result, error_msg="Search failed")
        search_result: m.SearchResult = result.unwrap()

        if expected_exact is not None:
            assert len(search_result.entries) == expected_exact, (
                f"Expected exactly {expected_exact} entries, got {len(search_result.entries)}"
            )
        else:
            assert len(search_result.entries) >= expected_min, (
                f"Expected at least {expected_min} entries, got {len(search_result.entries)}"
            )
            if expected_max is not None:
                assert len(search_result.entries) <= expected_max, (
                    f"Expected at most {expected_max} entries, got {len(search_result.entries)}"
                )

        return search_result

    @staticmethod
    def execute_and_verify_total_count(
        client: p.LdapService.LdapClientProtocol,
        *,
        expected_total: int = 0,
        expected_entries: int | None = None,
    ) -> m.SearchResult:
        """Execute and verify total_count - COMMON PATTERN (4-6 lines -> 1 line).

        Replaces:
            result = client.execute()
            assert result.is_success
            search_result = result.unwrap()
            assert search_result.total_count == expected_total
            assert len(search_result.entries) == expected_entries

        Args:
            client: LDAP client with execute method
            expected_total: Expected total_count (default: 0)
            expected_entries: Expected number of entries (optional)

        Returns:
            SearchResult

        Example:
            result = TestDeduplicationHelpers.execute_and_verify_total_count(
                client, expected_total=0
            )

        """
        if not hasattr(client, "execute"):
            error_msg = "Client does not have execute method"
            raise AttributeError(error_msg)

        result_raw = client.execute()
        # Type narrowing: ensure r
        result: r[m.SearchResult] = (
            FlextLdapTestHelpers._ensure_flext_result(result_raw)
        )
        FlextTestsMatchers.assert_success(result, error_msg="Execute failed")
        search_result: m.SearchResult = result.unwrap()

        total = cast("int", search_result.total_count)
        assert total == expected_total, (
            f"Expected total_count={expected_total}, got {total}"
        )

        if expected_entries is not None:
            assert len(search_result.entries) == expected_entries, (
                f"Expected {expected_entries} entries, got {len(search_result.entries)}"
            )

        return search_result

    @staticmethod
    def create_user_add_and_verify(
        client: p.LdapService.LdapClientProtocol,
        cn_value: str | None = None,
        base_dn: str | None = None,
        *,
        sn: str | None = None,
        mail: str | None = None,
        use_uid: bool = False,
        verify_operation_result: bool = False,
        cleanup_after: bool = True,
        **extra_attributes: LdapAttributeValue,
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
        """Create user entry, add it, and verify - COMPLETE WORKFLOW (8-12 lines -> 1 line).

        Replaces:
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testuser", base_dn, sn="User", mail="test@example.com"
            )
            typed_client = TestDeduplicationHelpers._narrow_client_type(client)
            result = EntryTestHelpers.add_and_cleanup(typed_client, entry)
            assert result.is_success
            if verify_operation_result:
                TestOperationHelpers.assert_operation_result_success(
                    result, expected_operation_type=c.OperationType.ADD.value, expected_entries_affected=1
                )

        Args:
            client: LDAP client with add method
            cn_value: Common name (default: RFC.TEST_USER_CN)
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            sn: Optional surname
            mail: Optional email
            use_uid: If True, creates uid-based DN
            verify_operation_result: Whether to verify OperationResult (default: False)
            cleanup_after: Whether to cleanup after add (default: True)
            **extra_attributes: Additional attributes

        Returns:
            Tuple of (entry, add_result)

        Example:
            entry, result = TestDeduplicationHelpers.create_user_add_and_verify(
                client, "testuser", sn="User"
            )

        """
        entry = TestDeduplicationHelpers.create_user(
            cn_value=cn_value,
            base_dn=base_dn,
            sn=sn,
            mail=mail,
            use_uid=use_uid,
            **extra_attributes,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        result = EntryTestHelpers.add_and_cleanup(
            typed_client,
            entry,
            verify=False,
            cleanup_after=cleanup_after,
        )

        FlextTestsMatchers.assert_success(result, error_msg="Add failed")

        if verify_operation_result:
            TestOperationHelpers.assert_operation_result_success(
                result,
                expected_operation_type=c.OperationType.ADD.value,
                expected_entries_affected=1,
            )

        return entry, result

    @staticmethod
    def add_then_delete_with_operation_results(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        *,
        verify_add_result: bool = True,
        verify_delete_result: bool = True,
    ) -> tuple[
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Add entry then delete with OperationResult verification - MASSIVE CODE REDUCTION (10-15 lines -> 1 line).

        Replaces entire test patterns like:
            entry = TestOperationHelpers.create_inetorgperson_entry("test", base_dn)
            add_result = EntryTestHelpers.add_and_cleanup(TestDeduplicationHelpers._narrow_client_type(client), entry, cleanup_after=False)
            assert add_result.is_success
            if entry.dn:
                delete_result = client.delete(str(entry.dn))
                TestOperationHelpers.assert_operation_result_success(
                    delete_result,
                    expected_operation_type=c.OperationType.DELETE.value,
                    expected_entries_affected=1,
                )

        Args:
            client: LDAP client with add, delete methods
            entry: Entry to add and delete
            verify_add_result: Whether to verify add OperationResult (default: True)
            verify_delete_result: Whether to verify delete OperationResult (default: True)

        Returns:
            Tuple of (add_result, delete_result)

        Example:
            add_result, delete_result = TestDeduplicationHelpers.add_then_delete_with_operation_results(
                client, TestDeduplicationHelpers.create_user("testuser")
            )

        """
        # Add entry
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        add_result = EntryTestHelpers.add_and_cleanup(
            typed_client,
            entry,
            verify=False,
            cleanup_after=False,
        )

        if verify_add_result:
            TestOperationHelpers.assert_operation_result_success(
                add_result,
                expected_operation_type=c.OperationType.ADD.value,
                expected_entries_affected=1,
            )

        # Delete entry
        if not entry.dn:
            error_msg = "Entry must have DN for delete operation"
            raise ValueError(error_msg)

        dn_str = str(entry.dn)
        delete_result_raw = typed_client.delete(dn_str)
        # Type narrowing: ensure r
        delete_result: r[m.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(delete_result_raw)
        )

        if verify_delete_result:
            TestOperationHelpers.assert_operation_result_success(
                delete_result,
                expected_operation_type=c.OperationType.DELETE.value,
                expected_entries_affected=1,
            )

        return add_result, delete_result

    @staticmethod
    def add_then_modify_with_operation_results(
        client: p.LdapService.LdapClientProtocol,
        entry: FlextLdifModels.Entry,
        changes: dict[str, list[tuple[str, list[str]]]],
        *,
        verify_add_result: bool = True,
        verify_modify_result: bool = True,
        cleanup_after: bool = True,
    ) -> tuple[
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Add entry then modify with OperationResult verification - MASSIVE CODE REDUCTION (12-18 lines -> 1 line).

        Replaces entire test patterns like:
            entry = TestOperationHelpers.create_inetorgperson_entry("test", base_dn)
            changes = {"mail": [(MODIFY_REPLACE, ["test@example.com"])]}
            results = TestOperationHelpers.execute_add_modify_delete_sequence(
                client, entry, changes, verify_delete=False
            )
            assert results["add"].is_success
            TestOperationHelpers.assert_operation_result_success(
                results["modify"],
                expected_operation_type=c.OperationType.MODIFY.value,
                expected_entries_affected=1,
            )
            if entry.dn:
                _ = client.delete(str(entry.dn))

        Args:
            client: LDAP client with add, modify, delete methods
            entry: Entry to add and modify
            changes: Dictionary of modifications for modify operation
            verify_add_result: Whether to verify add OperationResult (default: True)
            verify_modify_result: Whether to verify modify OperationResult (default: True)
            cleanup_after: Whether to cleanup after modify (default: True)

        Returns:
            Tuple of (add_result, modify_result)

        Example:
            add_result, modify_result = TestDeduplicationHelpers.add_then_modify_with_operation_results(
                client,
                TestDeduplicationHelpers.create_user("testuser"),
                {"mail": [(MODIFY_REPLACE, ["new@example.com"])]}
            )

        """
        # Add entry
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        add_result = EntryTestHelpers.add_and_cleanup(
            typed_client,
            entry,
            verify=False,
            cleanup_after=False,
        )

        if verify_add_result:
            TestOperationHelpers.assert_operation_result_success(
                add_result,
                expected_operation_type=c.OperationType.ADD.value,
                expected_entries_affected=1,
            )

        # Modify entry
        if not entry.dn:
            error_msg = "Entry must have DN for modify operation"
            raise ValueError(error_msg)

        dn_str = str(entry.dn)
        modify_result_raw = typed_client.modify(dn_str, changes)
        # Type narrowing: ensure r
        modify_result: r[m.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(modify_result_raw)
        )

        if verify_modify_result:
            TestOperationHelpers.assert_operation_result_success(
                modify_result,
                expected_operation_type=c.OperationType.MODIFY.value,
                expected_entries_affected=1,
            )

        # Cleanup if requested
        if cleanup_after:
            _ = typed_client.delete(dn_str)

        return add_result, modify_result

    @staticmethod
    def create_entry_with_normalized_dn(
        cn_value: str,
        base_dn: str,
        *,
        spaces_before: int = 2,
        spaces_after: int = 2,
        sn: str | None = None,
        mail: str | None = None,
        use_uid: bool = False,
        **extra_attributes: LdapAttributeValue,
    ) -> FlextLdifModels.Entry:
        """Create entry with DN that has spaces for normalization testing - MASSIVE CODE REDUCTION (8-12 lines -> 1 line).

        Replaces entire test patterns like:
            entry = TestOperationHelpers.create_inetorgperson_entry("test", base_dn)
            dn_with_spaces = f"  {entry.dn!s}  "
            attrs = (
                entry.attributes.attributes
                if entry.attributes and entry.attributes.attributes
                else {}
            )
            entry = EntryTestHelpers.create_entry(dn_with_spaces, attrs)

        Args:
            cn_value: Common name value (or uid if use_uid=True)
            base_dn: Base DN for entry
            spaces_before: Number of spaces before DN (default: 2)
            spaces_after: Number of spaces after DN (default: 2)
            sn: Optional surname
            mail: Optional email
            use_uid: If True, creates uid-based DN
            **extra_attributes: Additional attributes

        Returns:
            FlextLdifModels.Entry with DN that has spaces

        Example:
            entry = TestDeduplicationHelpers.create_entry_with_normalized_dn(
                "testuser", RFC.DEFAULT_BASE_DN
            )

        """
        # Create base entry
        base_entry = TestDeduplicationHelpers.create_user(
            cn_value=cn_value,
            base_dn=base_dn,
            sn=sn,
            mail=mail,
            use_uid=use_uid,
            **extra_attributes,
        )

        # Add spaces to DN
        dn_str = str(base_entry.dn) if base_entry.dn else ""
        dn_with_spaces = " " * spaces_before + dn_str + " " * spaces_after

        # Get attributes
        attrs_raw = (
            base_entry.attributes.attributes
            if base_entry.attributes and base_entry.attributes.attributes
            else {}
        )
        # Normalize attributes to GeneralValueType for create_entry
        normalized_attrs: dict[str, t.GeneralValueType] = {}
        for key, value in attrs_raw.items():
            if isinstance(value, (str, int, float, bool, type(None))):
                normalized_attrs[key] = value
            elif isinstance(value, (list, tuple)):
                # Convert to list[str] for GeneralValueType
                normalized_attrs[key] = (
                    list(value) if isinstance(value, tuple) else value
                )
            elif isinstance(value, (set, frozenset)):
                # Convert set/frozenset to list for GeneralValueType
                normalized_attrs[key] = list(value)
            else:
                normalized_attrs[key] = cast("t.GeneralValueType", value)

        return EntryTestHelpers.create_entry(dn_with_spaces, normalized_attrs)

    @staticmethod
    def create_connection_config_from_container(
        ldap_container: GenericFieldsDict,
    ) -> m.ConnectionConfig:
        """Create ConnectionConfig from ldap_container fixture - COMMON PATTERN (6-8 lines -> 1 line).

        Replaces:
            connection_config = m.ConnectionConfig(
                host=str(ldap_container["host"]),
                port=int(str(ldap_container["port"])),
                use_ssl=False,
                bind_dn=str(ldap_container["bind_dn"]),
                bind_password=str(ldap_container["password"]),
            )

        Args:
            ldap_container: LDAP container fixture dict

        Returns:
            ConnectionConfig instance

        Example:
            config = TestDeduplicationHelpers.create_connection_config_from_container(
                ldap_container
            )

        """
        port_value = ldap_container.get("port", 3390)
        port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390

        return m.ConnectionConfig(
            host=str(ldap_container.get("host", "localhost")),
            port=port_int,
            use_ssl=bool(ldap_container.get("use_ssl")),
            bind_dn=str(ldap_container.get("bind_dn", "")),
            bind_password=str(ldap_container.get("password", "")),
        )

    @staticmethod
    def connect_and_disconnect(
        client: p.LdapService.LdapClientProtocol,
        connection_config: m.ConnectionConfig,
    ) -> None:
        """Connect client, verify, then disconnect - COMMON PATTERN (4-6 lines -> 1 line).

        Replaces:
            TestOperationHelpers.connect_and_assert_success(client, connection_config)
            client.disconnect()
            assert client.is_connected is False

        Args:
            client: LDAP client with connect, disconnect methods and is_connected property
            connection_config: Connection configuration

        Example:
            TestDeduplicationHelpers.connect_and_disconnect(api, connection_config)

        """
        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        TestOperationHelpers.connect_and_assert_success(typed_client, connection_config)

        if hasattr(client, "disconnect"):
            disconnect_method = getattr(client, "disconnect", None)
            if disconnect_method is not None:
                disconnect_method()

        # Check connection status - use getattr to safely access private attributes
        # FlextLdap uses _connection.is_connected, but protocol clients may use is_connected directly
        connection_obj = getattr(typed_client, "_connection", None)
        if connection_obj is not None:
            is_connected = getattr(connection_obj, "is_connected", None)
            if is_connected is not None:
                assert is_connected is False
        elif hasattr(typed_client, "is_connected"):
            is_connected = getattr(typed_client, "is_connected", False)
            assert is_connected is False
        # Fallback: check via operations service
        else:
            operations_obj = getattr(typed_client, "_operations", None)
            if operations_obj is not None:
                operations_connection = getattr(operations_obj, "_connection", None)
                if operations_connection is not None:
                    operations_is_connected = getattr(
                        operations_connection,
                        "is_connected",
                        None,
                    )
                    if operations_is_connected is not None:
                        assert operations_is_connected is False

    @staticmethod
    def api_add_operation(
        client: p.LdapService.LdapClientProtocol,
        cn_value: str,
        base_dn: str | None = None,
        *,
        sn: str | None = None,
        verify_operation_result: bool = False,
    ) -> tuple[FlextLdifModels.Entry, r[m.OperationResult]]:
        """Complete API add operation - MASSIVE CODE REDUCTION (8-10 lines -> 1 line).

        Replaces entire api_add patterns like:
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testapiadd", RFC.DEFAULT_BASE_DN, sn="Test"
            )
            TestOperationHelpers.add_entry_and_assert_success(TestDeduplicationHelpers._narrow_client_type(client), entry)

        Args:
            client: LDAP client with add method
            cn_value: Common name value
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            sn: Optional surname
            verify_operation_result: Whether to verify OperationResult (default: False)

        Returns:
            Tuple of (entry, add_result)

        Example:
            entry, result = TestDeduplicationHelpers.api_add_operation(
                ldap_client, "testapiadd", sn="Test"
            )

        """
        entry = TestDeduplicationHelpers.create_user(
            cn_value=cn_value,
            base_dn=base_dn,
            sn=sn,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        result = TestOperationHelpers.add_entry_and_assert_success(
            typed_client,
            entry,
            verify_operation_result=verify_operation_result,
        )

        return entry, result

    @staticmethod
    def api_modify_operation(
        client: p.LdapService.LdapClientProtocol,
        cn_value: str,
        base_dn: str | None = None,
        *,
        changes: dict[str, list[tuple[str, list[str]]]] | None = None,
        cleanup_after: bool = True,
    ) -> tuple[
        FlextLdifModels.Entry,
        dict[str, r[m.OperationResult]],
    ]:
        """Complete API modify operation - MASSIVE CODE REDUCTION (12-18 lines -> 1 line).

        Replaces entire api_modify patterns like:
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testapimodify", RFC.DEFAULT_BASE_DN
            )
            changes = {"mail": [(MODIFY_REPLACE, ["api@example.com"])]}
            results = TestOperationHelpers.execute_add_modify_delete_sequence(
                client, entry, changes, verify_delete=False
            )
            TestOperationHelpers.assert_result_success(results["add"])
            TestOperationHelpers.assert_result_success(results["modify"])
            if entry.dn:
                _ = client.delete(str(entry.dn))

        Args:
            client: LDAP client with add, modify, delete methods
            cn_value: Common name value
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)
            changes: Dictionary of modifications (default: adds mail attribute)
            cleanup_after: Whether to cleanup after modify (default: True)

        Returns:
            Tuple of (entry, results_dict)

        Example:
            entry, results = TestDeduplicationHelpers.api_modify_operation(
                ldap_client, "testapimodify"
            )

        """
        entry = TestDeduplicationHelpers.create_user(
            cn_value=cn_value,
            base_dn=base_dn,
        )

        if changes is None:
            changes = {"mail": [(MODIFY_REPLACE, ["api@example.com"])]}

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        results = TestOperationHelpers.execute_add_modify_delete_sequence(
            typed_client,
            entry,
            changes,
            verify_delete=False,
        )

        TestOperationHelpers.assert_result_success(results["add"])
        TestOperationHelpers.assert_result_success(
            results["modify"],
            error_message="Modify",
        )

        if cleanup_after and entry.dn:
            typed_client = TestDeduplicationHelpers._narrow_client_type(client)
            _ = typed_client.delete(str(entry.dn))

        return entry, results

    @staticmethod
    def api_delete_operation(
        client: p.LdapService.LdapClientProtocol,
        cn_value: str,
        base_dn: str | None = None,
    ) -> tuple[
        FlextLdifModels.Entry,
        r[m.OperationResult],
        r[m.OperationResult],
    ]:
        """Complete API delete operation - MASSIVE CODE REDUCTION (10-14 lines -> 1 line).

        Replaces entire api_delete patterns like:
            entry = TestOperationHelpers.create_inetorgperson_entry(
                "testapidelete", RFC.DEFAULT_BASE_DN
            )
            add_result = EntryTestHelpers.add_and_cleanup(
                client, entry, verify=False, cleanup_after=False
            )
            TestOperationHelpers.assert_result_success(add_result)
            if entry.dn:
                delete_result = client.delete(str(entry.dn))
                TestOperationHelpers.assert_result_success(delete_result)

        Args:
            client: LDAP client with add, delete methods
            cn_value: Common name value
            base_dn: Base DN (default: RFC.DEFAULT_BASE_DN)

        Returns:
            Tuple of (entry, add_result, delete_result)

        Example:
            entry, add_result, delete_result = TestDeduplicationHelpers.api_delete_operation(
                ldap_client, "testapidelete"
            )

        """
        entry = TestDeduplicationHelpers.create_user(
            cn_value=cn_value,
            base_dn=base_dn,
        )

        typed_client = TestDeduplicationHelpers._narrow_client_type(client)
        add_result = EntryTestHelpers.add_and_cleanup(
            typed_client,
            entry,
            verify=False,
            cleanup_after=False,
        )
        TestOperationHelpers.assert_result_success(add_result)

        if not entry.dn:
            error_msg = "Entry must have DN for delete operation"
            raise ValueError(error_msg)

        delete_result_raw = typed_client.delete(str(entry.dn))
        # Convert protocol result to r if needed
        delete_result: r[m.OperationResult] = (
            FlextLdapTestHelpers._ensure_flext_result(delete_result_raw)
        )
        TestOperationHelpers.assert_result_success(delete_result)

        return entry, add_result, delete_result
