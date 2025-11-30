"""Unit tests for FlextLdapModels domain validation.

Uses FlextUtilities, FlextTestsMatchers, and FlextTestsUtilities.ModelTestHelpers
for maximum code reduction. All factories, validation and assertions use centralized
flext-core patterns.

Tested module: flext_ldap.models
Test scope: Domain model validation, computed properties, factory methods
Coverage: 100% with parametrized edge cases

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar, cast

import pytest
from flext_core import FlextUtilities
from flext_tests import FlextTestsMatchers, FlextTestsUtilities

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldif import FlextLdifModels

from ..fixtures.constants import TestConstants
from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


class Scenario(StrEnum):
    """Test scenarios using Python 3.13 StrEnum."""

    DEFAULT = "default"
    CUSTOM = "custom"
    EDGE_CASE = "edge_case"


class SSLTLSMode(StrEnum):
    """SSL/TLS mutual exclusion scenarios."""

    BOTH_ENABLED = "both_enabled"
    BOTH_DISABLED = "both_disabled"
    SSL_ONLY = "ssl_only"
    TLS_ONLY = "tls_only"


# Parametrize tuples for pyrefly compatibility
_SCENARIO_PARAMS: tuple[Scenario, ...] = (
    Scenario.DEFAULT,
    Scenario.CUSTOM,
    Scenario.EDGE_CASE,
)

_SSL_TLS_PARAMS: tuple[SSLTLSMode, ...] = (
    SSLTLSMode.BOTH_ENABLED,
    SSLTLSMode.BOTH_DISABLED,
    SSLTLSMode.SSL_ONLY,
    SSLTLSMode.TLS_ONLY,
)


class TestFlextLdapModels:
    """Comprehensive tests for FLEXT-LDAP domain models.

    Uses FlextUtilities.Configuration.build_options_from_kwargs for model creation.
    Uses FlextTestsMatchers and FlextTestsUtilities.ModelTestHelpers for assertions.
    """

    # Single source of truth: ConnectionConfig scenarios
    _CONN_SCENARIOS: ClassVar[
        Mapping[Scenario, Mapping[str, str | int | bool | None]]
    ] = {
        Scenario.DEFAULT: {
            "host": "ldap.example.com",
            "port": 389,
            "use_ssl": False,
            "use_tls": False,
            "bind_dn": None,
            "bind_password": None,
            "timeout": 30,
            "auto_bind": True,
            "auto_range": True,
        },
        Scenario.CUSTOM: {
            "host": "secure.example.com",
            "port": 636,
            "use_ssl": True,
            "use_tls": False,
            "bind_dn": TestConstants.DEFAULT_BIND_DN,
            "bind_password": "secure_password",
            "timeout": 60,
            "auto_bind": False,
            "auto_range": False,
        },
        Scenario.EDGE_CASE: {
            "host": "a",
            "port": 1,
            "use_ssl": False,
            "use_tls": False,
            "bind_dn": None,
            "bind_password": None,
            "timeout": 300,
            "auto_bind": False,
            "auto_range": False,
        },
    }

    # Single source of truth: SearchOptions scenarios
    _SEARCH_SCENARIOS: ClassVar[
        Mapping[Scenario, Mapping[str, str | int | list[str] | None]]
    ] = {
        Scenario.DEFAULT: {
            "base_dn": TestConstants.DEFAULT_BASE_DN,
            "filter_str": "(objectClass=*)",
            "scope": "SUBTREE",
            "attributes": None,
            "size_limit": 0,
            "time_limit": 0,
        },
        Scenario.CUSTOM: {
            "base_dn": TestConstants.DEFAULT_BASE_DN,
            "filter_str": "(cn=test)",
            "scope": "ONELEVEL",
            "attributes": ["cn", "mail", "uid"],
            "size_limit": 100,
            "time_limit": 30,
        },
        Scenario.EDGE_CASE: {
            "base_dn": TestConstants.DEFAULT_BASE_DN,
            "filter_str": "(objectClass=*)",
            "scope": "BASE",
            "attributes": [],
            "size_limit": 1000,
            "time_limit": 3600,
        },
    }

    # SSL/TLS configuration lookup: (use_ssl, use_tls, should_fail)
    _SSL_TLS_CONFIG: ClassVar[Mapping[SSLTLSMode, tuple[bool, bool, bool]]] = {
        SSLTLSMode.BOTH_ENABLED: (True, True, True),
        SSLTLSMode.BOTH_DISABLED: (False, False, False),
        SSLTLSMode.SSL_ONLY: (True, False, False),
        SSLTLSMode.TLS_ONLY: (False, True, False),
    }

    # === ConnectionConfig Tests ===

    @pytest.mark.parametrize("scenario", _SCENARIO_PARAMS)
    def test_connection_config_scenarios(self, scenario: Scenario) -> None:
        """Test ConnectionConfig creation with all scenarios."""
        data = dict(self._CONN_SCENARIOS[scenario])

        # Use FlextUtilities for building model from kwargs
        result = FlextUtilities.Configuration.build_options_from_kwargs(
            model_class=FlextLdapModels.ConnectionConfig,
            explicit_options=None,
            default_factory=FlextLdapModels.ConnectionConfig,
            **data,
        )

        # Use FlextTestsMatchers for assertion
        config = FlextTestsMatchers.assert_success(result)

        # Use ModelTestHelpers.assert_attr_values for attribute validation
        FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
            config,
            dict(self._CONN_SCENARIOS[scenario]),
        )

    @pytest.mark.parametrize("mode", _SSL_TLS_PARAMS)
    def test_connection_config_ssl_tls_validation(self, mode: SSLTLSMode) -> None:
        """Test SSL/TLS mutual exclusion validation."""
        use_ssl, use_tls, should_fail = self._SSL_TLS_CONFIG[mode]

        if should_fail:
            with pytest.raises(ValueError, match="mutually exclusive"):
                FlextLdapModels.ConnectionConfig(
                    host="test.example.com",
                    use_ssl=use_ssl,
                    use_tls=use_tls,
                )
        else:
            config = FlextLdapModels.ConnectionConfig(
                host="test.example.com",
                use_ssl=use_ssl,
                use_tls=use_tls,
            )
            FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
                config,
                {"use_ssl": use_ssl, "use_tls": use_tls},
            )

    # === SearchOptions Tests ===

    @pytest.mark.parametrize("scenario", _SCENARIO_PARAMS)
    def test_search_options_scenarios(self, scenario: Scenario) -> None:
        """Test SearchOptions creation with all scenarios."""
        data = dict(self._SEARCH_SCENARIOS[scenario])

        # Use FlextUtilities for building model from kwargs
        result = FlextUtilities.Configuration.build_options_from_kwargs(
            model_class=FlextLdapModels.SearchOptions,
            explicit_options=None,
            default_factory=lambda: FlextLdapModels.SearchOptions(
                base_dn=TestConstants.DEFAULT_BASE_DN,
            ),
            **data,
        )

        options = FlextTestsMatchers.assert_success(result)

        # Use ModelTestHelpers for attribute validation
        FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
            options,
            dict(self._SEARCH_SCENARIOS[scenario]),
        )

    def test_search_options_invalid_base_dn(self) -> None:
        """Test SearchOptions rejects malformed base DN."""
        with pytest.raises(ValueError, match="Invalid base_dn format"):
            FlextLdapModels.SearchOptions(
                base_dn="invalid-dn-format",
                filter_str="(objectClass=*)",
                scope=FlextLdapConstants.SearchScope.SUBTREE,
            )

    @pytest.mark.parametrize(
        ("scope", "filter_str", "expected_scope", "expected_filter"),
        [
            ("BASE", "(cn=*)", "BASE", "(cn=*)"),
            ("SUBTREE", "(uid=test)", "SUBTREE", "(uid=test)"),
            ("SUBTREE", None, "SUBTREE", "(objectClass=*)"),
        ],
    )
    def test_search_options_normalized(
        self,
        scope: str,
        filter_str: str | None,
        expected_scope: str,
        expected_filter: str,
    ) -> None:
        """Test SearchOptions.normalized with various inputs."""
        scope_literal: FlextLdapConstants.SearchScope
        if scope == FlextLdapConstants.SearchScope.BASE:
            scope_literal = FlextLdapConstants.SearchScope.BASE
        elif scope == FlextLdapConstants.SearchScope.ONELEVEL:
            scope_literal = FlextLdapConstants.SearchScope.ONELEVEL
        else:
            scope_literal = FlextLdapConstants.SearchScope.SUBTREE

        if filter_str is not None:
            options = FlextLdapModels.SearchOptions.normalized(
                base_dn=TestConstants.DEFAULT_BASE_DN,
                scope=scope_literal,
                filter_str=filter_str,
            )
        else:
            options = FlextLdapModels.SearchOptions.normalized(
                base_dn=TestConstants.DEFAULT_BASE_DN,
                scope=scope_literal,
            )

        FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
            options,
            {"scope": expected_scope, "filter_str": expected_filter},
        )

    # === OperationResult Tests ===

    @pytest.mark.parametrize(
        ("success", "op_type", "entries"),
        [
            (True, "add", 1),
            (False, "delete", 0),
            (True, "modify", 5),
            (True, "search", 10),
        ],
    )
    def test_operation_result_scenarios(
        self,
        success: bool,
        op_type: str,
        entries: int,
    ) -> None:
        """Test OperationResult with various scenarios."""
        operation_type_literal: FlextLdapConstants.OperationType
        if op_type == "add":
            operation_type_literal = FlextLdapConstants.OperationType.ADD
        elif op_type == "modify":
            operation_type_literal = FlextLdapConstants.OperationType.MODIFY
        elif op_type == "delete":
            operation_type_literal = FlextLdapConstants.OperationType.DELETE
        elif op_type == "modify_dn":
            operation_type_literal = FlextLdapConstants.OperationType.MODIFY_DN
        elif op_type == "compare":
            operation_type_literal = FlextLdapConstants.OperationType.COMPARE
        elif op_type == "bind":
            operation_type_literal = FlextLdapConstants.OperationType.BIND
        elif op_type == "unbind":
            operation_type_literal = FlextLdapConstants.OperationType.UNBIND
        else:
            operation_type_literal = FlextLdapConstants.OperationType.SEARCH
        result = FlextLdapModels.OperationResult(
            success=success,
            operation_type=operation_type_literal,
            entries_affected=entries,
        )

        FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
            result,
            {
                "success": success,
                "operation_type": op_type,
                "entries_affected": entries,
            },
        )

    # === SyncStats Tests ===

    @pytest.mark.parametrize(
        ("added", "skipped", "failed", "total", "duration"),
        [
            (0, 0, 0, 0, 0.0),
            (5, 2, 1, 8, 1.5),
            (10, 0, 0, 10, 2.0),
        ],
    )
    def test_sync_stats_initialization(
        self,
        added: int,
        skipped: int,
        failed: int,
        total: int,
        duration: float,
    ) -> None:
        """Test SyncStats initialization with various values."""
        stats = FlextLdapModels.SyncStats(
            added=added,
            skipped=skipped,
            failed=failed,
            total=total,
            duration_seconds=duration,
        )

        FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
            stats,
            {
                "added": added,
                "skipped": skipped,
                "failed": failed,
                "total": total,
                "duration_seconds": duration,
            },
        )

    @pytest.mark.parametrize(
        ("added", "skipped", "failed", "total", "expected_rate"),
        [
            (7, 2, 1, 10, 0.9),
            (10, 0, 0, 10, 1.0),
            (0, 0, 5, 5, 0.0),
            (0, 0, 0, 0, 0.0),
        ],
    )
    def test_sync_stats_success_rate(
        self,
        added: int,
        skipped: int,
        failed: int,
        total: int,
        expected_rate: float,
    ) -> None:
        """Test SyncStats.success_rate computed property."""
        stats = FlextLdapModels.SyncStats(
            added=added,
            skipped=skipped,
            failed=failed,
            total=total,
            duration_seconds=0.0,
        )

        # Access computed property - Pydantic computed_field accessed via getattr
        success_rate_value = cast("float", stats.success_rate)
        assert success_rate_value == expected_rate

    def test_sync_stats_from_counters(self) -> None:
        """Test SyncStats.from_counters factory method."""
        stats = FlextLdapModels.SyncStats.from_counters(
            added=10,
            skipped=5,
            failed=2,
            duration_seconds=1.5,
        )

        FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
            stats,
            {
                "added": 10,
                "skipped": 5,
                "failed": 2,
                "total": 17,
                "duration_seconds": 1.5,
            },
        )

    # === SearchResult Tests ===

    def test_search_result_total_count(self) -> None:
        """Test SearchResult.total_count computed property."""
        # Use TestDeduplicationHelpers.create_entry instead of private _create_entry
        entries = [
            TestDeduplicationHelpers.create_entry(
                "cn=user1,dc=example,dc=com",
                {"cn": ["test"], "objectClass": ["top", "person"]},
            ),
            TestDeduplicationHelpers.create_entry(
                "cn=user2,dc=example,dc=com",
                {"cn": ["test"], "objectClass": ["top", "person"]},
            ),
        ]
        options = FlextLdapModels.SearchOptions(
            base_dn=TestConstants.DEFAULT_BASE_DN,
        )

        result = FlextLdapModels.SearchResult(entries=entries, search_options=options)

        # Access computed property - Pydantic computed_field accessed via getattr
        total_count_value = cast("int", result.total_count)
        assert total_count_value == 2

    @pytest.mark.parametrize(
        ("entries_data", "expected_categories"),
        [
            (
                [
                    ("cn=u1,dc=example,dc=com", ["person", "top"]),
                    ("cn=u2,dc=example,dc=com", ["person", "top"]),
                    ("ou=org,dc=example,dc=com", ["organizationalUnit"]),
                ],
                {"person": 2, "organizationalUnit": 1},
            ),
            ([], {}),
        ],
    )
    def test_search_result_by_objectclass(
        self,
        entries_data: list[tuple[str, list[str]]],
        expected_categories: dict[str, int],
    ) -> None:
        """Test SearchResult.by_objectclass categorization."""
        # Use TestDeduplicationHelpers.create_entry
        entries = [
            TestDeduplicationHelpers.create_entry(
                dn,
                {"cn": ["test"], "objectClass": oc},
            )
            for dn, oc in entries_data
        ]
        options = FlextLdapModels.SearchOptions(
            base_dn=TestConstants.DEFAULT_BASE_DN,
        )

        result = FlextLdapModels.SearchResult(entries=entries, search_options=options)
        # Access computed property - Pydantic computed_field accessed via getattr
        categories = cast(
            "dict[str, list[FlextLdifModels.Entry]]",
            result.by_objectclass,
        )

        for oc, expected_count in expected_categories.items():
            assert len(categories.get(oc, [])) == expected_count

    def test_search_result_by_objectclass_missing(self) -> None:
        """Test by_objectclass handles missing objectClass."""
        entry = TestDeduplicationHelpers.create_entry(
            TestConstants.TEST_USER_DN,
            {"cn": ["test"]},  # No objectClass
        )
        options = FlextLdapModels.SearchOptions(
            base_dn=TestConstants.DEFAULT_BASE_DN,
        )

        result = FlextLdapModels.SearchResult(entries=[entry], search_options=options)
        # Access computed property - Pydantic computed_field accessed via getattr
        categories = cast(
            "dict[str, list[FlextLdifModels.Entry]]",
            result.by_objectclass,
        )

        assert "unknown" in categories
        assert len(categories["unknown"]) == 1

    # === BatchOperations Tests ===

    @pytest.mark.parametrize(
        ("total", "successful", "failed"),
        [(10, 8, 2), (0, 0, 0), (5, 5, 0)],
    )
    def test_batch_upsert_result(
        self,
        total: int,
        successful: int,
        failed: int,
    ) -> None:
        """Test BatchUpsertResult basic properties."""
        result = FlextLdapModels.BatchUpsertResult(
            total_processed=total,
            successful=successful,
            failed=failed,
            results=[],
        )

        expected_rate = 0.0 if total == 0 else successful / total
        FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
            result,
            {
                "total_processed": total,
                "successful": successful,
                "failed": failed,
                "success_rate": expected_rate,
            },
        )

    def test_batch_upsert_result_with_results(self) -> None:
        """Test BatchUpsertResult with individual results."""
        results = [
            FlextLdapModels.UpsertResult(
                success=True,
                dn="cn=t1,dc=example,dc=com",
                operation=FlextLdapConstants.OperationType.ADD,
            ),
            FlextLdapModels.UpsertResult(
                success=False,
                dn="cn=t2,dc=example,dc=com",
                operation=FlextLdapConstants.OperationType.MODIFY,
                error="Entry not found",
            ),
        ]

        batch = FlextLdapModels.BatchUpsertResult(
            total_processed=2,
            successful=1,
            failed=1,
            results=results,
        )

        assert len(batch.results) == 2
        assert batch.results[0].success is True
        assert batch.results[1].error == "Entry not found"

    @pytest.mark.parametrize(
        ("success", "operation", "error"),
        [
            (True, "add", None),
            (False, "modify", "Entry not found"),
            (True, "search", None),
        ],
    )
    def test_upsert_result(
        self,
        success: bool,
        operation: str,
        error: str | None,
    ) -> None:
        """Test UpsertResult scenarios."""
        operation_type_literal: FlextLdapConstants.OperationType
        if operation == "add":
            operation_type_literal = FlextLdapConstants.OperationType.ADD
        elif operation == "modify":
            operation_type_literal = FlextLdapConstants.OperationType.MODIFY
        elif operation == "delete":
            operation_type_literal = FlextLdapConstants.OperationType.DELETE
        elif operation == "modify_dn":
            operation_type_literal = FlextLdapConstants.OperationType.MODIFY_DN
        elif operation == "compare":
            operation_type_literal = FlextLdapConstants.OperationType.COMPARE
        elif operation == "bind":
            operation_type_literal = FlextLdapConstants.OperationType.BIND
        elif operation == "unbind":
            operation_type_literal = FlextLdapConstants.OperationType.UNBIND
        else:
            operation_type_literal = FlextLdapConstants.OperationType.SEARCH
        result = FlextLdapModels.UpsertResult(
            success=success,
            dn="cn=test,dc=example,dc=com",
            operation=operation_type_literal,
            error=error,
        )

        FlextTestsUtilities.ModelTestHelpers.assert_attr_values(
            result,
            {"success": success, "operation": operation, "error": error},
        )
