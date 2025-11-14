"""Unit tests for FlextLdapModels.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.models import FlextLdapModels


class TestConnectionConfig:
    """Tests for ConnectionConfig model."""

    def test_connection_config_defaults(self) -> None:
        """Test ConnectionConfig with default values."""
        config = FlextLdapModels.ConnectionConfig(host="ldap.example.com")
        assert config.host == "ldap.example.com"
        assert config.port == 389
        assert config.use_ssl is False
        assert config.use_tls is False
        assert config.bind_dn is None
        assert config.bind_password is None
        assert config.timeout == 30
        assert config.auto_bind is True
        assert config.auto_range is True

    def test_connection_config_custom(self) -> None:
        """Test ConnectionConfig with custom values."""
        config = FlextLdapModels.ConnectionConfig(
            host="ldap.example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="password",
            timeout=60,
        )
        assert config.host == "ldap.example.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.bind_dn == "cn=admin,dc=example,dc=com"
        assert config.bind_password == "password"
        assert config.timeout == 60


class TestSearchOptions:
    """Tests for SearchOptions model."""

    def test_search_options_defaults(self) -> None:
        """Test SearchOptions with default values."""
        options = FlextLdapModels.SearchOptions(base_dn="dc=example,dc=com")
        assert options.base_dn == "dc=example,dc=com"
        assert options.scope == "SUBTREE"
        assert options.filter_str == "(objectClass=*)"
        assert options.attributes is None
        assert options.size_limit == 0
        assert options.time_limit == 0

    def test_search_options_custom(self) -> None:
        """Test SearchOptions with custom values."""
        options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            scope="ONELEVEL",
            filter_str="(cn=test)",
            attributes=["cn", "sn"],
            size_limit=100,
            time_limit=30,
        )
        assert options.base_dn == "dc=example,dc=com"
        assert options.scope == "ONELEVEL"
        assert options.filter_str == "(cn=test)"
        assert options.attributes == ["cn", "sn"]
        assert options.size_limit == 100
        assert options.time_limit == 30


class TestOperationResult:
    """Tests for OperationResult model."""

    def test_operation_result_success(self) -> None:
        """Test OperationResult for successful operation."""
        result = FlextLdapModels.OperationResult(
            success=True,
            operation_type="add",
            message="Entry added successfully",
            entries_affected=1,
        )
        assert result.success is True
        assert result.operation_type == "add"
        assert result.message == "Entry added successfully"
        assert result.entries_affected == 1

    def test_operation_result_failure(self) -> None:
        """Test OperationResult for failed operation."""
        result = FlextLdapModels.OperationResult(
            success=False,
            operation_type="delete",
            message="Entry not found",
            entries_affected=0,
        )
        assert result.success is False
        assert result.operation_type == "delete"
        assert result.message == "Entry not found"
        assert result.entries_affected == 0


class TestSearchResult:
    """Tests for SearchResult model."""

    def test_search_result_empty(self) -> None:
        """Test SearchResult with no entries."""
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )
        result = FlextLdapModels.SearchResult(
            entries=[],
            total_count=0,
            search_options=search_options,
        )
        assert len(result.entries) == 0
        assert result.total_count == 0
        assert result.search_options == search_options


class TestSyncStats:
    """Tests for SyncStats model."""

    def test_sync_stats_defaults(self) -> None:
        """Test SyncStats with default values."""
        stats = FlextLdapModels.SyncStats()
        assert stats.added == 0
        assert stats.skipped == 0
        assert stats.failed == 0
        assert stats.total == 0
        assert stats.duration_seconds == 0.0

    def test_sync_stats_success_rate_with_zero_total(self) -> None:
        """Test success_rate when total is zero (should return 0.0)."""
        stats = FlextLdapModels.SyncStats(
            added=0,
            skipped=0,
            failed=0,
            total=0,
        )
        assert stats.success_rate == 0.0

    def test_sync_stats_success_rate_calculation(self) -> None:
        """Test success_rate calculation with values."""
        stats = FlextLdapModels.SyncStats(
            added=5,
            skipped=3,
            failed=2,
            total=10,
        )
        # success_rate = (added + skipped) / total = (5 + 3) / 10 = 0.8
        assert stats.success_rate == 0.8

    def test_sync_stats_success_rate_all_skipped(self) -> None:
        """Test success_rate when all entries are skipped."""
        stats = FlextLdapModels.SyncStats(
            added=0,
            skipped=10,
            failed=0,
            total=10,
        )
        assert stats.success_rate == 1.0

    def test_sync_stats_success_rate_all_added(self) -> None:
        """Test success_rate when all entries are added."""
        stats = FlextLdapModels.SyncStats(
            added=10,
            skipped=0,
            failed=0,
            total=10,
        )
        assert stats.success_rate == 1.0

    def test_sync_stats_success_rate_partial_failure(self) -> None:
        """Test success_rate with partial failures."""
        stats = FlextLdapModels.SyncStats(
            added=7,
            skipped=2,
            failed=1,
            total=10,
        )
        # success_rate = (7 + 2) / 10 = 0.9
        assert stats.success_rate == 0.9
