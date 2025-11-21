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
        options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )
        assert options.base_dn == "dc=example,dc=com"
        assert options.filter_str == "(objectClass=*)"
        assert options.scope == "SUBTREE"
        assert options.attributes is None
        assert options.size_limit == 0
        assert options.time_limit == 0

    def test_search_options_custom(self) -> None:
        """Test SearchOptions with custom values."""
        options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(cn=test)",
            scope="ONELEVEL",
            attributes=["cn", "mail"],
            size_limit=100,
            time_limit=30,
        )
        assert options.base_dn == "dc=example,dc=com"
        assert options.filter_str == "(cn=test)"
        assert options.scope == "ONELEVEL"
        assert options.attributes == ["cn", "mail"]
        assert options.size_limit == 100
        assert options.time_limit == 30


class TestOperationResult:
    """Tests for OperationResult model."""

    def test_operation_result_success(self) -> None:
        """Test OperationResult with success."""
        result = FlextLdapModels.OperationResult(
            success=True,
            operation_type="add",
            entries_affected=1,
        )
        assert result.success is True
        assert result.operation_type == "add"
        assert result.entries_affected == 1

    def test_operation_result_failure(self) -> None:
        """Test OperationResult with failure."""
        result = FlextLdapModels.OperationResult(
            success=False,
            operation_type="add",
            entries_affected=0,
        )
        assert result.success is False
        assert result.operation_type == "add"
        assert result.entries_affected == 0


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

    def test_sync_stats_custom(self) -> None:
        """Test SyncStats with custom values."""
        stats = FlextLdapModels.SyncStats(
            added=5,
            skipped=2,
            failed=1,
            total=8,
            duration_seconds=1.5,
        )
        assert stats.added == 5
        assert stats.skipped == 2
        assert stats.failed == 1
        assert stats.total == 8
        assert stats.duration_seconds == 1.5

    def test_sync_stats_success_rate(self) -> None:
        """Test SyncStats success_rate calculation."""
        stats = FlextLdapModels.SyncStats(
            added=7,
            skipped=2,
            failed=1,
            total=10,
        )
        # success_rate = (7 + 2) / 10 = 0.9
        assert stats.success_rate == 0.9

    def test_sync_stats_success_rate_zero_total(self) -> None:
        """Test SyncStats success_rate when total is 0 (covers line 309)."""
        stats = FlextLdapModels.SyncStats(
            added=0,
            skipped=0,
            failed=0,
            total=0,  # Zero total - should return 0.0 (covers line 309)
        )
        # When total is 0, success_rate should return 0.0 (covers line 309)
        assert stats.success_rate == 0.0
