"""Unit tests for FlextLdapModels.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from flext_ldif.models import FlextLdifModels

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
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="password",
            timeout=60,
        )
        assert config.host == "ldap.example.com"
        assert config.port == 636
        assert config.use_ssl is True
        assert config.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert config.bind_password == "password"
        assert config.timeout == 60

    def test_connection_config_ssl_tls_mutual_exclusion(self) -> None:
        """Test ConnectionConfig validates SSL/TLS mutual exclusion (covers lines 117-121)."""
        # Both SSL and TLS should raise ValueError
        with pytest.raises(ValueError, match="mutually exclusive"):
            FlextLdapModels.ConnectionConfig(
                host="ldap.example.com",
                use_ssl=True,
                use_tls=True,
            )

    def test_connection_config_ssl_only(self) -> None:
        """Test ConnectionConfig with SSL only."""
        config = FlextLdapModels.ConnectionConfig(
            host="ldap.example.com",
            use_ssl=True,
            use_tls=False,
        )
        assert config.use_ssl is True
        assert config.use_tls is False

    def test_connection_config_tls_only(self) -> None:
        """Test ConnectionConfig with TLS only."""
        config = FlextLdapModels.ConnectionConfig(
            host="ldap.example.com",
            use_ssl=False,
            use_tls=True,
        )
        assert config.use_ssl is False
        assert config.use_tls is True


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
        assert cast("float", stats.success_rate) == 0.9

    def test_sync_stats_success_rate_zero_total(self) -> None:
        """Test SyncStats success_rate when total is 0 (covers line 309)."""
        stats = FlextLdapModels.SyncStats(
            added=0,
            skipped=0,
            failed=0,
            total=0,  # Zero total - should return 0.0 (covers line 309)
        )
        # When total is 0, success_rate should return 0.0 (covers line 309)
        assert cast("float", stats.success_rate) == 0.0

    def test_sync_stats_from_counters(self) -> None:
        """Test SyncStats.from_counters method (covers lines 493-494)."""
        stats = FlextLdapModels.SyncStats.from_counters(
            added=10,
            skipped=5,
            failed=2,
            duration_seconds=1.5,
        )
        assert stats.added == 10
        assert stats.skipped == 5
        assert stats.failed == 2
        assert stats.total == 17  # 10 + 5 + 2
        assert stats.duration_seconds == 1.5


class TestSearchOptionsValidation:
    """Tests for SearchOptions validation."""

    def test_search_options_invalid_base_dn(self) -> None:
        """Test SearchOptions with invalid base_dn (covers lines 187-188)."""
        with pytest.raises(ValueError, match="Invalid base_dn format"):
            FlextLdapModels.SearchOptions(
                base_dn="invalid-dn-format",
                filter_str="(objectClass=*)",
            )


class TestSearchOptionsNormalized:
    """Tests for SearchOptions.normalized method."""

    def test_search_options_normalized_with_scope(self) -> None:
        """Test SearchOptions.normalized with scope (covers lines 227-244)."""
        options = FlextLdapModels.SearchOptions.normalized(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert options.base_dn == "dc=example,dc=com"
        assert options.filter_str == "(objectClass=*)"
        assert options.scope == "BASE"

    def test_search_options_normalized_without_scope(self) -> None:
        """Test SearchOptions.normalized without scope (uses default, covers lines 230-237)."""
        options = FlextLdapModels.SearchOptions.normalized(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )
        assert options.base_dn == "dc=example,dc=com"
        assert options.filter_str == "(objectClass=*)"
        # Should use default scope SUBTREE
        assert options.scope == "SUBTREE"

    def test_search_options_normalized_without_filter(self) -> None:
        """Test SearchOptions.normalized without filter (uses default, covers lines 238-242)."""
        options = FlextLdapModels.SearchOptions.normalized(
            base_dn="dc=example,dc=com",
        )
        assert options.base_dn == "dc=example,dc=com"
        # Should use default filter
        assert options.filter_str is not None


class TestSearchResult:
    """Tests for SearchResult model."""

    def test_search_result_count(self) -> None:
        """Test SearchResult.count property (covers line 322)."""
        entry1 = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=user1,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["user1"]}),
        )
        entry2 = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=user2,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["user2"]}),
        )

        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )

        search_result = FlextLdapModels.SearchResult(
            entries=[entry1, entry2],
            search_options=search_options,
        )

        # Test count property (computed field)
        assert search_result.total_count == 2

    def test_search_result_by_objectclass(self) -> None:
        """Test SearchResult.by_objectclass property (covers lines 341-360)."""
        # Create entries with different objectClasses
        entry1 = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=user1,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"objectClass": ["person", "top"], "cn": ["user1"]}
            ),
        )
        entry2 = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=user2,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"objectClass": ["person", "top"], "cn": ["user2"]}
            ),
        )
        entry3 = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="ou=org,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"objectClass": ["organizationalUnit"], "ou": ["org"]}
            ),
        )

        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )

        search_result = FlextLdapModels.SearchResult(
            entries=[entry1, entry2, entry3],
            search_options=search_options,
        )

        # Test by_objectclass property (computed field)
        categories = search_result.by_objectclass
        assert isinstance(categories, dict)
        # Should have categories for "person" and "organizationalUnit"
        assert "person" in categories
        assert "organizationalUnit" in categories
        # person category should have 2 entries
        assert len(categories["person"]) == 2
        # organizationalUnit category should have 1 entry
        assert len(categories["organizationalUnit"]) == 1

    def test_search_result_by_objectclass_without_objectclass(self) -> None:
        """Test SearchResult.by_objectclass with entries without objectClass (covers line 354)."""
        # Create entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"]}  # No objectClass
            ),
        )

        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
        )

        search_result = FlextLdapModels.SearchResult(
            entries=[entry],
            search_options=search_options,
        )

        # Test by_objectclass property (computed field)
        categories = search_result.by_objectclass
        assert isinstance(categories, dict)
        # Should have "unknown" category for entries without objectClass
        assert "unknown" in categories
        assert len(categories["unknown"]) == 1
