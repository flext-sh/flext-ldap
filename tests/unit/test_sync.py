"""Unit tests for flext_ldap.services.sync.FlextLdapSyncService.

**Modules Tested:**
- `flext_ldap.services.sync.FlextLdapSyncService` - LDIF to LDAP synchronization service

**Test Scope:**
- Service initialization and dependency injection
- Execute method (health check)
- SyncStats model creation
- BaseDNTransformer functionality
- BatchSync inner class
- Method existence validation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldap import (
    FlextLdapConnection,
    FlextLdapOperations,
    FlextLdapSettings,
    FlextLdapSyncService,
    t,
)
from tests import m

pytestmark = pytest.mark.unit


class TestsFlextLdapSync:
    """Comprehensive tests for FlextLdapSyncService using factories and DRY principles.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

    Uses parametrized tests and constants for maximum code reuse.
    All helper logic is nested within this single class following FLEXT patterns.
    """

    @classmethod
    def _create_operations(cls) -> FlextLdapOperations:
        """Factory method for creating operations instances."""
        connection = FlextLdapConnection(config=FlextLdapSettings())
        return FlextLdapOperations(connection=connection)

    @staticmethod
    def _entry(dn: str) -> m.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(attributes={}),
        )

    def test_sync_service_initialization(self) -> None:
        operations = self._create_operations()
        sync_service = FlextLdapSyncService(operations=operations)
        tm.that(sync_service, is_=FlextLdapSyncService, none=False)
        tm.that(hasattr(sync_service, "_generate_datetime_utc"), eq=True)

    def test_sync_service_init_without_operations_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="operations parameter is required"):
            FlextLdapSyncService(operations=None)

    def test_execute_returns_empty_stats(self) -> None:
        """Test execute() returns empty sync stats for health check."""
        operations = self._create_operations()
        sync_service = FlextLdapSyncService(operations=operations)
        result = sync_service.execute()
        stats = tm.ok(result)
        assert isinstance(stats, m.Ldap.SyncStats), "expected SyncStats"
        tm.that(stats.synced, eq=0)
        tm.that(stats.skipped, eq=0)
        tm.that(stats.failed, eq=0)
        tm.that(stats.total, eq=0)

    def test_sync_stats_creation(self) -> None:
        """Test SyncStats model creation."""
        stats = m.Ldap.SyncStats(
            synced=10, skipped=2, failed=1, total=13, duration_seconds=100.5
        )
        tm.that(stats.synced, eq=10)
        tm.that(stats.skipped, eq=2)
        tm.that(stats.failed, eq=1)
        tm.that(stats.total, eq=13)
        tm.that(stats.duration_seconds, eq=100.5)

    @pytest.mark.parametrize(
        ("kwargs", "expected_source", "expected_target"),
        [
            pytest.param({}, "", "", id="defaults"),
            pytest.param(
                {"source_basedn": "dc=old,dc=com", "target_basedn": "dc=new,dc=com"},
                "dc=old,dc=com",
                "dc=new,dc=com",
                id="explicit_transform",
            ),
        ],
    )
    def test_sync_options(
        self,
        kwargs: t.StrMapping,
        expected_source: str,
        expected_target: str,
    ) -> None:
        options = m.Ldap.SyncOptions(**kwargs)
        tm.that(options.source_basedn, eq=expected_source)
        tm.that(options.target_basedn, eq=expected_target)

    @pytest.mark.parametrize(
        ("dn", "source_basedn", "target_basedn", "expected_dn"),
        [
            pytest.param(
                "cn=user,dc=example,dc=com",
                "",
                "",
                "cn=user,dc=example,dc=com",
                id="no_transformation",
            ),
            pytest.param(
                "cn=user,dc=old,dc=com",
                "dc=old,dc=com",
                "dc=new,dc=com",
                "cn=user,dc=new,dc=com",
                id="direct_replace",
            ),
            pytest.param(
                "cn=user,dc=old,dc=com",
                "DC=OLD,DC=COM",
                "dc=new,dc=com",
                "cn=user,dc=new,dc=com",
                id="case_insensitive",
            ),
        ],
    )
    def test_base_dn_transformer(
        self,
        dn: str,
        source_basedn: str,
        target_basedn: str,
        expected_dn: str,
    ) -> None:
        transformed = FlextLdapSyncService.BaseDNTransformer.transform(
            [self._entry(dn)],
            source_basedn=source_basedn,
            target_basedn=target_basedn,
        )
        tm.that(transformed, len=1)
        tm.that(transformed[0].dn, none=False)
        assert transformed[0].dn is not None
        tm.that(transformed[0].dn.value, eq=expected_dn)

    def test_sync_ldif_file_missing_path_returns_failure(self) -> None:
        sync_service = FlextLdapSyncService(operations=self._create_operations())
        result = sync_service.sync_ldif_file(
            Path("/tmp/flext-nonexistent-sync-input.ldif"),
            m.Ldap.SyncOptions(),
        )
        tm.fail(result)

    def test_batch_sync_initialization(self) -> None:
        """Test BatchSync inner class initialization."""
        operations = self._create_operations()
        batch_sync = FlextLdapSyncService.BatchSync(operations=operations)
        assert batch_sync is not None
        assert isinstance(batch_sync, FlextLdapSyncService.BatchSync)

    def test_sync_service_methods_exist(self) -> None:
        """Test that all expected methods exist on sync service."""
        operations = self._create_operations()
        sync_service = FlextLdapSyncService(operations=operations)
        tm.that(sync_service, attrs=["execute", "sync_ldif_file"])
        tm.that(callable(sync_service.execute), eq=True)
        tm.that(callable(sync_service.sync_ldif_file), eq=True)

    def test_sync_service_inner_classes_exist(self) -> None:
        """Test that inner classes exist."""
        tm.that(hasattr(FlextLdapSyncService, "BatchSync"), eq=True)
        tm.that(hasattr(FlextLdapSyncService, "BaseDNTransformer"), eq=True)
        assert isinstance(FlextLdapSyncService.BatchSync, type)
        assert isinstance(FlextLdapSyncService.BaseDNTransformer, type)
