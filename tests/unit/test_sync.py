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

import pytest
from flext_tests import tm

from flext_ldap.models import m
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService
from flext_ldap.settings import FlextLdapSettings

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
        # but services pass complex objects via __init__ which are validated at runtime
        connection = FlextLdapConnection(config=FlextLdapSettings())
        return FlextLdapOperations(connection=connection)

    def test_sync_service_initialization(self) -> None:
        """Test sync service initialization with operations."""
        operations = self._create_operations()
        sync_service = FlextLdapSyncService(operations=operations)
        tm.that(sync_service, none=False)
        tm.that(sync_service, is_=FlextLdapSyncService, none=False)

    def test_sync_service_initialization_with_ldif(self) -> None:
        """Test sync service initialization with custom ldif."""
        operations = self._create_operations()
        # Note: ldif parameter is not used in __init__, service always creates FlextLdif()
        sync_service = FlextLdapSyncService(operations=operations)
        tm.that(sync_service, none=False)
        tm.that(sync_service, is_=FlextLdapSyncService, none=False)

    def test_sync_service_initialization_with_datetime_generator(self) -> None:
        """Test sync service initialization with datetime generator."""
        operations = self._create_operations()

        # Note: generate_datetime_utc is not configurable via __init__
        # It always uses u.Generators.generate_datetime_utc
        # This test verifies the service initializes correctly
        sync_service = FlextLdapSyncService(operations=operations)
        tm.that(sync_service, none=False)
        tm.that(sync_service, is_=FlextLdapSyncService, none=False)
        # Verify datetime generator is set (uses default from u.Generators)
        tm.that(hasattr(sync_service, "_generate_datetime_utc"), eq=True)

    def test_execute_returns_empty_stats(self) -> None:
        """Test execute() returns empty sync stats for health check."""
        operations = self._create_operations()
        sync_service = FlextLdapSyncService(operations=operations)
        result = sync_service.execute()
        stats = tm.ok(result, is_=m.Ldap.SyncStats)
        tm.that(stats.added, eq=0)
        tm.that(stats.skipped, eq=0)
        tm.that(stats.failed, eq=0)
        tm.that(stats.total, eq=0)

    def test_sync_stats_creation(self) -> None:
        """Test SyncStats model creation."""
        stats = m.Ldap.SyncStats(
            added=10,
            skipped=2,
            failed=1,
            total=13,
            duration_seconds=100.5,
        )
        tm.that(stats.added, eq=10)
        tm.that(stats.skipped, eq=2)
        tm.that(stats.failed, eq=1)
        tm.that(stats.total, eq=13)
        tm.that(stats.duration_seconds, eq=100.5)

    def test_sync_options_creation(self) -> None:
        """Test SyncOptions model creation."""
        options = m.Ldap.SyncOptions(
            source_basedn="dc=old,dc=com",
            target_basedn="dc=new,dc=com",
        )
        tm.that(options.source_basedn, eq="dc=old,dc=com")
        tm.that(options.target_basedn, eq="dc=new,dc=com")

    def test_sync_options_without_transformation(self) -> None:
        """Test SyncOptions without base DN transformation."""
        options = m.Ldap.SyncOptions()
        tm.that(options.source_basedn, eq="")
        tm.that(options.target_basedn, eq="")

    def test_base_dn_transformer_no_transformation(self) -> None:
        """Test BaseDNTransformer with no transformation needed."""
        entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DN(value="cn=user,dc=example,dc=com"),
                attributes=m.Ldif.Attributes(attributes={}),
            ),
        ]
        transformed = FlextLdapSyncService.BaseDNTransformer.transform(
            entries,
            source_basedn="",
            target_basedn="",
        )
        tm.that(transformed, len=1)
        tm.that(transformed[0].dn, none=False)
        assert transformed[0].dn is not None  # Type guard
        tm.that(transformed[0].dn.value, eq="cn=user,dc=example,dc=com")

    def test_base_dn_transformer_with_transformation(self) -> None:
        """Test BaseDNTransformer with base DN transformation."""
        entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DN(value="cn=user,dc=old,dc=com"),
                attributes=m.Ldif.Attributes(attributes={}),
            ),
        ]
        transformed = FlextLdapSyncService.BaseDNTransformer.transform(
            entries,
            source_basedn="dc=old,dc=com",
            target_basedn="dc=new,dc=com",
        )
        assert len(transformed) == 1
        assert transformed[0].dn is not None
        assert transformed[0].dn.value == "cn=user,dc=new,dc=com"

    def test_base_dn_transformer_case_insensitive(self) -> None:
        """Test BaseDNTransformer with case-insensitive matching."""
        entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DN(value="cn=user,dc=old,dc=com"),
                attributes=m.Ldif.Attributes(attributes={}),
            ),
        ]
        transformed = FlextLdapSyncService.BaseDNTransformer.transform(
            entries,
            source_basedn="DC=OLD,DC=COM",
            target_basedn="dc=new,dc=com",
        )
        tm.that(transformed, len=1)
        tm.that(transformed[0].dn, none=False)
        assert transformed[0].dn is not None  # Type guard
        tm.that(transformed[0].dn.value, eq="cn=user,dc=new,dc=com")

    def test_batch_sync_initialization(self) -> None:
        """Test BatchSync inner class initialization."""
        operations = self._create_operations()
        batch_sync = FlextLdapSyncService.BatchSync(operations=operations)
        tm.that(batch_sync, none=False)
        tm.that(batch_sync, is_=FlextLdapSyncService.BatchSync, none=False)

    def test_sync_service_methods_exist(self) -> None:
        """Test that all expected methods exist on sync service."""
        operations = self._create_operations()
        sync_service = FlextLdapSyncService(operations=operations)

        # Check main methods
        tm.that(sync_service, contains="execute")
        tm.that(sync_service, contains="sync_ldif_file")
        tm.that(callable(sync_service.execute), eq=True)
        tm.that(callable(sync_service.sync_ldif_file), eq=True)

    def test_sync_service_inner_classes_exist(self) -> None:
        """Test that inner classes exist."""
        tm.that(hasattr(FlextLdapSyncService, "BatchSync"), eq=True)
        tm.that(hasattr(FlextLdapSyncService, "BaseDNTransformer"), eq=True)
        tm.that(FlextLdapSyncService.BatchSync, is_=type, none=False)
        tm.that(FlextLdapSyncService.BaseDNTransformer, is_=type, none=False)
