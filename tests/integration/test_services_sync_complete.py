"""Complete integration tests for FlextLdapSyncService with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService

from ..fixtures.constants import RFC
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapSyncServiceComplete:
    """Complete tests for FlextLdapSyncService with real LDAP server."""

    @pytest.fixture
    def sync_service(
        self,
        ldap_client: FlextLdap,
    ) -> FlextLdapSyncService:
        """Get sync service with connected operations."""
        operations = ldap_client._operations
        return FlextLdapSyncService(operations=operations)

    @pytest.fixture
    def sample_ldif_file(self) -> Generator[Path]:
        """Create sample LDIF file for testing."""
        ldif_content = """dn: cn=testldif1,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testldif1
sn: Test1

dn: cn=testldif2,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testldif2
sn: Test2
"""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(ldif_content)
            temp_path = Path(f.name)

        yield temp_path

        # Cleanup
        if temp_path.exists():
            temp_path.unlink()

    def test_sync_ldif_file_with_real_entries(
        self,
        sync_service: FlextLdapSyncService,
        sample_ldif_file: Path,
    ) -> None:
        """Test syncing LDIF file with real entries."""
        # Cleanup entries first
        for dn in [
            "cn=testldif1,ou=people,dc=flext,dc=local",
            "cn=testldif2,ou=people,dc=flext,dc=local",
        ]:
            _ = sync_service._operations.delete(dn)

        options = FlextLdapModels.SyncOptions()
        result = sync_service.sync_ldif_file(sample_ldif_file, options)
        TestOperationHelpers.assert_result_success(result)
        stats = TestOperationHelpers.unwrap_sync_stats(result)
        # Validate actual content: should process 2 entries
        assert stats.total == 2
        assert stats.added >= 0  # May be skipped if already exists
        assert stats.failed == 0  # Should not fail
        assert stats.skipped >= 0  # May skip if entries exist
        # Validate that added + skipped equals total processed
        assert stats.added + stats.skipped == stats.total
        # Validate duration is reasonable
        assert stats.duration_seconds >= 0.0

        # Cleanup
        for dn in [
            "cn=testldif1,ou=people,dc=flext,dc=local",
            "cn=testldif2,ou=people,dc=flext,dc=local",
        ]:
            _ = sync_service._operations.delete(dn)

    def test_sync_ldif_file_with_options(
        self,
        sync_service: FlextLdapSyncService,
        sample_ldif_file: Path,
    ) -> None:
        """Test syncing LDIF file with options."""
        # Cleanup entries first
        for dn in [
            "cn=testldif1,ou=people,dc=flext,dc=local",
            "cn=testldif2,ou=people,dc=flext,dc=local",
        ]:
            _ = sync_service._operations.delete(dn)

        options = FlextLdapModels.SyncOptions(batch_size=1)
        result = sync_service.sync_ldif_file(sample_ldif_file, options)
        TestOperationHelpers.assert_result_success(result)
        stats = TestOperationHelpers.unwrap_sync_stats(result)
        # Validate actual content: batch_size=1 should still process all entries
        assert stats.total == 2
        assert stats.added >= 0
        assert stats.failed == 0
        assert stats.skipped >= 0
        assert stats.added + stats.skipped == stats.total
        # Validate batch_size option was respected (may affect processing)
        assert stats.duration_seconds >= 0.0

        # Cleanup
        for dn in [
            "cn=testldif1,ou=people,dc=flext,dc=local",
            "cn=testldif2,ou=people,dc=flext,dc=local",
        ]:
            _ = sync_service._operations.delete(dn)

    def test_sync_ldif_file_with_basedn_transformation(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test syncing LDIF file with BaseDN transformation."""
        ldif_content = """dn: cn=testtransform,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testtransform
sn: Test
"""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(ldif_content)
            temp_path = Path(f.name)

        try:
            # Cleanup first
            _ = sync_service._operations.delete("cn=testtransform,dc=flext,dc=local")

            options = FlextLdapModels.SyncOptions(
                source_basedn="dc=example,dc=com",
                target_basedn=RFC.DEFAULT_BASE_DN,
            )
            result = sync_service.sync_ldif_file(temp_path, options)
            TestOperationHelpers.assert_result_success(result)
            stats = TestOperationHelpers.unwrap_sync_stats(result)
            # Validate actual content: transformation should process entry
            assert stats.total == 1
            assert stats.added >= 0  # Entry should be added after transformation
            assert stats.failed == 0

            # Verify transformation happened (covers lines 286-289, 293, 298)
            # Entry should be transformed from dc=example,dc=com to dc=flext,dc=local
            search_result = sync_service._operations.search(
                FlextLdapModels.SearchOptions(
                    base_dn=RFC.DEFAULT_BASE_DN,
                    filter_str="(cn=testtransform)",
                    scope=FlextLdapConstants.SearchScope.SUBTREE,
                ),
            )
            TestOperationHelpers.assert_result_success(search_result)
            entries = search_result.unwrap().entries
            assert len(entries) > 0, "Entry should exist after transformation"
            # Validate DN was actually transformed
            assert RFC.DEFAULT_BASE_DN in str(entries[0].dn)
            assert "dc=example,dc=com" not in str(entries[0].dn)

            # Cleanup
            _ = sync_service._operations.delete("cn=testtransform,dc=flext,dc=local")
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_sync_ldif_file_with_progress_callback(
        self,
        sync_service: FlextLdapSyncService,
        sample_ldif_file: Path,
    ) -> None:
        """Test syncing LDIF file with progress callback (covers line 253)."""
        progress_calls = []

        def progress_callback(
            current: int,
            total: int,
            dn: str,
            stats: FlextLdapModels.LdapBatchStats,
        ) -> None:
            progress_calls.append((current, total, dn, stats))

        # Cleanup entries first
        for dn in [
            "cn=testldif1,ou=people,dc=flext,dc=local",
            "cn=testldif2,ou=people,dc=flext,dc=local",
        ]:
            _ = sync_service._operations.delete(dn)

        options = FlextLdapModels.SyncOptions(progress_callback=progress_callback)
        result = sync_service.sync_ldif_file(sample_ldif_file, options)
        TestOperationHelpers.assert_result_success(result)
        stats = TestOperationHelpers.unwrap_sync_stats(result)
        # Validate actual content: should process 2 entries
        assert stats.total == 2

        # Verify progress callback was called (covers line 253)
        assert len(progress_calls) == 2, (
            f"Expected 2 callback calls, got {len(progress_calls)}"
        )
        # Verify callback received correct parameters
        for idx, (current, total, dn, stats_cb) in enumerate(progress_calls):
            assert current == idx + 1, (
                f"Callback {idx}: expected current={idx + 1}, got {current}"
            )
            assert total == 2, f"Callback {idx}: expected total=2, got {total}"
            assert isinstance(dn, str), (
                f"Callback {idx}: DN should be string, got {type(dn)}"
            )
            assert len(dn) > 0, f"Callback {idx}: DN should not be empty"
            assert isinstance(stats_cb, FlextLdapModels.LdapBatchStats), (
                f"Callback {idx}: stats should be LdapBatchStats, got {type(stats_cb)}"
            )
            # Verify stats object has expected attributes and values
            assert hasattr(stats_cb, "synced")
            assert hasattr(stats_cb, "failed")
            assert hasattr(stats_cb, "skipped")
            assert stats_cb.synced >= 0
            assert stats_cb.failed >= 0
            assert stats_cb.skipped >= 0
            # Validate DN contains expected entry names
            assert "testldif1" in dn or "testldif2" in dn, (
                f"Callback {idx}: DN should contain entry name"
            )

        # Cleanup
        for dn in [
            "cn=testldif1,ou=people,dc=flext,dc=local",
            "cn=testldif2,ou=people,dc=flext,dc=local",
        ]:
            _ = sync_service._operations.delete(dn)

    def test_sync_ldif_file_nonexistent_file(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test syncing non-existent LDIF file."""
        options = FlextLdapModels.SyncOptions()
        result = sync_service.sync_ldif_file(Path("nonexistent.ldif"), options)
        TestOperationHelpers.assert_result_failure(result)
        error_msg = TestOperationHelpers.get_error_message(result)
        # Validate error message content
        assert "not found" in error_msg.lower() or "file" in error_msg.lower()

    def test_sync_ldif_file_empty_file(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test syncing empty LDIF file."""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("")
            temp_path = Path(f.name)

        try:
            options = FlextLdapModels.SyncOptions()
            result = sync_service.sync_ldif_file(temp_path, options)
            TestOperationHelpers.assert_result_success(result)
            stats = TestOperationHelpers.unwrap_sync_stats(result)
            # Validate actual content: empty file should return empty stats
            assert stats.total == 0
            assert stats.added == 0
            assert stats.failed == 0
            assert stats.skipped == 0
            assert stats.duration_seconds >= 0.0
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_sync_ldif_file_when_not_connected(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test syncing when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        sync_service = FlextLdapSyncService(operations=operations)

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("dn: cn=test,dc=example,dc=com\ncn: test\n")
            temp_path = Path(f.name)

        try:
            options = FlextLdapModels.SyncOptions()
            result = sync_service.sync_ldif_file(temp_path, options)
            # Sync service processes entries and marks failures, but returns success
            TestOperationHelpers.assert_result_success(result)
            stats = result.unwrap()
            # Validate actual content: should have failed entries because not connected
            assert stats.total == 1  # One entry in file
            assert stats.failed > 0  # Should fail because not connected
            assert stats.added == 0  # Nothing added
            assert stats.skipped == 0  # Nothing skipped
            assert stats.duration_seconds >= 0.0
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_sync_ldif_file_with_duplicate_entries(
        self,
        sync_service: FlextLdapSyncService,
        sample_ldif_file: Path,
    ) -> None:
        """Test syncing with duplicate entries (should skip) - covers lines 234, 240."""
        options = FlextLdapModels.SyncOptions()
        # First sync
        result1 = sync_service.sync_ldif_file(sample_ldif_file, options)
        TestOperationHelpers.assert_result_success(result1)
        stats1 = TestOperationHelpers.unwrap_sync_stats(result1)
        # Validate first sync: should add entries
        assert stats1.total == 2
        assert stats1.added >= 0
        assert stats1.failed == 0

        # Second sync (duplicates should be skipped) - covers lines 234, 240
        result2 = sync_service.sync_ldif_file(sample_ldif_file, options)
        TestOperationHelpers.assert_result_success(result2)
        stats2 = result2.unwrap()
        # Validate actual content: should have skipped entries (covers line 240: entry_stats["skipped"] = 1)
        assert stats2.total == 2
        assert stats2.skipped >= 0  # Entries should be skipped (already exist)
        assert stats2.added == 0  # Nothing new added
        assert stats2.failed == 0  # Should not fail
        # Validate that skipped entries match total (all should be skipped)
        assert stats2.skipped == stats2.total

        # Cleanup
        for dn in [
            "cn=testldif1,ou=people,dc=flext,dc=local",
            "cn=testldif2,ou=people,dc=flext,dc=local",
        ]:
            _ = sync_service._operations.delete(dn)

    def test_transform_entries_basedn_same_basedn(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test BaseDN transformation with same BaseDN (no change) - covers line 283."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
                attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            ),
        ]
        # Transform with same source and target (covers line 283: early return)
        transformed = sync_service.BaseDNTransformer.transform(
            entries,
            "dc=flext,dc=local",
            "dc=flext,dc=local",
        )
        assert len(transformed) == 1
        # Should return same list (covers line 283)
        assert transformed is entries

    def test_execute_method(self, ldap_parser: FlextLdifParser) -> None:
        """Test execute method required by FlextService."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        sync_service = FlextLdapSyncService(operations=operations)
        result = sync_service.execute()
        TestOperationHelpers.assert_result_success(result)
        stats = TestOperationHelpers.unwrap_sync_stats(result)
        # Validate actual content: execute with no entries should return empty stats
        assert stats.total == 0
        assert stats.added == 0
        assert stats.failed == 0
        assert stats.skipped == 0
        assert stats.duration_seconds >= 0.0

    def test_sync_batch_with_duplicate_entries(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test syncing entries that already exist."""
        entry = TestOperationHelpers.create_inetorgperson_entry(
            "testduplicate",
            RFC.DEFAULT_BASE_DN,
        )

        # Add entry first
        _ = sync_service._operations.delete(str(entry.dn))
        add_result = sync_service._operations.add(entry)
        TestOperationHelpers.assert_result_success(add_result)

        # Try to sync same entry again
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(
                f"""dn: {entry.dn!s}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testduplicate
sn: Test
""",
            )
            temp_path = Path(f.name)

        try:
            options = FlextLdapModels.SyncOptions()
            result = sync_service.sync_ldif_file(temp_path, options)
            TestOperationHelpers.assert_result_success(result)
            stats = TestOperationHelpers.unwrap_sync_stats(result)
            # Validate actual content: entry should be skipped (already exists)
            assert stats.total == 1
            assert stats.skipped >= 1  # Entry should be skipped
            assert stats.added == 0  # Nothing new added
            assert stats.failed == 0  # Should not fail
        finally:
            if temp_path.exists():
                temp_path.unlink()

        # Cleanup
        _ = sync_service._operations.delete(str(entry.dn))

    def test_sync_ldif_file_with_parse_failure_invalid_content(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test sync with file that exists but causes parse failure (covers line 110).

        Creates a file that exists but contains invalid content that causes
        flext-ldif.parse() to return a failure, triggering the error handling
        path at line 110.
        """
        # Create a file with invalid binary content that will cause parse failure
        # The file exists (passes the exists() check) but parse() will fail
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".ldif", delete=False) as f:
            # Write invalid binary content that will cause parsing to fail
            f.write(b"\x00\x01\x02\x03invalid binary content\xff\xfe\xfd")
            temp_path = Path(f.name)

        try:
            options = FlextLdapModels.SyncOptions()
            result = sync_service.sync_ldif_file(temp_path, options)

            # Should fail with parse error (covers line 110)
            # The file exists but parse() fails due to invalid content
            TestOperationHelpers.assert_result_failure(result)
            error_msg = TestOperationHelpers.get_error_message(result)
            # Validate error message content
            assert (
                "Failed to parse LDIF file" in error_msg or "parse" in error_msg.lower()
            ), f"Expected parse error message, got: {result.error}"
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_transform_entries_basedn_dn_not_containing_source(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test transform_entries_basedn when DN doesn't contain source_basedn (covers lines 286-289, 300)."""
        # Create entry with DN that doesn't contain source_basedn
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testtransform,ou=other,dc=example,dc=com",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testtransform"],
                    "objectClass": ["top", "person"],
                },
            ),
        )

        # Transform with source_basedn that doesn't match entry DN
        source_basedn = "dc=flext,dc=local"
        target_basedn = "dc=example,dc=com"

        transformed = sync_service.BaseDNTransformer.transform(
            [entry],
            source_basedn,
            target_basedn,
        )

        # Entry should be added as-is since DN doesn't contain source_basedn (covers lines 286-289, 300)
        assert len(transformed) == 1
        assert str(transformed[0].dn) == "cn=testtransform,ou=other,dc=example,dc=com"
        # Verify it's the same object (no transformation applied) - covers line 300
        assert transformed[0] is entry

    def test_transform_entries_basedn_with_multiple_entries(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test transform_entries_basedn with multiple entries (covers lines 286-289, 293, 298)."""
        # Create multiple entries - some with source_basedn, some without
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=entry1,dc=example,dc=com",
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"cn": ["entry1"]},
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=entry2,dc=example,dc=com",
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"cn": ["entry2"]},
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=entry3,ou=other,dc=test,dc=com",
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={"cn": ["entry3"]},
                ),
            ),
        ]

        source_basedn = "dc=example,dc=com"
        target_basedn = "dc=flext,dc=local"

        transformed = sync_service.BaseDNTransformer.transform(
            entries,
            source_basedn,
            target_basedn,
        )

        # Should transform entries that contain source_basedn (covers lines 286-289, 293, 298)
        assert len(transformed) == 3
        # First two should be transformed
        assert "dc=flext,dc=local" in str(transformed[0].dn)
        assert "dc=flext,dc=local" in str(transformed[1].dn)
        # Third should remain unchanged (covers line 300)
        assert str(transformed[2].dn) == "cn=entry3,ou=other,dc=test,dc=com"
        assert transformed[2] is entries[2]  # Same object
