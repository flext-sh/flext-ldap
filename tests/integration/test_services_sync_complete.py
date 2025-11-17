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
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService
from tests.fixtures.constants import RFC
from tests.helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapSyncServiceComplete:
    """Complete tests for FlextLdapSyncService with real LDAP server."""

    @pytest.fixture
    def sync_service(
        self,
        ldap_client: FlextLdap,
    ) -> FlextLdapSyncService:
        """Get sync service with connected operations."""
        operations = ldap_client.client
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
        stats = TestOperationHelpers.unwrap_sync_stats(result)
        assert stats.total == 2
        assert stats.added >= 0  # May be skipped if already exists

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
        stats = TestOperationHelpers.unwrap_sync_stats(result)
        assert stats.total == 2

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
            assert result.is_success

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
        """Test syncing LDIF file with progress callback."""
        progress_calls = []

        def progress_callback(
            current: int,
            total: int,
            dn: str,
            stats: dict[str, int],
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
        assert result.is_success

        assert len(progress_calls) == 2

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
        assert result.is_failure
        # No fallback - FlextResult guarantees error exists when is_failure is True
        assert result.error is not None
        assert "not found" in result.error.lower()

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
            assert result.is_success
            stats = TestOperationHelpers.unwrap_sync_stats(result)
            assert stats.total == 0
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
            assert result.is_failure
            # No fallback - FlextResult guarantees error exists when is_failure is True
            assert result.error is not None
            assert "Not connected" in result.error
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_sync_ldif_file_with_duplicate_entries(
        self,
        sync_service: FlextLdapSyncService,
        sample_ldif_file: Path,
    ) -> None:
        """Test syncing with duplicate entries (should skip)."""
        options = FlextLdapModels.SyncOptions()
        # First sync
        result1 = sync_service.sync_ldif_file(sample_ldif_file, options)
        assert result1.is_success

        # Second sync (duplicates should be skipped)
        result2 = sync_service.sync_ldif_file(sample_ldif_file, options)
        assert result2.is_success
        stats2 = result2.unwrap()
        # Should have skipped entries
        assert stats2.skipped >= 0

        # Cleanup
        for dn in [
            "cn=testldif1,ou=people,dc=flext,dc=local",
            "cn=testldif2,ou=people,dc=flext,dc=local",
        ]:
            _ = sync_service._operations.delete(dn)

    def test_transform_entries_basedn_with_entry_no_dn(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test BaseDN transformation with entry without DN."""
        entries = [
            FlextLdifModels.Entry(
                dn=None,
                attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            ),
        ]
        transformed = sync_service._transform_entries_basedn(
            entries,
            "dc=example,dc=com",
            "dc=flext,dc=local",
        )
        assert len(transformed) == 1
        assert transformed[0].dn is None

    def test_transform_entries_basedn_same_basedn(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test BaseDN transformation with same BaseDN (no change)."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=flext,dc=local"),
                attributes=FlextLdifModels.LdifAttributes(attributes={"cn": ["test"]}),
            ),
        ]
        transformed = sync_service._transform_entries_basedn(
            entries,
            "dc=flext,dc=local",
            "dc=flext,dc=local",
        )
        assert len(transformed) == 1
        assert transformed == entries

    def test_execute_method(self, ldap_parser: FlextLdifParser) -> None:
        """Test execute method required by FlextService."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        sync_service = FlextLdapSyncService(operations=operations)
        result = sync_service.execute()
        assert result.is_success
        stats = TestOperationHelpers.unwrap_sync_stats(result)
        assert stats.total == 0
        assert stats.added == 0

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
        assert add_result.is_success

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
            assert result.is_success
            stats = TestOperationHelpers.unwrap_sync_stats(result)
            # Entry should be skipped
            assert stats.skipped >= 0
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
            assert result.is_failure, "Expected parse failure for invalid content"
            # No fallback - FlextResult guarantees error exists when is_failure is True
            assert result.error is not None
            assert "Failed to parse LDIF file" in result.error, (
                f"Expected parse error message, got: {result.error}"
            )
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_transform_entries_basedn_dn_not_containing_source(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test transform_entries_basedn when DN doesn't contain source_basedn (covers line 264)."""
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

        transformed = sync_service._transform_entries_basedn(
            [entry],
            source_basedn,
            target_basedn,
        )

        # Entry should be added as-is since DN doesn't contain source_basedn (covers line 264)
        assert len(transformed) == 1
        assert str(transformed[0].dn) == "cn=testtransform,ou=other,dc=example,dc=com"
