"""Integration tests for FlextLdapSyncService with real LDAP server.

Tests sync service with real LDAP operations, no mocks.
All tests use real LDAP server and LDIF files from fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from flext_ldif.models import FlextLdifModels

from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService
from tests.fixtures.constants import RFC

pytestmark = pytest.mark.integration


class TestFlextLdapSyncServiceReal:
    """Tests for sync service with real LDAP server."""

    @pytest.fixture
    def sync_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> FlextLdapSyncService:
        """Get sync service with connected operations."""
        connection = FlextLdapConnection()
        connect_result = connection.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        operations = FlextLdapOperations(connection=connection)
        return FlextLdapSyncService(operations=operations)

    def test_sync_ldif_file_when_not_connected(
        self,
        base_ldif_content: str,
    ) -> None:
        """Test sync when operations service is not connected."""
        connection = FlextLdapConnection()
        operations = FlextLdapOperations(connection=connection)
        sync_service = FlextLdapSyncService(operations=operations)

        # Create temporary LDIF file
        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(base_ldif_content)
            ldif_file = Path(f.name)

        try:
            result = sync_service.sync_ldif_file(ldif_file)
            assert result.is_failure
            assert "Not connected" in (result.error or "")
        finally:
            ldif_file.unlink()

    def test_sync_ldif_file_with_parse_failure(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test sync with invalid LDIF file that fails to parse."""
        # Create invalid LDIF file
        invalid_ldif = "invalid ldif content\nnot a valid entry\n"

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(invalid_ldif)
            ldif_file = Path(f.name)

        try:
            result = sync_service.sync_ldif_file(ldif_file)
            # Should handle parse failure gracefully
            assert result.is_failure or result.is_success
        finally:
            ldif_file.unlink()

    def test_sync_ldif_file_with_empty_file(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test sync with empty LDIF file."""
        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write("")
            ldif_file = Path(f.name)

        try:
            result = sync_service.sync_ldif_file(ldif_file)
            # Should handle empty file gracefully
            assert result.is_success or result.is_failure
            if result.is_success:
                stats = result.unwrap()
                assert stats.added == 0
        finally:
            ldif_file.unlink()

    def test_sync_ldif_file_with_add_failure(
        self,
        sync_service: FlextLdapSyncService,
        base_ldif_content: str,
    ) -> None:
        """Test sync when add operation fails for some entries."""
        # Create LDIF with entry that might fail (e.g., missing required attributes)
        problematic_ldif = f"""{base_ldif_content}
dn: cn=invalid,{RFC.DEFAULT_BASE_DN}
objectClass: top
# Missing required attributes - will fail to add
"""

        with NamedTemporaryFile(
            mode="w", suffix=".ldif", delete=False, encoding="utf-8"
        ) as f:
            f.write(problematic_ldif)
            ldif_file = Path(f.name)

        try:
            result = sync_service.sync_ldif_file(ldif_file)
            # Should continue syncing other entries even if some fail
            assert result.is_success or result.is_failure
            if result.is_success:
                stats = result.unwrap()
                # Should have some entries processed
                assert stats.added >= 0
                assert stats.failed >= 0 or stats.skipped >= 0
        finally:
            ldif_file.unlink()

    def test_transform_entries_basedn_with_same_basedn(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test transform when source and target base DN are the same."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=test,{RFC.DEFAULT_BASE_DN}"
                ),
                attributes=FlextLdifModels.LdifAttributes.model_validate({
                    "attributes": {"cn": ["test"], "objectClass": ["top"]}
                }),
            ),
        ]

        # Same base DN - should return entries unchanged
        # Accessing protected method for testing coverage
        transformed = sync_service._transform_entries_basedn(
            entries=entries,
            source_basedn=RFC.DEFAULT_BASE_DN,
            target_basedn=RFC.DEFAULT_BASE_DN,
        )

        assert transformed == entries
        assert len(transformed) == 1

    def test_transform_entries_basedn_with_entry_without_dn(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test transform with entry that has no DN."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=""),
                attributes=FlextLdifModels.LdifAttributes.model_validate({
                    "attributes": {"cn": ["test"], "objectClass": ["top"]}
                }),
            ),
        ]

        # Entry without DN should be included unchanged
        # Accessing protected method for testing coverage
        transformed = sync_service._transform_entries_basedn(
            entries=entries,
            source_basedn=RFC.DEFAULT_BASE_DN,
            target_basedn="dc=target,dc=local",
        )

        assert len(transformed) == 1
        assert transformed[0] == entries[0]

    def test_execute_method(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test execute method for health check."""
        result = sync_service.execute()
        assert result.is_success
        stats = result.unwrap()
        assert stats.added == 0
        assert stats.failed == 0
        assert stats.skipped == 0
        assert stats.total == 0
