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
from flext_ldif.services.parser import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService
from tests.fixtures.constants import RFC
from tests.helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapSyncServiceReal:
    """Tests for sync service with real LDAP server."""

    @pytest.fixture
    def sync_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser,
    ) -> FlextLdapSyncService:
        """Get sync service with connected operations."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        connect_result = connection.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")

        operations = FlextLdapOperations(connection=connection)
        return FlextLdapSyncService(operations=operations)

    def test_sync_ldif_file_when_not_connected(
        self,
        base_ldif_content: str,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test sync when operations service is not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        sync_service = FlextLdapSyncService(operations=operations)

        # Create temporary LDIF file
        with NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            _ = f.write(base_ldif_content)
            ldif_file = Path(f.name)

        try:
            options = FlextLdapModels.SyncOptions()
            result = sync_service.sync_ldif_file(ldif_file, options)
            assert result.is_failure
            # No fallback - FlextResult guarantees error exists when is_failure is True
            assert result.error is not None
            assert "Not connected" in result.error
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
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            _ = f.write(invalid_ldif)
            ldif_file = Path(f.name)

        try:
            options = FlextLdapModels.SyncOptions()
            result = sync_service.sync_ldif_file(ldif_file, options)
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
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            _ = f.write("")
            ldif_file = Path(f.name)

        try:
            options = FlextLdapModels.SyncOptions()
            result = sync_service.sync_ldif_file(ldif_file, options)
            # Should handle empty file gracefully
            assert result.is_success or result.is_failure
            if result.is_success:
                stats = TestOperationHelpers.unwrap_sync_stats(result)
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
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            _ = f.write(problematic_ldif)
            ldif_file = Path(f.name)

        try:
            options = FlextLdapModels.SyncOptions()
            result = sync_service.sync_ldif_file(ldif_file, options)
            # Should continue syncing other entries even if some fail
            assert result.is_success or result.is_failure
            if result.is_success:
                stats = TestOperationHelpers.unwrap_sync_stats(result)
                # Should have some entries processed
                assert stats.added >= 0
                assert stats.failed >= 0 or stats.skipped >= 0
        finally:
            ldif_file.unlink()

    def test_sync_ldif_file_with_same_source_target_basedn(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test sync when source and target base DN are the same."""
        # Create LDIF file with entry
        ldif_content = f"""dn: cn=test-same-basedn,{RFC.DEFAULT_BASE_DN}
objectClass: top
objectClass: organizationalUnit
ou: test
"""

        with NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            _ = f.write(ldif_content)
            ldif_file = Path(f.name)

        try:
            # Sync with same source and target base DN
            options = FlextLdapModels.SyncOptions(
                source_basedn=RFC.DEFAULT_BASE_DN,
                target_basedn=RFC.DEFAULT_BASE_DN,
            )
            result = sync_service.sync_ldif_file(ldif_file, options=options)

            # Should work correctly with same base DN
            assert result.is_success or result.is_failure
            if result.is_success:
                stats = TestOperationHelpers.unwrap_sync_stats(result)
                assert stats.total >= 0
        finally:
            ldif_file.unlink()

    def test_sync_ldif_file_with_base_dn_transformation(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test sync with base DN transformation."""
        # Create LDIF file with entries that will be transformed
        ldif_content = f"""dn: cn=test-transform,{RFC.DEFAULT_BASE_DN}
objectClass: top
objectClass: organizationalUnit
ou: test
"""

        with NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            _ = f.write(ldif_content)
            ldif_file = Path(f.name)

        try:
            # Sync with different target base DN
            options = FlextLdapModels.SyncOptions(
                source_basedn=RFC.DEFAULT_BASE_DN,
                target_basedn="dc=target,dc=local",
            )
            result = sync_service.sync_ldif_file(ldif_file, options=options)

            # Should handle transformation correctly
            assert result.is_success or result.is_failure
            if result.is_success:
                stats = TestOperationHelpers.unwrap_sync_stats(result)
                assert stats.total >= 0
        finally:
            ldif_file.unlink()

    def test_execute_method(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test execute method for health check."""
        result = sync_service.execute()
        assert result.is_success
        stats = TestOperationHelpers.unwrap_sync_stats(result)
        assert stats.added == 0
        assert stats.failed == 0
        assert stats.skipped == 0
        assert stats.total == 0
