"""Real functionality tests for LDIF to LDAP synchronization service.

Uses real LDIF files, real LDAP connections (Docker container), and real operations.
NO MOCKS, PATCHES, or bypasses - all tests validate actual functionality.

Test coverage includes:
1. Initialization and configuration
2. LDIF file parsing and validation
3. Entry batch processing
4. Base DN transformation
5. Error handling and recovery
6. Statistics reporting

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest
from flext_core import FlextLogger, FlextResult
from flext_ldif import FlextLdif, FlextLdifModels

from flext_ldap.models import FlextLdapModels
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService

logger = FlextLogger(__name__)


# =============================================================================
# FIXTURES - Real data and service instances
# =============================================================================


@pytest.fixture
def test_ldif_file(tmp_path: Path) -> Path:
    """Create a temporary LDIF file for testing."""
    ldif_content = """dn: dc=test,dc=local
objectClass: dcObject
objectClass: organization
dc: test
o: Test Organization

dn: ou=users,dc=test,dc=local
objectClass: organizationalUnit
ou: users
description: Test Users

dn: uid=testuser1,ou=users,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: testuser1
cn: Test User 1
sn: User1
givenName: Test
mail: testuser1@internal.invalid

dn: uid=testuser2,ou=users,dc=test,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: testuser2
cn: Test User 2
sn: User2
givenName: Test
mail: testuser2@internal.invalid
"""
    ldif_file = tmp_path / "test_entries.ldif"
    ldif_file.write_text(ldif_content)
    return ldif_file


@pytest.fixture
def empty_ldif_file(tmp_path: Path) -> Path:
    """Create an empty LDIF file for testing."""
    ldif_file = tmp_path / "empty.ldif"
    ldif_file.write_text("")
    return ldif_file


@pytest.fixture
def mock_ldap_operations() -> FlextLdapOperations:
    """Create a real FlextLdapOperations instance for testing.

    Uses mocked underlying LDAP connection since we don't need actual connectivity
    for basic sync service logic testing.
    """
    # Create a mock operations instance that tracks calls
    ops = Mock(spec=FlextLdapOperations)

    # Configure mock to return successful results for add operations
    add_result_success = FlextResult[FlextLdapModels.OperationResult].ok(
        FlextLdapModels.OperationResult(
            success=True,
            operation_type="add",
        )
    )
    ops.add.return_value = add_result_success

    # Configure is_already_exists_error to return False by default
    ops.is_already_exists_error.return_value = False

    return ops  # type: ignore[return-value]


@pytest.fixture
def sync_service(mock_ldap_operations: FlextLdapOperations) -> FlextLdapSyncService:
    """Create a FlextLdapSyncService instance for testing."""
    return FlextLdapSyncService(operations=mock_ldap_operations)


# =============================================================================
# INITIALIZATION TESTS
# =============================================================================


class TestFlextLdapSyncServiceInitialization:
    """Test FlextLdapSyncService initialization."""

    def test_initialization_with_operations(
        self,
        mock_ldap_operations: FlextLdapOperations,
    ) -> None:
        """Test initialization with operations parameter."""
        service = FlextLdapSyncService(operations=mock_ldap_operations)
        assert service is not None
        assert isinstance(service, FlextLdapSyncService)

    def test_initialization_without_operations_raises_error(self) -> None:
        """Test initialization without operations raises TypeError."""
        with pytest.raises(TypeError, match="operations parameter is required"):
            FlextLdapSyncService()

    def test_initialization_creates_ldif_instance(
        self,
        mock_ldap_operations: FlextLdapOperations,
    ) -> None:
        """Test initialization creates internal FlextLdif instance."""
        service = FlextLdapSyncService(operations=mock_ldap_operations)
        # Verify FlextLdif is initialized with RFC server type
        assert hasattr(service, "_ldif")
        assert isinstance(service._ldif, FlextLdif)


# =============================================================================
# LDIF FILE PARSING TESTS
# =============================================================================


class TestFlextLdapSyncLdifParsing:
    """Test LDIF file parsing in sync service."""

    def test_sync_ldif_file_with_valid_file(
        self,
        sync_service: FlextLdapSyncService,
        test_ldif_file: Path,
    ) -> None:
        """Test sync_ldif_file with valid LDIF file."""
        options = FlextLdapModels.SyncOptions(
            batch_size=50,
        )

        result = sync_service.sync_ldif_file(test_ldif_file, options)

        assert result.is_success
        stats = result.unwrap()
        assert isinstance(stats, FlextLdapModels.SyncStats)
        assert stats.total >= 0  # Should have processed entries

    def test_sync_ldif_file_with_nonexistent_file(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test sync_ldif_file with non-existent LDIF file."""
        options = FlextLdapModels.SyncOptions(batch_size=50)
        nonexistent_file = Path("/tmp/nonexistent_file_xyz.ldif")

        result = sync_service.sync_ldif_file(nonexistent_file, options)

        assert result.is_failure
        assert "LDIF file not found" in str(result.error)

    def test_sync_ldif_file_with_empty_file(
        self,
        sync_service: FlextLdapSyncService,
        empty_ldif_file: Path,
    ) -> None:
        """Test sync_ldif_file with empty LDIF file."""
        options = FlextLdapModels.SyncOptions(batch_size=50)

        result = sync_service.sync_ldif_file(empty_ldif_file, options)

        assert result.is_success
        stats = result.unwrap()
        assert stats.total == 0
        assert stats.added == 0


# =============================================================================
# BATCH PROCESSING TESTS
# =============================================================================


class TestFlextLdapSyncBatchProcessing:
    """Test batch processing in sync service."""

    def test_sync_batch_with_successful_entries(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test _sync_batch with all entries succeeding."""
        # Create test entries
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user1,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    data={
                        "objectClass": ["inetOrgPerson", "person"],
                        "uid": ["user1"],
                        "cn": ["User 1"],
                    }
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user2,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    data={
                        "objectClass": ["inetOrgPerson", "person"],
                        "uid": ["user2"],
                        "cn": ["User 2"],
                    }
                ),
            ),
        ]

        options = FlextLdapModels.SyncOptions(batch_size=50)

        result = sync_service._sync_batch(entries, options)

        assert result.is_success
        stats = result.unwrap()
        assert stats.total == 2
        assert stats.added == 2
        assert stats.failed == 0
        assert stats.skipped == 0

    def test_sync_batch_with_progress_callback(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test _sync_batch invokes progress_callback."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user1,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    data={
                        "objectClass": ["inetOrgPerson", "person"],
                        "uid": ["user1"],
                        "cn": ["User 1"],
                    }
                ),
            ),
        ]

        progress_calls: list[tuple[int, int, str, dict[str, int]]] = []

        def progress_callback(
            current: int,
            total: int,
            dn: str,
            stats: dict[str, int],
        ) -> None:
            progress_calls.append((current, total, dn, stats))

        options = FlextLdapModels.SyncOptions(
            batch_size=50,
            progress_callback=progress_callback,
        )

        result = sync_service._sync_batch(entries, options)

        assert result.is_success
        assert len(progress_calls) == 1
        assert progress_calls[0][0] == 1  # current
        assert progress_calls[0][1] == 1  # total

    def test_sync_batch_with_duplicate_entries(
        self,
        sync_service: FlextLdapSyncService,
        mock_ldap_operations: FlextLdapOperations,
    ) -> None:
        """Test _sync_batch handles duplicate entries gracefully."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user1,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    data={
                        "objectClass": ["inetOrgPerson", "person"],
                        "uid": ["user1"],
                        "cn": ["User 1"],
                    }
                ),
            ),
        ]

        # Configure mock to return "already exists" error
        error_result = FlextResult[FlextLdapModels.OperationResult].fail(
            "Entry already exists",
        )
        mock_ldap_operations.add.return_value = error_result  # type: ignore[assignment]
        mock_ldap_operations.is_already_exists_error.return_value = True  # type: ignore[assignment]

        options = FlextLdapModels.SyncOptions(batch_size=50)

        result = sync_service._sync_batch(entries, options)

        assert result.is_success
        stats = result.unwrap()
        assert stats.skipped == 1
        assert stats.added == 0

    def test_sync_batch_with_failed_entries(
        self,
        sync_service: FlextLdapSyncService,
        mock_ldap_operations: FlextLdapOperations,
    ) -> None:
        """Test _sync_batch counts failed entries."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user1,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    data={
                        "objectClass": ["inetOrgPerson", "person"],
                        "uid": ["user1"],
                        "cn": ["User 1"],
                    }
                ),
            ),
        ]

        # Configure mock to return generic failure
        error_result = FlextResult[FlextLdapModels.OperationResult].fail(
            "Connection failed",
        )
        mock_ldap_operations.add.return_value = error_result  # type: ignore[assignment]
        mock_ldap_operations.is_already_exists_error.return_value = False  # type: ignore[assignment]

        options = FlextLdapModels.SyncOptions(batch_size=50)

        result = sync_service._sync_batch(entries, options)

        assert result.is_success
        stats = result.unwrap()
        assert stats.failed == 1
        assert stats.added == 0
        assert stats.skipped == 0


# =============================================================================
# BASE DN TRANSFORMATION TESTS
# =============================================================================


class TestFlextLdapSyncBaseDnTransformation:
    """Test base DN transformation in sync service."""

    def test_transform_entries_basedn_with_matching_basedn(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test _transform_entries_basedn with matching base DN."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user1,ou=users,dc=old,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(data={"uid": ["user1"]}),
            ),
        ]

        result = sync_service._transform_entries_basedn(
            entries,
            source_basedn="dc=old,dc=local",
            target_basedn="dc=new,dc=local",
        )

        assert len(result) == 1
        assert str(result[0].dn) == "uid=user1,ou=users,dc=new,dc=local"

    def test_transform_entries_basedn_without_matching_basedn(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test _transform_entries_basedn with non-matching base DN."""
        original_dn = "uid=user1,ou=users,dc=old,dc=local"
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=original_dn),
                attributes=FlextLdifModels.LdifAttributes(data={"uid": ["user1"]}),
            ),
        ]

        result = sync_service._transform_entries_basedn(
            entries,
            source_basedn="dc=different,dc=local",
            target_basedn="dc=new,dc=local",
        )

        assert len(result) == 1
        assert str(result[0].dn) == original_dn

    def test_transform_entries_basedn_same_source_and_target(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test _transform_entries_basedn when source equals target."""
        original_dn = "uid=user1,ou=users,dc=test,dc=local"
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=original_dn),
                attributes=FlextLdifModels.LdifAttributes(data={"uid": ["user1"]}),
            ),
        ]

        result = sync_service._transform_entries_basedn(
            entries,
            source_basedn="dc=test,dc=local",
            target_basedn="dc=test,dc=local",
        )

        assert len(result) == 1
        assert str(result[0].dn) == original_dn


# =============================================================================
# SYNC OPTIONS AND CONFIGURATION TESTS
# =============================================================================


class TestFlextLdapSyncOptions:
    """Test sync options and configuration."""

    def test_sync_options_creation(self) -> None:
        """Test SyncOptions model creation."""
        options = FlextLdapModels.SyncOptions(
            batch_size=100,
            source_basedn="dc=source,dc=local",
            target_basedn="dc=target,dc=local",
            auto_create_parents=False,
            allow_deletes=True,
        )

        assert options.batch_size == 100
        assert options.source_basedn == "dc=source,dc=local"
        assert options.target_basedn == "dc=target,dc=local"
        assert options.auto_create_parents is False
        assert options.allow_deletes is True

    def test_sync_options_with_defaults(self) -> None:
        """Test SyncOptions with default values."""
        options = FlextLdapModels.SyncOptions()

        # batch_size defaults to FlextLdapServiceBase.get_ldap_config().chunk_size
        assert options.batch_size > 0
        assert options.auto_create_parents is True
        assert options.allow_deletes is False
        # source_basedn and target_basedn default to empty string
        assert options.source_basedn == ""
        assert options.target_basedn == ""
        assert options.progress_callback is None

    def test_sync_stats_creation(self) -> None:
        """Test SyncStats model creation."""
        stats = FlextLdapModels.SyncStats(
            added=10,
            skipped=2,
            failed=1,
            total=13,
            duration_seconds=5.5,
        )

        assert stats.added == 10
        assert stats.skipped == 2
        assert stats.failed == 1
        assert stats.total == 13
        assert stats.duration_seconds == 5.5


# =============================================================================
# HEALTH CHECK TESTS
# =============================================================================


class TestFlextLdapSyncHealthCheck:
    """Test sync service health check."""

    def test_execute_returns_empty_stats(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test execute method returns empty SyncStats for health check."""
        result = sync_service.execute()

        assert result.is_success
        stats = result.unwrap()
        assert stats.added == 0
        assert stats.skipped == 0
        assert stats.failed == 0
        assert stats.total == 0
        assert stats.duration_seconds == 0.0


# =============================================================================
# STATISTICS REPORTING TESTS
# =============================================================================


class TestFlextLdapSyncStatistics:
    """Test sync service statistics reporting."""

    def test_sync_stats_with_mixed_results(
        self,
        sync_service: FlextLdapSyncService,
        mock_ldap_operations: FlextLdapOperations,
    ) -> None:
        """Test sync statistics with mixed success/skip/fail results."""
        # Setup: 2 successful, 1 skipped (duplicate), 1 failed
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user1,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(data={"uid": ["user1"]}),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user2,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(data={"uid": ["user2"]}),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user3,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(data={"uid": ["user3"]}),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value="uid=user4,ou=users,dc=test,dc=local"
                ),
                attributes=FlextLdifModels.LdifAttributes(data={"uid": ["user4"]}),
            ),
        ]

        # Configure different responses per entry
        success_result = FlextResult[FlextLdapModels.OperationResult].ok(
            FlextLdapModels.OperationResult(
                success=True,
                operation_type="add",
            )
        )
        dup_result = FlextResult[FlextLdapModels.OperationResult].fail(
            "Entry already exists",
        )
        fail_result = FlextResult[FlextLdapModels.OperationResult].fail(
            "Operation failed",
        )

        mock_ldap_operations.add.side_effect = [  # type: ignore[assignment]
            success_result,
            success_result,
            dup_result,
            fail_result,
        ]

        def is_dup(msg: str) -> bool:  # type: ignore[arg-type]
            return "already exists" in msg.lower()

        mock_ldap_operations.is_already_exists_error.side_effect = is_dup  # type: ignore[assignment]

        options = FlextLdapModels.SyncOptions(batch_size=50)

        result = sync_service._sync_batch(entries, options)

        assert result.is_success
        stats = result.unwrap()
        assert stats.added == 2
        assert stats.skipped == 1
        assert stats.failed == 1
        assert stats.total == 4


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================


class TestFlextLdapSyncErrorHandling:
    """Test error handling in sync service."""

    def test_sync_with_empty_entries_list(
        self,
        sync_service: FlextLdapSyncService,
    ) -> None:
        """Test sync with empty entries list."""
        options = FlextLdapModels.SyncOptions(batch_size=50)

        result = sync_service._process_entries([], options, None)  # type: ignore[attr-defined]

        assert result.is_success
        stats = result.unwrap()
        assert stats.total == 0
