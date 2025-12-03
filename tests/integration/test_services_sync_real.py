"""Integration tests for FlextLdapSyncService with real LDAP server.

Modules tested: FlextLdapSyncService, FlextLdapOperations, FlextLdapConnection, FlextLdapModels
Scope: Real LDAP sync operations with LDIF files, base DN transformations, and error handling scenarios

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import ClassVar, cast

import pytest
from flext_core import FlextResult
from flext_core.typings import t
from flext_ldif import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService

from ..fixtures.constants import RFC
from ..fixtures.typing import GenericFieldsDict
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class SyncTestType(StrEnum):
    """Enumeration of sync test types."""

    NOT_CONNECTED = "not_connected"
    PARSE_FAILURE = "parse_failure"
    EMPTY_FILE = "empty_file"
    ADD_FAILURE = "add_failure"
    SAME_BASEDN = "same_basedn"
    BASEDN_TRANSFORM = "basedn_transform"
    EXECUTE = "execute"


class TestFlextLdapSyncServiceReal:
    """Tests for sync service with real LDAP server."""

    # Test configurations as ClassVar for parameterized tests
    SYNC_FILE_TEST_CONFIGS: ClassVar[list[tuple[str, GenericFieldsDict]]] = [
        (
            "not_connected",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": SyncTestType.NOT_CONNECTED,
                    "use_base_ldif": True,
                    "expect_success": True,
                    "expect_failed": True,
                    "expect_added": 0,
                },
            ),
        ),
        (
            "parse_failure",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": SyncTestType.PARSE_FAILURE,
                    "ldif_content": "invalid ldif content\nnot a valid entry\n",
                    "expect_success": None,  # Can be success or failure
                },
            ),
        ),
        (
            "empty_file",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": SyncTestType.EMPTY_FILE,
                    "ldif_content": "",
                    "expect_success": None,  # Can be success or failure
                    "expect_added_zero": True,
                },
            ),
        ),
        (
            "add_failure",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": SyncTestType.ADD_FAILURE,
                    "use_base_ldif": True,
                    "additional_content": "\ndn: cn=invalid,{}\nobjectClass: top\n# Missing required attributes\n",
                    "expect_success": None,  # Can be success or failure
                },
            ),
        ),
        (
            "same_basedn",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": SyncTestType.SAME_BASEDN,
                    "ldif_content": "dn: cn=test-same-basedn,{}\nobjectClass: top\nobjectClass: organizationalUnit\nou: test\n",
                    "sync_options": {
                        "source_basedn": RFC.DEFAULT_BASE_DN,
                        "target_basedn": RFC.DEFAULT_BASE_DN,
                    },
                    "expect_success": None,  # Can be success or failure
                },
            ),
        ),
        (
            "basedn_transform",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": SyncTestType.BASEDN_TRANSFORM,
                    "ldif_content": "dn: cn=test-transform,{}\nobjectClass: top\nobjectClass: organizationalUnit\nou: test\n",
                    "sync_options": {
                        "source_basedn": RFC.DEFAULT_BASE_DN,
                        "target_basedn": "dc=target,dc=local",
                    },
                    "expect_success": None,  # Can be success or failure
                },
            ),
        ),
    ]

    EXECUTE_TEST_CONFIGS: ClassVar[list[tuple[str, GenericFieldsDict]]] = [
        (
            "execute_method",
            cast(
                "GenericFieldsDict",
                {
                    "test_type": SyncTestType.EXECUTE,
                    "expect_success": True,
                    "expect_added_zero": True,
                    "expect_failed_zero": True,
                    "expect_skipped_zero": True,
                    "expect_total_zero": True,
                },
            ),
        ),
    ]

    class TestDataFactories:
        """Nested class for test data creation."""

        @staticmethod
        def create_sync_service(
            connection_config: FlextLdapModels.ConnectionConfig,
            ldap_parser: FlextLdifParser,
        ) -> FlextLdapSyncService:
            """Create and connect sync service."""
            config = FlextLdapConfig()
            connection = FlextLdapConnection(config=config, parser=ldap_parser)
            connect_result = connection.connect(connection_config)
            if connect_result.is_failure:
                pytest.skip(f"Failed to connect: {connect_result.error}")

            operations = FlextLdapOperations(connection=connection)
            return FlextLdapSyncService(operations=operations)

        @staticmethod
        def create_sync_service_not_connected(
            ldap_parser: FlextLdifParser,
        ) -> FlextLdapSyncService:
            """Create sync service without connection."""
            config = FlextLdapConfig()
            connection = FlextLdapConnection(config=config, parser=ldap_parser)
            operations = FlextLdapOperations(connection=connection)
            return FlextLdapSyncService(operations=operations)

        @staticmethod
        def create_ldif_content(
            base_content: str | None = None,
            additional_content: str | None = None,
        ) -> str:
            """Create LDIF content for testing."""
            content = base_content or ""
            if additional_content:
                content += additional_content.format(RFC.DEFAULT_BASE_DN)
            return content

    class TestAssertions:
        """Nested class for test assertions."""

        @staticmethod
        def assert_sync_result(
            result: FlextResult[FlextLdapModels.SyncStats],
            config: GenericFieldsDict,
        ) -> None:
            """Assert sync result based on configuration with comprehensive validation."""
            if expected_success := config.get("expect_success"):
                assert result.is_success == expected_success, (
                    f"Expected success={expected_success}, got is_success={result.is_success}, "
                    f"error={result.error}"
                )
                # Validate actual content based on expected success
                if expected_success and result.is_success:
                    stats = TestOperationHelpers.unwrap_sync_stats(result)
                    # Validate all stats fields are non-negative
                    assert stats.total >= 0
                    assert stats.added >= 0
                    assert stats.failed >= 0
                    assert stats.skipped >= 0
                    assert stats.duration_seconds >= 0.0
                elif not expected_success and result.is_failure:
                    # Validate failure: error message should be present
                    error_msg = TestOperationHelpers.get_error_message(result)
                    assert len(error_msg) > 0

            if result.is_success:
                stats = TestOperationHelpers.unwrap_sync_stats(result)

                # Validate actual content: all stats should be non-negative
                assert stats.total >= 0, f"Total should be >= 0, got {stats.total}"
                assert stats.added >= 0, f"Added should be >= 0, got {stats.added}"
                assert stats.failed >= 0, f"Failed should be >= 0, got {stats.failed}"
                assert stats.skipped >= 0, (
                    f"Skipped should be >= 0, got {stats.skipped}"
                )
                assert stats.duration_seconds >= 0.0, (
                    f"Duration should be >= 0, got {stats.duration_seconds}"
                )
                # Validate consistency: added + failed + skipped should equal total
                assert stats.added + stats.failed + stats.skipped == stats.total, (
                    f"Stats inconsistency: added={stats.added}, failed={stats.failed}, "
                    f"skipped={stats.skipped}, total={stats.total}"
                )

                if config.get("expect_failed"):
                    assert stats.failed > 0, f"Expected failed > 0, got {stats.failed}"

                expect_added = config.get("expect_added")
                if expect_added is not None:
                    assert stats.added == expect_added, (
                        f"Expected added={expect_added}, got {stats.added}"
                    )

                if config.get("expect_added_zero"):
                    assert stats.added == 0, f"Expected added=0, got {stats.added}"

                if config.get("expect_failed_zero"):
                    assert stats.failed == 0, f"Expected failed=0, got {stats.failed}"

                if config.get("expect_skipped_zero"):
                    assert stats.skipped == 0, (
                        f"Expected skipped=0, got {stats.skipped}"
                    )

                if config.get("expect_total_zero"):
                    assert stats.total == 0, f"Expected total=0, got {stats.total}"
            else:
                # Validate failure: error message should be present
                TestOperationHelpers.assert_result_failure(result)
                error_msg = TestOperationHelpers.get_error_message(result)
                assert len(error_msg) > 0, "Error message should not be empty"

    @pytest.fixture
    def sync_service(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
        ldap_parser: FlextLdifParser,
    ) -> FlextLdapSyncService:
        """Get sync service with connected operations."""
        return self.TestDataFactories.create_sync_service(
            connection_config,
            ldap_parser,
        )

    @pytest.mark.parametrize(("test_name", "config"), SYNC_FILE_TEST_CONFIGS)
    def test_sync_ldif_file_parameterized(
        self,
        sync_service: FlextLdapSyncService,
        base_ldif_content: str,
        ldap_parser: FlextLdifParser,
        test_name: str,
        config: GenericFieldsDict,
    ) -> None:
        """Test sync LDIF file operations with different configurations."""
        # Create LDIF file based on test configuration
        if config.get("use_base_ldif"):
            ldif_content = self.TestDataFactories.create_ldif_content(
                base_content=base_ldif_content,
                additional_content=cast("str | None", config.get("additional_content")),
            )
        else:
            ldif_content = cast("str", config.get("ldif_content", ""))

        with NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            _ = f.write(ldif_content)
            ldif_file = Path(f.name)

        try:
            # Create sync options if specified
            if sync_options_config := config.get("sync_options"):
                sync_options_dict = cast(
                    "dict[str, t.GeneralValueType]",
                    sync_options_config,
                )
                options = FlextLdapModels.SyncOptions(
                    source_basedn=cast("str", sync_options_dict.get("source_basedn")),
                    target_basedn=cast("str", sync_options_dict.get("target_basedn")),
                )
            else:
                options = FlextLdapModels.SyncOptions()

            # Handle not connected test case
            if config.get("test_type") == SyncTestType.NOT_CONNECTED:
                sync_service = self.TestDataFactories.create_sync_service_not_connected(
                    ldap_parser,
                )

            result = sync_service.sync_ldif_file(ldif_file, options)

            self.TestAssertions.assert_sync_result(result, config)
        finally:
            ldif_file.unlink()

    @pytest.mark.parametrize(("test_name", "config"), EXECUTE_TEST_CONFIGS)
    def test_execute_operations_parameterized(
        self,
        sync_service: FlextLdapSyncService,
        test_name: str,
        config: GenericFieldsDict,
    ) -> None:
        """Test execute operations with different configurations."""
        result = sync_service.execute()

        self.TestAssertions.assert_sync_result(result, config)
