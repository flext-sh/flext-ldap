"""Unit tests for FlextLdapSyncService.

Tests sync service functionality with proper mocking to cover edge cases
that are difficult to test in integration tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import PropertyMock, patch

import pytest
from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.services.sync import FlextLdapSyncService
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


class TestFlextLdapSyncServiceUnit:
    """Unit tests for FlextLdapSyncService with mocks."""

    def test_sync_ldif_file_parse_failure(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test sync_ldif_file when parse() returns failure (covers line 110).

        Uses patch at the module level to mock FlextLdif.get_instance().parse()
        before the service is created, following proper architecture patterns.
        """
        # Setup
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)

        # Create a real file path
        test_file = Path("/tmp/test_sync_parse_failure.ldif")
        test_file.write_text("test content", encoding="utf-8")

        try:
            # Mock is_connected property to return True
            with patch.object(
                type(operations),
                "is_connected",
                new_callable=PropertyMock,
                return_value=True,
            ):
                # Create service after mocking is_connected
                sync_service = FlextLdapSyncService(operations=operations)

                # Mock flext-ldif parse method at the instance level using patch
                # Patch the parse method call, not the attribute assignment
                with patch(
                    "flext_ldap.services.sync.FlextLdif.get_instance",
                ) as mock_get_instance:
                    mock_ldif = mock_get_instance.return_value
                    mock_ldif.parse.return_value = FlextResult[
                        list[FlextLdifModels.Entry]
                    ].fail("Parse error: Invalid LDIF format")

                    # Recreate service to use mocked instance
                    sync_service._ldif = mock_ldif

                    sync_options = FlextLdapModels.SyncOptions()
                    result = sync_service.sync_ldif_file(test_file, sync_options)

                    # Should fail with parse error (covers line 110)
                    assert result.is_failure
                    # No fallback - FlextResult guarantees error exists when is_failure is True
                    assert result.error is not None
                    assert "Failed to parse LDIF file" in result.error
        finally:
            if test_file.exists():
                test_file.unlink()

    def test_sync_ldif_file_sync_batch_failure(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test sync_ldif_file when _sync_batch returns failure (covers line 144).

        Uses patch to mock _sync_batch method to return failure, testing
        the error handling path at line 144.
        """
        # Setup
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)

        # Create a real file with valid LDIF content
        test_file = Path("/tmp/test_sync_batch_failure.ldif")
        test_file.write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
            encoding="utf-8",
        )

        try:
            # Mock is_connected property to return True
            with patch.object(
                type(operations),
                "is_connected",
                new_callable=PropertyMock,
                return_value=True,
            ):
                # Create service
                sync_service = FlextLdapSyncService(operations=operations)

                # Use real helper to create entry
                test_entry = TestDeduplicationHelpers.create_entry(
                    "cn=test,dc=example,dc=com",
                    {"cn": ["test"], "objectClass": ["person"]},
                )

                # Patch parse method at instance level
                with patch(
                    "flext_ldap.services.sync.FlextLdif.get_instance",
                ) as mock_get_instance:
                    mock_ldif = mock_get_instance.return_value
                    mock_ldif.parse.return_value = FlextResult[
                        list[FlextLdifModels.Entry]
                    ].ok([test_entry])

                    # Recreate service to use mocked instance
                    sync_service._ldif = mock_ldif

                    # Mock _sync_batch to return failure (covers line 144)
                    with patch.object(
                        sync_service,
                        "_sync_batch",
                        return_value=FlextResult[FlextLdapModels.SyncStats].fail(
                            "Batch sync failed: Connection lost",
                        ),
                    ):
                        sync_options = FlextLdapModels.SyncOptions()
                        result = sync_service.sync_ldif_file(test_file, sync_options)

                        # Should fail with batch error (covers line 144)
                        assert result.is_failure
                        # No fallback - FlextResult guarantees error exists when is_failure is True
                        assert result.error is not None
                        assert "Batch sync failed" in result.error
        finally:
            if test_file.exists():
                test_file.unlink()
