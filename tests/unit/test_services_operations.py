"""Unit tests for FlextLdapOperations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.services.parser import FlextLdifParser
from ldap3 import MODIFY_REPLACE

from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers


class TestFlextLdapOperations:
    """Tests for FlextLdapOperations service."""

    def test_operations_initialization(self, ldap_parser: FlextLdifParser) -> None:
        """Test operations service initialization."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        assert operations is not None
        assert operations._connection == connection

    def test_search_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test search when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        search_options = TestDeduplicationHelpers.create_search(
            base_dn="dc=example,dc=com",
        )
        result = operations.search(search_options)
        TestDeduplicationHelpers.assert_failure(result, expected_error="Not connected")

    def test_add_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test add when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        entry = TestDeduplicationHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )
        result = operations.add(entry)
        TestDeduplicationHelpers.assert_failure(result, expected_error="Not connected")

    def test_modify_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test modify when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        result = operations.modify("cn=test,dc=example,dc=com", changes)
        TestDeduplicationHelpers.assert_failure(result, expected_error="Not connected")

    def test_delete_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test delete when not connected."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        result = operations.delete("cn=test,dc=example,dc=com")
        TestDeduplicationHelpers.assert_failure(result, expected_error="Not connected")

    def test_execute_when_not_connected(self, ldap_parser: FlextLdifParser) -> None:
        """Test execute when not connected returns empty health check."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)
        operations = FlextLdapOperations(connection=connection)
        result = operations.execute()
        # Execute returns empty result as health check, not failure
        assert result.is_success
        search_result = result.unwrap()
        assert search_result.total_count == 0
        assert len(search_result.entries) == 0
