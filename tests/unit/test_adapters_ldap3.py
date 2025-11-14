"""Unit tests for Ldap3Adapter.

Tests Ldap3Adapter with proper mocking to cover edge cases and error paths
that are difficult to test in integration tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from flext_core import FlextResult
from flext_ldif.models import FlextLdifModels

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.models import FlextLdapModels

pytestmark = pytest.mark.unit


class TestLdap3AdapterUnit:
    """Unit tests for Ldap3Adapter with mocks."""

    def test_connect_with_import_error(self) -> None:
        """Test connect when ldap3 import fails (covers line 110)."""
        adapter = Ldap3Adapter()

        # Mock ImportError by patching the import
        with patch(
            "flext_ldap.adapters.ldap3.Server",
            side_effect=ImportError("ldap3 not installed"),
        ):
            config = FlextLdapModels.ConnectionConfig(host="localhost", port=389)
            result = adapter.connect(config)

            # Should fail with import error (covers line 110)
            assert result.is_failure
            assert "ldap3 library not installed" in (result.error or "")

    def test_disconnect_with_exception(self) -> None:
        """Test disconnect when unbind raises exception (covers lines 120-121)."""
        adapter = Ldap3Adapter()

        # Create a mock connection that raises exception on unbind
        mock_connection = MagicMock()
        mock_connection.unbind.side_effect = Exception("Connection error")
        adapter._connection = mock_connection  # type: ignore[assignment]
        adapter._server = MagicMock()  # type: ignore[assignment]

        # Disconnect should handle exception gracefully (covers lines 120-121)
        adapter.disconnect()

        # Connection should be cleared even if exception occurred
        assert adapter._connection is None
        assert adapter._server is None

    def test_connection_property(self) -> None:
        """Test connection property access (covers line 134)."""
        adapter = Ldap3Adapter()

        # Set a mock connection
        mock_connection = MagicMock()
        adapter._connection = mock_connection  # type: ignore[assignment]

        # Access connection property (covers line 134)
        connection = adapter.connection
        assert connection == mock_connection

    def test_search_with_parse_failure(self) -> None:
        """Test search when parse fails (covers lines 228-230)."""
        adapter = Ldap3Adapter()

        # Mock connection and search
        mock_connection = MagicMock()
        mock_connection.entries = [MagicMock(), MagicMock()]
        adapter._connection = mock_connection  # type: ignore[assignment]
        adapter._server = MagicMock()  # type: ignore[assignment]
        adapter.is_connected = True  # type: ignore[assignment]

        # Mock entry adapter to return failure
        mock_entry_adapter = MagicMock()
        mock_entry_adapter.ldap3_to_ldif_entry.return_value = FlextResult[
            FlextLdifModels.Entry
        ].fail("Parse error")
        adapter._entry_adapter = mock_entry_adapter  # type: ignore[assignment]

        # Mock parse to return failure
        with patch(
            "flext_ldap.adapters.ldap3.FlextLdifModels.Entry.from_ldap3_list",
            return_value=FlextResult[list[FlextLdifModels.Entry]].fail("Parse failed"),
        ):
            search_options = FlextLdapModels.SearchOptions(
                base_dn="dc=example,dc=com",
                filter_str="(objectClass=*)",
            )
            result = adapter.search(search_options)

            # Should fail with parse error (covers lines 228-230)
            assert result.is_failure
            assert "Failed to parse LDAP results" in (
                result.error or ""
            ) or "Parse failed" in (result.error or "")

    def test_add_when_not_connected(self) -> None:
        """Test add when not connected (covers line 254)."""
        adapter = Ldap3Adapter()
        adapter._connection = None  # type: ignore[assignment]
        adapter.is_connected = False  # type: ignore[assignment]

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )

        result = adapter.add(entry)

        # Should fail with not connected error (covers line 254)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_add_with_conversion_failure(self) -> None:
        """Test add when entry conversion fails (covers line 260)."""
        adapter = Ldap3Adapter()

        # Mock connection
        mock_connection = MagicMock()
        adapter._connection = mock_connection  # type: ignore[assignment]
        adapter.is_connected = True  # type: ignore[assignment]

        # Mock entry adapter to return failure
        mock_entry_adapter = MagicMock()
        mock_entry_adapter.ldif_entry_to_ldap3_attributes.return_value = FlextResult[
            dict[str, list[str]]
        ].fail("Conversion error")
        adapter._entry_adapter = mock_entry_adapter  # type: ignore[assignment]

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )

        result = adapter.add(entry)

        # Should fail with conversion error (covers line 260)
        assert result.is_failure
        assert "Failed to convert entry attributes" in (result.error or "")

    def test_modify_when_not_connected(self) -> None:
        """Test modify when not connected (covers line 301)."""
        adapter = Ldap3Adapter()
        adapter._connection = None  # type: ignore[assignment]
        adapter.is_connected = False  # type: ignore[assignment]

        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [("REPLACE", ["test@example.com"])],
        }

        result = adapter.modify("cn=test,dc=example,dc=com", changes)

        # Should fail with not connected error (covers line 301)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_delete_when_not_connected(self) -> None:
        """Test delete when not connected (covers line 340)."""
        adapter = Ldap3Adapter()
        adapter._connection = None  # type: ignore[assignment]
        adapter.is_connected = False  # type: ignore[assignment]

        result = adapter.delete("cn=test,dc=example,dc=com")

        # Should fail with not connected error (covers line 340)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_get_entry_when_not_connected(self) -> None:
        """Test get_entry when not connected (covers line 371)."""
        adapter = Ldap3Adapter()
        adapter.is_connected = False  # type: ignore[assignment]

        result = adapter.get_entry("cn=test,dc=example,dc=com")

        # Should fail with not connected error (covers line 371)
        assert result.is_failure
        assert "Not connected" in (result.error or "")
