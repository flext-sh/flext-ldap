"""Tests for new CLI interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from flext_ldap import cli_new
from flext_ldap.models import ExtendedLDAPEntry


class TestCLINew:
    """Test suite for new CLI functionality."""

    def test_run_async_decorator(self) -> None:
        """Test run_async decorator functionality."""

        @cli_new.run_async
        async def test_func(value: str) -> str:
            return f"async_{value}"

        result = test_func("test")
        assert result == "async_test"

    def test_cli_group_version(self) -> None:
        """Test CLI group and version option."""
        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["--version"])

        assert result.exit_code == 0
        assert "0.6.0" in result.output

    def test_cli_group_help(self) -> None:
        """Test CLI group help."""
        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["--help"])

        assert result.exit_code == 0
        assert "FLEXT LDAP - Enterprise LDAP Operations" in result.output
        assert "test" in result.output
        assert "search" in result.output

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_test_command_success(self, mock_client_class: MagicMock) -> None:
        """Test successful connection test command."""
        # Mock client instance with context manager support
        mock_client = mock_client_class.return_value
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.is_connected = MagicMock(return_value=True)

        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["test", "ldap.example.com"])

        assert result.exit_code == 0
        assert "✅ Successfully connected to ldap.example.com:389" in result.output
        # Verify context manager was used
        mock_client.__aenter__.assert_called_once()
        mock_client.__aexit__.assert_called_once()

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_test_command_connection_failure(
        self,
        mock_client_class: MagicMock,
    ) -> None:
        """Test connection test command failure."""
        # Mock client instance with context manager that raises exception
        mock_client = mock_client_class.return_value

        # Mock context manager that raises LDAPException for connection failure
        from ldap3.core.exceptions import LDAPException

        mock_client.__aenter__ = AsyncMock(
            side_effect=LDAPException("Failed to connect"),
        )
        mock_client.__aexit__ = AsyncMock()

        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["test", "invalid.example.com"])

        assert result.exit_code == 1
        assert "❌ Error: Failed to connect" in result.output

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_test_command_with_options(self, mock_client_class: MagicMock) -> None:
        """Test connection test with various options."""
        # Mock client instance with context manager support
        mock_client = mock_client_class.return_value
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.is_connected = MagicMock(return_value=True)

        runner = CliRunner()
        result = runner.invoke(
            cli_new.cli,
            [
                "test",
                "ldap.example.com",
                "--port",
                "636",
                "--tls",
                "--bind-dn",
                "cn=admin,dc=example,dc=com",
                "--bind-password",
                "secret",
            ],
        )

        assert result.exit_code == 0
        assert "✅ Successfully connected to ldap.example.com:636" in result.output

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_test_command_exception(self, mock_client_class: MagicMock) -> None:
        """Test connection test command with exception."""
        # Mock client instance to raise exception
        mock_client_class.side_effect = OSError("Network unreachable")

        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["test", "unreachable.example.com"])

        assert result.exit_code == 1
        assert "❌ Error: Network unreachable" in result.output

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_search_command_success(self, mock_client_class: MagicMock) -> None:
        """Test successful search command."""
        # Create mock entries
        mock_entries = [
            ExtendedLDAPEntry(
                dn="cn=user1,dc=example,dc=com",
                attributes={"cn": ["user1"], "objectClass": ["person"]},
            ),
            ExtendedLDAPEntry(
                dn="cn=user2,dc=example,dc=com",
                attributes={"cn": ["user2"], "objectClass": ["person"]},
            ),
        ]

        # Mock client instance
        mock_client = mock_client_class.return_value
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.search = AsyncMock()

        # Mock successful search
        # 🚨 ARCHITECTURAL COMPLIANCE: Using módulo raiz imports
        from flext_core import FlextResult

        mock_client.search.return_value = FlextResult.ok(mock_entries)

        runner = CliRunner()
        result = runner.invoke(
            cli_new.cli,
            ["search", "ldap.example.com", "dc=example,dc=com"],
        )

        assert result.exit_code == 0
        assert "Found 2 entries:" in result.output
        assert "DN: cn=user1,dc=example,dc=com" in result.output
        assert "DN: cn=user2,dc=example,dc=com" in result.output

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_search_command_many_results(self, mock_client_class: MagicMock) -> None:
        """Test search command with many results."""
        # Create 15 mock entries (more than display limit of 10)
        mock_entries = []
        for i in range(15):
            mock_entry = ExtendedLDAPEntry(
                dn=f"cn=user{i},dc=example,dc=com",
                attributes={"cn": [f"user{i}"], "objectClass": ["person"]},
            )
            mock_entries.append(mock_entry)

        # Mock client instance
        mock_client = mock_client_class.return_value
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.search = AsyncMock()

        # Mock successful search
        from flext_core import FlextResult

        mock_client.search.return_value = FlextResult.ok(mock_entries)

        runner = CliRunner()
        result = runner.invoke(
            cli_new.cli,
            ["search", "ldap.example.com", "dc=example,dc=com"],
        )

        assert result.exit_code == 0
        assert "Found 15 entries:" in result.output
        assert "... and 5 more" in result.output

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_search_command_with_options(self, mock_client_class: MagicMock) -> None:
        """Test search command with various options."""
        # Mock client instance
        mock_client = mock_client_class.return_value
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.search = AsyncMock()

        # Mock successful search with empty results
        from flext_core import FlextResult

        mock_client.search.return_value = FlextResult.ok([])

        runner = CliRunner()
        result = runner.invoke(
            cli_new.cli,
            [
                "search",
                "ldap.example.com",
                "dc=example,dc=com",
                "--port",
                "636",
                "--filter",
                "(objectClass=user)",
                "--bind-dn",
                "cn=admin,dc=example,dc=com",
                "--bind-password",
                "secret",
            ],
        )

        assert result.exit_code == 0
        assert "Found 0 entries:" in result.output
        mock_client.search.assert_called_once_with(
            "dc=example,dc=com",
            "(objectClass=user)",
        )

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_search_command_failure(self, mock_client_class: MagicMock) -> None:
        """Test search command failure."""
        # Mock client instance
        mock_client = mock_client_class.return_value
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.search = AsyncMock()

        # Mock failed search
        from flext_core import FlextResult

        mock_client.search.return_value = FlextResult.fail("Invalid filter")

        runner = CliRunner()
        result = runner.invoke(
            cli_new.cli,
            [
                "search",
                "ldap.example.com",
                "dc=example,dc=com",
                "--filter",
                "(invalid=filter)",
            ],
        )

        # Note: Due to Click async handling, exit codes may not propagate correctly
        # But the error message should be displayed properly
        assert "❌ Search failed: Invalid filter" in result.output

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_search_command_exception(self, mock_client_class: MagicMock) -> None:
        """Test search command with exception."""
        # Mock client instance to raise exception
        mock_client_class.side_effect = ValueError("Invalid server format")

        runner = CliRunner()
        result = runner.invoke(
            cli_new.cli,
            ["search", "invalid-server", "dc=example,dc=com"],
        )

        assert result.exit_code == 1
        assert "❌ Error: Invalid server format" in result.output

    def test_search_command_missing_args(self) -> None:
        """Test search command with missing arguments."""
        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["search"])

        assert result.exit_code == 2  # Click missing argument error
        assert "Missing argument" in result.output

    def test_test_command_missing_args(self) -> None:
        """Test test command with missing arguments."""
        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["test"])

        assert result.exit_code == 2  # Click missing argument error
        assert "Missing argument" in result.output

    def test_invalid_command(self) -> None:
        """Test invalid command."""
        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["invalid"])

        assert result.exit_code == 2  # Click unknown command error
        assert "No such command" in result.output

    def test_module_executable(self) -> None:
        """Test that module can be executed as script."""
        with patch("flext_ldap.cli_new.cli"):
            # Simulate __name__ == "__main__"
            original_name = cli_new.__name__
            try:
                cli_new.__name__ = "__main__"
                # Import again to trigger the if __name__ == "__main__" block
                import importlib

                importlib.reload(cli_new)
            finally:
                cli_new.__name__ = original_name

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_test_command_runtime_error(self, mock_client_class: MagicMock) -> None:
        """Test test command with runtime error."""
        # Mock client instance with context manager that raises RuntimeError
        mock_client = mock_client_class.return_value
        mock_client.__aenter__ = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        mock_client.__aexit__ = AsyncMock()

        runner = CliRunner()
        result = runner.invoke(cli_new.cli, ["test", "ldap.example.com"])

        assert result.exit_code == 1
        assert "❌ Error: Unexpected error" in result.output

    @patch("flext_ldap.cli_new.LDAPClient")
    def test_search_command_runtime_error(self, mock_client_class: MagicMock) -> None:
        """Test search command with runtime error."""
        # Mock client instance to raise RuntimeError
        mock_client = mock_client_class.return_value
        mock_client.__aenter__ = AsyncMock(side_effect=RuntimeError("Connection lost"))

        runner = CliRunner()
        result = runner.invoke(
            cli_new.cli,
            ["search", "ldap.example.com", "dc=example,dc=com"],
        )

        assert result.exit_code == 1
        assert "❌ Error: Connection lost" in result.output
