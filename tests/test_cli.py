"""Tests for CLI interface.

# Constants
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from flext_core import FlextResult
from flext_ldap import cli
from flext_ldap.models import ExtendedLDAPEntry


class TestCLI:
    """Test suite for CLI functionality."""

    @pytest.mark.asyncio
    async def test_test_connection_success(self) -> None:
        """Test successful connection test."""
        with patch("flext_ldap.cli.FlextLdapClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock()
            mock_client.return_value.__aexit__ = AsyncMock()

            # Should not raise exception
            await cli.test_connection("ldap.example.com", 389)

            mock_client.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_connection_failure(self) -> None:
        """Test connection test failure."""
        with patch("flext_ldap.cli.FlextLdapClient") as mock_client:
            mock_client.return_value.__aenter__.side_effect = OSError(
                "Connection failed",
            )

            with pytest.raises(SystemExit) as exc_info:
                await cli.test_connection("invalid.example.com", 389)

            if exc_info.value.code != 1:

                msg = f"Expected {1}, got {exc_info.value.code}"
                raise AssertionError(msg)

    @pytest.mark.asyncio
    async def test_search_entries_success(self) -> None:
        """Test successful search entries."""
        mock_entry = ExtendedLDAPEntry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )

        with patch("flext_ldap.cli.FlextLdapClient") as mock_client:
            mock_client_instance = mock_client.return_value
            mock_client_instance.__aenter__ = AsyncMock(
                return_value=mock_client_instance,
            )
            mock_client_instance.__aexit__ = AsyncMock()

            # Mock successful search result
            # 🚨 ARCHITECTURAL COMPLIANCE: Using módulo raiz imports

            mock_result = FlextResult.ok([mock_entry])
            mock_client_instance.search = AsyncMock(return_value=mock_result)

            # Should not raise exception
            await cli.search_entries(
                "ldap.example.com",
                "dc=example,dc=com",
                "(objectClass=person)",
                389,
            )

            mock_client_instance.search.assert_called_once_with(
                "",
                "(objectClass=person)",
            )

    @pytest.mark.asyncio
    async def test_search_entries_failure(self) -> None:
        """Test search entries failure."""
        with (
            patch("flext_ldap.cli.FlextLdapClient") as mock_client,
            patch("flext_ldap.cli.sys.exit") as mock_exit,
        ):
            mock_client_instance = mock_client.return_value
            mock_client_instance.__aenter__ = AsyncMock(
                return_value=mock_client_instance,
            )
            mock_client_instance.__aexit__ = AsyncMock()

            # Mock failed search result

            mock_result: FlextResult[list[dict[str, Any]]] = FlextResult.fail(
                "Search failed",
            )
            mock_client_instance.search = AsyncMock(return_value=mock_result)

            await cli.search_entries(
                "ldap.example.com",
                "dc=example,dc=com",
                "(objectClass=person)",
                389,
            )

            mock_exit.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_search_entries_connection_error(self) -> None:
        """Test search entries with connection error."""
        with patch("flext_ldap.cli.FlextLdapClient") as mock_client:
            mock_client.return_value.__aenter__.side_effect = OSError(
                "Connection failed",
            )

            with pytest.raises(SystemExit) as exc_info:
                await cli.search_entries(
                    "invalid.example.com",
                    "dc=example,dc=com",
                    "(objectClass=person)",
                    389,
                )

            if exc_info.value.code != 1:

                msg = f"Expected {1}, got {exc_info.value.code}"
                raise AssertionError(msg)

    @pytest.mark.asyncio
    async def test_search_entries_many_results(self) -> None:
        """Test search with many results (more than display limit)."""
        # Create 15 mock entries (more than MAX_DISPLAY_ENTRIES = 10)
        mock_entries = []
        for i in range(15):
            mock_entry = ExtendedLDAPEntry(
                dn=f"cn=test{i},dc=example,dc=com",
                attributes={
                    "cn": [f"test{i}"],
                    "objectClass": ["person"],
                    "mail": [
                        f"test{i}@example.com",
                        "alt@example.com",
                        "third@example.com",
                        "fourth@example.com",
                    ],
                },
            )
            mock_entries.append(mock_entry)

        with patch("flext_ldap.cli.FlextLdapClient") as mock_client:
            mock_client_instance = mock_client.return_value
            mock_client_instance.__aenter__ = AsyncMock(
                return_value=mock_client_instance,
            )
            mock_client_instance.__aexit__ = AsyncMock()

            # Mock successful search result with many entries

            mock_result = FlextResult.ok(mock_entries)
            mock_client_instance.search = AsyncMock(return_value=mock_result)

            # Should not raise exception
            await cli.search_entries(
                "ldap.example.com",
                "dc=example,dc=com",
                "(objectClass=person)",
                389,
            )

            mock_client_instance.search.assert_called_once()

    def test_handle_command_insufficient_args(self) -> None:
        """Test handle_command with insufficient arguments."""
        with pytest.raises(SystemExit) as exc_info:
            cli.handle_command(["flext-infrastructure.databases.flext-ldap"])

        if exc_info.value.code != 1:

            msg = f"Expected {1}, got {exc_info.value.code}"
            raise AssertionError(msg)

    def test_handle_command_test_insufficient_args(self) -> None:
        """Test handle_command test with insufficient arguments."""
        with pytest.raises(SystemExit) as exc_info:
            cli.handle_command(["flext-infrastructure.databases.flext-ldap", "test"])

        if exc_info.value.code != 1:

            msg = f"Expected {1}, got {exc_info.value.code}"
            raise AssertionError(msg)

    def test_handle_command_test_success(self) -> None:
        """Test handle_command test with valid arguments."""
        with patch("flext_ldap.cli.asyncio.run") as mock_run:
            cli.handle_command(
                [
                    "flext-infrastructure.databases.flext-ldap",
                    "test",
                    "ldap.example.com",
                ],
            )

            mock_run.assert_called_once()
            # Verify asyncio.run was called with a coroutine and clean it up
            args, _kwargs = mock_run.call_args
            coroutine = args[0]
            assert hasattr(coroutine, "__await__")  # Coroutine object check
            # Properly close the coroutine to prevent warnings
            if hasattr(coroutine, "close"):
                coroutine.close()

    def test_handle_command_test_with_port(self) -> None:
        """Test handle_command test with custom port."""
        with patch("flext_ldap.cli.asyncio.run") as mock_run:
            cli.handle_command(
                [
                    "flext-infrastructure.databases.flext-ldap",
                    "test",
                    "ldap.example.com",
                    "636",
                ],
            )

            mock_run.assert_called_once()
            # Verify asyncio.run was called with a coroutine and clean it up
            args, _kwargs = mock_run.call_args
            coroutine = args[0]
            assert hasattr(coroutine, "__await__")  # Coroutine object check
            # Properly close the coroutine to prevent warnings
            if hasattr(coroutine, "close"):
                coroutine.close()

    def test_handle_command_search_insufficient_args(self) -> None:
        """Test handle_command search with insufficient arguments."""
        with pytest.raises(SystemExit) as exc_info:
            cli.handle_command(
                [
                    "flext-infrastructure.databases.flext-ldap",
                    "search",
                    "ldap.example.com",
                ],
            )

        if exc_info.value.code != 1:

            msg = f"Expected {1}, got {exc_info.value.code}"
            raise AssertionError(msg)

    def test_handle_command_search_success(self) -> None:
        """Test handle_command search with valid arguments."""
        with patch("flext_ldap.cli.asyncio.run") as mock_run:
            cli.handle_command(
                [
                    "flext-infrastructure.databases.flext-ldap",
                    "search",
                    "ldap.example.com",
                    "dc=example,dc=com",
                ],
            )

            mock_run.assert_called_once()
            # Verify asyncio.run was called with a coroutine and clean it up
            args, _kwargs = mock_run.call_args
            coroutine = args[0]
            assert hasattr(coroutine, "__await__")  # Coroutine object check
            # Properly close the coroutine to prevent warnings
            if hasattr(coroutine, "close"):
                coroutine.close()

    def test_handle_command_search_with_filter(self) -> None:
        """Test handle_command search with custom filter."""
        with patch("flext_ldap.cli.asyncio.run") as mock_run:
            cli.handle_command(
                [
                    "flext-infrastructure.databases.flext-ldap",
                    "search",
                    "ldap.example.com",
                    "dc=example,dc=com",
                    "(objectClass=user)",
                ],
            )

            mock_run.assert_called_once()
            # Verify asyncio.run was called with a coroutine and clean it up
            args, _kwargs = mock_run.call_args
            coroutine = args[0]
            assert hasattr(coroutine, "__await__")  # Coroutine object check
            # Properly close the coroutine to prevent warnings
            if hasattr(coroutine, "close"):
                coroutine.close()

    def test_handle_command_search_with_port(self) -> None:
        """Test handle_command search with custom port."""
        with patch("flext_ldap.cli.asyncio.run") as mock_run:
            cli.handle_command(
                [
                    "flext-infrastructure.databases.flext-ldap",
                    "search",
                    "ldap.example.com",
                    "dc=example,dc=com",
                    "(objectClass=user)",
                    "636",
                ],
            )

            mock_run.assert_called_once()
            # Verify asyncio.run was called with a coroutine and clean it up
            args, _kwargs = mock_run.call_args
            coroutine = args[0]
            assert hasattr(coroutine, "__await__")  # Coroutine object check
            # Properly close the coroutine to prevent warnings
            if hasattr(coroutine, "close"):
                coroutine.close()

    def test_handle_command_invalid_command(self) -> None:
        """Test handle_command with invalid command."""
        with pytest.raises(SystemExit) as exc_info:
            cli.handle_command(
                ["flext-infrastructure.databases.flext-ldap", "invalid", "arg"],
            )

        if exc_info.value.code != 1:

            msg = f"Expected {1}, got {exc_info.value.code}"
            raise AssertionError(msg)

    def test_main_function(self) -> None:
        """Test main function."""
        with (
            patch(
                "flext_ldap.cli.sys.argv",
                [
                    "flext-infrastructure.databases.flext-ldap",
                    "test",
                    "ldap.example.com",
                ],
            ),
            patch("flext_ldap.cli.handle_command") as mock_handle,
        ):
            cli.main()

            mock_handle.assert_called_once_with(
                [
                    "flext-infrastructure.databases.flext-ldap",
                    "test",
                    "ldap.example.com",
                ],
            )

    def test_constants_defined(self) -> None:
        """Test that all constants are properly defined."""
        if cli.DEFAULT_LDAP_PORT != 389:
            msg = f"Expected {389}, got {cli.DEFAULT_LDAP_PORT}"
            raise AssertionError(msg)
        assert cli.MINIMUM_ARGS_FOR_COMMAND == EXPECTED_BULK_SIZE
        if cli.MINIMUM_ARGS_FOR_CONNECTION != EXPECTED_DATA_COUNT:
            msg = f"Expected {3}, got {cli.MINIMUM_ARGS_FOR_CONNECTION}"
            raise AssertionError(msg)
        assert cli.MINIMUM_ARGS_FOR_SEARCH == 4
        if cli.PORT_ARG_INDEX != EXPECTED_DATA_COUNT:
            msg = f"Expected {3}, got {cli.PORT_ARG_INDEX}"
            raise AssertionError(msg)
        assert cli.FILTER_ARG_INDEX == 4
        if cli.SEARCH_PORT_ARG_INDEX != 5:
            msg = f"Expected {5}, got {cli.SEARCH_PORT_ARG_INDEX}"
            raise AssertionError(msg)
        assert cli.MAX_DISPLAY_ENTRIES == 10

    def test_module_executable(self) -> None:
        """Test that module can be executed as script."""
        with patch("flext_ldap.cli.main"):
            # Simulate __name__ == "__main__"
            original_name = cli.__name__
            try:
                cli.__name__ = "__main__"
                # Import again to trigger the if __name__ == "__main__" block

                importlib.reload(cli)
            finally:
                cli.__name__ = original_name
