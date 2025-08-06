"""Tests for modern CLI interface using flext-cli patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from click.testing import CliRunner
from flext_core import FlextResult

from flext_ldap.cli import (
    LDAPConnectionHandler,
    LDAPConnectionTestParams,
    LDAPSearchHandler,
    LDAPUserHandler,
    cli,
)


# FBT smell elimination constants for tests - SOLID DRY Principle
class TestConnectionResult:
    """Test connection result constants - eliminates FBT003 positional booleans."""

    SUCCESS = True
    FAILURE = False


class TestOperationResult:
    """Test operation result constants - eliminates FBT003 positional booleans."""

    SUCCESS = True
    FAILURE = False


class TestCLI:
    """Test suite for modern CLI functionality with flext-cli patterns."""

    def test_cli_version_option(self) -> None:
        """Test CLI version option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "0.9.0" in result.output

    def test_cli_help_option(self) -> None:
        """Test CLI help option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "FLEXT LDAP - Enterprise LDAP Operations" in result.output
        assert "test" in result.output
        assert "search" in result.output
        assert "user-info" in result.output
        assert "create-user" in result.output
        assert "list-users" in result.output

    def test_version_command(self) -> None:
        """Test version command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])

        assert result.exit_code == 0
        assert "FLEXT LDAP v0.9.0" in result.output

    def test_main_function_success(self) -> None:
        """Test main function calls cli."""
        with patch("flext_ldap.cli.cli") as mock_cli:
            from flext_ldap.cli import main

            main()
            mock_cli.assert_called_once()

    def test_missing_arguments(self) -> None:
        """Test commands with missing arguments."""
        runner = CliRunner()

        # Test command needs server argument
        result = runner.invoke(cli, ["test"])
        assert result.exit_code == 2
        assert "Missing argument" in result.output

        # Search command needs server and base_dn arguments
        result = runner.invoke(cli, ["search"])
        assert result.exit_code == 2
        assert "Missing argument" in result.output


class TestLDAPConnectionHandler:
    """Test suite for LDAP connection handler."""

    def test_test_connection_success(self) -> None:
        """Test successful connection test."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS methods
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.is_connected.return_value = TestConnectionResult.SUCCESS

            params = LDAPConnectionTestParams(server="ldap.example.com", port=389)
            result = LDAPConnectionHandler.test_connection(params)

            assert result.success
            assert (
                "Successfully connected to ldap://ldap.example.com:389" in result.data
            )

    def test_test_connection_failure(self) -> None:
        """Test connection test failure."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect is SYNCHRONOUS method
            mock_client.connect.return_value = FlextResult.fail("Connection refused")

            params = LDAPConnectionTestParams(server="invalid.example.com", port=389)
            result = LDAPConnectionHandler.test_connection(params)

            assert result.is_failure
            assert "Connection failed" in result.error


class TestLDAPSearchHandler:
    """Test suite for LDAP search handler."""

    def test_search_entries_success(self) -> None:
        """Test successful search entries."""
        mock_entries = [
            {
                "dn": "cn=user1,dc=example,dc=com",
                "attributes": {"cn": ["user1"], "objectClass": ["person"]},
            }
        ]

        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, search is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.search = AsyncMock(return_value=FlextResult.ok(mock_entries))
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            from flext_ldap.cli import LDAPSearchParams

            params = LDAPSearchParams(
                server="ldap.example.com", base_dn="dc=example,dc=com"
            )
            result = LDAPSearchHandler.search_entries(params)

            assert result.success
            assert len(result.data) == 1
            assert result.data[0].dn == "cn=user1,dc=example,dc=com"

    def test_search_entries_connection_failure(self) -> None:
        """Test search entries with connection failure."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect is SYNCHRONOUS method
            mock_client.connect.return_value = FlextResult.fail("Connection failed")

            from flext_ldap.cli import LDAPSearchParams

            params = LDAPSearchParams(
                server="invalid.example.com", base_dn="dc=example,dc=com"
            )
            result = LDAPSearchHandler.search_entries(params)

            assert result.is_failure
            assert "Connection failed" in result.error


class TestLDAPUserHandler:
    """Test suite for LDAP user handler."""

    def test_get_user_info_success(self) -> None:
        """Test successful user info retrieval."""
        mock_user_data = {
            "dn": "cn=john,dc=example,dc=com",
            "attributes": {"uid": ["john"], "cn": ["John Doe"], "sn": ["Doe"]},
        }

        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, search is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.search = AsyncMock(
                return_value=FlextResult.ok([mock_user_data])
            )
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            result = LDAPUserHandler.get_user_info("john")

            assert result.success
            assert result.data["attributes"]["uid"] == ["john"]

    def test_get_user_info_not_found(self) -> None:
        """Test user info when user not found."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, search is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.search = AsyncMock(
                return_value=FlextResult.ok([])
            )  # Empty results
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            result = LDAPUserHandler.get_user_info("nonexistent")

            assert result.is_failure
            assert "User nonexistent not found" in result.error

    def test_create_user_success(self) -> None:
        """Test successful user creation."""
        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, add is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.add = AsyncMock(
                return_value=FlextResult.ok(TestOperationResult.SUCCESS)
            )
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            from flext_ldap.cli import LDAPUserParams

            params = LDAPUserParams(uid="john", cn="John Doe", sn="Doe")
            result = LDAPUserHandler.create_user(params)

            assert result.success
            assert result.data["uid"] == "john"
            assert result.data["cn"] == "John Doe"

    def test_list_users_success(self) -> None:
        """Test successful user listing."""
        mock_users = [
            {
                "dn": "cn=john,dc=example,dc=com",
                "attributes": {"uid": ["john"], "cn": ["John Doe"], "sn": ["Doe"]},
            },
            {
                "dn": "cn=jane,dc=example,dc=com",
                "attributes": {"uid": ["jane"], "cn": ["Jane Smith"], "sn": ["Smith"]},
            },
        ]

        with patch("flext_ldap.cli.FlextLdapSimpleClient") as mock_client_class:
            mock_client = mock_client_class.return_value
            # connect/disconnect are SYNCHRONOUS, search is ASYNCHRONOUS
            mock_client.connect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )
            mock_client.search = AsyncMock(return_value=FlextResult.ok(mock_users))
            mock_client.disconnect.return_value = FlextResult.ok(
                TestConnectionResult.SUCCESS
            )

            result = LDAPUserHandler.list_users()

            assert result.success
            assert len(result.data) == 2


class TestCLICommands:
    """Test actual CLI command invocations."""

    @patch.object(LDAPConnectionHandler, "test_connection")
    def test_test_command_success(self, mock_test) -> None:
        """Test test command invocation."""
        mock_test.return_value = FlextResult.ok("Connection successful")

        runner = CliRunner()
        result = runner.invoke(cli, ["test", "ldap.example.com"])

        assert result.exit_code == 0
        assert "✅" in result.output
        mock_test.assert_called_once()

    @patch.object(LDAPConnectionHandler, "test_connection")
    def test_test_command_failure(self, mock_test) -> None:
        """Test test command failure."""
        mock_test.return_value = FlextResult.fail("Connection failed")

        runner = CliRunner()
        result = runner.invoke(cli, ["test", "ldap.example.com"])

        assert result.exit_code == 0
        assert "❌" in result.output

    @patch.object(LDAPSearchHandler, "search_entries")
    def test_search_command_success(self, mock_search) -> None:
        """Test search command invocation."""
        from flext_ldap.values import ExtendedLDAPEntry

        mock_entries = [
            ExtendedLDAPEntry(
                dn="cn=test,dc=example,dc=com",
                attributes={"cn": ["test"], "mail": ["test@example.com"]},
            )
        ]
        mock_search.return_value = FlextResult.ok(mock_entries)

        runner = CliRunner()
        result = runner.invoke(cli, ["search", "ldap.example.com", "dc=example,dc=com"])

        assert result.exit_code == 0
        assert "📊" in result.output
        mock_search.assert_called_once()

    @patch.object(LDAPSearchHandler, "search_entries")
    def test_search_command_with_options(self, mock_search) -> None:
        """Test search command with all options."""
        mock_search.return_value = FlextResult.ok([])

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "search",
                "ldap.example.com",
                "dc=example,dc=com",
                "--filter",
                "(objectClass=person)",
                "--limit",
                "25",
                "--port",
                "636",
                "--ssl",
                "--bind-dn",
                "cn=admin,dc=example,dc=com",
                "--bind-password",
                "secret",
            ],
        )

        assert result.exit_code == 0

    @patch.object(LDAPUserHandler, "get_user_info")
    def test_user_info_command_success(self, mock_get_user) -> None:
        """Test user-info command success."""
        mock_user = {"uid": "john", "cn": "John Doe", "dn": "cn=john,dc=example,dc=com"}
        mock_get_user.return_value = FlextResult.ok(mock_user)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["user-info", "john", "--server", "ldap.example.com"]
        )

        assert result.exit_code == 0
        assert "✅" in result.output

    @patch.object(LDAPUserHandler, "get_user_info")
    def test_user_info_command_failure(self, mock_get_user) -> None:
        """Test user-info command failure."""
        mock_get_user.return_value = FlextResult.fail("User not found")

        runner = CliRunner()
        result = runner.invoke(cli, ["user-info", "nonexistent"])

        assert result.exit_code == 0
        assert "❌" in result.output

    @patch.object(LDAPUserHandler, "create_user")
    def test_create_user_command_success(self, mock_create) -> None:
        """Test create-user command success."""
        mock_user = {
            "uid": "john",
            "cn": "John Doe",
            "dn": "cn=john,ou=users,dc=example,dc=com",
            "mail": "john@example.com",
        }
        mock_create.return_value = FlextResult.ok(mock_user)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "create-user",
                "john",
                "John Doe",
                "Doe",
                "--mail",
                "john@example.com",
                "--base-dn",
                "ou=users,dc=example,dc=com",
                "--server",
                "ldap.example.com",
            ],
        )

        assert result.exit_code == 0
        assert "✅" in result.output

    @patch.object(LDAPUserHandler, "create_user")
    def test_create_user_command_failure(self, mock_create) -> None:
        """Test create-user command failure."""
        mock_create.return_value = FlextResult.fail("User creation failed")

        runner = CliRunner()
        result = runner.invoke(cli, ["create-user", "john", "John Doe", "Doe"])

        assert result.exit_code == 0
        assert "❌" in result.output

    @patch.object(LDAPUserHandler, "list_users")
    def test_list_users_command_success(self, mock_list_users) -> None:
        """Test list-users command success."""
        mock_users = [
            {"uid": "john", "cn": "John Doe", "mail": "john@example.com"},
            {"uid": "jane", "cn": "Jane Smith", "mail": "jane@example.com"},
        ]
        mock_list_users.return_value = FlextResult.ok(mock_users)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["list-users", "--limit", "50", "--server", "ldap.example.com"]
        )

        assert result.exit_code == 0
        assert "📋" in result.output

    @patch.object(LDAPUserHandler, "list_users")
    def test_list_users_command_empty(self, mock_list_users) -> None:
        """Test list-users command with empty results."""
        mock_list_users.return_value = FlextResult.ok([])

        runner = CliRunner()
        result = runner.invoke(cli, ["list-users"])

        assert result.exit_code == 0
        assert "No users found" in result.output

    @patch.object(LDAPUserHandler, "list_users")
    def test_list_users_command_failure(self, mock_list_users) -> None:
        """Test list-users command failure."""
        mock_list_users.return_value = FlextResult.fail("Connection failed")

        runner = CliRunner()
        result = runner.invoke(cli, ["list-users"])

        assert result.exit_code == 0
        assert "❌" in result.output


class TestCLIMainFunctionErrorHandling:
    """Test main function error handling scenarios."""

    @patch("flext_ldap.cli.cli")
    def test_main_keyboard_interrupt(self, mock_cli) -> None:
        """Test main function keyboard interrupt handling."""
        mock_cli.side_effect = KeyboardInterrupt()

        import pytest

        from flext_ldap.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    @patch("flext_ldap.cli.cli")
    def test_main_unexpected_error(self, mock_cli) -> None:
        """Test main function unexpected error handling."""
        mock_cli.side_effect = RuntimeError("Unexpected error")

        import pytest

        from flext_ldap.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1


class TestCLIDisplayFunctions:
    """Test CLI display and formatting functions."""

    def test_display_connection_success(self, capsys) -> None:
        """Test display_connection_success function."""
        from flext_ldap.cli import display_connection_success

        display_connection_success("Connection established")
        captured = capsys.readouterr()

        assert "✅" in captured.out
        assert "Connection established" in captured.out

    def test_display_search_results(self, capsys) -> None:
        """Test display_search_results function."""
        from flext_ldap.cli import display_search_results
        from flext_ldap.values import ExtendedLDAPEntry

        entries = [
            ExtendedLDAPEntry(
                dn="cn=test,dc=example,dc=com",
                attributes={
                    "cn": ["Test User"],
                    "mail": ["test@example.com"],
                    "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                },
            )
        ]

        display_search_results(entries)
        captured = capsys.readouterr()

        assert "📊 Found 1 entries" in captured.out
        assert "cn=test,dc=example,dc=com" in captured.out
        assert "Test User" in captured.out

    def test_display_search_results_many_values(self, capsys) -> None:
        """Test display_search_results with many attribute values."""
        from flext_ldap.cli import display_search_results
        from flext_ldap.values import ExtendedLDAPEntry

        entries = [
            ExtendedLDAPEntry(
                dn="cn=test,dc=example,dc=com",
                attributes={
                    "cn": ["Test User"],
                    "objectClass": [
                        "person",
                        "org",
                        "inet",
                        "extra1",
                        "extra2",
                    ],  # More than MAX_DISPLAY_VALUES
                },
            )
        ]

        display_search_results(entries)
        captured = capsys.readouterr()

        assert "and 2 more" in captured.out

    def test_display_user_info(self, capsys) -> None:
        """Test display_user_info function."""
        from uuid import uuid4

        from flext_ldap.cli import display_user_info
        from flext_ldap.entities import FlextLdapUser

        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.com",
        )

        display_user_info(user)
        captured = capsys.readouterr()

        assert "✅ Found user: Test User" in captured.out
        assert "test@example.com" in captured.out

    def test_display_users_list_with_dicts(self, capsys) -> None:
        """Test display_users_list with dict users."""
        from flext_ldap.cli import display_users_list

        users = [
            {"uid": "john", "cn": "John Doe", "mail": "john@example.com"},
            {"uid": "jane", "cn": "Jane Smith", "mail": "jane@example.com"},
        ]

        display_users_list(users)
        captured = capsys.readouterr()

        assert "📋 Total users: 2" in captured.out
        assert "john" in captured.out
        assert "John Doe" in captured.out

    def test_display_users_list_with_objects(self, capsys) -> None:
        """Test display_users_list with object users."""
        from flext_ldap.cli import display_users_list

        class MockUser:
            def __init__(self, uid, cn, mail):
                self.uid = uid
                self.cn = cn
                self.mail = mail

        users = [
            MockUser("john", "John Doe", "john@example.com"),
            MockUser("jane", "Jane Smith", "jane@example.com"),
        ]

        display_users_list(users)
        captured = capsys.readouterr()

        assert "📋 Total users: 2" in captured.out
        assert "john" in captured.out

    def test_display_users_list_empty(self, capsys) -> None:
        """Test display_users_list with empty list."""
        from flext_ldap.cli import display_users_list

        display_users_list([])
        captured = capsys.readouterr()

        assert "📋 Total users: 0" in captured.out
        assert "No users found" in captured.out


class TestCLIParameterObjects:
    """Test CLI parameter object classes and their methods."""

    def test_ldap_connection_test_params_from_args(self) -> None:
        """Test LDAPConnectionTestParams.from_args method."""
        from flext_ldap.cli import LDAPConnectionTestParams

        params = LDAPConnectionTestParams.from_args(
            "ldap.example.com",
            636,
            use_ssl=True,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
        )

        assert params.server == "ldap.example.com"
        assert params.port == 636
        assert params.use_ssl is True
        assert params.bind_dn == "cn=admin,dc=example,dc=com"
        assert params.bind_password == "secret"

    def test_ldap_search_params_from_click_args(self) -> None:
        """Test LDAPSearchParams.from_click_args method."""
        from flext_ldap.cli import LDAPSearchParams

        params = LDAPSearchParams.from_click_args(
            "ldap.example.com",
            "dc=example,dc=com",
            "(objectClass=person)",
            port="636",
            ssl=True,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            limit="25",
        )

        assert params.server == "ldap.example.com"
        assert params.base_dn == "dc=example,dc=com"
        assert params.filter_str == "(objectClass=person)"
        assert params.port == 636
        assert params.use_ssl is True
        assert params.bind_dn == "cn=admin,dc=example,dc=com"
        assert params.bind_password == "secret"
        assert params.limit == 25

    def test_ldap_search_params_safe_int_conversion(self) -> None:
        """Test LDAPSearchParams._safe_int_conversion method."""
        from flext_ldap.cli import LDAPSearchParams

        # Test integer input
        assert LDAPSearchParams._safe_int_conversion(389, 636) == 389

        # Test string integer input
        assert LDAPSearchParams._safe_int_conversion("389", 636) == 389

        # Test invalid string input
        assert LDAPSearchParams._safe_int_conversion("invalid", 636) == 636

        # Test None input
        assert LDAPSearchParams._safe_int_conversion(None, 636) == 636

    def test_ldap_user_params_from_click_args(self) -> None:
        """Test LDAPUserParams.from_click_args method."""
        from flext_ldap.cli import LDAPUserParams

        params = LDAPUserParams.from_click_args(
            "john",
            "John Doe",
            "Doe",
            mail="john@example.com",
            base_dn="ou=users,dc=example,dc=com",
            server="ldap.example.com",
        )

        assert params.uid == "john"
        assert params.cn == "John Doe"
        assert params.sn == "Doe"
        assert params.mail == "john@example.com"
        assert params.base_dn == "ou=users,dc=example,dc=com"
        assert params.server == "ldap.example.com"


class TestCLIConstants:
    """Test CLI constants and configuration classes."""

    def test_ssl_mode_constants(self) -> None:
        """Test SSLMode constants."""
        from flext_ldap.cli import SSLMode

        assert SSLMode.ENABLED is True
        assert SSLMode.DISABLED is False

    def test_connection_result_constants(self) -> None:
        """Test ConnectionResult constants."""
        from flext_ldap.cli import ConnectionResult

        assert ConnectionResult.SUCCESS is True
        assert ConnectionResult.FAILURE is False

    def test_authentication_required_constants(self) -> None:
        """Test AuthenticationRequired constants."""
        from flext_ldap.cli import AuthenticationRequired

        assert AuthenticationRequired.REQUIRED is True
        assert AuthenticationRequired.NOT_REQUIRED is False

    def test_password_special_chars_constants(self) -> None:
        """Test PasswordSpecialChars constants."""
        from flext_ldap.cli import PasswordSpecialChars

        assert PasswordSpecialChars.REQUIRED is True
        assert PasswordSpecialChars.NOT_REQUIRED is False

    def test_ldap_operation_outcome_constants(self) -> None:
        """Test LDAPOperationOutcome constants."""
        from flext_ldap.cli import LDAPOperationOutcome

        assert LDAPOperationOutcome.SUCCESS is True
        assert LDAPOperationOutcome.FAILURE is False

    def test_max_display_values_constant(self) -> None:
        """Test MAX_DISPLAY_VALUES constant."""
        from flext_ldap.cli import MAX_DISPLAY_VALUES

        assert MAX_DISPLAY_VALUES == 3


class TestBaseLDAPHandler:
    """Test BaseLDAPHandler utility methods."""

    def test_create_connection_config(self) -> None:
        """Test _create_connection_config method."""
        from flext_ldap.cli import BaseLDAPHandler

        config = BaseLDAPHandler._create_connection_config(
            "ldap.example.com", 636, use_ssl=True
        )

        assert config.server == "ldap.example.com"
        assert config.port == 636
        assert config.use_ssl is True

    def test_create_auth_config_with_credentials(self) -> None:
        """Test _create_auth_config with credentials."""
        from flext_ldap.cli import BaseLDAPHandler

        auth_config = BaseLDAPHandler._create_auth_config(
            "cn=admin,dc=example,dc=com", "secret"
        )

        assert auth_config is not None
        assert auth_config.bind_dn == "cn=admin,dc=example,dc=com"
        assert auth_config.bind_password.get_secret_value() == "secret"

    def test_create_auth_config_without_credentials(self) -> None:
        """Test _create_auth_config without credentials."""
        from flext_ldap.cli import BaseLDAPHandler

        auth_config = BaseLDAPHandler._create_auth_config(None, None)

        assert auth_config is None
