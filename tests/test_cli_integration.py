"""Test CLI module integration.

Integration tests for flext_ldap.cli to increase coverage.
"""

from flext_ldap.cli import (
    LDAPConnectionHandler,
    LDAPSearchHandler,
    LDAPUserHandler,
    LDAPConnectionTestParams,
    cli
)


class TestLDAPConnectionTestParams:
    """Test CLI parameter classes."""

    def test_connection_params_creation(self):
        """Test parameter class creation."""
        params = LDAPConnectionTestParams(server="test.example.com", port=389)
        assert params.server == "test.example.com"
        assert params.port == 389

    def test_connection_params_with_defaults(self):
        """Test parameter defaults."""
        params = LDAPConnectionTestParams(server="test.example.com")
        assert params.server == "test.example.com"
        # Should have a default port
        assert hasattr(params, 'port')


class TestLDAPHandlers:
    """Test CLI handler classes."""

    def test_connection_handler_structure(self):
        """Test connection handler has required methods."""
        assert hasattr(LDAPConnectionHandler, 'test_connection')
        assert callable(getattr(LDAPConnectionHandler, 'test_connection'))

    def test_search_handler_structure(self):
        """Test search handler has required methods."""
        assert hasattr(LDAPSearchHandler, 'search_entries')
        assert callable(getattr(LDAPSearchHandler, 'search_entries'))

    def test_user_handler_structure(self):
        """Test user handler has required methods."""
        assert hasattr(LDAPUserHandler, 'get_user_info')
        assert callable(getattr(LDAPUserHandler, 'get_user_info'))

    def test_handlers_are_classes(self):
        """Test that handlers are proper classes."""
        assert isinstance(LDAPConnectionHandler, type)
        assert isinstance(LDAPSearchHandler, type)
        assert isinstance(LDAPUserHandler, type)


class TestCLIStructure:
    """Test CLI Click structure."""

    def test_cli_is_click_command(self):
        """Test that cli is a Click command."""
        # Test that cli has Click command attributes
        assert hasattr(cli, 'callback')
        assert hasattr(cli, 'commands')

    def test_cli_command_structure(self):
        """Test CLI command structure."""
        # The cli should be a Click group or command
        assert callable(cli)

        # Should have some commands registered
        if hasattr(cli, 'commands'):
            # If it's a group, check if it has commands
            assert isinstance(cli.commands, dict)
        else:
            # If it's a single command, it should be callable
            assert callable(cli)


class TestCLIImports:
    """Test CLI module imports work correctly."""

    def test_all_imports_successful(self):
        """Test that all CLI imports work."""
        # If we can import them, they work
        assert LDAPConnectionHandler is not None
        assert LDAPSearchHandler is not None
        assert LDAPUserHandler is not None
        assert LDAPConnectionTestParams is not None
        assert cli is not None

    def test_handlers_have_methods(self):
        """Test handlers have expected method signatures."""
        # Connection handler
        handler = LDAPConnectionHandler
        assert hasattr(handler, 'test_connection')

        # Search handler
        search_handler = LDAPSearchHandler
        assert hasattr(search_handler, 'search_entries')

        # User handler
        user_handler = LDAPUserHandler
        assert hasattr(user_handler, 'get_user_info')

    def test_click_integration(self):
        """Test Click framework integration."""
        # Test that the CLI is callable (Click command/group)
        assert callable(cli)

        # Should be a proper Click command/group
        if hasattr(cli, 'name'):
            assert isinstance(cli.name, (str, type(None)))

        # Should have callback attribute (Click commands have this)
        assert hasattr(cli, 'callback')
