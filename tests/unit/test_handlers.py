"""Comprehensive unit tests for FlextLdapHandlers module.

Tests CQRS command and query handlers with real functionality and Clean Architecture patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.handlers import FlextLdapHandlers


class TestFlextLdapHandlers:
    """Comprehensive test cases for FlextLdapHandlers."""

    def test_handlers_initialization(self) -> None:
        """Test handlers module initialization."""
        handlers = FlextLdapHandlers()
        assert handlers is not None
        assert hasattr(FlextLdapHandlers, "FlextLdapCreateUserCommandHandler")
        assert hasattr(FlextLdapHandlers, "FlextLdapUpdateUserCommandHandler")
        assert hasattr(FlextLdapHandlers, "FlextLdapGetUserQueryHandler")
        assert hasattr(FlextLdapHandlers, "FlextLdapListUsersQueryHandler")

    def test_handlers_basic_functionality(self) -> None:
        """Test basic handlers functionality."""
        handlers = FlextLdapHandlers()
        assert hasattr(handlers, "__class__")

    # =========================================================================
    # COMMAND HANDLER TESTS
    # =========================================================================

    def test_create_user_command_handler_initialization(self) -> None:
        """Test create user command handler initialization."""
        handler = FlextLdapHandlers.FlextLdapCreateUserCommandHandler()
        assert handler is not None
        assert hasattr(handler, "handle")
        assert hasattr(handler, "can_handle")

    def test_create_user_command_handler_can_handle_invalid(self) -> None:
        """Test create user command handler can_handle with invalid input."""
        handler = FlextLdapHandlers.FlextLdapCreateUserCommandHandler()

        # Test with invalid object (not a command)
        invalid_input = "not a command"

        # Handler should return False
        result = handler.can_handle(invalid_input)
        assert result is False

    def test_update_user_command_handler_initialization(self) -> None:
        """Test update user command handler initialization."""
        handler = FlextLdapHandlers.FlextLdapUpdateUserCommandHandler()
        assert handler is not None
        assert hasattr(handler, "handle")
        assert hasattr(handler, "can_handle")

    def test_update_user_command_handler_can_handle_invalid(self) -> None:
        """Test update user command handler can_handle with invalid input."""
        handler = FlextLdapHandlers.FlextLdapUpdateUserCommandHandler()

        # Test with invalid object (not a command)
        invalid_input = 123

        # Handler should return False
        result = handler.can_handle(invalid_input)
        assert result is False

    # =========================================================================
    # QUERY HANDLER TESTS
    # =========================================================================

    def test_get_user_query_handler_initialization(self) -> None:
        """Test get user query handler initialization."""
        handler = FlextLdapHandlers.FlextLdapGetUserQueryHandler()
        assert handler is not None
        assert hasattr(handler, "handle")
        assert hasattr(handler, "can_handle")

    def test_get_user_query_handler_can_handle_invalid(self) -> None:
        """Test get user query handler can_handle with invalid input."""
        handler = FlextLdapHandlers.FlextLdapGetUserQueryHandler()

        # Test with invalid object (not a query)
        invalid_input = {"not": "a query"}

        # Handler should return False
        result = handler.can_handle(invalid_input)
        assert result is False

    def test_list_users_query_handler_initialization(self) -> None:
        """Test list users query handler initialization."""
        handler = FlextLdapHandlers.FlextLdapListUsersQueryHandler()
        assert handler is not None
        assert hasattr(handler, "handle")
        assert hasattr(handler, "can_handle")

    def test_list_users_query_handler_can_handle_invalid(self) -> None:
        """Test list users query handler can_handle with invalid input."""
        handler = FlextLdapHandlers.FlextLdapListUsersQueryHandler()

        # Test with invalid object (not a query)
        invalid_input = ["not", "a", "query"]

        # Handler should return False
        result = handler.can_handle(invalid_input)
        assert result is False

    # =========================================================================
    # HANDLER REGISTRY TESTS
    # =========================================================================

    def test_handler_registry_has_static_methods(self) -> None:
        """Test handler registry has static factory methods."""
        # Registry has static methods, doesn't need instantiation
        assert hasattr(
            FlextLdapHandlers.FlextLdapLdapHandlerRegistry, "get_command_handlers"
        )
        assert hasattr(
            FlextLdapHandlers.FlextLdapLdapHandlerRegistry, "get_query_handlers"
        )
        assert hasattr(
            FlextLdapHandlers.FlextLdapLdapHandlerRegistry, "get_all_handlers"
        )

    def test_handler_registry_get_command_handlers(self) -> None:
        """Test handler registry get_command_handlers method."""
        command_handlers = (
            FlextLdapHandlers.FlextLdapLdapHandlerRegistry.get_command_handlers()
        )

        # Should return a list of command handlers
        assert isinstance(command_handlers, list)
        assert len(command_handlers) > 0
        # All should be command handler instances
        for handler in command_handlers:
            assert hasattr(handler, "handle")
            assert hasattr(handler, "can_handle")

    def test_handler_registry_get_query_handlers(self) -> None:
        """Test handler registry get_query_handlers method."""
        query_handlers = (
            FlextLdapHandlers.FlextLdapLdapHandlerRegistry.get_query_handlers()
        )

        # Should return a list of query handlers
        assert isinstance(query_handlers, list)
        assert len(query_handlers) > 0
        # All should be query handler instances
        for handler in query_handlers:
            assert hasattr(handler, "handle")
            assert hasattr(handler, "can_handle")

    def test_handler_registry_get_all_handlers(self) -> None:
        """Test handler registry get_all_handlers method."""
        all_handlers = FlextLdapHandlers.FlextLdapLdapHandlerRegistry.get_all_handlers()

        # Should return combined list of command and query handlers
        assert isinstance(all_handlers, list)
        assert len(all_handlers) > 0

        # Should include both command and query handlers
        command_count = len(
            FlextLdapHandlers.FlextLdapLdapHandlerRegistry.get_command_handlers()
        )
        query_count = len(
            FlextLdapHandlers.FlextLdapLdapHandlerRegistry.get_query_handlers()
        )
        assert len(all_handlers) == command_count + query_count

    # =========================================================================
    # PROTOCOL COMPLIANCE TESTS
    # =========================================================================

    def test_command_handler_implements_handler_protocol(self) -> None:
        """Test command handlers implement Application.Handler protocol."""
        handler = FlextLdapHandlers.FlextLdapCreateUserCommandHandler()

        # Should have protocol methods
        assert callable(getattr(handler, "handle", None))
        assert callable(getattr(handler, "can_handle", None))

    def test_query_handler_implements_handler_protocol(self) -> None:
        """Test query handlers implement Application.Handler protocol."""
        handler = FlextLdapHandlers.FlextLdapGetUserQueryHandler()

        # Should have protocol methods
        assert callable(getattr(handler, "handle", None))
        assert callable(getattr(handler, "can_handle", None))

    # =========================================================================
    # ERROR HANDLING TESTS
    # =========================================================================

    def test_command_handler_invalid_command(self) -> None:
        """Test command handler with invalid command type."""
        handler = FlextLdapHandlers.FlextLdapCreateUserCommandHandler()

        # Try with non-command object
        invalid_command = "not a command"

        # can_handle should return False
        result = handler.can_handle(invalid_command)
        assert result is False

    def test_query_handler_invalid_query(self) -> None:
        """Test query handler with invalid query type."""
        handler = FlextLdapHandlers.FlextLdapGetUserQueryHandler()

        # Try with non-query object
        invalid_query = "not a query"

        # can_handle should return False
        result = handler.can_handle(invalid_query)
        assert result is False
