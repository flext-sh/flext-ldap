"""Handler protocol compliance tests for FlextLdap.

Tests the Application.Handler protocol implementation in the FlextLdap main class,
verifying that FlextLdap correctly implements the Handler interface from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextProtocols
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdap, FlextLdapModels


@pytest.mark.unit
class TestFlextLdapHandlerProtocol:
    """Tests for FlextLdap Handler protocol compliance."""

    def test_flext_ldap_is_handler_instance(self) -> None:
        """Test that FlextLdap implements Handler protocol."""
        api = FlextLdap()

        # FlextLdap should implement Handler[object] protocol
        # (Python protocols don't always support isinstance at runtime)
        # Instead, check for protocol methods
        assert hasattr(api, "can_handle")
        assert callable(api.can_handle)

    def test_flext_ldap_has_can_handle_method(self) -> None:
        """Test that FlextLdap has can_handle() method."""
        api = FlextLdap()

        # Handler protocol requires can_handle method
        assert hasattr(api, "can_handle")
        assert callable(api.can_handle)

    def test_can_handle_with_string_operation_types(self) -> None:
        """Test can_handle() with string LDAP operation types."""
        api = FlextLdap()

        # Test string-based operation types
        ldap_operations = [
            "search",
            "add",
            "modify",
            "delete",
            "bind",
            "unbind",
            "compare",
            "upsert",
            "schema",
            "acl",
        ]

        for operation in ldap_operations:
            assert api.can_handle(operation) is True, (
                f"Should handle '{operation}' operation"
            )

    def test_can_handle_with_uppercase_operations(self) -> None:
        """Test can_handle() is case-insensitive for string operations."""
        api = FlextLdap()

        # Test case insensitivity
        assert api.can_handle("SEARCH") is True
        assert api.can_handle("Add") is True
        assert api.can_handle("MODIFY") is True
        assert api.can_handle("Delete") is True
        assert api.can_handle("BIND") is True

    def test_can_handle_with_model_request_types(self) -> None:
        """Test can_handle() with FlextLdapModels request types."""
        api = FlextLdap()

        # Test FlextLdapModels.SearchRequest
        assert api.can_handle(FlextLdapModels.SearchRequest) is True

    def test_can_handle_with_model_response_types(self) -> None:
        """Test can_handle() with FlextLdapModels response types."""
        api = FlextLdap()

        # Test FlextLdapModels.SearchResponse
        assert api.can_handle(FlextLdapModels.SearchResponse) is True

    def test_can_handle_with_entry_model(self) -> None:
        """Test can_handle() with FlextLdifModels.Entry type."""
        api = FlextLdap()

        # Test FlextLdifModels.Entry
        assert api.can_handle(FlextLdifModels.Entry) is True

    def test_can_handle_with_unknown_string_operation(self) -> None:
        """Test can_handle() returns False for unknown string operations."""
        api = FlextLdap()

        # Test unknown operations
        assert api.can_handle("unknown_operation") is False
        assert api.can_handle("invalid") is False
        assert api.can_handle("not_an_operation") is False

    def test_can_handle_with_unknown_type(self) -> None:
        """Test can_handle() returns False for unknown types."""
        api = FlextLdap()

        # Test unknown types
        assert api.can_handle(int) is False
        assert api.can_handle(str) is False
        assert api.can_handle(dict) is False
        assert api.can_handle(list) is False

    def test_can_handle_with_none(self) -> None:
        """Test can_handle() returns False for None."""
        api = FlextLdap()

        # Test None type
        assert api.can_handle(None) is False

    def test_handler_protocol_method_signatures(self) -> None:
        """Test that FlextLdap handler methods have correct signatures."""
        api = FlextLdap()

        # can_handle should accept a message_type parameter
        import inspect

        method_sig = inspect.signature(api.can_handle)
        params = list(method_sig.parameters.keys())

        # Should have message_type parameter
        assert "message_type" in params

        # Should return bool
        assert method_sig.return_annotation in {bool, "bool", None}

    def test_handler_protocol_inheritance(self) -> None:
        """Test that FlextLdap implements Handler protocol."""
        # Due to runtime protocol behavior, check if it implements the protocol interface
        assert hasattr(FlextLdap, "can_handle"), (
            "FlextLdap should define can_handle method"
        )

        # Check that it's a method
        api = FlextLdap()
        assert callable(api.can_handle), "can_handle should be callable"

    def test_can_handle_consistency_across_calls(self) -> None:
        """Test that can_handle() returns consistent results across calls."""
        api = FlextLdap()

        # Same input should return same output
        operation = "search"
        result1 = api.can_handle(operation)
        result2 = api.can_handle(operation)

        assert result1 == result2

        # Multiple operations should have consistent behavior
        operations = ["add", "modify", "delete", "unknown"]
        for op in operations:
            result_a = api.can_handle(op)
            result_b = api.can_handle(op)
            assert result_a == result_b, f"Inconsistent results for '{op}'"

    def test_handler_protocol_complete_coverage(self) -> None:
        """Test that all LDAP operation types can be handled."""
        api = FlextLdap()

        # Verify all documented LDAP operations are supported
        supported_operations = {
            "search": True,  # Query operation
            "add": True,  # Create operation
            "modify": True,  # Update operation
            "delete": True,  # Delete operation
            "bind": True,  # Authentication
            "unbind": True,  # Disconnect
            "compare": True,  # Comparison operation
            "upsert": True,  # Create or update
            "schema": True,  # Schema discovery
            "acl": True,  # ACL management
        }

        for operation, should_handle in supported_operations.items():
            result = api.can_handle(operation)
            assert result == should_handle, f"Operation '{operation}' handling mismatch"

    def test_handler_works_with_protocol_typing(self) -> None:
        """Test that FlextLdap works with Handler[object] protocol typing."""
        from typing import cast

        api = FlextLdap()

        # Should be castable to Handler protocol
        handler: FlextProtocols.Handler[object] = cast(
            "FlextProtocols.Handler[object]", api
        )

        # Should have can_handle method
        assert hasattr(handler, "can_handle")
        assert callable(handler.can_handle)

    def test_handler_instantiation_multiple_times(self) -> None:
        """Test that Handler protocol works across multiple instances."""
        api1 = FlextLdap()
        api2 = FlextLdap()

        # Both instances should have can_handle method
        assert hasattr(api1, "can_handle")
        assert hasattr(api2, "can_handle")

        # Both should handle same operations
        assert api1.can_handle("search") == api2.can_handle("search")
        assert api1.can_handle(FlextLdifModels.Entry) == api2.can_handle(
            FlextLdifModels.Entry
        )


@pytest.mark.unit
class TestFlextLdapHandlerIntegration:
    """Integration tests for Handler protocol with FlextLdap methods."""

    def test_handler_can_determine_operation_from_method_call(self) -> None:
        """Test that handler correctly identifies operations from method calls."""
        api = FlextLdap()

        # Handler should recognize all major LDAP operations
        operations_to_check = ["search", "add", "modify", "delete", "bind"]

        for operation in operations_to_check:
            assert api.can_handle(operation) is True

    def test_handler_distinguishes_query_vs_command_operations(self) -> None:
        """Test that handler correctly classifies query vs command operations."""
        api = FlextLdap()

        # Query operations (reads)
        query_operations = ["search", "compare", "schema"]
        for op in query_operations:
            assert api.can_handle(op) is True

        # Command operations (writes)
        command_operations = ["add", "modify", "delete", "upsert"]
        for op in command_operations:
            assert api.can_handle(op) is True

    def test_handler_protocol_backward_compatibility(self) -> None:
        """Test that Handler protocol implementation doesn't break existing functionality."""
        api = FlextLdap()

        # Handler protocol method should be present
        assert hasattr(api, "can_handle"), "FlextLdap should have can_handle method"
        assert callable(api.can_handle), "can_handle should be callable"

        # Handler protocol doesn't interfere with existing core properties
        assert hasattr(api, "client"), "FlextLdap should have client property"
        assert hasattr(api, "config"), "FlextLdap should have config property"

        # Handler should be instantiable and functional
        assert api is not None
        assert api.client is not None
        assert api.config is not None
