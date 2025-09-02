"""Valid protocols tests - testing only protocols after FLEXT refactoring.

Tests protocols that remain valid after eliminating local abstract classes
and using flext-core patterns instead.
"""

from __future__ import annotations

from typing import get_type_hints

import flext_ldap.protocols as protocols_module

# Test ONLY valid protocols after FLEXT compliance refactoring
from flext_ldap.protocols import (
    FlextLDAPConnectionProtocol,
    FlextLDAPEntryProtocol,
    FlextLDAPGroupProtocol,
    FlextLDAPSearchProtocol,
    FlextLDAPUserProtocol,
)


class TestValidProtocolDefinitions:
    """Test valid protocol definitions after FLEXT compliance."""

    def test_runtime_checkable_protocols(self) -> None:
        """Test protocols are runtime checkable."""
        valid_protocols = [
            FlextLDAPConnectionProtocol,
            FlextLDAPSearchProtocol,
            FlextLDAPEntryProtocol,
            FlextLDAPUserProtocol,
            FlextLDAPGroupProtocol,
        ]

        for protocol in valid_protocols:
            # Check that protocols are runtime checkable (have _is_protocol = True)
            assert hasattr(protocol, "_is_protocol")
            assert getattr(protocol, "_is_protocol", False) is True

    def test_protocol_method_annotations(self) -> None:
        """Test protocols have proper method annotations."""
        # Test FlextLDAPConnectionProtocol
        hints = get_type_hints(FlextLDAPConnectionProtocol.connect)
        assert "return" in hints

        # Test FlextLDAPSearchProtocol
        hints = get_type_hints(FlextLDAPSearchProtocol.search)
        assert "return" in hints

    def test_protocols_export_correctly(self) -> None:
        """Test valid protocols are exported from protocols module."""
        valid_exports = [
            "FlextLDAPConnectionProtocol",
            "FlextLDAPSearchProtocol",
            "FlextLDAPEntryProtocol",
            "FlextLDAPUserProtocol",
            "FlextLDAPGroupProtocol",
            "FlextLDAPRepositoryProtocol",
            "FlextLDAPValidatorProtocol",
        ]

        for export_name in valid_exports:
            assert hasattr(protocols_module, export_name)


class TestProtocolCompliance:
    """Test protocol compliance with FLEXT standards."""

    def test_protocols_use_flext_result(self) -> None:
        """Test protocols use FlextResult for type safety."""
        # Check that async methods return FlextResult
        connection_hints = get_type_hints(FlextLDAPConnectionProtocol.connect)
        assert "FlextResult" in str(connection_hints.get("return", ""))

        search_hints = get_type_hints(FlextLDAPSearchProtocol.search)
        assert "FlextResult" in str(search_hints.get("return", ""))

    def test_no_local_abstract_classes_imported(self) -> None:
        """Verify no local abstract classes are imported after refactoring."""
        # These should NOT exist after FLEXT refactoring
        forbidden_classes = [
            "FlextLDAPOperationsBase",
            "FlextLDAPServiceBase",
            "FlextLDAPClientBase",
        ]

        for forbidden in forbidden_classes:
            assert not hasattr(protocols_module, forbidden), (
                f"{forbidden} should be removed - use flext-core instead"
            )
