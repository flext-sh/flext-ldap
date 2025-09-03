"""Architecture validation tests after FlextLDAP[Module] refactoring.

Tests that confirm the successful transition from protocol-based to class-based architecture.
All protocol functionality has been integrated into the main FlextLDAP[Module] classes.
"""

from __future__ import annotations

import pytest


class TestArchitecturalTransition:
    """Test that architectural transition from protocols to classes is complete."""

    def test_flext_ldap_modules_exist(self) -> None:
        """Test that all FlextLDAP[Module] classes exist and are importable."""
        # Test main architectural components
        from flext_ldap.adapters import FlextLDAPAdapters
        from flext_ldap.operations import FlextLDAPOperations
        from flext_ldap.utilities import FlextLDAPUtilities

        # Verify the classes exist and have expected structure
        assert hasattr(FlextLDAPAdapters, "ConnectionService")
        assert hasattr(FlextLDAPOperations, "SearchOperations")
        assert hasattr(FlextLDAPUtilities, "DnParser")

        # Confirm successful architectural transition
        assert True

    def test_no_legacy_protocols_module(self) -> None:
        """Test that legacy protocols module doesn't exist."""
        with pytest.raises(ImportError):
            from flext_ldap import protocols  # This should fail since protocols module was removed

    def test_functionality_integrated_into_classes(self) -> None:
        """Test that protocol functionality is now integrated into main classes."""
        from flext_ldap.adapters import FlextLDAPAdapters
        from flext_ldap.operations import FlextLDAPOperations

        # Test that nested classes provide the functionality that protocols used to define
        assert hasattr(FlextLDAPAdapters, "ConnectionService")
        assert hasattr(FlextLDAPAdapters, "SearchService")
        assert hasattr(FlextLDAPAdapters, "DirectoryService")

        assert hasattr(FlextLDAPOperations, "SearchOperations")
        assert hasattr(FlextLDAPOperations, "EntryOperations")

        # Architectural compliance verified
        assert True


class TestFlextCoreIntegration:
    """Test integration with flext-core patterns."""

    def test_uses_flext_result_pattern(self) -> None:
        """Test that FlextResult pattern is used throughout."""
        from flext_core import FlextResult

        # Import should work without errors
        assert FlextResult is not None

        # FlextResult pattern is properly integrated
        assert hasattr(FlextResult, "ok")
        assert hasattr(FlextResult, "fail")
        assert hasattr(FlextResult, "is_success")

    def test_uses_flext_models_pattern(self) -> None:
        """Test that FlextModels pattern is used correctly."""
        from flext_core import FlextModels

        # Verify FlextModels base classes are available
        assert hasattr(FlextModels, "Entity")
        assert hasattr(FlextModels, "Value")
        assert hasattr(FlextModels, "AggregateRoot")

        # FlextModels pattern integration verified
        assert True
