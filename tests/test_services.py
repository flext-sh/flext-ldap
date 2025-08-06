"""FLEXT-LDAP Services Tests - Backward Compatibility and Service Layer Testing.

Comprehensive test suite for FLEXT-LDAP service layer, validating backward
compatibility, deprecation warnings, and proper service imports following
Clean Architecture patterns.

This test module ensures the service layer maintains backward compatibility
while guiding users toward modern patterns and proper deprecation handling.

Test Coverage:
    - Direct service imports from application layer
    - Legacy service name compatibility with deprecation warnings
    - Proper AttributeError handling for invalid service names
    - Warning message content and stacklevel validation
    - Service class identity and functionality validation

Architecture:
    Tests are organized to validate the service layer's role as a compatibility
    bridge between legacy code and modern Clean Architecture patterns,
    ensuring smooth migration path for existing consumers.

Author: FLEXT Development Team

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import warnings

import pytest

# Import the services module and FlextLdapService
import flext_ldap.services as services_module
from flext_ldap.application.ldap_service import FlextLdapService


class TestFlextLdapServicesDirectImports:
    """Test suite for direct service imports and module structure.

    Validates that the services module properly exposes the modern
    FlextLdapService and maintains clean architecture boundaries.
    """

    def test_direct_flext_ldap_service_import(self) -> None:
        """Test that FlextLdapService can be imported directly."""
        # FlextLdapService should be available as direct import
        assert hasattr(services_module, "FlextLdapService")

        # Should be the same class as from application layer
        direct_service = services_module.FlextLdapService
        application_service = FlextLdapService

        assert direct_service is application_service
        assert direct_service.__name__ == "FlextLdapService"

    def test_module_docstring_and_metadata(self) -> None:
        """Test module has proper documentation and metadata."""
        assert services_module.__doc__ is not None
        assert "CLEAN ARCHITECTURE CONSOLIDATION" in services_module.__doc__
        assert "Copyright (c) 2025 FLEXT Team" in services_module.__doc__


class TestLegacyServiceCompatibility:
    """Test suite for legacy service name compatibility.

    Comprehensive testing of backward compatibility features including
    deprecation warnings, proper service mapping, and warning content.
    """

    def test_legacy_user_service_compatibility(self) -> None:
        """Test legacy FlextLdapUserService compatibility with deprecation warning."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access legacy service name
            legacy_service = services_module.FlextLdapUserService

            # Should return the modern FlextLdapService
            assert legacy_service is FlextLdapService

            # Should trigger exactly one deprecation warning
            assert len(warning_list) == 1
            warning_msg = warning_list[0]

            # Validate warning properties
            assert issubclass(warning_msg.category, DeprecationWarning)
            assert "FlextLdapUserService is deprecated" in str(warning_msg.message)
            assert "Use FlextLdapService from application layer" in str(
                warning_msg.message
            )
            assert "from flext_ldap.application import FlextLdapService" in str(
                warning_msg.message
            )
            assert "will be removed in v1.0.0" in str(warning_msg.message)

    def test_legacy_user_application_service_compatibility(self) -> None:
        """Test legacy FlextLdapUserApplicationService compatibility."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access legacy service name
            legacy_service = services_module.FlextLdapUserApplicationService

            # Should return the modern FlextLdapService
            assert legacy_service is FlextLdapService

            # Should trigger deprecation warning
            assert len(warning_list) == 1
            assert "FlextLdapUserApplicationService is deprecated" in str(
                warning_list[0].message
            )

    def test_legacy_group_service_compatibility(self) -> None:
        """Test legacy FlextLdapGroupService compatibility."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access legacy service name
            legacy_service = services_module.FlextLdapGroupService

            # Should return the modern FlextLdapService
            assert legacy_service is FlextLdapService

            # Should trigger deprecation warning
            assert len(warning_list) == 1
            assert "FlextLdapGroupService is deprecated" in str(warning_list[0].message)

    def test_legacy_operation_service_compatibility(self) -> None:
        """Test legacy FlextLdapOperationService compatibility."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access legacy service name
            legacy_service = services_module.FlextLdapOperationService

            # Should return the modern FlextLdapService
            assert legacy_service is FlextLdapService

            # Should trigger deprecation warning
            assert len(warning_list) == 1
            assert "FlextLdapOperationService is deprecated" in str(
                warning_list[0].message
            )

    def test_legacy_connection_service_compatibility(self) -> None:
        """Test legacy FlextLdapConnectionService compatibility."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access legacy service name
            legacy_service = services_module.FlextLdapConnectionService

            # Should return the modern FlextLdapService
            assert legacy_service is FlextLdapService

            # Should trigger deprecation warning
            assert len(warning_list) == 1
            assert "FlextLdapConnectionService is deprecated" in str(
                warning_list[0].message
            )

    def test_legacy_connection_application_service_compatibility(self) -> None:
        """Test legacy FlextLdapConnectionApplicationService compatibility."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access legacy service name
            legacy_service = services_module.FlextLdapConnectionApplicationService

            # Should return the modern FlextLdapService
            assert legacy_service is FlextLdapService

            # Should trigger deprecation warning
            assert len(warning_list) == 1
            assert "FlextLdapConnectionApplicationService is deprecated" in str(
                warning_list[0].message
            )


class TestServiceAttributeErrorHandling:
    """Test suite for proper error handling of invalid service names.

    Validates that requesting non-existent services raises appropriate
    AttributeError with helpful error messages.
    """

    def test_invalid_service_name_raises_attribute_error(self) -> None:
        """Test that invalid service names raise AttributeError."""
        invalid_names = [
            "NonExistentService",
            "FlextLdapInvalidService",
            "SomeRandomServiceName",
            "FlextLdapUnknownService",
        ]

        for invalid_name in invalid_names:
            with pytest.raises(AttributeError) as exc_info:
                getattr(services_module, invalid_name)

            error_message = str(exc_info.value)
            assert (
                f"module 'flext_ldap.services' has no attribute '{invalid_name}'"
                in error_message
            )

    def test_empty_string_service_name(self) -> None:
        """Test that empty string service name raises AttributeError."""
        with pytest.raises(AttributeError) as exc_info:
            getattr(services_module, "")

        error_message = str(exc_info.value)
        assert "module 'flext_ldap.services' has no attribute ''" in error_message

    def test_numeric_service_name(self) -> None:
        """Test that numeric service names raise AttributeError."""
        with pytest.raises(AttributeError) as exc_info:
            getattr(services_module, "123")

        error_message = str(exc_info.value)
        assert "module 'flext_ldap.services' has no attribute '123'" in error_message


class TestDeprecationWarningDetails:
    """Test suite for detailed deprecation warning validation.

    Validates the content, formatting, and stacklevel of deprecation
    warnings to ensure proper user guidance toward modern patterns.
    """

    def test_deprecation_warning_stacklevel(self) -> None:
        """Test that deprecation warnings use correct stacklevel."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access legacy service to trigger warning
            _ = services_module.FlextLdapUserService

            # Validate stacklevel is set (should be 2 based on __getattr__ call)
            warning_msg = warning_list[0]
            # The warning should originate from this test function, not from __getattr__
            assert warning_msg.filename.endswith("test_services.py")

    def test_deprecation_warning_content_structure(self) -> None:
        """Test deprecation warning message structure and content."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access legacy service to trigger warning
            _ = services_module.FlextLdapUserService

            warning_message = str(warning_list[0].message)

            # Should contain all required components
            assert "🚨 DEPRECATED SERVICE:" in warning_message
            assert "✅ MODERN SOLUTION:" in warning_message
            assert "💡 Import:" in warning_message
            assert "🏗️ This wrapper layer adds no value" in warning_message

            # Should provide clear migration path
            assert (
                "from flext_ldap.application import FlextLdapService" in warning_message
            )

    def test_multiple_legacy_access_produces_multiple_warnings(self) -> None:
        """Test that multiple legacy service accesses produce multiple warnings."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Access multiple legacy services
            _ = services_module.FlextLdapUserService
            _ = services_module.FlextLdapGroupService
            _ = services_module.FlextLdapOperationService

            # Should produce 3 warnings
            assert len(warning_list) == 3

            # Each warning should be for different service
            service_names = [str(w.message) for w in warning_list]
            assert any("FlextLdapUserService" in msg for msg in service_names)
            assert any("FlextLdapGroupService" in msg for msg in service_names)
            assert any("FlextLdapOperationService" in msg for msg in service_names)


class TestServiceModuleBehavior:
    """Test suite for overall service module behavior and integration.

    Validates the module's behavior as a whole, including proper imports,
    attribute access patterns, and integration with the application layer.
    """

    def test_services_module_has_getattr(self) -> None:
        """Test that services module has __getattr__ function."""
        assert hasattr(services_module, "__getattr__")
        assert callable(services_module.__getattr__)

    def test_direct_import_no_warning(self) -> None:
        """Test that direct FlextLdapService import produces no warnings."""
        with warnings.catch_warnings(record=True) as warning_list:
            warnings.simplefilter("always")

            # Direct access to modern service should not trigger warning
            modern_service = services_module.FlextLdapService

            # Should return the correct service with no warnings
            assert modern_service is FlextLdapService
            assert len(warning_list) == 0

    def test_service_identity_consistency(self) -> None:
        """Test that all legacy services return the same FlextLdapService instance."""
        legacy_services = [
            "FlextLdapUserApplicationService",
            "FlextLdapUserService",
            "FlextLdapGroupService",
            "FlextLdapOperationService",
            "FlextLdapConnectionApplicationService",
            "FlextLdapConnectionService",
        ]

        # Suppress warnings for this test
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)

            # All legacy services should return the same modern service
            for service_name in legacy_services:
                legacy_service = getattr(services_module, service_name)
                assert legacy_service is FlextLdapService
                assert legacy_service.__name__ == "FlextLdapService"

    def test_services_module_minimal_public_interface(self) -> None:
        """Test that services module has minimal public interface."""
        # Should primarily expose FlextLdapService and __getattr__
        # Other attributes should be implementation details

        # FlextLdapService should be available
        assert hasattr(services_module, "FlextLdapService")

        # __getattr__ should handle legacy names
        assert hasattr(services_module, "__getattr__")

        # Module should have docstring
        assert services_module.__doc__ is not None
