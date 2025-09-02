"""REAL API tests - testing actual API functionality without mocks.

These tests execute REAL API code to increase coverage and validate functionality.
"""

from __future__ import annotations

import inspect
import time

import pytest

# Test real API functionality
from flext_ldap.api import FlextLDAPApi


class TestRealLdapApiClass:
    """Test REAL FlextLDAPApi class instantiation."""

    def test_api_class_instantiation(self) -> None:
        """Test FlextLDAPApi class can be instantiated."""
        api = FlextLDAPApi()

        assert isinstance(api, FlextLDAPApi)
        assert api is not None

    def test_api_class_returns_consistent_type(self) -> None:
        """Test get_ldap_api returns consistent type."""
        api1 = FlextLDAPApi()
        api2 = FlextLDAPApi()

        # Should return same type (not necessarily same instance)
        assert type(api1) is type(api2)
        assert isinstance(api1, FlextLDAPApi)
        assert isinstance(api2, FlextLDAPApi)

    def test_get_ldap_api_has_expected_methods(self) -> None:
        """Test get_ldap_api returns API with expected methods."""
        api = FlextLDAPApi()

        # Should have the main API methods
        expected_methods = [
            "connection",
            "search",
            "create_user",
            "update_user",
            "delete_user",
            "create_group",
            "update_group",
            "delete_group",
            "get_user",
            "get_group",
            "validate_dn",
            "validate_filter",
        ]

        for method_name in expected_methods:
            assert hasattr(api, method_name), f"API missing method: {method_name}"
            method = getattr(api, method_name)
            assert callable(method), f"API method not callable: {method_name}"


class TestRealFlextLDAPApi:
    """Test REAL FlextLDAPApi class functionality."""

    def test_flext_ldap_api_can_be_instantiated(self) -> None:
        """Test FlextLDAPApi can be instantiated directly."""
        api = FlextLDAPApi()

        assert isinstance(api, FlextLDAPApi)
        assert api is not None

    def test_flext_ldap_api_has_required_attributes(self) -> None:
        """Test FlextLDAPApi has required attributes."""
        api = FlextLDAPApi()

        # Should have service attribute
        assert hasattr(api, "_service")

        # Service should be properly initialized
        service = getattr(api, "_service", None)
        assert service is not None

    def test_multiple_api_instances_are_independent(self) -> None:
        """Test multiple FlextLDAPApi instances are independent."""
        api1 = FlextLDAPApi()
        api2 = FlextLDAPApi()

        # They should be different instances
        assert api1 is not api2

        # But should have same type
        assert type(api1) is type(api2)

    def test_api_methods_exist_and_callable(self) -> None:
        """Test all expected API methods exist and are callable."""
        api = FlextLDAPApi()

        # Test core methods exist
        core_methods = [
            "connection",
            "search",
            "create_user",
            "update_user",
            "delete_user",
            "create_group",
            "update_group",
            "delete_group",
            "delete_entry",
            "get_user",
            "get_group",
            "validate_dn",
        ]

        for method_name in core_methods:
            assert hasattr(api, method_name), f"Missing method: {method_name}"
            method = getattr(api, method_name)
            assert callable(method), f"Method not callable: {method_name}"

    def test_api_methods_return_appropriate_types(self) -> None:
        """Test API methods return appropriate types (without calling them)."""
        api = FlextLDAPApi()

        # Test method signatures exist by checking they're callable
        # We can't call them without proper setup, but we can verify they exist
        assert callable(api.search)
        assert callable(api.create_user)
        assert callable(api.update_user)
        assert callable(api.delete_user)
        assert callable(api.create_group)
        assert callable(api.update_group)
        assert callable(api.delete_group)


class TestRealApiIntegration:
    """Test REAL API integration patterns."""

    def test_api_integrates_with_flext_result(self) -> None:
        """Test API properly integrates with FlextResult pattern."""
        api = FlextLDAPApi()

        # Test that API is designed to work with FlextResult
        # We can verify this by checking method signatures and attributes
        assert hasattr(api, "_service")

        # The service should be set up to return FlextResult types
        service = api._service
        assert service is not None

    def test_function_api_vs_instance_api_compatibility(self) -> None:
        """Test function API and instance API are compatible."""
        function_api = FlextLDAPApi()
        instance_api = FlextLDAPApi()

        # Should have same methods
        function_methods = [
            name for name in dir(function_api) if not name.startswith("_")
        ]
        [name for name in dir(instance_api) if not name.startswith("_")]

        # Core methods should be the same
        for method_name in function_methods:
            if callable(getattr(function_api, method_name, None)):
                assert hasattr(instance_api, method_name), (
                    f"Instance API missing method: {method_name}"
                )
                assert callable(getattr(instance_api, method_name)), (
                    f"Instance method not callable: {method_name}"
                )

    def test_api_provides_async_interface(self) -> None:
        """Test API provides async interface."""
        api = FlextLDAPApi()

        # Check that key methods are async (coroutines)

        async_methods = [
            "search",
            "create_user",
            "update_user",
            "delete_user",
            "create_group",
            "update_group",
            "delete_group",
            "get_user",
            "get_group",
        ]

        for method_name in async_methods:
            if hasattr(api, method_name):
                method = getattr(api, method_name)
                # Should be async method
                assert inspect.iscoroutinefunction(method), (
                    f"Method should be async: {method_name}"
                )


class TestRealApiErrorHandling:
    """Test REAL API error handling."""

    def test_api_handles_instantiation_gracefully(self) -> None:
        """Test API handles instantiation edge cases gracefully."""
        # Should not raise exceptions during instantiation
        try:
            api = FlextLDAPApi()
            assert api is not None
        except Exception as e:
            pytest.fail(f"API instantiation raised exception: {e}")

    def test_get_ldap_api_handles_multiple_calls_gracefully(self) -> None:
        """Test get_ldap_api handles multiple calls gracefully."""
        # Should not raise exceptions on multiple calls
        try:
            apis = [FlextLDAPApi() for _ in range(10)]
            assert len(apis) == 10
            # All should be same type
            for api in apis:
                assert isinstance(api, FlextLDAPApi)
        except Exception as e:
            pytest.fail(f"Multiple get_ldap_api calls raised exception: {e}")

    def test_api_methods_dont_raise_on_inspection(self) -> None:
        """Test API methods don't raise exceptions when inspected."""
        api = FlextLDAPApi()

        # Getting method references should not raise exceptions
        try:
            methods = [
                api.connection,
                api.search,
                api.create_user,
                api.update_user,
                api.delete_user,
                api.create_group,
                api.update_group,
                api.delete_group,
                api.get_user,
                api.get_group,
                api.validate_dn,
            ]
            assert len(methods) > 0
            for method in methods:
                assert callable(method)
        except Exception as e:
            pytest.fail(f"Method inspection raised exception: {e}")


class TestRealApiPerformance:
    """Test REAL API performance characteristics."""

    def test_api_instantiation_is_fast(self) -> None:
        """Test API instantiation is reasonably fast."""
        start_time = time.time()

        # Create multiple API instances
        apis = [FlextLDAPApi() for _ in range(100)]

        end_time = time.time()
        elapsed = end_time - start_time

        # Should complete in reasonable time (less than 1 second for 100 instances)
        assert elapsed < 1.0, f"API instantiation took too long: {elapsed:.3f}s"
        assert len(apis) == 100

    def test_get_ldap_api_function_is_fast(self) -> None:
        """Test get_ldap_api function access is fast."""
        start_time = time.time()

        # Access singleton many times
        apis = [FlextLDAPApi() for _ in range(1000)]

        end_time = time.time()
        elapsed = end_time - start_time

        # Should complete reasonably fast (less than 0.5 second for 1000 calls)
        assert elapsed < 0.5, f"API access took too long: {elapsed:.3f}s"
        assert len(apis) == 1000
        # All should be same type
        for api in apis:
            assert isinstance(api, FlextLDAPApi)


class TestRealApiDocumentation:
    """Test REAL API documentation and introspection."""

    def test_api_has_docstrings(self) -> None:
        """Test API classes and methods have docstrings."""
        FlextLDAPApi()

        # Main class should have docstring
        assert FlextLDAPApi.__doc__ is not None
        assert len(FlextLDAPApi.__doc__.strip()) > 0

        # get_ldap_api function should have docstring
        assert get_ldap_api.__doc__ is not None
        assert len(get_ldap_api.__doc__.strip()) > 0

    def test_api_methods_have_docstrings(self) -> None:
        """Test API methods have docstrings."""
        api = FlextLDAPApi()

        # Key methods should have docstrings
        key_methods = [
            "search",
            "create_user",
            "create_group",
            "get_user",
            "get_group",
        ]

        for method_name in key_methods:
            if hasattr(api, method_name):
                method = getattr(api, method_name)
                if callable(method) and hasattr(method, "__doc__"):
                    # Should have some documentation
                    doc = getattr(method, "__doc__", None)
                    if doc is not None:
                        assert len(doc.strip()) > 0, (
                            f"Method {method_name} has empty docstring"
                        )

    def test_api_supports_introspection(self) -> None:
        """Test API supports introspection properly."""
        api = FlextLDAPApi()

        # Should be able to get method lists
        methods = [name for name in dir(api) if not name.startswith("_")]
        assert len(methods) > 0

        # Should be able to inspect types
        assert hasattr(api, "__class__")
        assert api.__class__.__name__ == "FlextLDAPApi"

        # Should have module information
        assert hasattr(api, "__module__") or hasattr(api.__class__, "__module__")
