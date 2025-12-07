"""Unit tests for FlextLdapServiceBase - Base service pattern.

Provides comprehensive testing of FlextLdapServiceBase inheritance from FlextService,
type parameters, config access patterns, and logger availability.

Test Coverage:
- FlextLdapServiceBase class existence and inheritance
- Generic type parameter TDomainResult
- Config property access
- Logger availability
- Service instantiation patterns
- Export alias 's'

All tests use real functionality without mocks, following FLEXT patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

import pytest
from flext_core import FlextConfig, FlextService, r
from flext_tests import u

from flext_ldap import base
from flext_ldap.base import FlextLdapServiceBase, s

pytestmark = [pytest.mark.unit]


class TestsFlextLdapBase:
    """Comprehensive tests for FlextLdapServiceBase.

    Architecture: Single class per module following FLEXT patterns.
    Tests base service patterns without requiring actual LDAP connections.

    Uses parametrized tests and factory methods for code reduction (DRY).
    Expected reduction: 360 lines → ~220 lines (39% reduction).
    """

    # =========================================================================
    # FACTORY METHODS FOR PARAMETRIZATION
    # =========================================================================

    @staticmethod
    def _get_model_config_attributes() -> list[tuple[str, object]]:
        """Factory: Return model config attribute tests (attr_name, expected_value)."""
        return [
            ("arbitrary_types_allowed", True),
            ("extra", "forbid"),
            ("use_enum_values", True),
            ("validate_assignment", True),
        ]

    # =========================================================================
    # Class Structure Tests
    # =========================================================================

    def test_class_structure(self) -> None:
        """Test FlextLdapServiceBase class structure, inheritance, and generics."""
        # Class exists
        assert FlextLdapServiceBase is not None

        # Inherits from FlextService
        assert issubclass(FlextLdapServiceBase, FlextService)

        # Is a generic class
        assert hasattr(FlextLdapServiceBase, "__class_getitem__")

    def test_exports_and_aliases(self) -> None:
        """Test module exports and short aliases."""
        # Short alias exists
        assert s is FlextLdapServiceBase

        # Module exports are correct
        assert "FlextLdapServiceBase" in base.__all__
        assert "s" in base.__all__

    # =========================================================================
    # Concrete Service Implementation Tests
    # =========================================================================

    def test_concrete_service_creation(self) -> None:
        """Test creating a concrete service that extends FlextLdapServiceBase."""

        class ConcreteTestService(FlextLdapServiceBase[str]):
            """Concrete service for testing."""

            @override
            def execute(self) -> r[str]:
                """Execute service logic."""
                return r[str].ok("test_result")

        # Create instance
        service = ConcreteTestService()
        assert service is not None
        assert isinstance(service, FlextLdapServiceBase)
        assert isinstance(service, FlextService)

    def test_concrete_service_execute_returns_result(self) -> None:
        """Test concrete service execute method returns FlextResult."""

        class ExecuteTestService(FlextLdapServiceBase[str]):
            """Service that tests execute method."""

            @override
            def execute(self) -> r[str]:
                """Execute and return success."""
                return r[str].ok("success_value")

        service = ExecuteTestService()
        result = service.execute()

        # Use flext_tests automation for result validation
        value = u.Tests.Result.assert_success(result, "Execute should return success")
        assert value == "success_value"

    def test_concrete_service_execute_can_fail(self) -> None:
        """Test concrete service execute method can return failure."""

        class FailingTestService(FlextLdapServiceBase[str]):
            """Service that tests failure handling."""

            @override
            def execute(self) -> r[str]:
                """Execute and return failure."""
                return r[str].fail("operation_failed")

        service = FailingTestService()
        result = service.execute()

        # Use flext_tests automation for failure validation
        error = u.Tests.Result.assert_failure(result, "operation_failed")
        assert error == "operation_failed"

    # =========================================================================
    # Config Access Tests
    # =========================================================================

    def test_service_has_config_property(self) -> None:
        """Test service has config property."""

        class ConfigTestService(FlextLdapServiceBase[bool]):
            """Service that tests config access."""

            @override
            def execute(self) -> r[bool]:
                """Execute with config access."""
                return r[bool].ok(True)

        service = ConfigTestService()
        # config property comes from FlextMixins (x)
        assert hasattr(service, "config")
        config = service.config
        assert config is not None
        assert isinstance(config, FlextConfig)

    def test_service_config_provides_equivalent_values(self) -> None:
        """Test service config provides equivalent values to global instance."""

        class GlobalConfigService(FlextLdapServiceBase[bool]):
            """Service that tests global config access."""

            @override
            def execute(self) -> r[bool]:
                """Execute with config access."""
                return r[bool].ok(True)

        service = GlobalConfigService()
        config = service.config
        global_config = FlextConfig.get_global_instance()

        # Config provides equivalent values (may be cloned instance)
        assert config.app_name == global_config.app_name
        assert config.version == global_config.version
        assert config.debug == global_config.debug

    # =========================================================================
    # Logger Access Tests
    # =========================================================================

    def test_service_has_logger_property(self) -> None:
        """Test service has logger property."""

        class LoggerTestService(FlextLdapServiceBase[bool]):
            """Service that tests logger access."""

            @override
            def execute(self) -> r[bool]:
                """Execute with logger access."""
                return r[bool].ok(True)

        service = LoggerTestService()
        # logger property comes from FlextMixins (x)
        assert hasattr(service, "logger")
        logger = service.logger
        assert logger is not None

    # =========================================================================
    # Type Parameter Tests
    # =========================================================================

    def test_service_with_primitive_type_parameters(self) -> None:
        """Test service with various primitive type parameters."""

        class BoolService(FlextLdapServiceBase[bool]):
            """Service returning bool."""

            @override
            def execute(self) -> r[bool]:
                """Execute and return bool."""
                return r[bool].ok(True)

        class IntService(FlextLdapServiceBase[int]):
            """Service returning int."""

            @override
            def execute(self) -> r[int]:
                """Execute and return int."""
                return r[int].ok(42)

        # Test bool - validate real limits
        bool_result = BoolService().execute()
        bool_value = u.Tests.Result.assert_success(
            bool_result, "Bool service should succeed"
        )
        assert isinstance(bool_value, bool)
        assert bool_value is True
        # Validate that bool service actually returns bool type
        assert type(bool_value).__name__ == "bool"

        # Test int - validate real limits
        int_result = IntService().execute()
        int_value = u.Tests.Result.assert_success(
            int_result, "Int service should succeed"
        )
        assert isinstance(int_value, int)
        assert int_value == 42
        # Validate that int service actually returns int type
        assert type(int_value).__name__ == "int"

    def test_service_with_collection_type_parameters(self) -> None:
        """Test service with collection type parameters (list, dict)."""

        class ListService(FlextLdapServiceBase[list[str]]):
            """Service returning list of strings."""

            @override
            def execute(self) -> r[list[str]]:
                """Execute and return list."""
                return r[list[str]].ok(["a", "b", "c"])

        class DictService(FlextLdapServiceBase[dict[str, int]]):
            """Service returning dict."""

            @override
            def execute(self) -> r[dict[str, int]]:
                """Execute and return dict."""
                return r[dict[str, int]].ok({"count": 10})

        # Test list - validate real limits and structure
        list_result = ListService().execute()
        list_value = u.Tests.Result.assert_success(
            list_result, "List service should succeed"
        )
        assert isinstance(list_value, list)
        assert len(list_value) == 3  # Validate actual length
        assert list_value == ["a", "b", "c"]
        # Validate all elements are strings
        assert all(isinstance(item, str) for item in list_value)

        # Test dict - validate real limits and structure
        dict_result = DictService().execute()
        dict_value = u.Tests.Result.assert_success(
            dict_result, "Dict service should succeed"
        )
        assert isinstance(dict_value, dict)
        assert len(dict_value) == 1  # Validate actual size
        assert dict_value == {"count": 10}
        # Validate dict values are correct types
        assert isinstance(dict_value["count"], int)

    # =========================================================================
    # Model Config Tests
    # =========================================================================

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        _get_model_config_attributes(),
    )
    def test_service_model_config_attributes(
        self,
        attr_name: str,
        expected_value: object,
    ) -> None:
        """Test service inherits correct model config attributes from FlextService."""

        class ConfigTestService(FlextLdapServiceBase[bool]):
            """Service to test model config inheritance."""

            @override
            def execute(self) -> r[bool]:
                """Execute."""
                return r[bool].ok(True)

        model_config = ConfigTestService.model_config
        assert model_config.get(attr_name) == expected_value

    # =========================================================================
    # Service Docstring Tests
    # =========================================================================

    def test_class_has_docstring(self) -> None:
        """Test FlextLdapServiceBase has documentation."""
        assert FlextLdapServiceBase.__doc__ is not None
        assert "Base class" in FlextLdapServiceBase.__doc__

    def test_docstring_mentions_config_access(self) -> None:
        """Test docstring documents config access pattern."""
        assert FlextLdapServiceBase.__doc__ is not None
        assert "config" in FlextLdapServiceBase.__doc__.lower()

    # =========================================================================
    # Multiple Services Tests
    # =========================================================================

    def test_multiple_services_independent(self) -> None:
        """Test multiple service instances are independent."""

        class IndependentServiceA(FlextLdapServiceBase[str]):
            """Service A."""

            @override
            def execute(self) -> r[str]:
                """Execute A."""
                return r[str].ok("A")

        class IndependentServiceB(FlextLdapServiceBase[str]):
            """Service B."""

            @override
            def execute(self) -> r[str]:
                """Execute B."""
                return r[str].ok("B")

        service_a = IndependentServiceA()
        service_b = IndependentServiceB()

        # Validate services are truly independent - test multiple executions
        result_a1 = service_a.execute()
        result_b1 = service_b.execute()
        result_a2 = service_a.execute()
        result_b2 = service_b.execute()

        # Use flext_tests automation
        value_a1 = u.Tests.Result.assert_success(result_a1, "Service A should succeed")
        value_b1 = u.Tests.Result.assert_success(result_b1, "Service B should succeed")
        value_a2 = u.Tests.Result.assert_success(
            result_a2, "Service A should succeed again"
        )
        value_b2 = u.Tests.Result.assert_success(
            result_b2, "Service B should succeed again"
        )

        assert value_a1 == "A"
        assert value_b1 == "B"
        assert value_a2 == "A"  # Validate consistency
        assert value_b2 == "B"  # Validate consistency
        # Validate services don't interfere with each other
        assert value_a1 == value_a2
        assert value_b1 == value_b2

    # =========================================================================
    # Import Pattern Tests
    # =========================================================================

    def test_base_module_has_flext_ldap_service_base(self) -> None:
        """Test base module contains FlextLdapServiceBase class."""
        assert hasattr(base, "FlextLdapServiceBase")
        assert base.FlextLdapServiceBase is FlextLdapServiceBase

    def test_base_module_has_short_alias_s(self) -> None:
        """Test base module contains short alias 's'."""
        assert hasattr(base, "s")
        assert base.s is FlextLdapServiceBase


__all__ = [
    "TestsFlextLdapBase",
]
