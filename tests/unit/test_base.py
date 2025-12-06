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
            ("frozen", True),
            ("arbitrary_types_allowed", True),
            ("extra", "forbid"),
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

        assert result.is_success
        assert result.value == "success_value"

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

        assert result.is_failure
        assert result.error == "operation_failed"

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

        # Test bool
        bool_result = BoolService().execute()
        assert isinstance(bool_result.value, bool)
        assert bool_result.value is True

        # Test int
        int_result = IntService().execute()
        assert isinstance(int_result.value, int)
        assert int_result.value == 42

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

        # Test list
        list_result = ListService().execute()
        assert isinstance(list_result.value, list)
        assert list_result.value == ["a", "b", "c"]

        # Test dict
        dict_result = DictService().execute()
        assert isinstance(dict_result.value, dict)
        assert dict_result.value == {"count": 10}

    # =========================================================================
    # Model Config Tests
    # =========================================================================

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"),
        _get_model_config_attributes.__func__(),
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

        assert service_a.execute().value == "A"
        assert service_b.execute().value == "B"

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
