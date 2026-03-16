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
from flext_core import FlextService, FlextSettings, p, r

from flext_ldap import FlextLdapServiceBase, base, s

pytestmark = [pytest.mark.unit]


class TestsFlextLdapBase:
    """Comprehensive tests for FlextLdapServiceBase.

    Architecture: Single class per module following FLEXT patterns.
    Tests base service patterns without requiring actual LDAP connections.

    Uses parametrized tests and factory methods for code reduction (DRY).
    Expected reduction: 360 lines → ~220 lines (39% reduction).
    """

    @staticmethod
    def _get_model_config_attributes() -> list[tuple[str, object]]:
        """Factory: Return model config attribute tests (attr_name, expected_value)."""
        return [
            ("arbitrary_types_allowed", True),
            ("extra", "forbid"),
            ("use_enum_values", True),
            ("validate_assignment", True),
        ]

    def test_class_structure(self) -> None:
        """Test FlextLdapServiceBase class structure, inheritance, and generics."""
        assert FlextLdapServiceBase is not None
        assert issubclass(FlextLdapServiceBase, FlextService)
        assert hasattr(FlextLdapServiceBase, "__class_getitem__")

    def test_exports_and_aliases(self) -> None:
        """Test module exports and short aliases."""
        assert s is FlextLdapServiceBase
        assert "FlextLdapServiceBase" in base.__all__
        assert "s" in base.__all__

    def test_concrete_service_creation(self) -> None:
        """Test creating a concrete service that extends FlextLdapServiceBase."""

        class ConcreteTestService(FlextLdapServiceBase[str]):
            """Concrete service for testing."""

            @override
            def execute(self) -> r[str]:
                """Execute service logic."""
                return r[str].ok("test_result")

        service = ConcreteTestService()
        assert service is not None
        assert isinstance(service, FlextLdapServiceBase)
        assert isinstance(service, FlextService)

    def test_concrete_service_execute_returns_result(self) -> None:
        """Test concrete service execute method returns r."""

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

    def test_service_has_config_property(self) -> None:
        """Test service has config property."""

        class ConfigTestService(FlextLdapServiceBase[bool]):
            """Service that tests config access."""

            @override
            def execute(self) -> r[bool]:
                """Execute with config access."""
                return r[bool].ok(True)

        service = ConfigTestService()
        assert hasattr(service, "config")
        config = service.config
        assert config is not None
        assert isinstance(config, p.Settings)

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
        global_config = FlextSettings.get_global()
        assert config.app_name == global_config.app_name
        assert config.version == global_config.version
        assert getattr(config, "debug", False) == getattr(global_config, "debug", False)

    def test_service_has_logger_property(self) -> None:
        """Test service has logger property."""

        class LoggerTestService(FlextLdapServiceBase[bool]):
            """Service that tests logger access."""

            @override
            def execute(self) -> r[bool]:
                """Execute with logger access."""
                return r[bool].ok(True)

        service = LoggerTestService()
        assert hasattr(service, "logger")
        logger = service.logger
        assert logger is not None

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

        bool_result = BoolService().execute()
        assert bool_result.is_success
        bool_value: bool = bool_result.value
        assert isinstance(bool_value, bool)
        assert bool_value is True
        assert type(bool_value).__name__ == "bool"
        int_result = IntService().execute()
        assert int_result.is_success
        int_value: int = int_result.value
        assert isinstance(int_value, int)
        assert int_value == 42
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

        list_result = ListService().execute()
        assert list_result.is_success
        list_value: list[str] = list_result.value
        assert isinstance(list_value, list)
        assert len(list_value) == 3
        assert list_value == ["a", "b", "c"]
        assert all(isinstance(item, str) for item in list_value)
        dict_result = DictService().execute()
        assert dict_result.is_success
        dict_value: dict[str, int] = dict_result.value
        assert isinstance(dict_value, dict)
        assert len(dict_value) == 1
        assert dict_value == {"count": 10}
        assert isinstance(dict_value["count"], int)

    @pytest.mark.parametrize(
        ("attr_name", "expected_value"), _get_model_config_attributes()
    )
    def test_service_model_config_attributes(
        self, attr_name: str, expected_value: str | float | bool | None
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

    def test_class_has_docstring(self) -> None:
        """Test FlextLdapServiceBase has documentation."""
        assert FlextLdapServiceBase.__doc__ is not None
        assert "Base class" in FlextLdapServiceBase.__doc__

    def test_docstring_mentions_config_access(self) -> None:
        """Test docstring documents config access pattern."""
        assert FlextLdapServiceBase.__doc__ is not None
        assert "config" in FlextLdapServiceBase.__doc__.lower()

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
        result_a1 = service_a.execute()
        result_b1 = service_b.execute()
        result_a2 = service_a.execute()
        result_b2 = service_b.execute()
        assert result_a1.is_success
        value_a1: str = result_a1.value
        assert result_b1.is_success
        value_b1: str = result_b1.value
        assert result_a2.is_success
        value_a2: str = result_a2.value
        assert result_b2.is_success
        value_b2: str = result_b2.value
        assert value_a1 == "A"
        assert value_b1 == "B"
        assert value_a2 == "A"
        assert value_b2 == "B"
        assert value_a1 == value_a2
        assert value_b1 == value_b2

    def test_base_module_has_flext_ldap_service_base(self) -> None:
        """Test base module contains FlextLdapServiceBase class."""
        assert hasattr(base, "FlextLdapServiceBase")
        assert base.FlextLdapServiceBase is FlextLdapServiceBase

    def test_base_module_has_short_alias_s(self) -> None:
        """Test base module contains short alias 's'."""
        assert hasattr(base, "s")
        assert base.s is FlextLdapServiceBase


__all__ = ["TestsFlextLdapBase"]
