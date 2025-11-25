"""Unit tests for FlextLdapServiceBase.

**Modules Tested:**
- flext_ldap.base.FlextLdapServiceBase: Base service class for LDAP operations

**Scope:**
- Service initialization and configuration access
- Base service patterns and inheritance
- Config property access and namespace validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

import pytest
from flext_core import FlextConfig, FlextResult

from flext_ldap.base import FlextLdapServiceBase

pytestmark = pytest.mark.unit


class _TestServiceBase(FlextLdapServiceBase[bool]):
    """Test service implementation for testing base class.

    Concrete implementation of FlextLdapServiceBase[bool] used in unit tests
    to validate base service patterns and inheritance behavior.
    """

    def execute(self, **_kwargs: object) -> FlextResult[bool]:
        """Execute test service returning success result.

        Args:
            **kwargs: Unused keyword arguments for interface compatibility

        Returns:
            FlextResult[bool]: Always returns success with True value

        """
        return FlextResult[bool].ok(True)


@dataclass(frozen=True, slots=True)
class ServiceTestFactory:
    """Factory for creating and validating test services.

    Uses Python 3.13 dataclasses with slots for efficient test data creation
    and validation patterns.
    """

    # Expected config namespaces for validation
    EXPECTED_NAMESPACES: ClassVar[tuple[str, ...]] = ("ldap", "ldif")

    @staticmethod
    def create_test_service() -> FlextLdapServiceBase[bool]:
        """Factory method to create test service instance.

        Returns:
            FlextLdapServiceBase[bool]: Concrete test service implementation

        """
        return _TestServiceBase()

    @staticmethod
    def assert_config_valid(config: FlextConfig) -> None:
        """Validate configuration object structure and namespaces.

        Args:
            config: Config object to validate

        Raises:
            AssertionError: If config is invalid or missing expected attributes

        """
        assert config is not None
        assert isinstance(config, FlextConfig)
        for namespace in ServiceTestFactory.EXPECTED_NAMESPACES:
            assert hasattr(config, namespace), f"Config missing namespace: {namespace}"


class TestFlextLdapServiceBase:
    """Comprehensive tests for FlextLdapServiceBase.

    Single class per module with flat test methods covering:
    - Service initialization and instantiation
    - Configuration property access and validation
    - Base service inheritance behavior

    All tests use factory pattern for consistent test data generation.
    """

    _factory = ServiceTestFactory()

    def test_service_initialization(self) -> None:
        """Test service initialization creates valid instance.

        Covers FlextLdapServiceBase initialization and config property setup.
        """
        service = self._factory.create_test_service()
        assert service is not None
        assert service.config is not None

    def test_config_property_returns_global_config(self) -> None:
        """Test config property returns valid global FlextConfig instance.

        Covers FlextLdapServiceBase.config property and namespace validation.
        """
        service = self._factory.create_test_service()
        config = service.config
        self._factory.assert_config_valid(config)
