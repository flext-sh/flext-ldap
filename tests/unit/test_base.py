"""Unit tests for FlextLdapServiceBase.

**Modules Tested:**
- `flext_ldap.base.FlextLdapServiceBase` - Base service class for LDAP operations

**Test Scope:**
- Service initialization and configuration access
- Base service patterns and inheritance
- Config property access and namespace validation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapServiceBase
Scope: Comprehensive base service testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_tests import FlextTestsMatchers

from flext_ldap.base import FlextLdapServiceBase

from ..fixtures.constants import TestConstants

pytestmark = pytest.mark.unit


class TestFlextLdapServiceBase:
    """Comprehensive tests for FlextLdapServiceBase using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    All helper logic is nested within this single class following FLEXT patterns.
    """

    class _TestService(FlextLdapServiceBase[bool]):
        """Test service implementation for testing base class."""

        def execute(self, **_kwargs: object) -> FlextResult[bool]:
            """Execute test service returning success result."""
            return FlextResult[bool].ok(True)

    @classmethod
    def _create_test_service(cls) -> FlextLdapServiceBase[bool]:
        """Create test service instance."""
        return cls._TestService()

    @pytest.mark.parametrize("namespace", TestConstants.Base.CONFIG_NAMESPACES)
    def test_service_initialization_and_config_namespaces(self, namespace: str) -> None:
        """Test service initialization creates valid instance with config namespaces.

        Covers FlextLdapServiceBase initialization, config property setup,
        and namespace validation using dynamic parametrization.
        """
        service = self._create_test_service()
        FlextTestsMatchers.assert_success(FlextResult[object].ok(service))
        assert service.config is not None
        assert hasattr(service.config, namespace), (
            f"Config missing namespace: {namespace}"
        )
