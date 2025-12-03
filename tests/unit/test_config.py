"""Unit tests for FlextLdapConfig configuration management.

**Modules Tested:**
- `flext_ldap.config.FlextLdapConfig` - LDAP configuration management with singleton pattern

**Test Scope:**
- Singleton pattern (get_instance returns same instance)
- Default configuration values from constants
- Optional attributes default to None
- Required attributes presence validation
- Processing-related configuration defaults

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapConfig
Scope: Comprehensive configuration testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

import pytest
from flext_core.typings import t

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants

pytestmark = pytest.mark.unit


class TestFlextLdapConfig:
    """Comprehensive tests for FlextLdapConfig using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    All helper logic is nested within this single class following FLEXT patterns.
    """

    # Default value expectations using mapping for DRY
    _DEFAULT_VALUES: ClassVar[Mapping[str, object]] = {
        "host": "localhost",
        "port": FlextLdapConstants.ConnectionDefaults.PORT,
        "use_ssl": False,
        "use_tls": False,
        "auto_bind": FlextLdapConstants.ConnectionDefaults.AUTO_BIND,
        "pool_size": FlextLdapConstants.ConnectionDefaults.POOL_SIZE,
        "timeout": FlextLdapConstants.ConnectionDefaults.TIMEOUT,
        "max_results": 1000,
        "chunk_size": 100,
    }

    # Optional attributes that default to None
    _NONE_ATTRIBUTES: ClassVar[tuple[str, ...]] = (
        "bind_dn",
        "bind_password",
        "base_dn",
    )

    # All required attributes for validation
    _ALL_ATTRIBUTES: ClassVar[tuple[str, ...]] = (
        "host",
        "port",
        "use_ssl",
        "use_tls",
        "bind_dn",
        "bind_password",
        "timeout",
        "auto_bind",
        "auto_range",
        "pool_size",
        "pool_lifetime",
        "max_results",
        "chunk_size",
        "base_dn",
    )

    @staticmethod
    def _get_config() -> FlextLdapConfig:
        """Factory method for getting config singleton instance."""
        # FlextConfig uses singleton pattern via __new__, so instantiation returns singleton
        return FlextLdapConfig()

    def test_get_instance_returns_singleton(self) -> None:
        """Test get_instance returns same singleton instance."""
        instance1 = self._get_config()
        instance2 = self._get_config()
        assert instance1 is instance2
        assert isinstance(instance1, FlextLdapConfig)

    @pytest.mark.parametrize(
        ("attr", "expected"),
        [(attr, expected) for attr, expected in _DEFAULT_VALUES.items()],
    )
    def test_default_config_values(
        self,
        attr: str,
        expected: t.GeneralValueType,
    ) -> None:
        """Test default configuration values match expected constants."""
        # Reset singleton to ensure clean state for default value testing
        FlextLdapConfig._reset_instance()
        config = self._get_config()
        assert getattr(config, attr) == expected

    @pytest.mark.parametrize("attr", _NONE_ATTRIBUTES)
    def test_default_none_values(self, attr: str) -> None:
        """Test optional attributes default to None (no automatic binding)."""
        # Reset singleton to ensure clean state for default value testing
        FlextLdapConfig._reset_instance()
        config = self._get_config()
        assert getattr(config, attr) is None

    @pytest.mark.parametrize("attr", _ALL_ATTRIBUTES)
    def test_config_has_required_attribute(self, attr: str) -> None:
        """Test config instance has all required LDAP attributes."""
        config = self._get_config()
        assert hasattr(config, attr)

    def test_processing_defaults(self) -> None:
        """Test processing-related configuration defaults."""
        # Reset singleton to ensure clean state for default value testing
        FlextLdapConfig._reset_instance()
        config = self._get_config()
        assert config.max_results == self._DEFAULT_VALUES["max_results"]
        assert config.chunk_size == self._DEFAULT_VALUES["chunk_size"]
