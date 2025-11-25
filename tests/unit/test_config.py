"""Unit tests for FlextLdapConfig.

**Modules Tested:**
- flext_ldap.config.FlextLdapConfig: LDAP configuration management

**Scope:**
- Singleton pattern (get_instance)
- Default configuration values
- Configuration field validation
- Required attributes presence

**Test Helpers Used:**
- Config fixture: Provides FlextLdapConfig singleton instance
- FlextLdapConstants: Centralized constant values for assertions

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants

pytestmark = pytest.mark.unit


@pytest.fixture
def config() -> FlextLdapConfig:
    """Provide FlextLdapConfig singleton instance for testing."""
    return FlextLdapConfig.get_instance()


class TestFlextLdapConfig:
    """Tests for FlextLdapConfig covering singleton pattern and configuration values.

    Single class per module with parametrized test methods covering:
    - Singleton pattern (get_instance)
    - Default configuration values
    - Configuration field validation
    - Required attributes presence
    """

    def test_get_instance_returns_singleton(self) -> None:
        """Test get_instance returns same singleton instance."""
        instance1 = FlextLdapConfig.get_instance()
        instance2 = FlextLdapConfig.get_instance()

        assert instance1 is instance2
        assert isinstance(instance1, FlextLdapConfig)

    @pytest.mark.parametrize(("attr", "expected"), [
        ("host", "localhost"),
        ("port", FlextLdapConstants.ConnectionDefaults.PORT),
        ("use_ssl", False),
        ("use_tls", False),
        ("auto_bind", FlextLdapConstants.ConnectionDefaults.AUTO_BIND),
        ("pool_size", FlextLdapConstants.ConnectionDefaults.POOL_SIZE),
        ("timeout", FlextLdapConstants.ConnectionDefaults.TIMEOUT),
    ])
    def test_default_config_values(
        self,
        config: FlextLdapConfig,
        attr: str,
        expected: object,
    ) -> None:
        """Test default configuration values match expected constants."""
        assert getattr(config, attr) == expected

    @pytest.mark.parametrize("attr", [
        "bind_dn",
        "bind_password",
        "base_dn",
    ])
    def test_default_none_values(
        self,
        config: FlextLdapConfig,
        attr: str,
    ) -> None:
        """Test optional attributes default to None (no automatic binding)."""
        assert getattr(config, attr) is None

    @pytest.mark.parametrize("attr", [
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
    ])
    def test_config_has_required_attribute(
        self,
        config: FlextLdapConfig,
        attr: str,
    ) -> None:
        """Test config instance has all required LDAP attributes."""
        assert hasattr(config, attr)

    def test_processing_defaults(self, config: FlextLdapConfig) -> None:
        """Test processing-related configuration defaults."""
        assert config.max_results == 1000
        assert config.chunk_size == 100
