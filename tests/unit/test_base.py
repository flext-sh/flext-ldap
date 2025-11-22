"""Unit tests for FlextLdapServiceBase.

Tests base service patterns and config access methods.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import LdapFlextConfig

pytestmark = pytest.mark.unit


class _TestServiceBase(FlextLdapServiceBase[bool]):
    """Test service for testing base class (prefixed with _ to avoid pytest collection)."""

    def execute(self, **kwargs: object) -> FlextResult[bool]:
        """Execute test service."""
        return FlextResult[bool].ok(True)


class TestFlextLdapServiceBase:
    """Tests for FlextLdapServiceBase."""

    def test_service_initialization(self) -> None:
        """Test service initialization (covers line 39)."""
        service = _TestServiceBase()
        assert service is not None
        assert service.config is not None

    def test_config_property_with_injected_config(self) -> None:
        """Test config property with injected config (covers line 54)."""
        service = _TestServiceBase()
        custom_config = LdapFlextConfig.get_global_instance()
        service.with_config(custom_config)
        assert service.config == custom_config

    def test_with_config_method(self) -> None:
        """Test with_config method for dependency injection (covers lines 67-68)."""
        service = _TestServiceBase()
        custom_config = LdapFlextConfig.get_global_instance()
        result = service.with_config(custom_config)
        # Should return self for chaining
        assert result is service
        assert service._injected_config == custom_config

    def test_ldap_config_property(self) -> None:
        """Test ldap_config property (covers line 82)."""
        service = _TestServiceBase()
        ldap_config = service.ldap_config
        assert ldap_config is not None
        assert hasattr(ldap_config, "host")

    def test_ldif_config_property(self) -> None:
        """Test ldif_config property (covers line 92)."""
        service = _TestServiceBase()
        ldif_config = service.ldif_config
        assert ldif_config is not None
        assert hasattr(ldif_config, "ldif_encoding")

    def test_get_flext_config_static(self) -> None:
        """Test get_flext_config static method (covers line 106)."""
        config = FlextLdapServiceBase.get_flext_config()
        assert config is not None
        assert isinstance(config, LdapFlextConfig)

    def test_get_ldap_config_static(self) -> None:
        """Test get_ldap_config static method (covers line 116)."""
        ldap_config = FlextLdapServiceBase.get_ldap_config()
        assert ldap_config is not None
        assert hasattr(ldap_config, "host")

    def test_get_ldif_config_static(self) -> None:
        """Test get_ldif_config static method (covers line 126)."""
        ldif_config = FlextLdapServiceBase.get_ldif_config()
        assert ldif_config is not None
        assert hasattr(ldif_config, "ldif_encoding")
