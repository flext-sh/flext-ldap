"""Unit tests for FlextLdap singleton methods.

Tests get_instance and _reset_instance methods for singleton pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifParser

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig

pytestmark = pytest.mark.unit


class TestFlextLdapSingleton:
    """Tests for FlextLdap singleton pattern methods."""

    def test_get_instance_creates_singleton(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test get_instance creates singleton instance (covers lines 128-131).

        Tests that get_instance() creates a singleton and returns the same instance
        on subsequent calls.
        """
        # Reset singleton before test
        FlextLdap._reset_instance()

        # First call should create instance
        instance1 = FlextLdap.get_instance(parser=ldap_parser)
        assert instance1 is not None

        # Second call should return same instance
        instance2 = FlextLdap.get_instance()
        assert instance2 is instance1

        # Third call with different config should still return same instance
        # (singleton pattern - config is only used on first creation)
        config = FlextLdapConfig(host="different.example.com")
        instance3 = FlextLdap.get_instance(config=config)
        assert instance3 is instance1

        # Cleanup
        FlextLdap._reset_instance()

    def test_get_instance_with_config_and_parser(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test get_instance with both config and parser (covers line 130)."""
        # Reset singleton before test
        FlextLdap._reset_instance()

        config = FlextLdapConfig(host="test.example.com", port=389)
        instance = FlextLdap.get_instance(config=config, parser=ldap_parser)

        assert instance is not None
        assert instance._config == config
        assert instance._parser == ldap_parser

        # Cleanup
        FlextLdap._reset_instance()

    def test_reset_instance_clears_singleton(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test _reset_instance clears singleton (covers line 150)."""
        # Reset singleton before test
        FlextLdap._reset_instance()

        # Create instance
        instance1 = FlextLdap.get_instance(parser=ldap_parser)
        assert instance1 is not None

        # Reset singleton
        FlextLdap._reset_instance()

        # New call should create new instance
        instance2 = FlextLdap.get_instance(parser=ldap_parser)
        assert instance2 is not None
        # Should be different instance (singleton was reset)
        assert instance2 is not instance1

        # Cleanup
        FlextLdap._reset_instance()
