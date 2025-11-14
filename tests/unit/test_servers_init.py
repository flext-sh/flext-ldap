"""Unit tests for servers module __init__.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


class TestServersInit:
    """Tests for servers module initialization."""

    def test_servers_module_imports(self) -> None:
        """Test that servers module can be imported."""
        from flext_ldap import servers

        assert servers is not None

    def test_servers_all_defined(self) -> None:
        """Test that __all__ is defined in servers module."""
        from flext_ldap.servers import __all__

        assert isinstance(__all__, list)
        # Currently all imports are commented out, so __all__ should be empty or contain commented items
        # This test ensures the module structure is correct
