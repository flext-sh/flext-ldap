"""Behavioral contract: LDAP services resolve the project settings.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldap import FlextLdapSettings, ldap, settings

pytestmark = pytest.mark.unit


class TestsFlextLdapServiceSettingsContract:
    """The LDAP facade resolves the project settings, not the core root."""

    @staticmethod
    def test_facade_settings_resolve_project_settings() -> None:
        """Verify the facade settings expose the project LDAP branch."""
        resolved = ldap.settings
        assert isinstance(resolved, FlextLdapSettings)
        tm.that(resolved.Ldap.host, eq=settings.Ldap.host)
        tm.that(resolved.Ldap.port, eq=settings.Ldap.port)
