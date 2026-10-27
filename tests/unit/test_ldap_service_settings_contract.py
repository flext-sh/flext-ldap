"""Behavioral contract: LDAP services resolve the project settings.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapSettings, ldap, settings
from tests import tm

pytestmark = pytest.mark.unit


class TestsFlextLdapServiceSettingsContract:
    """The LDAP facade resolves the project settings, not the core root."""

    @staticmethod
    def test_facade_settings_resolve_project_settings() -> None:
        """Verify the facade settings expose the project LDAP branch."""
        resolved = tm.instance(ldap.settings, FlextLdapSettings)
        tm.that(resolved.Ldap.host, eq=settings.Ldap.host)
        tm.that(resolved.Ldap.port, eq=settings.Ldap.port)
