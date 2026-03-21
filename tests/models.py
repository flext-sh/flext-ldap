"""Test model definitions extending src models for centralized test objects.

This module provides test-specific model extensions that inherit from
src/flext_ldap/models.py classes. This centralizes test objects without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import m

from flext_ldap import FlextLdapModels


class TestsFlextLdapModels(FlextTestsModels, FlextLdapModels):
    """Test models - composição de m + FlextLdapModels.

    Hierarquia:
    - m: Utilitários de teste genéricos
    - FlextLdapModels: Models de domínio do projeto
    - TestsFlextLdapModels: Composição + namespace .Tests

    Access patterns:
    - tm.Tests.* - Test fixtures (ConnectionConfig, SearchOptions, etc.)
    - m.Ldap.* - Production domain models
    """

    class Ldap(FlextLdapModels.Ldap):
        """LDAP test models."""

        class Tests(FlextTestsModels.Tests):
            """Test fixture models namespace."""


# Short aliases for tests
m = TestsFlextLdapModels

__all__ = [
    "TestsFlextLdapModels",
    "m",
]
