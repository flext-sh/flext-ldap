"""Test model definitions extending src models for centralized test objects.

This module provides test-specific model extensions that inherit from
src/flext_ldap/models.py classes. This centralizes test objects without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsModels

from flext_ldap import FlextLdapModels


class FlextLdapTestModels(FlextTestsModels, FlextLdapModels):
    """Test models - composição de FlextTestsModels + FlextLdapModels.

    Hierarquia:
    - FlextTestsModels: Utilitários de teste genéricos
    - FlextLdapModels: Models de domínio do projeto
    - FlextLdapTestModels: Composição + namespace .Tests

    Access patterns:
    - m.Tests.* - Test fixtures (ConnectionConfig, SearchOptions, etc.)
    - m.Ldap.* - Production domain models
    """

    class Ldap(FlextLdapModels.Ldap):
        """LDAP test models."""

        class Tests(FlextTestsModels.Tests):
            """Test fixture models namespace."""


# Short aliases for tests
m = FlextLdapTestModels

__all__ = [
    "FlextLdapTestModels",
    "m",
]
