"""Models for flext-ldap tests.

Provides TestsLdapModels, extending FlextTestsModels with flext-ldap-specific models.
All generic test models come from flext_tests.

Architecture:
- FlextTestsModels (flext_tests) = Generic models for all FLEXT projects
- TestsLdapModels (tests/) = flext-ldap-specific models extending FlextTestsModels

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsDocker

from flext_ldap.models import FlextLdapModels


class TestsFlextLdapModels(FlextLdapModels):
    """Models for flext-ldap tests - extends FlextLdapModels.

    Architecture: Extends FlextLdapModels (which already extends FlextModels).
    FlextTestsDocker provides Docker-specific models and utilities.
    All generic models from FlextTestsModels are available via composition.
    All production models from FlextLdapModels are available through inheritance.

    Rules:
    - NEVER redeclare models from FlextLdapModels
    - Only flext-ldap-specific models allowed
    - All generic test models come from FlextTestsModels (via composition)
    - All production models come from FlextLdapModels (via inheritance)
    """

    # Re-export FlextTestsDocker for Docker-specific utilities
    Docker = FlextTestsDocker

    # Test-specific models can be added here as nested classes
    # Example:
    # class TestSearchOptions(SearchOptions):
    #     """Test-specific search options."""
    #     pass


__all__ = [
    "TestsFlextLdapModels",
    "m",
]

# Alias for simplified usage
m = TestsFlextLdapModels
