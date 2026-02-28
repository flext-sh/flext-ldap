"""Service base for flext-ldap tests.

Provides LdapTestsServiceBase, extending FlextService with test-specific service
functionality for flext-ldap test infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextService, T


class TestsFlextLdapServiceBase(FlextService[T]):
    """Service base for flext-ldap tests - extends FlextService.

    Architecture: Extends FlextService with test-specific service functionality.
    All base service functionality from FlextService is available through inheritance.
    """


__all__ = ["TestsFlextLdapServiceBase", "s"]

# Alias for simplified usage
s = TestsFlextLdapServiceBase
