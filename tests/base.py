"""Service base for flext-ldap tests.

Provides LdapTestsServiceBase, extending FlextService with test-specific service
functionality for flext-ldap test infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeVar, override

from flext_core import FlextService, r, t

T = TypeVar("T", bound=t.ValueOrModel | list[t.ValueOrModel])


class TestsFlextLdapServiceBase(FlextService[T]):
    """Service base for flext-ldap tests - extends FlextService.

    Architecture: Extends FlextService with test-specific service functionality.
    All base service functionality from FlextService is available through inheritance.
    """

    @override
    def execute(self) -> r[T]:
        """Execute domain service logic.

        This is the core business logic method that must be implemented by all
        concrete service subclasses. It contains the actual domain operations,
        business rules, and result generation logic specific to each service.

        Returns:
            r[T]: Result containing domain result or error

        """
        msg = "TestsFlextLdapServiceBase.execute must be overridden by subclass"
        raise NotImplementedError(msg)


__all__ = ["TestsFlextLdapServiceBase", "s"]
s = TestsFlextLdapServiceBase
