"""Test model definitions extending src models for centralized test objects.

This module provides test-specific model extensions that inherit from
src/flext_ldap/models.py classes. This centralizes test objects without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from flext_tests import FlextTestsModels, r

from flext_ldap import m
from tests.base import s

if TYPE_CHECKING:
    from tests import p


class TestsFlextLdapModels(m, FlextTestsModels):
    """Test models - composição de TestsFlextModels + m."""

    class Ldap(m.Ldap):
        """LDAP test models."""

        class Tests:
            """Test fixture models namespace."""

            FAIL_ERROR_MESSAGE = "nope"

            class SuccessService(s[bool]):
                """Test service that always succeeds."""

                @override
                def execute(self) -> p.Result[bool]:
                    return r[bool].ok(True)

            class FailService(s[bool]):
                """Test service that always fails."""

                @override
                def execute(self) -> p.Result[bool]:
                    return r[bool].fail(
                        TestsFlextLdapModels.Ldap.Tests.FAIL_ERROR_MESSAGE,
                    )


# Short aliases for tests
m = TestsFlextLdapModels

__all__: list[str] = [
    "TestsFlextLdapModels",
    "m",
]
