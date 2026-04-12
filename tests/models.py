"""Test model definitions extending src models for centralized test objects.

This module provides test-specific model extensions that inherit from
src/flext_ldap/models.py classes. This centralizes test objects without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_tests import FlextTestsModels

from flext_core import r, s
from flext_ldap import m
from tests import t


class TestsFlextLdapModels(m, FlextTestsModels):
    """Test models - composição de TestsFlextModels + m."""

    class Ldap(m.Ldap):
        """LDAP test models."""

        class Tests:
            """Test fixture models namespace."""

            EMPTY = ""
            USER_EXAMPLE_DN = "cn=user,dc=example,dc=com"
            FAIL_ERROR_MESSAGE = "nope"

            class MockLdap3Attribute:
                """Mock ldap3 Attribute satisfying p.Ldap.Ldap3Attribute."""

                def __init__(self, vals: t.StrSequence) -> None:
                    self.values: t.Ldap.Ldap3AttributeValues = vals
                    self.raw_values: t.MutableSequenceOf[bytes] = [
                        v.encode() for v in vals
                    ]
                    self.value: t.Ldap.Ldap3AttributeValue = (
                        vals[0] if vals else TestsFlextLdapModels.Ldap.Tests.EMPTY
                    )

            class MockLdap3Entry:
                """Mock ldap3 Entry satisfying p.Ldap.Ldap3Entry."""

                def __init__(
                    self,
                    dn: str | None = None,
                    attrs: t.StrSequenceMapping | None = None,
                ) -> None:
                    self.entry_dn: str | None = (
                        dn
                        if dn is not None
                        else TestsFlextLdapModels.Ldap.Tests.USER_EXAMPLE_DN
                    )
                    self._attrs: t.StrSequenceMapping = attrs or {}

                @property
                def entry_attributes_as_dict(
                    self,
                ) -> t.StrSequenceMapping:
                    return self._attrs

                @property
                def entry_attributes(self) -> t.StrSequence:
                    return list(self._attrs)

                def __getitem__(
                    self,
                    item: str,
                ) -> TestsFlextLdapModels.Ldap.Tests.MockLdap3Attribute:
                    """Return mock attribute for the given item name."""
                    return TestsFlextLdapModels.Ldap.Tests.MockLdap3Attribute(
                        list(self._attrs.get(item, [])),
                    )

            class SuccessService(s[bool]):
                """Test service that always succeeds."""

                @override
                def execute(self) -> r[bool]:
                    return r[bool].ok(True)

            class FailService(s[bool]):
                """Test service that always fails."""

                @override
                def execute(self) -> r[bool]:
                    return r[bool].fail(
                        TestsFlextLdapModels.Ldap.Tests.FAIL_ERROR_MESSAGE,
                    )


# Short aliases for tests
m = TestsFlextLdapModels

__all__: list[str] = [
    "TestsFlextLdapModels",
    "m",
]
