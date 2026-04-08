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

from flext_core import r
from flext_ldap import m
from tests import s, t

# Constants used as defaults in mock classes — direct strings to avoid
# circular import with tests.constants (which loads through tests.__init__)
_EMPTY = ""
_USER_EXAMPLE_DN = "cn=user,dc=example,dc=com"
_FAIL_ERROR_MESSAGE = "nope"


class FlextLdapTestModels(m, FlextTestsModels):
    """Test models - composição de FlextTestsModels + m.

    Hierarquia:
    - FlextTestsModels: Utilitários de teste genéricos
    - m: Models de domínio do projeto
    - FlextLdapTestModels: Composição + namespace .Tests

    Access patterns:
    - m.Tests.* - Test fixtures (ConnectionConfig, SearchOptions, etc.)
    - m.Ldap.* - Production domain models
    """

    class Ldap(m.Ldap):
        """LDAP test models."""

        class Tests(FlextTestsModels.Tests):
            """Test fixture models namespace."""

            class MockLdap3Attribute:
                """Mock ldap3 Attribute satisfying p.Ldap.Ldap3Attribute."""

                def __init__(self, vals: t.StrSequence) -> None:
                    self.values: t.Ldap.Ldap3AttributeValues = vals
                    self.raw_values: t.MutableSequenceOf[bytes] = [
                        v.encode() for v in vals
                    ]
                    self.value: t.Ldap.Ldap3AttributeValue = vals[0] if vals else _EMPTY

            class MockLdap3Entry:
                """Mock ldap3 Entry satisfying p.Ldap.Ldap3Entry."""

                def __init__(
                    self,
                    dn: str = _USER_EXAMPLE_DN,
                    attrs: t.StrSequenceMapping | None = None,
                ) -> None:
                    self.entry_dn: str | None = dn
                    self._attrs: t.StrSequenceMapping = attrs or {}

                @property
                def entry_attributes_as_dict(
                    self,
                ) -> t.Ldap.Ldap3AttributeDict:
                    return self._attrs

                @property
                def entry_attributes(self) -> t.StrSequence:
                    return list(self._attrs)

                def __getitem__(
                    self,
                    item: str,
                ) -> FlextLdapTestModels.Ldap.Tests.MockLdap3Attribute:
                    """Return mock attribute for the given item name."""
                    return FlextLdapTestModels.Ldap.Tests.MockLdap3Attribute(
                        list(self._attrs.get(item, [])),
                    )

            class SuccessService(s[m.Ldap.SearchResult]):
                """Test service that always succeeds."""

                @override
                def execute(self) -> r[m.Ldap.SearchResult]:
                    return r[m.Ldap.SearchResult].ok(
                        m.Ldap.SearchResult(
                            entries=[],
                            search_options=None,
                        ),
                    )

            class FailService(s[m.Ldap.SearchResult]):
                """Test service that always fails."""

                @override
                def execute(self) -> r[m.Ldap.SearchResult]:
                    return r[m.Ldap.SearchResult].fail(
                        _FAIL_ERROR_MESSAGE,
                    )


# Short aliases for tests
m = FlextLdapTestModels

__all__ = [
    "FlextLdapTestModels",
    "m",
]
