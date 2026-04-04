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
from flext_ldap import FlextLdapModels, FlextLdapServiceBase
from tests.constants import FlextLdapTestConstants
from tests.typings import FlextLdapTestTypes


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

            class MockLdap3Attribute:
                """Mock ldap3 Attribute satisfying p.Ldap.Ldap3Attribute."""

                def __init__(self, vals: FlextLdapTestTypes.StrSequence) -> None:
                    self.values: FlextLdapTestTypes.Ldap.Ldap3AttributeValues = vals
                    self.raw_values: list[bytes] = [v.encode() for v in vals]
                    self.value: FlextLdapTestTypes.Ldap.Ldap3AttributeValue = (
                        vals[0]
                        if vals
                        else FlextLdapTestConstants.Ldap.Tests.StringValues.EMPTY
                    )

            class MockLdap3Entry:
                """Mock ldap3 Entry satisfying p.Ldap.Ldap3Entry."""

                def __init__(
                    self,
                    dn: str = FlextLdapTestConstants.Ldap.Tests.EntryDN.USER_EXAMPLE,
                    attrs: FlextLdapTestTypes.StrSequenceMapping | None = None,
                ) -> None:
                    self.entry_dn: str | None = dn
                    self._attrs: FlextLdapTestTypes.StrSequenceMapping = attrs or {}

                @property
                def entry_attributes_as_dict(
                    self,
                ) -> FlextLdapTestTypes.Ldap.Ldap3AttributeDict:
                    return self._attrs

                @property
                def entry_attributes(self) -> FlextLdapTestTypes.StrSequence:
                    return list(self._attrs)

                def __getitem__(
                    self,
                    item: str,
                ) -> FlextLdapTestModels.Ldap.Tests.MockLdap3Attribute:
                    return FlextLdapTestModels.Ldap.Tests.MockLdap3Attribute(
                        list(self._attrs.get(item, [])),
                    )

            class SuccessService(FlextLdapServiceBase):
                """Test service that always succeeds."""

                @override
                def execute(
                    self,
                    **_kwargs: str | float | bool | None,
                ) -> r[FlextLdapModels.Ldap.SearchResult]:
                    return r[FlextLdapModels.Ldap.SearchResult].ok(
                        FlextLdapModels.Ldap.SearchResult(
                            entries=[],
                            search_options=None,
                        ),
                    )

            class FailService(FlextLdapServiceBase):
                """Test service that always fails."""

                @override
                def execute(
                    self,
                    **_kwargs: str | float | bool | None,
                ) -> r[FlextLdapModels.Ldap.SearchResult]:
                    return r[FlextLdapModels.Ldap.SearchResult].fail(
                        FlextLdapTestConstants.Ldap.Tests.Base.FAIL_ERROR_MESSAGE,
                    )


# Short aliases for tests
m = FlextLdapTestModels

__all__ = [
    "FlextLdapTestModels",
    "m",
]
