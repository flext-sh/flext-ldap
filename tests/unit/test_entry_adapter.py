"""Unit tests for flext_ldap.adapters.entry.FlextLdapEntryAdapter.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from tests.constants import c
from tests.models import m
from tests.utilities import u

pytestmark = pytest.mark.unit


class TestsFlextLdapEntryAdapter:
    """Tests for FlextLdapEntryAdapter real conversion logic.

    Only behaviours that exercise actual conversion logic with real
    ``m.Ldif.Entry`` inputs are tested. Declaration-only assertions and
    duck-typed mock-driven tests have been removed.
    """

    def test_ldif_entry_to_ldap3_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={
                    k: list(v)
                    for k, v in c.Ldap.Tests.ENTRY_ADAPTER_SAMPLE_ATTRIBUTES.items()
                },
                attribute_metadata={},
            ),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attributes = u.Ldap.Tests.ok(result)
        u.Ldap.Tests.that(
            attributes,
            keys=list(c.Ldap.Tests.ENTRY_ADAPTER_SAMPLE_ATTRIBUTES),
            kv={
                key: list(values)
                for key, values in c.Ldap.Tests.ENTRY_ADAPTER_SAMPLE_ATTRIBUTES.items()
            },
        )

    def test_ldif_entry_to_ldap3_attributes_with_empty_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={},
                attribute_metadata={},
            ),
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        err = u.Ldap.Tests.fail(
            result,
            has=c.Ldap.Tests.ENTRY_ADAPTER_NO_ATTRIBUTES_ERROR,
        )
        u.Ldap.Tests.that(
            err.lower(),
            contains=c.Ldap.Tests.ENTRY_ADAPTER_NO_ATTRIBUTES_ERROR,
        )


__all__: list[str] = ["TestsFlextLdapEntryAdapter"]
