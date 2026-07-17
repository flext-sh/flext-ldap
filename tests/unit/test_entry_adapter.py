"""Behavioral unit tests for flext_ldap.adapters.entry.FlextLdapEntryAdapter.

Architecture: Single class per module following FLEXT patterns.
Assertions target the observable public contract only:
- ``r[T]`` success/failure outcomes of the conversion methods.
- Public model state of the produced ``m.Ldif.Entry`` (dn, attributes, metadata).
- Value/return contracts of ``execute`` and ``ldif_entry_to_ldap3_attributes``.

No private attribute/method access, no internal-collaborator spying, no
patching of the unit under test. The only test double is a structural ldap3
Entry standing in for the genuine external ldap3 boundary.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from tests import c, m, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapEntryAdapter:
    """Behavioral contract tests for FlextLdapEntryAdapter conversions."""

    class _Ldap3Attribute:
        """Structural stand-in for one external ldap3 attribute object."""

        def __init__(self, values: t.Ldap.Ldap3AttributeValues) -> None:
            self._values = values

        @property
        def values(self) -> t.Ldap.Ldap3AttributeValues:
            return self._values

        @property
        def value(self) -> t.Ldap.Ldap3EntryValue:
            return self._values[0] if self._values else ""

    class _Ldap3Entry:
        """Structural stand-in for the external ldap3 Entry boundary.

        Implements the ``p.Ldap.Ldap3Entry`` structural contract. Not a mock of
        the unit under test.
        """

        def __init__(
            self,
            dn: str,
            attributes: t.Ldap.Ldap3AttributeDict,
        ) -> None:
            self._dn = dn
            self._attributes = attributes

        @property
        def entry_dn(self) -> str:
            return self._dn

        @property
        def entry_attributes(self) -> t.StrSequence:
            return tuple(self._attributes)

        @property
        def entry_attributes_as_dict(self) -> t.Ldap.Ldap3AttributeDict:
            return self._attributes

        def __getitem__(
            self,
            attribute_name: str,
        ) -> TestsFlextLdapEntryAdapter._Ldap3Attribute:
            return TestsFlextLdapEntryAdapter._Ldap3Attribute(
                self._attributes[attribute_name] or (),
            )

    @staticmethod
    def _ldif_entry(attributes: t.MappingKV[str, t.StrSequence]) -> m.Ldif.Entry:
        """Build an ``m.Ldif.Entry`` via the public model API."""
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE),
            attributes=m.Ldif.Attributes(
                attributes={key: list(values) for key, values in attributes.items()},
                attribute_metadata={},
            ),
        )

    # ------------------------------------------------------------------
    # execute() — s protocol contract
    # ------------------------------------------------------------------

    def test_execute_reports_adapter_ready(self) -> None:
        adapter = FlextLdapEntryAdapter()

        result = adapter.execute()

        tm.that(u.Ldap.Tests.ok(result), eq=True)

    # ------------------------------------------------------------------
    # ldif_entry_to_ldap3_attributes() — LDIF -> ldap3 attributes
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "attributes",
        [
            {"cn": ("user",), "sn": ("Doe",)},
            {"cn": ("user",)},
            {"objectClass": ("top", "person"), "cn": ("user",)},
        ],
    )
    def test_ldif_to_ldap3_attributes_preserves_names_and_values(
        self,
        attributes: t.MappingKV[str, t.StrSequence],
    ) -> None:
        adapter = FlextLdapEntryAdapter()
        entry = self._ldif_entry(attributes)

        result = adapter.ldif_entry_to_ldap3_attributes(entry)

        converted = u.Ldap.Tests.ok(result)
        u.Ldap.Tests.that(
            converted,
            keys=list(attributes),
            kv={key: list(values) for key, values in attributes.items()},
        )

    def test_ldif_to_ldap3_attributes_empty_returns_failure(self) -> None:
        adapter = FlextLdapEntryAdapter()
        entry = self._ldif_entry({})

        result = adapter.ldif_entry_to_ldap3_attributes(entry)

        err = u.Ldap.Tests.fail(
            result,
            has=c.Ldap.Tests.ENTRY_ADAPTER_NO_ATTRIBUTES_ERROR,
        )
        u.Ldap.Tests.that(
            err.lower(),
            contains=c.Ldap.Tests.ENTRY_ADAPTER_NO_ATTRIBUTES_ERROR,
        )

    # ------------------------------------------------------------------
    # ldap3_to_ldif_entry() — ldap3 Entry -> LDIF entry
    # ------------------------------------------------------------------

    def test_ldap3_to_ldif_preserves_dn_and_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        source = self._Ldap3Entry(
            dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            attributes={"cn": ["user"], "sn": ["Doe"]},
        )

        result = adapter.ldap3_to_ldif_entry(source)

        entry = u.Ldap.Tests.ok(result)
        dn = entry.dn
        attributes = entry.attributes
        assert dn is not None
        assert attributes is not None
        tm.that(dn.value, eq=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE)
        tm.that(attributes.attributes, eq={"cn": ["user"], "sn": ["Doe"]})

    def test_ldap3_to_ldif_tracks_base64_attributes_for_non_ascii(self) -> None:
        adapter = FlextLdapEntryAdapter()
        source = self._Ldap3Entry(
            dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            attributes={"cn": ["naïve"]},
        )

        result = adapter.ldap3_to_ldif_entry(source)

        entry = u.Ldap.Tests.ok(result)
        metadata = entry.metadata
        assert metadata is not None
        tm.that(metadata.extensions["base64_encoded_attributes"], eq=["cn"])

    @pytest.mark.parametrize(
        "server_type",
        [
            c.Ldif.ServerTypes.RFC,
            c.Ldif.ServerTypes.OPENLDAP,
            c.Ldif.ServerTypes.OUD,
        ],
    )
    def test_ldap3_to_ldif_records_configured_server_type(
        self,
        server_type: str,
    ) -> None:
        adapter = FlextLdapEntryAdapter(server_type=server_type)
        source = self._Ldap3Entry(
            dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            attributes={"cn": ["user"]},
        )

        result = adapter.ldap3_to_ldif_entry(source)

        entry = u.Ldap.Tests.ok(result)
        metadata = entry.metadata
        assert metadata is not None
        tm.that(metadata.server_type, eq=server_type)

    def test_default_server_type_is_rfc(self) -> None:
        adapter = FlextLdapEntryAdapter()
        source = self._Ldap3Entry(
            dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            attributes={"cn": ["user"]},
        )

        result = adapter.ldap3_to_ldif_entry(source)

        entry = u.Ldap.Tests.ok(result)
        metadata = entry.metadata
        assert metadata is not None
        tm.that(metadata.server_type, eq=c.Ldif.ServerTypes.RFC)

    def test_conversion_round_trip_preserves_attributes(self) -> None:
        adapter = FlextLdapEntryAdapter()
        original = {"cn": ["user"], "sn": ["Doe"]}
        source = self._Ldap3Entry(
            dn=c.Ldap.Tests.ENTRY_DN_USER_EXAMPLE,
            attributes=original,
        )

        ldif_entry = u.Ldap.Tests.ok(adapter.ldap3_to_ldif_entry(source))
        round_tripped = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)

        converted = u.Ldap.Tests.ok(round_tripped)
        u.Ldap.Tests.that(
            converted,
            keys=list(original),
            kv=original,
        )


__all__: list[str] = ["TestsFlextLdapEntryAdapter"]
