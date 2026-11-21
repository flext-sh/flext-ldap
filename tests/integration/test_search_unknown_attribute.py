"""A search may select an attribute the server schema does not define.

RFC 4511 §4.5.1.8: a server ignores an attribute description it does not
recognize, so the search answers with the attributes it knows. ldap3 refuses
such a selection on the client once the schema is loaded; the adapter keeps
the protocol behaviour. A consumer comparing a directory with entries of a
newer schema (a migration preview) depends on it.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from uuid import uuid4

import pytest

from tests import c, ldap, m, t, tm, u

pytestmark = [pytest.mark.integration, pytest.mark.docker]


class TestsFlextLdapSearchUnknownAttribute:
    """An undefined attribute in the selection does not fail the search."""

    @staticmethod
    def test_search_answers_the_known_attributes(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """The entry comes back with ``cn``; the undefined attribute is absent."""
        conn_config = u.Tests.create_connection_config(ldap_container)
        base_dn = str(ldap_container["base_dn"])
        identifier = f"flext-ldap-unknown-attr-{uuid4().hex}"
        dn = f"uid={identifier},{base_dn}"
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {
                    "objectClass": list(c.Tests.ADD_WRAPPER_OBJECT_CLASSES),
                    "uid": [identifier],
                    "cn": [identifier],
                    "sn": [identifier],
                },
                "attribute_metadata": {},
                "metadata": None,
            }),
            changetype=None,
            metadata=None,
            validation_metadata=None,
            domain_events=[],
        )
        tm.ok(ldap.connect(conn_config))
        try:
            tm.ok(ldap.add(entry))
            found = ldap.search(
                m.Ldap.SearchOptions(
                    base_dn=base_dn,
                    filter_str=f"(uid={identifier})",
                    scope=c.Ldap.SearchScope.SUBTREE,
                    attributes=["cn", "flextUndefinedAttribute20261115"],
                )
            )
            tm.ok(found)
            entries = tm.not_none(found.value).entries
            tm.that(len(entries), eq=1)
            stored = tm.not_none(entries[0].attributes).attributes
            tm.that(list(stored.get("cn", [])), eq=[identifier])
            tm.that("flextUndefinedAttribute20261115" in stored, eq=False)
        finally:
            _ = ldap.delete(dn)
            ldap.disconnect()
