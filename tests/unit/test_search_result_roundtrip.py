"""LDAP search result validation contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import m, tm


def test_search_result_preserves_entry_and_roundtrips() -> None:
    """Validate entries through their native owner without copying instances."""
    entry = m.Ldif.Entry.create(
        dn="cn=person,dc=example,dc=org", attributes={"cn": ["person"]}
    ).unwrap()
    result = m.Ldap.SearchResult(
        entries=[entry],
        search_options=m.Ldap.SearchOptions(base_dn="dc=example,dc=org"),
    )
    tm.that(result.entries[0] is entry)
    restored = m.Ldap.SearchResult.model_validate_json(result.model_dump_json())
    tm.that(restored.entries[0].dn_str, eq=entry.dn_str)
