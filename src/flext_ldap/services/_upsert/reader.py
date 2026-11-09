"""Bounded LDAP reads shared by upsert planning and application.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from flext_ldap import c, m, p, r, t, u


@dataclass(frozen=True, repr=False)
class _Observed:
    entries: dict[str, p.Ldif.Entry]
    explicit: dict[str, frozenset[str]]


class FlextLdapServicesUpsertReader:
    """Read requested DNs by projection, never a subtree dump."""

    def __init__(self, operations: p.Ldap.LdapOperations) -> None:
        self._ops = operations

    def _requests(
        self,
        group: Sequence[p.Ldif.Entry],
        attributes: tuple[str, ...],
    ) -> p.Result[list[p.Ldap.SearchOptions]]:
        """Read exact DNs without assuming RDN attributes are searchable.

        Returns:
            BASE requests for the requested entries.

        """
        controls: t.Ldap.SearchControls | None = None
        if c.Ldap.AttributeName.ALL_ATTRIBUTES in attributes:
            supported = self._ops.supports_control(
                c.Ldap.REAL_ATTRIBUTES_ONLY_CONTROL_OID
            )
            if supported.failure:
                return r[list[p.Ldap.SearchOptions]].from_failure(supported)
            if supported.value:
                controls = ((c.Ldap.REAL_ATTRIBUTES_ONLY_CONTROL_OID, True, None),)
        return r[list[p.Ldap.SearchOptions]].ok([
            m.Ldap.SearchOptions(
                base_dn=e.dn_str,
                scope=c.Ldap.SearchScope.BASE,
                attributes=list(attributes),
                controls=controls,
            )
            for e in group
        ])

    def _read_queries(
        self,
        queries: Sequence[p.Ldap.SearchOptions],
        requested: set[str],
        keys: dict[str, str],
    ) -> p.Result[dict[str, p.Ldif.Entry]]:
        """Execute protocol requests without treating an incomplete read as absence.

        Returns:
            Requested entries only; LDAP 32 is a genuine empty result.

        """
        entries: dict[str, p.Ldif.Entry] = {}
        for query in queries:
            found = self._ops.search(query)
            if found.failure:
                if self._ops.no_such_object_error(str(found.error)):
                    continue
                return r[dict[str, p.Ldif.Entry]].from_failure(found)
            for entry in found.value.entries:
                if entry.dn_str not in keys:
                    key = u.Ldif.dn_key(entry.dn_str)
                    if key.failure:
                        return r[dict[str, p.Ldif.Entry]].from_failure(key)
                    keys[entry.dn_str] = key.value
                key = keys[entry.dn_str]
                if key in requested:
                    entries[key] = entry
        return r[dict[str, p.Ldif.Entry]].ok(entries)

    def read(
        self,
        entries: Sequence[p.Ldif.Entry],
        planned: Mapping[str, p.Ldif.Entry],
        keys: dict[str, str],
    ) -> p.Result[_Observed]:
        """Read a unique-DN wave, using only explicitly declared prior ADDs.

        Returns:
            Actual requested entries and named projections, or the read failure.

        """
        groups: dict[tuple[str, ...], list[p.Ldif.Entry]] = {}
        observed = _Observed({}, {})
        for entry in entries:
            key = keys[entry.dn_str]
            if key in planned:
                observed.entries[key] = planned[key]
                continue
            attributes = (
                tuple(sorted({op.attribute for op in entry.change_operations}))
                if entry.changetype == c.Ldif.ChangeType.MODIFY
                else tuple(
                    sorted({
                        c.Ldap.AttributeName.ALL_ATTRIBUTES,
                        *entry.attributes_dict,
                    })
                )
            )
            groups.setdefault(attributes, []).append(entry)
        for attributes, group in groups.items():
            queries = self._requests(group, attributes)
            if queries.failure:
                return r[_Observed].from_failure(queries)
            for entry in group:
                observed.explicit[keys[entry.dn_str]] = frozenset(
                    a.lower()
                    for a in attributes
                    if a != c.Ldap.AttributeName.ALL_ATTRIBUTES
                )
            found = self._read_queries(
                queries.value, {keys[entry.dn_str] for entry in group}, keys
            )
            if found.failure:
                return r[_Observed].from_failure(found)
            observed.entries.update(found.value)
        return r[_Observed].ok(observed)
