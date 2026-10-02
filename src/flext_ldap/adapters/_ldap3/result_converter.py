"""LDAP3 adapter — FlextLdapLdap3ResultConverter.

Composes ``FlextLdapLdap3ResultExtract`` for DN/attribute/metadata extraction
and exposes the public ``convert_*`` API consumed by ``FlextLdapLdap3SearchExecutor``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier=MIT
"""

from __future__ import annotations

from flext_ldif import r

from flext_ldap import m, p, t
from flext_ldap.adapters._ldap3.result_extract import FlextLdapLdap3ResultExtract


class FlextLdapLdap3ResultConverter(FlextLdapLdap3ResultExtract):
    """LDAP3 result conversion (SRP).

    Public API:
        - ``convert_ldap3_results`` — translate ``connection.entries`` to parser
          ``(dn, attrs)`` tuples.
        - ``convert_parsed_entries`` — translate ``ParseResponse`` from
          ``FlextLdifParser`` into ``r[t.SequenceOf[m.Ldif.Entry]]``.

    Internal helpers (DN/attribute/metadata extraction + value normalization)
    are inherited via ``FlextLdapLdap3ResultExtract`` per AGENTS.md §2.3
    MRO Composition + §3.1 200-LOC cap.
    """

    @staticmethod
    def convert_ldap3_results(
        connection: p.Ldap.Ldap3Connection,
    ) -> t.SequenceOf[t.Pair[str, t.MappingKV[str, t.StrSequence]]]:
        """Convert ``connection.entries`` to parser-compatible (dn, attrs) tuples.

        None values become empty lists; single values become ``[value]``;
        multi-values stay as lists. Type information is normalized to strings.

        Returns:
            The resulting
            ``t.SequenceOf[t.Pair[str, t.MappingKV[str, t.StrSequence]]]`` value.

        """
        results: t.MutableSequenceOf[t.Pair[str, t.MappingKV[str, t.StrSequence]]] = []
        entries: t.SequenceOf[p.Ldif.Ldap3Entry] = getattr(connection, "entries", [])
        for entry in entries:
            dn = entry.entry_dn or ""
            attrs_dict = FlextLdapLdap3ResultConverter.extract_attrs_dict(
                entry.entry_attributes_as_dict,
            )
            results.append((dn, attrs_dict))
        return results

    @staticmethod
    def convert_parsed_entries(
        parse_response: m.Ldif.ParseResponse | p.Ldif.Ldap3ParseResponse,
    ) -> p.Result[t.SequenceOf[m.Ldif.Entry]]:
        """Translate ``ParseResponse`` from ``FlextLdifParser`` into typed entries.

        Pre-validated ``m.Ldif.Entry`` instances pass through unchanged;
        protocol-typed entries are reconstructed via ``extract_dn``,
        ``extract_attributes``, ``extract_metadata``.

        Returns:
            The resulting ``p.Result[t.SequenceOf[m.Ldif.Entry]]`` value.

        """
        entries_raw = parse_response.entries
        if not entries_raw:
            return r[t.SequenceOf[m.Ldif.Entry]].ok([])
        entries: t.MutableSequenceOf[m.Ldif.Entry] = []
        for entry_raw in entries_raw:
            if isinstance(entry_raw, m.Ldif.Entry):
                entries.append(entry_raw)
                continue
            entries.append(
                m.Ldif.Entry(
                    dn=FlextLdapLdap3ResultConverter.extract_dn(entry_raw),
                    attributes=FlextLdapLdap3ResultConverter.extract_attributes(
                        entry_raw,
                    ),
                    changetype=None,
                    metadata=FlextLdapLdap3ResultConverter.extract_metadata(entry_raw),
                    validation_metadata=None,
                ),
            )
        return r[t.SequenceOf[m.Ldif.Entry]].ok(entries)


__all__: list[str] = ["FlextLdapLdap3ResultConverter"]
