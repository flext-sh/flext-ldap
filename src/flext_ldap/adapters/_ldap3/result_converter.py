"""LDAP3 adapter — ResultConverter.

Composes ``ResultConverterExtractMixin`` for DN/attribute/metadata extraction
and exposes the public ``convert_*`` API consumed by ``SearchExecutor``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import m, p, t
from flext_ldap.adapters._ldap3.result_extract import ResultConverterExtractMixin
from flext_ldif import r


class ResultConverter(ResultConverterExtractMixin):
    """LDAP3 result conversion (SRP).

    Public API:
        - ``convert_ldap3_results`` — translate ``connection.entries`` to parser
          ``(dn, attrs)`` tuples.
        - ``convert_parsed_entries`` — translate ``ParseResponse`` from
          ``FlextLdifParser`` into ``r[t.SequenceOf[p.Ldif.Entry]]``.

    Internal helpers (DN/attribute/metadata extraction + value normalization)
    are inherited via ``ResultConverterExtractMixin`` per AGENTS.md §2.3
    MRO Composition + §3.1 200-LOC cap.
    """

    @staticmethod
    def convert_ldap3_results(
        connection: p.Ldap.Ldap3Connection,
    ) -> t.SequenceOf[t.Pair[str, t.MappingKV[str, t.StrSequence]]]:
        """Convert ``connection.entries`` to parser-compatible (dn, attrs) tuples.

        None values become empty lists; single values become ``[value]``;
        multi-values stay as lists. Type information is normalized to strings.
        """
        results: t.MutableSequenceOf[t.Pair[str, t.MappingKV[str, t.StrSequence]]] = []
        entries: t.SequenceOf[p.Ldap.Ldap3Entry] = getattr(connection, "entries", [])
        for entry in entries:
            dn = entry.entry_dn or ""
            attrs_dict = ResultConverter.extract_attrs_dict(
                entry.entry_attributes_as_dict,
            )
            results.append((dn, attrs_dict))
        return results

    @staticmethod
    def convert_parsed_entries(
        parse_response: m.Ldif.ParseResponse | p.Ldap.Ldap3ParseResponse,
    ) -> p.Result[t.SequenceOf[p.Ldif.Entry]]:
        """Translate ``ParseResponse`` from ``FlextLdifParser`` into typed entries.

        Pre-validated ``m.Ldif.Entry`` instances pass through unchanged;
        protocol-typed entries are reconstructed via ``extract_dn``,
        ``extract_attributes``, ``extract_metadata``.
        """
        entries_raw = parse_response.entries
        if not entries_raw:
            return r[t.SequenceOf[p.Ldif.Entry]].ok([])
        entries: t.MutableSequenceOf[p.Ldif.Entry] = []
        for entry_raw in entries_raw:
            if isinstance(entry_raw, m.Ldif.Entry):
                entries.append(entry_raw)
                continue
            entries.append(
                m.Ldif.Entry(
                    dn=ResultConverter.extract_dn(entry_raw),
                    attributes=ResultConverter.extract_attributes(entry_raw),
                    changetype=None,
                    metadata=ResultConverter.extract_metadata(entry_raw),
                    validation_metadata=None,
                ),
            )
        return r[t.SequenceOf[p.Ldif.Entry]].ok(entries)


__all__: list[str] = ["ResultConverter"]
