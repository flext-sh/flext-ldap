"""LDAP3 adapter — FlextLdapLdap3ResultConverter.

Composes ``FlextLdapLdap3ResultExtract`` for DN/attribute/metadata extraction
and exposes the public ``convert_*`` API consumed by ``FlextLdapLdap3SearchExecutor``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence, Sequence

from flext_ldif import r

from flext_ldap.adapters._ldap3 import FlextLdapLdap3ResultExtract
from flext_ldap.models import m
from flext_ldap.protocols import p


class FlextLdapLdap3ResultConverter(FlextLdapLdap3ResultExtract):
    """LDAP3 result conversion (SRP).

    Public API:
        - ``convert_ldap3_results`` — translate native response records to parser
          ``(dn, attrs)`` tuples.
        - ``convert_parsed_entries`` — translate ``ParseResponse`` from
          ``FlextLdifParser`` into ``r[Sequence[p.Ldif.Entry]]``.

    Internal helpers (DN/attribute/metadata extraction + value normalization)
    are inherited via ``FlextLdapLdap3ResultExtract`` per AGENTS.md §2.3
    MRO Composition + §3.1 200-LOC cap.
    """

    @staticmethod
    def convert_ldap3_results(
        connection: p.Ldap.Ldap3Connection,
    ) -> Sequence[tuple[str, Mapping[str, Sequence[str]]]]:
        """Convert native response records without the lossy Entry abstraction.

        None values become empty lists; single values become ``[value]``;
        multi-values stay as lists. Type information is normalized to strings.

        Returns:
            The resulting ``Sequence[tuple[str, Mapping[str,
                Sequence[str]]]]``.

        Raises:
            TypeError: If a search entry lacks a DN or attribute mapping.

        """
        results: MutableSequence[tuple[str, Mapping[str, Sequence[str]]]] = []
        for response in connection.response or ():
            if response.get("type") != "searchResEntry":
                continue
            dn, attributes = response.get("dn"), response.get("attributes")
            if not isinstance(dn, str) or not isinstance(attributes, Mapping):
                msg = "LDAP search entry requires a DN and attribute mapping"
                raise TypeError(msg)
            attrs_dict = FlextLdapLdap3ResultConverter.extract_attrs_dict(attributes)
            results.append((dn, attrs_dict))
        return results

    @staticmethod
    def convert_parsed_entries(
        parse_response: p.Ldif.ParseResponse | p.Ldif.Ldap3ParseResponse,
    ) -> p.Result[Sequence[p.Ldif.Entry]]:
        """Translate ``ParseResponse`` from ``FlextLdifParser`` into typed entries.

        Pre-validated ``m.Ldif.Entry`` instances pass through unchanged;
        protocol-typed entries are reconstructed via ``extract_dn``,
        ``extract_attributes``, ``extract_metadata``.

        Returns:
            The resulting ``p.Result[Sequence[p.Ldif.Entry]]``.

        """
        entries_raw = parse_response.entries
        if not entries_raw:
            return r[Sequence[p.Ldif.Entry]].ok([])
        entries: MutableSequence[p.Ldif.Entry] = []
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
                    domain_events=[],
                    metadata=FlextLdapLdap3ResultConverter.extract_metadata(entry_raw),
                    validation_metadata=None,
                ),
            )
        return r[Sequence[p.Ldif.Entry]].ok(entries)


__all__: list[str] = ["FlextLdapLdap3ResultConverter"]
