"""LDAP3 adapter — SearchExecutor.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import c, m, p, t
from flext_ldap.adapters._ldap3.result_converter import ResultConverter
from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
from flext_ldif import r


class SearchExecutor:
    """LDAP search executor (SRP).

    Stateless dispatcher: invokes ldap3 Connection.search via
    ``FlextLdapLdap3Wrappers``, validates the result code, then delegates
    parsing to ``ResultConverter``.
    """

    @staticmethod
    def execute(
        connection: p.Ldap.Ldap3Connection,
        params: m.Ldap.SearchParams,
        server_type: c.Ldif.ServerTypes | str,
    ) -> p.Result[t.SequenceOf[m.Ldif.Entry]]:
        """Execute LDAP search and return parsed entries via ``ResultConverter``."""
        try:
            _ = FlextLdapLdap3Wrappers.search(
                connection,
                search_base=params.base_dn,
                search_filter=params.filter_str,
                search_scope=params.ldap_scope,
                attributes=params.search_attributes,
                size_limit=params.size_limit,
                time_limit=params.time_limit,
            )
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[t.SequenceOf[m.Ldif.Entry]].fail_op("Search", exc)
        conn_result = connection.result or {}
        result_code = conn_result.get("result", -1)
        if result_code not in c.Ldap.PARTIAL_SUCCESS_CODES:
            error_msg = conn_result.get("message", "LDAP search failed")
            error_desc = conn_result.get("description", "unknown")
            return r[t.SequenceOf[m.Ldif.Entry]].fail(
                f"LDAP search failed: {error_desc} - {error_msg}",
            )
        try:
            server_type_enum = (
                server_type
                if isinstance(server_type, c.Ldif.ServerTypes)
                else c.Ldif.ServerTypes(server_type)
            )
        except ValueError:
            return r[t.SequenceOf[m.Ldif.Entry]].fail(
                f"Unsupported server type: {server_type}",
            )
        _ = server_type_enum
        ldap3_results = ResultConverter.convert_ldap3_results(connection)
        entries: t.MutableSequenceOf[m.Ldif.Entry] = []
        for dn, attrs in ldap3_results:
            str_attrs: t.MutableMappingKV[str, t.MutableSequenceOf[str] | str] = {
                k: list(v) for k, v in attrs.items()
            }
            entry_result = m.Ldif.Entry.create(dn=dn, attributes=str_attrs)
            if entry_result.failure:
                return r[t.SequenceOf[m.Ldif.Entry]].fail(
                    entry_result.error or "Failed to create LDAP search entry",
                )
            entries.append(entry_result.value)
        return r[t.SequenceOf[m.Ldif.Entry]].ok(entries)


__all__: list[str] = ["SearchExecutor"]
