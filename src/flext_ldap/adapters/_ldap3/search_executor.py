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
    """Search operation execution logic (SRP)."""

    def __init__(self) -> None:
        """Initialize search executor with adapter instance.

        Business Rules:
            - Adapter is REQUIRED (no default, fail-fast pattern)
            - Executor stores reference for delegation to adapter
            - No connection validation at init (validated during execute)

        Architecture:
            - Inner class encapsulates search execution logic (SRP)
            - Uses ResultConverter directly for ldap3-result translation

        """
        super().__init__()

    def execute(
        self,
        connection: p.Ldap.Ldap3Connection,
        params: m.Ldap.SearchParams,
        server_type: c.Ldif.ServerTypes | str,
    ) -> p.Result[t.SequenceOf[m.Ldif.Entry]]:
        """Execute LDAP search and convert results.

        Business Rules:
            - Performs ldap3 Connection.search() with provided parameters
            - Validates LDAP result codes (allows partial success codes)
            - Parses results using FlextLdifParser.parse_ldap3_results()
            - Converts ParseResponse to t.SequenceOf[Entry] via ResultConverter
            - LDAPException is caught and converted to r.fail()

        Audit Implications:
            - Search parameters are logged by connection.search()
            - Result codes are validated for compliance
            - Server type normalization enables server application
            - Parse failures are logged with error details

        Architecture:
            - Uses ldap3 Connection.search() for protocol-level operation
            - Delegates to FlextLdifParser for server-specific parsing
            - Uses ResultConverter.convert_parsed_entries() for Entry conversion
            - Returns r pattern - no exceptions raised

        Args:
            connection: Active ldap3.Connection instance (must be bound).
            params: SearchParams dataclass with all search parameters.
            server_type: Server type (ServerTypes enum or string) for parsing servers.

        Returns:
            r[t.SequenceOf[Entry]]: Parsed entries or error if search/parse fails.

        """
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
            conn_result = connection.result or {}
            result_code = conn_result.get("result", -1)
            if result_code not in c.Ldap.PARTIAL_SUCCESS_CODES:
                error_msg = conn_result.get("message", "LDAP search failed")
                error_desc = conn_result.get("description", "unknown")
                return r[t.SequenceOf[m.Ldif.Entry]].fail(
                    f"LDAP search failed: {error_desc} - {error_msg}",
                )
            ldap3_results = ResultConverter.convert_ldap3_results(
                connection,
            )
            if isinstance(server_type, c.Ldif.ServerTypes):
                server_type_str = server_type.value
            else:
                server_type_str = server_type
            valid_server_types = {
                c.Ldif.ServerTypes.RFC,
                c.Ldif.ServerTypes.OID,
                c.Ldif.ServerTypes.OUD,
                c.Ldif.ServerTypes.OPENLDAP,
                c.Ldif.ServerTypes.OPENLDAP1,
                c.Ldif.ServerTypes.APACHE,
                c.Ldif.ServerTypes.DS389,
                c.Ldif.ServerTypes.NOVELL,
                c.Ldif.ServerTypes.IBM_TIVOLI,
                c.Ldif.ServerTypes.AD,
                c.Ldif.ServerTypes.RELAXED,
            }
            if server_type_str not in valid_server_types:
                return r[t.SequenceOf[m.Ldif.Entry]].fail(
                    f"Unsupported server type: {server_type_str}",
                )
            entries: t.MutableSequenceOf[m.Ldif.Entry] = []
            for dn, attrs in ldap3_results:
                str_attrs: t.MutableMappingKV[str, t.MutableSequenceOf[str] | str] = {
                    k: list(v) for k, v in attrs.items()
                }
                entry_result = m.Ldif.Entry.create(
                    dn=dn,
                    attributes=str_attrs,
                )
                if entry_result.failure:
                    return r[t.SequenceOf[m.Ldif.Entry]].fail(
                        entry_result.error or "Failed to create LDAP search entry",
                    )
                entries.append(entry_result.value)
            return r[t.SequenceOf[m.Ldif.Entry]].ok(entries)
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[t.SequenceOf[m.Ldif.Entry]].fail_op("Search", exc)


__all__: list[str] = ["SearchExecutor"]
