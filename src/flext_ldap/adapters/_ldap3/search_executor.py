"""LDAP3 adapter — FlextLdapLdap3SearchExecutor.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections import deque
from collections.abc import MutableMapping, MutableSequence, Sequence
from itertools import islice

from flext_ldif import r

from flext_ldap.adapters._ldap3 import (
    FlextLdapLdap3ResultConverter,
    FlextLdapLdap3Wrappers,
)
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.typings import t


class FlextLdapLdap3SearchExecutor:
    """LDAP search executor (SRP).

    Stateless dispatcher: pipelines ldap3 searches on the one ASYNC connection
    via ``FlextLdapLdap3Wrappers``, validates each result code, then delegates
    parsing to ``FlextLdapLdap3ResultConverter``.
    """

    @staticmethod
    def execute(
        connection: p.Ldap.Ldap3Connection,
        params: Sequence[p.Ldap.SearchParams],
        server_type: c.Ldif.ServerTypes | str,
    ) -> Sequence[p.Result[Sequence[p.Ldif.Entry]]]:
        """Execute searches with a bounded number outstanding, in request order.

        At most ``c.Ldap.MAX_OUTSTANDING_SEARCHES`` requests wait on the wire,
        so the batch costs about one round trip instead of one per request.
        Each request keeps its own outcome, including its own send failure.

        Returns:
            One entries result per request.

        """
        outcomes: MutableSequence[p.Result[Sequence[p.Ldif.Entry]]] = []
        queued = iter(params)
        pending: deque[p.Result[int]] = deque()
        while True:
            pending.extend(
                FlextLdapLdap3SearchExecutor._send(connection, query)
                for query in islice(
                    queued, c.Ldap.MAX_OUTSTANDING_SEARCHES - len(pending)
                )
            )
            if not pending:
                return outcomes
            outcomes.append(
                pending.popleft().flat_map(
                    lambda message_id: FlextLdapLdap3SearchExecutor._receive(
                        connection, message_id, server_type
                    )
                )
            )

    @staticmethod
    def _send(
        connection: p.Ldap.Ldap3Connection, params: p.Ldap.SearchParams
    ) -> p.Result[int]:
        """Send one search without awaiting it.

        Returns:
            The request message id, or the failure raised while sending.

        """
        try:
            return r[int].ok(FlextLdapLdap3Wrappers.search(connection, params))
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[int].fail_op("Search", exc)

    @staticmethod
    def _receive(
        connection: p.Ldap.Ldap3Connection,
        message_id: int,
        server_type: c.Ldif.ServerTypes | str,
    ) -> p.Result[Sequence[p.Ldif.Entry]]:
        """Await one sent search and parse its entries.

        Returns:
            The parsed entries, or the failure of that request.

        """
        try:
            response, result = FlextLdapLdap3Wrappers.response(connection, message_id)
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[Sequence[p.Ldif.Entry]].fail_op("Search", exc)
        return FlextLdapLdap3SearchExecutor._entries(response, result, server_type)

    @staticmethod
    def _entries(
        response: Sequence[t.Ldap.Ldap3SearchResponse],
        result: t.JsonMapping,
        server_type: c.Ldif.ServerTypes | str,
    ) -> p.Result[Sequence[p.Ldif.Entry]]:
        """Validate one search result code and parse its entries.

        Returns:
            The parsed entries, or the LDAP failure with its description.

        """
        result_code = result.get("result", -1)
        if result_code not in c.Ldap.PARTIAL_SUCCESS_CODES:
            error_msg = result.get("message", "LDAP search failed")
            error_desc = result.get("description", "unknown")
            return r[Sequence[p.Ldif.Entry]].fail(
                f"LDAP search failed: {error_desc} - {error_msg}",
            )
        try:
            server_type_enum = (
                server_type
                if isinstance(server_type, c.Ldif.ServerTypes)
                else c.Ldif.ServerTypes(server_type)
            )
        except ValueError:
            return r[Sequence[p.Ldif.Entry]].fail(
                f"Unsupported server type: {server_type}",
            )
        _ = server_type_enum
        ldap3_results = FlextLdapLdap3ResultConverter.convert_ldap3_results(response)
        entries: MutableSequence[p.Ldif.Entry] = []
        for dn, attrs in ldap3_results:
            str_attrs: MutableMapping[str, MutableSequence[str] | str] = {
                k: list(v) for k, v in attrs.items()
            }
            entry_result = m.Ldif.Entry.create(dn=dn, attributes=str_attrs)
            if entry_result.failure:
                return r[Sequence[p.Ldif.Entry]].from_failure(entry_result)
            entries.append(entry_result.value)
        return r[Sequence[p.Ldif.Entry]].ok(entries)


__all__: list[str] = ["FlextLdapLdap3SearchExecutor"]
