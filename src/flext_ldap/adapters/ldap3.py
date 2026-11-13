"""LDAP3 adapter — sole owner of ldap3 imports for flext-ldap.

Per AGENTS.md §2.7 (library abstraction): only this directory may import
``ldap3`` directly; consumers depend on the ``p.Ldap`` protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from itertools import starmap
from typing import ClassVar, override

from flext_ldif import e, r
from ldap3 import Server
from ldap3.utils.conv import escape_filter_chars

from flext_ldap.adapters import FlextLdapEntryAdapter
from flext_ldap.adapters._ldap3 import (
    FlextLdapLdap3ConnectionManager,
    FlextLdapLdap3OperationExecutor,
    FlextLdapLdap3ResultConverter,
    FlextLdapLdap3SearchExecutor,
    FlextLdapLdap3Wrappers,
)
from flext_ldap.base import s
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.typings import t
from flext_ldap.utilities import u


class FlextLdapLdap3Adapter(s[bool]):
    """Service adapter for ldap3 library following flext-ldif patterns.

    Wraps ldap3 p.Ldap.Ldap3Connection and Server objects to provide a simplified
    interface for LDAP operations. Reuses FlextLdifParser for automatic
    conversion of LDAP results to Entry models.
    """

    model_config = m.ConfigDict(frozen=False)

    ConnectionManager: ClassVar[type[FlextLdapLdap3ConnectionManager]] = (
        FlextLdapLdap3ConnectionManager
    )
    ResultConverter: ClassVar[type[FlextLdapLdap3ResultConverter]] = (
        FlextLdapLdap3ResultConverter
    )
    OperationExecutor: ClassVar[type[FlextLdapLdap3OperationExecutor]] = (
        FlextLdapLdap3OperationExecutor
    )
    SearchExecutor: ClassVar[type[FlextLdapLdap3SearchExecutor]] = (
        FlextLdapLdap3SearchExecutor
    )

    _connection: p.Ldap.Ldap3Connection | None
    _server: p.Ldif.Ldap3Server | None
    _entry_adapter: FlextLdapEntryAdapter

    def __init__(self) -> None:
        """Initialize adapter service."""
        self._connection = None
        self._server = None
        self._entry_adapter = FlextLdapEntryAdapter()

    @property
    def connection(self) -> p.Ldap.Ldap3Connection | None:
        """The underlying ldap3 Connection t.JsonValue."""
        return self._connection

    @property
    def is_connected(self) -> bool:
        """Whether adapter has an active connection."""
        if self._connection is None:
            return False
        return FlextLdapLdap3Wrappers.bound(self._connection)

    @staticmethod
    def _map_scope(scope: c.Ldap.SearchScope | str) -> p.Result[int]:
        """Map scope string to ldap3 scope constant.

        Returns:
            The resulting ``p.Result[int]``.

        """
        scope_enum: c.Ldap.SearchScope
        if isinstance(scope, c.Ldap.SearchScope):
            scope_enum = scope
        else:
            try:
                scope_enum = c.Ldap.SearchScope(scope.upper())
            except ValueError:
                return r[int].fail(f"Invalid LDAP scope: {scope}")
        if scope_enum in c.Ldap.LDAP3_SCOPE_BY_SEARCH_SCOPE:
            ldap3_value = c.Ldap.LDAP3_SCOPE_BY_SEARCH_SCOPE[scope_enum]
            return r[int].ok(int(ldap3_value))
        return r[int].fail(f"Invalid LDAP scope: {scope}")

    def root_dse(
        self, attributes: t.StrSequence
    ) -> p.Result[t.Ldap.OperationAttributes]:
        """Read the requested Root DSE attributes on the bound connection.

        Returns:
            The Root DSE attribute values, or the original read failure.

        """
        root = m.Ldap.SearchParams(
            base_dn="",
            filter_str=c.Ldap.ALL_ENTRIES_FILTER,
            ldap_scope=c.Ldap.SearchScopeValue.BASE,
            search_attributes=list(attributes),
            size_limit=0,
            time_limit=0,
        )
        found = self._get_connection().flat_map(
            lambda connection: self.SearchExecutor.execute(
                connection, [root], c.Ldif.ServerTypes.RFC
            )[0]
        )
        if found.failure:
            return r[t.Ldap.OperationAttributes].from_failure(found)
        if len(found.value) != 1:
            return r[t.Ldap.OperationAttributes].fail(
                "Root DSE search did not return one entry"
            )
        return r[t.Ldap.OperationAttributes].ok(found.value[0].attributes_dict)

    def supports_control(self, oid: str) -> p.Result[bool]:
        """Read advertised controls directly from the Root DSE.

        Returns:
            Whether the control is advertised, or the original capability failure.

        """
        return self.root_dse(["supportedControl"]).map(
            lambda attributes: (
                oid
                in next(
                    (
                        values
                        for name, values in attributes.items()
                        if name.lower() == "supportedcontrol"
                    ),
                    (),
                )
            )
        )

    def is_user_attribute(self, attribute: str) -> p.Result[bool]:
        """Read RFC 4512 USAGE from the SDK schema already loaded at bind.

        Returns:
            Whether this attribute is returned by `*`, or the missing fact.

        """
        connected = self._get_connection()
        if connected.failure:
            return r[bool].from_failure(connected)
        server = connected.value.server
        if not isinstance(server, Server) or server.schema is None:
            return r[bool].fail("Native LDAP schema metadata is unavailable")
        definition = server.schema.attribute_types.get(attribute.split(";", 1)[0])
        if definition is None:
            return r[bool].fail(
                f"Native schema has no attribute definition: {attribute}"
            )
        usage = definition.usage
        if usage is None or usage == "USER_APPLICATION":
            return r[bool].ok(value=True)
        if usage in {"DIRECTORY_OPERATION", "DISTRIBUTED_OPERATION", "DSA_OPERATION"}:
            return r[bool].ok(value=False)
        return r[bool].fail(f"Unknown native attribute USAGE: {usage}")

    @staticmethod
    def rdn_filter(dns: t.StrSequence) -> p.Result[str]:
        """Build an RFC 4515 OR of native decoded RDN conjunctions.

        Returns:
            The filter or the first invalid DN/RDN.

        """
        terms: list[str] = []
        for dn in dns:
            rdn = u.Ldif.parse_rdn(u.Ldif.split(dn)[0])
            if rdn.failure:
                return r[str].from_failure(rdn)
            pairs = [f"({a}={escape_filter_chars(v)})" for a, v in rdn.value]
            terms.append(pairs[0] if len(pairs) == 1 else "(&" + "".join(pairs) + ")")
        return r[str].ok("(|" + "".join(terms) + ")")

    def add(self, entry: p.Ldif.Entry) -> p.Result[p.Ldap.OperationResult]:
        """Add LDAP entry via railway: connection → attrs conversion → execute_add.

        Returns:
            The resulting ``p.Result[p.Ldap.OperationResult]``.

        """
        return self._get_connection().flat_map(
            lambda conn: (
                self._entry_adapter
                .ldif_entry_to_ldap3_attributes(entry)
                .map_error(lambda err: f"Failed to convert entry attributes: {err}")
                .flat_map(
                    lambda attrs: self.OperationExecutor.execute_add(
                        conn,
                        u.Ldif.resolve_dn_value(entry.dn)
                        if entry.dn is not None
                        else "unknown",
                        attrs,
                    ),
                )
            ),
        )

    def connect(self, settings: p.Ldap.ConnectionConfig) -> p.Result[bool]:
        """Establish ldap3 server+connection, run STARTTLS, verify bind.

        Returns:
            The resulting ``p.Result[bool]``.

        """
        try:
            # A second connect() on a live adapter orphans the previous
            # connection's socket (dropped without unbind). Release it first.
            if self._connection is not None:
                self.disconnect()
            connection = self._create_connection(settings)
        except c.Ldap.EXC_CONNECTION as exc:
            return r[bool].fail_op("Connection", exc)
        connected = False
        try:
            tls_result = self.ConnectionManager.handle_tls(connection, settings)
            if tls_result.failure:
                return tls_result
            if settings.auto_bind:
                try:
                    bound = FlextLdapLdap3Wrappers.bind(connection)
                except c.Ldap.EXC_CONNECTION as exc:
                    return r[bool].fail_op("Connection", exc)
                if not bound:
                    return e.fail_operation("bind to LDAP server")
            if not FlextLdapLdap3Wrappers.bound(connection):
                return e.fail_operation("bind to LDAP server")
            connected = True
            return r[bool].ok(value=True)
        finally:
            if not connected:
                self.disconnect()

    def delete(self, dn: str | m.Ldif.DN) -> p.Result[p.Ldap.OperationResult]:
        """Delete LDAP entry via railway: connection → execute_delete.

        Returns:
            The resulting ``p.Result[p.Ldap.OperationResult]``.

        """
        return self._get_connection().flat_map(
            lambda conn: self.OperationExecutor.execute_delete(conn, dn),
        )

    def disconnect(self) -> None:
        """Idempotent unbind that always clears connection state."""
        if self._connection is not None:
            try:
                self._unbind_connection()
            finally:
                self._connection = None
                self._server = None

    @override
    def execute(self) -> p.Result[bool]:
        """Service health check — succeeds when the connection is bound.

        Returns:
            The resulting ``p.Result[bool]``.

        """
        if not self.is_connected:
            return r[bool].fail(c.Ldap.ErrorMessage.NOT_CONNECTED)
        return r[bool].ok(value=True)

    def modify(
        self,
        dn: str | m.Ldif.DN,
        changes: t.Ldap.OperationChanges,
    ) -> p.Result[p.Ldap.OperationResult]:
        """Modify LDAP entry via railway: connection → execute_modify.

        Returns:
            The resulting ``p.Result[p.Ldap.OperationResult]``.

        """
        return self._get_connection().flat_map(
            lambda conn: self.OperationExecutor.execute_modify(conn, dn, changes),
        )

    def search_many(
        self,
        searches: Sequence[p.Ldap.SearchOptions],
        server_type: c.Ldif.ServerTypes | str = c.Ldif.ServerTypes.RFC,
    ) -> p.Result[Sequence[p.Result[p.Ldap.SearchResult]]]:
        """Pipeline LDAP searches and wrap each in ``m.Ldap.SearchResult``.

        Returns:
            One search result per request in request order, or the first
            connection or scope failure.

        """
        return (
            self
            ._get_connection()
            .flat_map(
                lambda connection: (
                    r[p.Ldap.SearchParams]
                    .traverse(searches, self._search_params, exceptions=())
                    .map(
                        lambda params: self.SearchExecutor.execute(
                            connection, params, server_type
                        )
                    )
                )
            )
            .map(
                lambda outcomes: list(
                    starmap(self._search_result, zip(outcomes, searches, strict=True))
                )
            )
        )

    @staticmethod
    def _search_params(
        options: p.Ldap.SearchOptions,
    ) -> p.Result[p.Ldap.SearchParams]:
        """Translate one request into native ldap3 search parameters.

        Returns:
            The ldap3 parameters, or the invalid scope failure.

        """
        return FlextLdapLdap3Adapter._map_scope(options.scope).map(
            lambda scope: m.Ldap.SearchParams(
                base_dn=options.base_dn,
                filter_str=options.filter_str,
                ldap_scope=scope,
                search_attributes=options.attributes or [],
                size_limit=options.size_limit,
                time_limit=options.time_limit,
                controls=options.controls,
            )
        )

    @staticmethod
    def _search_result(
        outcome: p.Result[Sequence[p.Ldif.Entry]],
        options: p.Ldap.SearchOptions,
    ) -> p.Result[p.Ldap.SearchResult]:
        """Wrap one request's entries with the options that produced them.

        Returns:
            The search result, or the request's own LDAP failure.

        """
        return outcome.map(
            lambda entries: m.Ldap.SearchResult(entries=entries, search_options=options)
        )

    def _get_connection(self) -> p.Result[p.Ldap.Ldap3Connection]:
        """Get connection with fast fail if not available.

        Returns:
            The resulting ``p.Result[p.Ldap.Ldap3Connection]``.

        """
        if not self.is_connected or self._connection is None:
            return r[p.Ldap.Ldap3Connection].fail(c.Ldap.ErrorMessage.NOT_CONNECTED)
        return r[p.Ldap.Ldap3Connection].ok(self._connection)

    def _create_connection(
        self,
        settings: p.Ldap.ConnectionConfig,
    ) -> p.Ldap.Ldap3Connection:
        """Create and store the ldap3 server and connection pair.

        Returns:
            The resulting ``p.Ldap.Ldap3Connection``.

        """
        self._server = self.ConnectionManager.create_server(settings)
        connection = self.ConnectionManager.create_connection(self._server, settings)
        self._connection = connection
        return connection

    def _unbind_connection(self) -> None:
        """Unbind and close LDAP connection."""
        if self._connection is not None:
            _ = FlextLdapLdap3Wrappers.unbind(self._connection)


__all__: list[str] = ["FlextLdapLdap3Adapter"]
