"""LDAP3 adapter — sole owner of ldap3 imports for flext-ldap.

Per AGENTS.md §2.7 (library abstraction): only this directory may import
``ldap3`` directly; consumers depend on the ``p.Ldap`` protocols.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldap import c, m, p, s, t, u
from flext_ldap.adapters._ldap3.connection_manager import (
    ConnectionManager as _ConnectionManager,
)
from flext_ldap.adapters._ldap3.operation_executor import (
    OperationExecutor as _OperationExecutor,
)
from flext_ldap.adapters._ldap3.result_converter import (
    ResultConverter as _ResultConverter,
)
from flext_ldap.adapters._ldap3.search_executor import (
    SearchExecutor as _SearchExecutor,
)
from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldif import e, r


class FlextLdapLdap3Adapter(s[bool]):
    """Service adapter for ldap3 library following flext-ldif patterns.

    Wraps ldap3 p.Ldap.Ldap3Connection and Server objects to provide a simplified
    interface for LDAP operations. Reuses FlextLdifParser for automatic
    conversion of LDAP results to Entry models.
    """

    model_config = m.ConfigDict(frozen=False)

    @staticmethod
    def _is_bound(connection: p.Ldap.Ldap3Connection) -> bool:
        """Check if ldap3 p.Ldap.Ldap3Connection is bound."""
        bound_state: bool = getattr(connection, "bound", False)
        return bound_state

    ConnectionManager: ClassVar[type[_ConnectionManager]] = _ConnectionManager
    ResultConverter: ClassVar[type[_ResultConverter]] = _ResultConverter
    OperationExecutor: ClassVar[type[_OperationExecutor]] = _OperationExecutor
    SearchExecutor: ClassVar[type[_SearchExecutor]] = _SearchExecutor

    _connection: p.Ldap.Ldap3Connection | None
    _server: p.Ldap.Ldap3Server | None
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
        """Check if adapter has an active connection."""
        if self._connection is None:
            return False
        return FlextLdapLdap3Adapter._is_bound(self._connection)

    @staticmethod
    def _map_scope(
        scope: c.Ldap.SearchScope | str,
    ) -> p.Result[int]:
        """Map scope string to ldap3 scope constant."""
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

    def add(
        self,
        entry: m.Ldif.Entry,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Add LDAP entry via railway: connection → attrs conversion → execute_add."""
        return self._get_connection().flat_map(
            lambda conn: (
                self._entry_adapter
                .ldif_entry_to_ldap3_attributes(
                    entry,
                )
                .map_error(lambda err: f"Failed to convert entry attributes: {err}")
                .flat_map(
                    lambda attrs: self.OperationExecutor.execute_add(
                        conn,
                        u.Ldif.get_dn_value(entry.dn)
                        if entry.dn is not None
                        else "unknown",
                        attrs,
                    ),
                )
            ),
        )

    def connect(
        self,
        settings: m.Ldap.ConnectionConfig,
    ) -> p.Result[bool]:
        """Establish ldap3 server+connection, run STARTTLS, verify bind."""
        try:
            connection = self._create_connection(settings)
        except c.Ldap.EXC_CONNECTION as exc:
            return r[bool].fail_op("Connection", exc)
        tls_result = self.ConnectionManager.handle_tls(connection, settings)
        if tls_result.failure:
            return tls_result
        if not FlextLdapLdap3Wrappers.is_bound(connection):
            return e.fail_operation("bind to LDAP server")
        return r[bool].ok(value=True)

    def delete(
        self,
        dn: str | m.Ldif.DN,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Delete LDAP entry via railway: connection → execute_delete."""
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
        """Service health check — succeeds when the connection is bound."""
        if not self.is_connected:
            return r[bool].fail(c.Ldap.ErrorMessage.NOT_CONNECTED)
        return r[bool].ok(value=True)

    def modify(
        self,
        dn: str | m.Ldif.DN,
        changes: t.Ldap.OperationChanges,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Modify LDAP entry via railway: connection → execute_modify."""
        return self._get_connection().flat_map(
            lambda conn: self.OperationExecutor.execute_modify(conn, dn, changes),
        )

    def search(
        self,
        search_options: m.Ldap.SearchOptions,
        server_type: c.Ldif.ServerTypes | str = c.Ldif.ServerTypes.RFC,
    ) -> p.Result[m.Ldap.SearchResult]:
        """Perform LDAP search and wrap entries in ``m.Ldap.SearchResult``."""
        return (
            self
            ._get_connection()
            .flat_map(
                lambda conn: FlextLdapLdap3Adapter._map_scope(
                    search_options.scope,
                ).flat_map(
                    lambda scope: self.SearchExecutor.execute(
                        conn,
                        m.Ldap.SearchParams(
                            base_dn=search_options.base_dn,
                            filter_str=search_options.filter_str,
                            ldap_scope=scope,
                            search_attributes=search_options.attributes or [],
                            size_limit=search_options.size_limit,
                            time_limit=search_options.time_limit,
                        ),
                        server_type,
                    ),
                ),
            )
            .map(
                lambda entries: m.Ldap.SearchResult(
                    entries=entries,
                    search_options=search_options,
                ),
            )
        )

    def _get_connection(self) -> p.Result[p.Ldap.Ldap3Connection]:
        """Get connection with fast fail if not available."""
        if not self.is_connected or self._connection is None:
            return r[p.Ldap.Ldap3Connection].fail(c.Ldap.ErrorMessage.NOT_CONNECTED)
        return r[p.Ldap.Ldap3Connection].ok(self._connection)

    def _create_connection(
        self,
        settings: m.Ldap.ConnectionConfig,
    ) -> p.Ldap.Ldap3Connection:
        """Create and store the ldap3 server and connection pair."""
        self._server = self.ConnectionManager.create_server(settings)
        connection = self.ConnectionManager.create_connection(
            self._server,
            settings,
        )
        self._connection = connection
        return connection

    def _unbind_connection(self) -> None:
        """Unbind and close LDAP connection."""
        if self._connection is not None:
            _ = FlextLdapLdap3Wrappers.unbind(self._connection)


class FlextLdapAdapterHost[
    TResult: t.JsonPayload | t.SequenceOf[t.JsonPayload] = t.JsonPayload
    | t.SequenceOf[t.JsonPayload],
](s[TResult]):
    """Own the shared ldap3 adapter behind the ``p.Ldap.LdapAdapter`` contract.

    Service mixins inherit this host to obtain the lazily constructed adapter
    via DIP: callers depend on the protocol while this module (the sole ldap3
    owner per AGENTS.md §2.7) constructs the concrete implementation.
    """

    _adapter: p.Ldap.LdapAdapter | None = u.PrivateAttr(default_factory=lambda: None)

    def _ensure_adapter(self) -> p.Ldap.LdapAdapter:
        """Return the shared ldap3 adapter for this service instance."""
        if self._adapter is None:
            self._adapter = FlextLdapLdap3Adapter()
        return self._adapter

    @property
    def is_connected(self) -> bool:
        """The ``True`` when the shared adapter has an active bind."""
        adapter = self._adapter
        if adapter is None:
            return False
        return adapter.is_connected
