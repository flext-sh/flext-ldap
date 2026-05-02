"""LDAP3 adapter service - Infrastructure wrapper for ldap3 library.

This module encapsulates all ldap3 library interactions, providing a clean
interface for the flext-ldap service layer. Only this adapter imports ldap3
directly; all other modules work with protocol abstractions.

Business Rules:
    - ldap3 library is ONLY imported here (zero tolerance for direct imports elsewhere)
    - Connection binding uses ldap3.Connection with auto_bind and auto_range options
    - STARTTLS is handled separately from SSL (mutual exclusion enforced in settings)
    - Search results are converted to m.Ldif.Entry via FlextLdifParser
    - CRUD operations (add, modify, delete) return r for consistency
    - LDAPException is caught and converted to r.fail() (no exceptions leak)

Audit Implications:
    - All LDAP operations are traceable via ldap3 connection logging
    - Connection failures are logged with host/port (credentials excluded)
    - Search operations log result counts for compliance reporting
    - CRUD operations log affected entry DNs for audit trail

Architecture Notes:
    - Implements Adapter pattern between ldap3 and flext-ldap service layer
    - Uses SRP via inner classes: ConnectionManager, ResultConverter, AttributeNormalizer
    - Extends s[bool] for health check capability
    - Pydantic frozen=False allows mutable connection state

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldap import FlextLdapEntryAdapter, c, m, p, s, t, u
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
from flext_ldif import e, r


class FlextLdapLdap3Adapter(s[bool]):
    """Service adapter for ldap3 library following flext-ldif patterns.

    Wraps ldap3 p.Ldap.Ldap3Connection and Server objects to provide a simplified
    interface for LDAP operations. Reuses FlextLdifParser for automatic
    conversion of LDAP results to Entry models.
    """

    model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=False)

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
        """Get underlying ldap3 Connection t.JsonValue."""
        return self._connection

    @property
    @override
    def is_connected(self) -> bool:
        """Check if adapter has an active connection."""
        if self._connection is None:
            return False
        return FlextLdapLdap3Adapter._is_bound(self._connection)

    @staticmethod
    def _map_scope(
        scope: c.Ldap.SearchScope | str,
    ) -> p.Result[int]:
        """Map scope string to ldap3 scope constant.

        Uses direct StrEnum value mapping for type-safe conversion.
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

    def add(
        self,
        entry: m.Ldif.Entry,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Add LDAP entry using Entry model.

        Business Rules:
            - Entry attributes are converted from m.Ldif.Entry to ldap3 format
            - DN is extracted using u.Ldif.get_dn_value()
            - Entry must be unique (LDAP error 68 if entry already exists)
            - Entry must conform to LDAP schema constraints
            - Connection must be established and bound before add operation

        Audit Implications:
            - Add operations are logged with entry DN
            - Successful adds log affected count (always 1)
            - Failed adds log error messages with DN for forensic analysis
            - Attribute conversion failures are logged before LDAP operation

        Architecture:
            - Uses FlextLdapEntryAdapter.ldif_entry_to_ldap3_attributes() for conversion
            - Uses OperationExecutor.execute_add() for protocol-level operation
            - Returns r pattern - no exceptions raised

        Args:
            entry: Entry model to add (must include DN and required attributes)

        Returns:
            r containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.failure:
            return r[m.Ldap.OperationResult].fail(
                connection_result.error or "",
            )
        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.failure:
            error_msg = attrs_result.error or ""
            return r[m.Ldap.OperationResult].fail(
                f"Failed to convert entry attributes: {error_msg}",
            )
        dn_str = u.Ldif.get_dn_value(entry.dn) if entry.dn is not None else "unknown"
        return self.OperationExecutor().execute_add(
            connection_result.value,
            dn_str,
            attrs_result.value,
        )

    def connect(
        self,
        settings: m.Ldap.ConnectionConfig,
    ) -> p.Result[bool]:
        """Establish LDAP connection using ldap3 library.

        Business Rules:
            - Creates ldap3 Server t.JsonValue based on SSL/TLS configuration
            - Creates ldap3 Connection t.JsonValue with bind credentials
            - STARTTLS is handled if use_tls=True and use_ssl=False
            - Connection must be bound (authenticated) to succeed
            - Connection state is tracked internally for subsequent operations

        Audit Implications:
            - Connection attempts are logged (host/port, credentials excluded)
            - TLS/SSL configuration is logged for security audit
            - Failed connections log error messages for forensic analysis
            - Connection state changes trigger audit events

        Architecture:
            - Uses ConnectionManager.create_server() for Server t.JsonValue
            - Uses ConnectionManager.create_connection() for Connection t.JsonValue
            - Uses ConnectionManager.handle_tls() for STARTTLS if needed
            - Returns r pattern - no exceptions raised

        Args:
            settings: Connection configuration (host, port, bind_dn, bind_password, SSL/TLS)

        Returns:
            r[bool] indicating connection success

        """
        try:
            self._server = self.ConnectionManager.create_server(settings)
            connection = self.ConnectionManager.create_connection(
                self._server,
                settings,
            )
            self._connection = connection
            tls_result = self.ConnectionManager.handle_tls(connection, settings)
            if tls_result.failure:
                return tls_result
            if not FlextLdapLdap3Wrappers.is_bound(connection):
                return e.fail_operation("bind to LDAP server")
            return r[bool].ok(value=True)
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
            t.Ldap.LDAPException,
        ) as exc:
            return r[bool].fail_op("Connection", exc)

    def delete(
        self,
        dn: str | m.Ldif.DN,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Delete LDAP entry.

        Business Rules:
            - Entry must exist before deletion (LDAP error 32 if not found)
            - Entry must not have children (LDAP error 66 if has children)
            - DN normalization is applied using u.Ldif.get_dn_value()
            - String DNs are converted to DN models for type safety
            - Connection must be established and bound before delete operation

        Audit Implications:
            - Delete operations are logged with DN for critical audit trail
            - Successful deletes log affected count (always 1)
            - Failed deletes log error messages with DN for forensic analysis

        Architecture:
            - Uses OperationExecutor.execute_delete() for protocol-level operation
            - DN conversion handled by u.Ldif
            - Returns r pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to delete (string or DN model)

        Returns:
            r containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.failure:
            return r[m.Ldap.OperationResult].fail(
                connection_result.error or "",
            )
        return self.OperationExecutor().execute_delete(connection_result.value, dn)

    def disconnect(self) -> None:
        """Close LDAP connection.

        Business Rules:
            - Gracefully closes LDAP connection and releases resources
            - No-op if already disconnected (idempotent operation)
            - Connection state is cleared after disconnection
            - Errors during unbind are logged but not propagated

        Audit Implications:
            - Disconnection errors are logged at DEBUG level
            - Connection state is cleared regardless of unbind success
            - Resource cleanup is guaranteed

        Architecture:
            - Uses ldap3 Connection.unbind() for protocol-level disconnection
            - Handles LDAPException and OSError gracefully
            - Always clears connection state (finally block)

        """
        if self._connection is not None:
            try:
                self._unbind_connection()
            finally:
                self._connection = None
                self._server = None

    @override
    def execute(self) -> p.Result[bool]:
        """Execute service health check.

        Business Rules:
            - Returns failure if connection is not bound (NOT_CONNECTED error)
            - Returns success if connection is active and bound
            - Does not perform network round-trip (cached state check)
            - Implements s.execute() contract

        Audit Implications:
            - Can be called by service orchestrators for health checks
            - Health status reflects connection state
            - No logging performed (lightweight check)

        Architecture:
            - Uses is_connected property for state check
            - Returns r pattern - no exceptions raised

        Returns:
            r[bool]: Success if connected, failure with NOT_CONNECTED if not.

        """
        if not self.is_connected:
            return r[bool].fail(c.Ldap.ErrorMessage.NOT_CONNECTED)
        return r[bool].ok(value=True)

    def modify(
        self,
        dn: str | m.Ldif.DN,
        changes: t.Ldap.OperationChanges,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Modify LDAP entry.

        Business Rules:
            - Entry must exist before modification (LDAP error 32 if not found)
            - Changes use ldap3 format: {attr_name: [(MODIFY_ADD|MODIFY_DELETE|MODIFY_REPLACE, [values])]}
            - DN normalization is applied using u.Ldif.get_dn_value()
            - String DNs are converted to DN models for type safety
            - Connection must be established and bound before modify operation

        Audit Implications:
            - Modify operations are logged with DN and change summary
            - Successful modifies log affected count (always 1)
            - Failed modifies log error messages with DN for forensic analysis

        Architecture:
            - Uses OperationExecutor.execute_modify() for protocol-level operation
            - DN conversion handled by u.Ldif
            - Returns r pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to modify (string or DN model)
            changes: Modification changes dict in ldap3 format

        Returns:
            r containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.failure:
            return r[m.Ldap.OperationResult].fail(
                connection_result.error or "",
            )
        return self.OperationExecutor().execute_modify(
            connection_result.value,
            dn,
            changes,
        )

    def search(
        self,
        search_options: m.Ldap.SearchOptions,
        server_type: c.Ldif.ServerTypes | str = c.Ldif.ServerTypes.RFC,
    ) -> p.Result[m.Ldap.SearchResult]:
        """Perform LDAP search operation and convert to Entry models.

        Business Rules:
            - Connection must be established and bound before search
            - Search scope is mapped from FlextLdapConstants to ldap3 format (ONELEVEL→LEVEL)
            - Server type determines parsing servers (OpenLDAP, OUD, OID, RFC)
            - Search results are parsed using FlextLdifParser.parse_ldap3_results()
            - Empty result sets return successful SearchResult with empty entries list
            - LDAP result codes are validated (partial success codes allowed)

        Audit Implications:
            - Search operations are logged with base_dn, filter, and scope
            - Result counts are logged for compliance reporting
            - Failed searches log error messages with search parameters
            - Server type normalization is logged for server tracking

        Architecture:
            - Uses SearchExecutor.execute() for protocol-level search
            - Uses FlextLdifParser for server-specific entry parsing
            - Returns r pattern - no exceptions raised

        Args:
            search_options: Search configuration (base_dn, filter_str, scope, attributes)
            server_type: LDAP server type for parsing servers (default: RFC)

        Returns:
            r containing SearchResult with Entry models

        """
        connection_result = self._get_connection()
        if connection_result.failure:
            error_msg = connection_result.error or ""
            return r[m.Ldap.SearchResult].fail(error_msg)
        scope_for_mapping: str | c.Ldap.SearchScope = search_options.scope
        scope_result = FlextLdapLdap3Adapter._map_scope(scope_for_mapping)
        if scope_result.failure:
            return r[m.Ldap.SearchResult].fail(
                scope_result.error or "",
            )
        search_params = m.Ldap.SearchParams(
            base_dn=search_options.base_dn,
            filter_str=search_options.filter_str,
            ldap_scope=scope_result.value,
            search_attributes=search_options.attributes or [],
            size_limit=search_options.size_limit,
            time_limit=search_options.time_limit,
        )
        entries_result = self.SearchExecutor().execute(
            connection_result.value,
            search_params,
            server_type,
        )
        if entries_result.failure:
            return r[m.Ldap.SearchResult].fail(
                entries_result.error or "",
            )
        return r[m.Ldap.SearchResult].ok(
            m.Ldap.SearchResult.model_validate({
                "entries": entries_result.value,
                "search_options": search_options,
            }),
        )

    def _get_connection(self) -> p.Result[p.Ldap.Ldap3Connection]:
        """Get connection with fast fail if not available."""
        if not self.is_connected or self._connection is None:
            return r[p.Ldap.Ldap3Connection].fail(c.Ldap.ErrorMessage.NOT_CONNECTED)
        return r[p.Ldap.Ldap3Connection].ok(self._connection)

    def _unbind_connection(self) -> None:
        """Unbind and close LDAP connection.

        This typed wrapper handles the untyped ldap3 unbind() call.
        Propagates exceptions to callers for explicit error handling.
        """
        if self._connection is not None:
            _ = FlextLdapLdap3Wrappers.unbind(self._connection)
