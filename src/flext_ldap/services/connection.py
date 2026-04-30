"""LDAP connection lifecycle MRO mixin.

Encapsulates connection creation, binding, and teardown while delegating the
protocol surface to :class:`~flext_ldap.adapters.ldap3.FlextLdapLdap3Adapter`. The
mixin keeps retries and optional heuristic server detection close to the
connection so the composed facade interacts with a single, typed entry point.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_ldap import FlextLdapServerDetector, c, m, p, s, u
from flext_ldif import r


class FlextLdapConnection(s):
    """Manage the LDAP connection lifecycle as an MRO mixin.

    Wraps ``FlextLdapLdap3Adapter`` to create/bind connections, optionally
    retry transient errors, and perform lightweight server detection after a
    successful bind. Adapter is initialized lazily on first ``connect()`` call.
    """

    def connect(
        self,
        connection_config: m.Ldap.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = c.Ldap.DEFAULT_MAX_RETRIES,
        retry_delay: float = c.Ldap.DEFAULT_RETRY_DELAY,
    ) -> p.Result[bool]:
        """Establish an LDAP connection with optional automatic retry."""
        adapter = self._ensure_adapter()

        def connect_once() -> r[bool]:
            connect_result = adapter.connect(connection_config)
            if connect_result.success:
                return r[bool].ok(value=connect_result.value)
            return r[bool].fail(connect_result.error)

        result: p.Result[bool] = (
            u.retry(
                operation=connect_once,
                max_attempts=max_retries,
                delay_seconds=retry_delay,
            )
            if auto_retry
            else adapter.connect(connection_config)
        )
        if result.success:
            try:
                self._detect_server_type_optional()
            except Exception as exc:  # pragma: no cover
                self.logger.debug(
                    "Server detection raised an exception and will be ignored",
                    operation=c.Ldap.OperationName.CONNECT,
                    error=str(exc),
                )
            return r[bool].ok(value=True)
        return result

    def disconnect(self) -> None:
        """Close the active LDAP connection if present."""
        if self._adapter is not None:
            self._adapter.disconnect()
        self._server_type = c.Ldap.DEFAULT_TYPE

    @override
    def execute(
        self,
    ) -> p.Result[m.Ldap.Response]:
        """Execute service health check."""
        if self.is_connected:
            return r[m.Ldap.Response].ok(
                m.Ldap.SearchResult(entries=[], search_options=None),
            )
        return r[m.Ldap.Response].fail(str(c.Ldap.ErrorMessage.NOT_CONNECTED))

    def _detect_server_type_optional(self) -> None:
        """Attempt automatic server type detection after successful connection."""
        adapter = self._ensure_adapter()
        connection = adapter.connection
        if not connection:
            return
        detector = FlextLdapServerDetector()
        detection_result: p.Result[str] = detector.detect_from_connection(connection)
        if detection_result.success:
            self._server_type = detection_result.value
            self.logger.info(
                "Server type detected automatically",
                operation=c.Ldap.OperationName.CONNECT,
                detected_server_type=detection_result.value,
            )
        else:
            self.logger.debug(
                "Server type detection failed (non-critical)",
                operation=c.Ldap.OperationName.CONNECT,
                error=detection_result.error or "",
            )
