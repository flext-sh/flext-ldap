"""LDAP connection lifecycle MRO mixin.

Encapsulates connection creation, binding, and teardown while delegating the
protocol surface to :class:`~flext_ldap.adapters.ldap3.FlextLdapLdap3Adapter`. The
mixin keeps retries and optional heuristic server detection close to the
connection so the composed facade interacts with a single, typed entry point.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from pydantic import ConfigDict, PrivateAttr

from flext_core import r
from flext_ldap import (
    FlextLdapServerDetector,
    FlextLdapServiceBase,
    FlextLdapSettings,
    c,
    m,
    u,
)
from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter
from flext_ldif import FlextLdif


class FlextLdapConnection(FlextLdapServiceBase[m.Ldap.SearchResult]):
    """Manage the LDAP connection lifecycle as an MRO mixin.

    Wraps ``FlextLdapLdap3Adapter`` to create/bind connections, optionally
    retry transient errors, and perform lightweight server detection after a
    successful bind. Adapter is initialized lazily on first ``connect()`` call.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=False,
        extra="forbid",
        arbitrary_types_allowed=True,
    )
    _adapter: FlextLdapLdap3Adapter | None = PrivateAttr(default=None)
    _ldif: FlextLdif | None = PrivateAttr(default=None)

    @classmethod
    @override
    def _get_service_config_type(cls) -> type[FlextLdapSettings]:
        return FlextLdapSettings

    def _ensure_adapter(self) -> FlextLdapLdap3Adapter:
        """Return adapter, creating it lazily if needed."""
        if self._adapter is None:
            self._adapter = FlextLdapLdap3Adapter()
        return self._adapter

    def _get_ldif(self) -> FlextLdif:
        """Return FlextLdif instance, creating lazily if needed."""
        if self._ldif is None:
            self._ldif = FlextLdif()
        return self._ldif

    @property
    def adapter(self) -> FlextLdapLdap3Adapter:
        """Get the underlying ldap3 adapter for direct protocol access."""
        return self._ensure_adapter()

    @property
    def is_connected(self) -> bool:
        """Check if service has an active, bound LDAP connection."""
        if self._adapter is None:
            return False
        return self._adapter.is_connected

    def connect(
        self,
        connection_config: m.Ldap.ConnectionConfig,
        *,
        auto_retry: bool = False,
        max_retries: int = c.Ldap.ConnectionDefaults.DEFAULT_MAX_RETRIES,
        retry_delay: float = c.Ldap.ConnectionDefaults.DEFAULT_RETRY_DELAY,
        **_kwargs: str | float | bool | None,
    ) -> r[bool]:
        """Establish an LDAP connection with optional automatic retry."""
        adapter = self._ensure_adapter()
        result: r[bool] = (
            u.retry(
                operation=lambda: adapter.connect(connection_config),
                max_attempts=max_retries,
                delay_seconds=retry_delay,
            )
            if auto_retry
            else adapter.connect(connection_config)
        )
        if result.success:
            self._detect_server_type_optional()
            return r[bool].ok(value=True)
        return result

    def disconnect(self) -> None:
        """Close the active LDAP connection if present."""
        if self._adapter is not None:
            self._adapter.disconnect()

    @override
    def execute(self, **_kwargs: str | float | bool | None) -> r[m.Ldap.SearchResult]:
        """Execute service health check."""
        if self.is_connected:
            return r[m.Ldap.SearchResult].ok(
                m.Ldap.SearchResult(entries=[], search_options=None),
            )
        return r[m.Ldap.SearchResult].fail(str(c.Ldap.ErrorStrings.NOT_CONNECTED))

    def _detect_server_type_optional(self) -> None:
        """Attempt automatic server type detection after successful connection."""
        adapter = self._ensure_adapter()
        connection = adapter.connection
        if not connection:
            return
        detector = FlextLdapServerDetector()
        detection_result: r[str] = detector.detect_from_connection(connection)
        if detection_result.success:
            self.logger.info(
                "Server type detected automatically",
                operation=c.Ldap.LdapOperationNames.CONNECT,
                detected_server_type=detection_result.value,
            )
        else:
            self.logger.debug(
                "Server type detection failed (non-critical)",
                operation=c.Ldap.LdapOperationNames.CONNECT,
                error=str(detection_result.error) if detection_result.error else "",
            )
