"""Detect LDAP server type from a bound ``ldap3`` connection."""

from __future__ import annotations

from typing import override

from flext_ldif import r

from flext_ldap.base import s
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.typings import t
from flext_ldap.utilities import u


class FlextLdapServerDetector(s):
    """High-level detector that delegates rootDSE parsing to ``u.Ldap``."""

    @staticmethod
    def _get_first_value(attrs: t.Ldap.OperationAttributes, key: str) -> str | None:
        """Compatibility shim for unit tests and older callers."""
        return u.Ldap.get_first_attribute_value(attrs, key)

    @staticmethod
    def _detect_from_attributes(
        vendor_name: str | None,
        vendor_version: str | None,
        naming_contexts: t.StrSequence,
        _supported_controls: t.StrSequence,
        supported_extensions: t.StrSequence,
    ) -> p.Result[str]:
        """Compatibility shim that delegates heuristic detection to utilities."""
        _ = _supported_controls
        return r[str].ok(
            u.Ldap.detect_server_type(
                vendor_name=vendor_name,
                vendor_version=vendor_version,
                naming_contexts=naming_contexts,
                supported_extensions=supported_extensions,
            ),
        )

    def detect_from_connection(
        self,
        connection: p.Ldap.Ldap3Connection,
    ) -> p.Result[str]:
        """Detect the effective LDAP server type from an active connection."""
        return u.Ldap.detect_from_connection(connection)

    @override
    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> p.Result[m.Ldap.Response]:
        """Detect server type using the provided ``connection`` keyword argument."""
        connection_raw = _kwargs.get("connection")
        if connection_raw is None:
            return r[m.Ldap.Response].fail("connection parameter required")
        if not isinstance(connection_raw, p.Ldap.Ldap3Connection):
            return r[m.Ldap.Response].fail(
                f"connection must be ldap3.Connection, got {type(connection_raw).__name__}",
            )
        return self.detect_from_connection(connection_raw).map(
            lambda detected_type: m.Ldap.OperationResult(
                success=True,
                operation_type=c.Ldap.LdapOperationNames.DETECT_FROM_CONNECTION,
                message=detected_type,
                entries_affected=0,
            ),
        )
