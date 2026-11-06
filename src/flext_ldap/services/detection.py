"""Detect LDAP server type from a bound ``ldap3`` connection.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldap/services/detection
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_ldif import e

from flext_ldap.base import s
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.utilities import u


class FlextLdapServerDetector(s[p.Ldap.OperationResult]):
    """High-level detector that delegates rootDSE parsing to ``u.Ldap``."""

    @staticmethod
    def detect_from_connection(
        connection: p.Ldap.Ldap3Connection | p.Ldif.RootDseConnection,
    ) -> p.Result[str]:
        """Detect the effective LDAP server type from an active connection.

        Returns:
            The resulting ``p.Result[str]``.

        """
        detection_result: p.Result[str] = u.Ldap.detect_from_connection(connection)
        return detection_result

    @override
    def execute(
        self, **kwargs: p.Ldap.Ldap3Connection | str | float | bool | None
    ) -> p.Result[p.Ldap.OperationResult]:
        """Detect server type using the provided ``connection`` keyword argument.

        Returns:
            The resulting ``p.Result[p.Ldap.OperationResult]``.

        """
        connection_raw = kwargs.get("connection")
        if connection_raw is None:
            return e.fail_validation("connection", error="parameter required")
        if not isinstance(connection_raw, p.Ldap.Ldap3Connection):
            return e.fail_type_mismatch(
                m.ServiceLookupParams(
                    service_name="connection",
                    expected_type="ldap3.Connection",
                    actual_type=type(connection_raw).__name__,
                ),
            )
        return self.detect_from_connection(connection_raw).map(
            lambda detected_type: m.Ldap.OperationResult(
                success=True,
                operation_type=c.Ldap.OperationName.DETECT_FROM_CONNECTION,
                message=detected_type,
                entries_affected=0,
            ),
        )


__all__: list[str] = ["FlextLdapServerDetector"]
