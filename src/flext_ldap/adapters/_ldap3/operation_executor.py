"""LDAP3 adapter — OperationExecutor.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldap import c, m, p, t, u
from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
from flext_ldif import r

if TYPE_CHECKING:
    from collections.abc import Callable


class OperationExecutor:
    """LDAP add/modify/delete dispatcher (SRP).

    Single ``_execute`` boundary translates ldap3 wrapper return values into
    ``r[p.Ldap.OperationResult]`` and centralises message generation through
    ``c.Ldap.OPERATION_SUCCESS_MESSAGES`` / ``OPERATION_FAILURE_PREFIXES``.
    """

    class ResultPayload(m.BaseModel):
        """Validated ldap3 operation result payload."""

        model_config = m.ConfigDict(frozen=True, extra="ignore")
        description: str | None = None

        @u.field_validator("description", mode="before")
        @classmethod
        def normalize_description(
            cls, value: t.Scalar | t.JsonList | t.JsonMapping | None
        ) -> str | None:
            """Normalize ldap3 JSON descriptions into the operation message text."""
            if value is None:
                return None
            if isinstance(value, str):
                return value
            return repr(value)

    @staticmethod
    def _execute(
        connection: p.Ldap.Ldap3Connection,
        operation_type: c.Ldap.OperationType,
        wrapper_call: Callable[[], bool],
    ) -> p.Result[p.Ldap.OperationResult]:
        failure_prefix = c.Ldap.OPERATION_FAILURE_PREFIXES[operation_type]
        try:
            if wrapper_call():
                return r[p.Ldap.OperationResult].ok(
                    m.Ldap.OperationResult(
                        success=True,
                        operation_type=operation_type,
                        message=c.Ldap.OPERATION_SUCCESS_MESSAGES[operation_type],
                        entries_affected=1,
                    )
                )
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[p.Ldap.OperationResult].fail_op(failure_prefix, exc)
        return OperationExecutor._extract_error_result(connection, failure_prefix)

    @staticmethod
    def _extract_error_result(
        connection: p.Ldap.Ldap3Connection, prefix: str
    ) -> p.Result[p.Ldap.OperationResult]:
        """Build ``r.fail`` from ``connection.result.description`` when present."""
        error_msg = f"{prefix}: LDAP operation returned failure status"
        result_payload = connection.result
        if result_payload is not None:
            payload = OperationExecutor.ResultPayload.model_validate(result_payload)
            description = payload.description
            if description is not None:
                error_msg = f"{prefix}: {description}"
        return r[p.Ldap.OperationResult].fail(error_msg)

    @staticmethod
    def execute_add(
        connection: p.Ldap.Ldap3Connection,
        dn_str: str,
        ldap_attrs: t.Ldap.OperationAttributes,
    ) -> p.Result[p.Ldap.OperationResult]:
        """Execute LDAP add via ``Connection.add`` and return ``r``."""
        attrs_dict: t.MappingKV[str, t.StrSequence] = {
            k: list(v) for k, v in ldap_attrs.items()
        }
        return OperationExecutor._execute(
            connection,
            c.Ldap.OperationType.ADD,
            lambda: FlextLdapLdap3Wrappers.add(connection, dn_str, None, attrs_dict),
        )

    @staticmethod
    def execute_delete(
        connection: p.Ldap.Ldap3Connection, dn: str | p.Ldif.DN
    ) -> p.Result[p.Ldap.OperationResult]:
        """Execute LDAP delete via ``Connection.delete`` and return ``r``."""
        dn_str = u.Ldif.get_dn_value(dn)
        return OperationExecutor._execute(
            connection,
            c.Ldap.OperationType.DELETE,
            lambda: FlextLdapLdap3Wrappers.delete(connection, dn_str),
        )

    @staticmethod
    def execute_modify(
        connection: p.Ldap.Ldap3Connection,
        dn: str | p.Ldif.DN,
        changes: t.Ldap.OperationChanges,
    ) -> p.Result[p.Ldap.OperationResult]:
        """Execute LDAP modify via ``Connection.modify`` and return ``r``."""
        dn_str = u.Ldif.get_dn_value(dn)
        return OperationExecutor._execute(
            connection,
            c.Ldap.OperationType.MODIFY,
            lambda: FlextLdapLdap3Wrappers.modify(connection, dn_str, changes),
        )


__all__: list[str] = ["OperationExecutor"]
