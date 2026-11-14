"""LDAP3 adapter — FlextLdapLdap3OperationExecutor.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_ldif import r

from flext_ldap.adapters._ldap3 import FlextLdapLdap3Wrappers
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.typings import t
from flext_ldap.utilities import u

if TYPE_CHECKING:
    from collections.abc import Callable


class FlextLdapLdap3OperationExecutor:
    """LDAP add/modify/delete dispatcher (SRP).

    Single ``_execute`` boundary translates ldap3 wrapper return values into
    ``r[p.Ldap.OperationResult]`` and centralises message generation through
    ``c.Ldap.OPERATION_SUCCESS_MESSAGES`` / ``OPERATION_FAILURE_PREFIXES``.
    """

    class ResultPayload(m.BaseModel):
        """Validated ldap3 operation result payload."""

        model_config = m.ConfigDict(frozen=True, extra="ignore")
        description: str | None = None
        message: str | None = None

        @m.field_validator("description", mode="before")
        @classmethod
        def normalize_description(
            cls,
            value: t.Scalar | t.JsonList | t.JsonMapping | None,
        ) -> str | None:
            """Normalize ldap3 JSON descriptions into the operation message text.

            Returns:
                The resulting ``str | None``.

            """
            if value is None:
                return None
            if isinstance(value, str):
                return value
            return repr(value)

    @staticmethod
    def _execute(
        connection: p.Ldap.Ldap3Connection,
        operation_type: c.Ldap.OperationType,
        wrapper_call: Callable[[], int],
    ) -> p.Result[p.Ldap.OperationResult]:
        failure_prefix = c.Ldap.OPERATION_FAILURE_PREFIXES[operation_type]
        try:
            _, result_payload = FlextLdapLdap3Wrappers.response(
                connection, wrapper_call()
            )
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[p.Ldap.OperationResult].fail_op(failure_prefix, exc)
        if result_payload.get("result") == c.Ldap.ResultCode.SUCCESS:
            return r[p.Ldap.OperationResult].ok(
                m.Ldap.OperationResult(
                    success=True,
                    operation_type=operation_type,
                    message=c.Ldap.OPERATION_SUCCESS_MESSAGES[operation_type],
                    entries_affected=1,
                ),
            )
        return FlextLdapLdap3OperationExecutor._extract_error_result(
            result_payload,
            failure_prefix,
        )

    @staticmethod
    def _extract_error_result(
        result_payload: t.JsonMapping,
        prefix: str,
    ) -> p.Result[p.Ldap.OperationResult]:
        """Build ``r.fail`` retaining the server description and diagnostic.

        Returns:
            The resulting ``p.Result[p.Ldap.OperationResult]``.

        """
        error_msg = f"{prefix}: LDAP operation returned failure status"
        payload = FlextLdapLdap3OperationExecutor.ResultPayload.model_validate(
            result_payload,
        )
        description = payload.description
        if description is not None:
            error_msg = f"{prefix}: {description}"
        if payload.message:
            error_msg = f"{error_msg}: {payload.message}"
        return r[p.Ldap.OperationResult].fail(
            error_msg,
            error_data=result_payload,
        )

    @staticmethod
    def execute_add(
        connection: p.Ldap.Ldap3Connection,
        dn_str: str,
        ldap_attrs: t.Ldap.OperationAttributes,
    ) -> p.Result[p.Ldap.OperationResult]:
        """Execute LDAP add via ``Connection.add`` and return ``r``.

        Returns:
            The resulting ``p.Result[p.Ldap.OperationResult]``.

        """
        attrs_dict: Mapping[str, Sequence[str]] = {
            k: list(v) for k, v in ldap_attrs.items()
        }
        return FlextLdapLdap3OperationExecutor._execute(
            connection,
            c.Ldap.OperationType.ADD,
            lambda: FlextLdapLdap3Wrappers.add(connection, dn_str, None, attrs_dict),
        )

    @staticmethod
    def execute_delete(
        connection: p.Ldap.Ldap3Connection,
        dn: str | m.Ldif.DN,
    ) -> p.Result[p.Ldap.OperationResult]:
        """Execute LDAP delete via ``Connection.delete`` and return ``r``.

        Returns:
            The resulting ``p.Result[p.Ldap.OperationResult]``.

        """
        dn_str = u.Ldif.resolve_dn_value(dn)
        return FlextLdapLdap3OperationExecutor._execute(
            connection,
            c.Ldap.OperationType.DELETE,
            lambda: FlextLdapLdap3Wrappers.delete(connection, dn_str),
        )

    @staticmethod
    def execute_modify(
        connection: p.Ldap.Ldap3Connection,
        dn: str | m.Ldif.DN,
        changes: t.Ldap.OperationChanges,
    ) -> p.Result[p.Ldap.OperationResult]:
        """Execute LDAP modify via ``Connection.modify`` and return ``r``.

        Returns:
            The resulting ``p.Result[p.Ldap.OperationResult]``.

        """
        dn_str = u.Ldif.resolve_dn_value(dn)
        return FlextLdapLdap3OperationExecutor._execute(
            connection,
            c.Ldap.OperationType.MODIFY,
            lambda: FlextLdapLdap3Wrappers.modify(connection, dn_str, changes),
        )


__all__: list[str] = ["FlextLdapLdap3OperationExecutor"]
