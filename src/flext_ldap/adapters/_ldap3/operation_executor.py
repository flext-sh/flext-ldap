"""LDAP3 adapter — OperationExecutor.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import c, m, p, t, u
from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
from flext_ldif import r


class OperationExecutor:
    """LDAP operation execution logic (SRP)."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()

    @staticmethod
    def _add_entry_to_ldap(
        connection: p.Ldap.Ldap3Connection,
        dn_str: str,
        attrs_dict: t.MappingKV[str, t.StrSequence],
    ) -> bool:
        """Add entry to LDAP directory.

        This typed wrapper handles the untyped ldap3 add() call.

        Args:
            connection: Active ldap3 Connection t.JsonValue.
            dn_str: Distinguished name string.
            attrs_dict: Attributes dictionary (str -> t.StrSequence).

        Returns:
            True if add succeeded, False otherwise.

        """
        return FlextLdapLdap3Wrappers.add(connection, dn_str, None, attrs_dict)

    @staticmethod
    def _delete_entry_from_ldap(
        connection: p.Ldap.Ldap3Connection, dn_str: str
    ) -> bool:
        """Delete entry from LDAP directory.

        This typed wrapper handles the untyped ldap3 delete() call.

        Args:
            connection: Active ldap3 Connection t.JsonValue.
            dn_str: Distinguished name string.

        Returns:
            True if delete succeeded, False otherwise.

        """
        return FlextLdapLdap3Wrappers.delete(connection, dn_str)

    @staticmethod
    def _extract_error_result(
        connection: p.Ldap.Ldap3Connection,
        prefix: str,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Extract error message from connection result.

        Business Rules:
            - Extracts error description from connection.result dict
            - Uses "description" field if available (most detailed)
            - Falls back to generic error message if description missing
            - Uses u.dict_like() for type-safe dict access

        Audit Implications:
            - Error messages preserve LDAP server error context
            - Description field contains server-specific error details
            - Error extraction enables proper error propagation

        Architecture:
            - Uses connection.result dict from ldap3
            - Uses u.dict_like() for type narrowing
            - Returns r.fail() with error message

        Args:
            connection: ldap3.Connection with error in connection.result.
            prefix: Error message prefix (e.g., "Add failed").

        Returns:
            r.fail() with extracted error message.

        """
        error_msg = f"{prefix}: LDAP operation returned failure status"
        result_dict = connection.result
        if isinstance(result_dict, dict):
            description = result_dict.get("description")
            match description:
                case str() as description_str:
                    error_msg = f"{prefix}: {description_str}"
                case None:
                    pass
                case _:
                    error_msg = f"{prefix}: {description!r}"
        return r[m.Ldap.OperationResult].fail(error_msg)

    @staticmethod
    def _modify_entry_in_ldap(
        connection: p.Ldap.Ldap3Connection,
        dn_str: str,
        changes: t.Ldap.OperationChanges,
    ) -> bool:
        """Modify entry in LDAP directory.

        This typed wrapper handles the untyped ldap3 modify() call.

        Args:
            connection: Active ldap3 Connection t.JsonValue.
            dn_str: Distinguished name string.
            changes: Modification changes dict in ldap3 format.

        Returns:
            True if modify succeeded, False otherwise.

        """
        return FlextLdapLdap3Wrappers.modify(connection, dn_str, changes)

    def execute_add(
        self,
        connection: p.Ldap.Ldap3Connection,
        dn_str: str,
        ldap_attrs: t.Ldap.OperationAttributes,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Execute LDAP add operation via ldap3 Connection.

        Business Rules:
            - Calls connection.add() with DN and attributes dict
            - LDAP error codes are extracted from connection.result
            - Success returns OperationResult with entries_affected=1
            - Failure returns r.fail() with error message

        Audit Implications:
            - LDAP operation errors are logged with description from server
            - Successful operations log success status

        Architecture:
            - Uses ldap3 Connection.add() for protocol-level operation
            - Error extraction uses _extract_error_result() helper
            - Returns r pattern - no exceptions raised

        Args:
            connection: Active ldap3 Connection t.JsonValue
            dn_str: Distinguished name as string
            ldap_attrs: Attributes dict in ldap3 format

        Returns:
            r containing OperationResult with success status

        """
        try:
            attrs_dict: t.MappingKV[str, t.StrSequence] = {
                k: list(v) for k, v in ldap_attrs.items()
            }
            if self._add_entry_to_ldap(connection, dn_str, attrs_dict):
                return r[m.Ldap.OperationResult].ok(
                    m.Ldap.OperationResult(
                        success=True,
                        operation_type=c.Ldap.OperationType.ADD,
                        message="Entry added successfully",
                        entries_affected=1,
                    ),
                )
            return self._extract_error_result(connection, "Add failed")
        except c.EXC_BROAD_IO_TYPE as exc:
            error_msg = f"Add failed: {exc!s}"
            return r[m.Ldap.OperationResult].fail(error_msg)

    def execute_delete(
        self,
        connection: p.Ldap.Ldap3Connection,
        dn: str | m.Ldif.DN,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Execute LDAP delete operation via ldap3 Connection.

        Business Rules:
            - DN is normalized using u.Ldif.get_dn_value()
            - Calls connection.delete() with DN string
            - LDAP error codes are extracted from connection.result
            - Success returns OperationResult with entries_affected=1
            - Failure returns r.fail() with error message

        Audit Implications:
            - LDAP operation errors are logged with description from server
            - Successful operations log success status

        Architecture:
            - Uses ldap3 Connection.delete() for protocol-level operation
            - Error extraction uses _extract_error_result() helper
            - Returns r pattern - no exceptions raised

        Args:
            connection: Active ldap3 Connection t.JsonValue
            dn: Distinguished name (string or DN model)

        Returns:
            r containing OperationResult with success status

        """
        try:
            dn_str = u.Ldif.get_dn_value(dn)
            if self._delete_entry_from_ldap(connection, dn_str):
                return r[m.Ldap.OperationResult].ok(
                    m.Ldap.OperationResult(
                        success=True,
                        operation_type=c.Ldap.OperationType.DELETE,
                        message="Entry deleted successfully",
                        entries_affected=1,
                    ),
                )
            return self._extract_error_result(connection, "Delete failed")
        except c.EXC_BROAD_IO_TYPE as exc:
            error_msg = f"Delete failed: {exc!s}"
            return r[m.Ldap.OperationResult].fail(error_msg)

    def execute_modify(
        self,
        connection: p.Ldap.Ldap3Connection,
        dn: str | m.Ldif.DN,
        changes: t.Ldap.OperationChanges,
    ) -> p.Result[m.Ldap.OperationResult]:
        """Execute LDAP modify operation via ldap3 Connection.

        Business Rules:
            - DN is normalized using u.Ldif.get_dn_value()
            - Calls connection.modify() with DN and changes dict
            - LDAP error codes are extracted from connection.result
            - Success returns OperationResult with entries_affected=1
            - Failure returns r.fail() with error message

        Audit Implications:
            - LDAP operation errors are logged with description from server
            - Successful operations log success status

        Architecture:
            - Uses ldap3 Connection.modify() for protocol-level operation
            - Error extraction uses _extract_error_result() helper
            - Returns r pattern - no exceptions raised

        Args:
            connection: Active ldap3 Connection t.JsonValue
            dn: Distinguished name (string or DN model)
            changes: Modification changes dict in ldap3 format

        Returns:
            r containing OperationResult with success status

        """
        try:
            dn_str = u.Ldif.get_dn_value(dn)
            if self._modify_entry_in_ldap(connection, dn_str, changes):
                return r[m.Ldap.OperationResult].ok(
                    m.Ldap.OperationResult(
                        success=True,
                        operation_type=c.Ldap.OperationType.MODIFY,
                        message="Entry modified successfully",
                        entries_affected=1,
                    ),
                )
            return self._extract_error_result(connection, "Modify failed")
        except c.EXC_BROAD_IO_TYPE as exc:
            error_msg = f"Modify failed: {exc!s}"
            return r[m.Ldap.OperationResult].fail(error_msg)


__all__: list[str] = ["OperationExecutor"]
