"""Upsert state machine for LDAP add-or-modify flows.

Split from ``FlextLdapOperations`` so the operations model carries no
self-referencing field annotation (deferred-self-reference gate); the handler
delegates every LDAP call back to the operations service instance it is
constructed with.

Business Rules:
    - Schema modifications (changetype=modify) use MODIFY_ADD operations
    - Regular entries attempt ADD first, then compare and MODIFY if exists
    - "Entry already exists" errors trigger comparison and modification
    - Idempotent: SKIPPED if entry already matches desired state

Audit Implications:
    - Returns operation type (ADDED, MODIFIED, SKIPPED) for tracking
    - All operations return r for consistent error handling
    - Error messages preserve original LDAP error context

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldap import c, m, p, t, u
from flext_ldif import r

if TYPE_CHECKING:
    from flext_ldap.services.operations import FlextLdapOperations


class FlextLdapUpsertHandler:
    """Handle add-or-modify flows for upsert calls."""

    def __init__(self, operations: FlextLdapOperations) -> None:
        """Initialize upsert handler with operations service.

        Business Rules:
            - Operations service is REQUIRED (no default, fail-fast pattern)
            - Handler stores reference for delegation to parent service
            - No connection validation at init (validated during execute)

        Architecture:
            - Encapsulates the upsert state machine
            - Delegates all LDAP operations to parent FlextLdapOperations
            - Enables testability through dependency injection

        Args:
            operations: FlextLdapOperations instance for LDAP operations.
                Must have active connection for execute() to succeed.

        """
        super().__init__()
        self._ops = operations

    def execute(self, entry: p.Ldif.Entry) -> p.Result[m.Ldap.LdapOperationResult]:
        """Execute an upsert operation for the provided entry.

        Business Rules:
            - Checks changetype attribute to route to schema modify vs regular add
            - Schema modifications use MODIFY_ADD for new schema elements
            - Regular entries use add-then-modify pattern for idempotency

        Audit Implication:
            Entry point for all upsert operations; returns operation type
            for audit trail (ADDED, MODIFIED, or SKIPPED).

        Returns:
            r with LdapOperationResult indicating operation type.

        """
        attrs = u.Ldap.extract_entry_attributes(entry)
        changetype_result = attrs.get(c.Ldap.AttributeName.CHANGETYPE, [])
        changetype_val: t.StrSequence = list(changetype_result)
        changetype = (
            u.Ldap.norm_str(changetype_val[0], case="lower") if changetype_val else ""
        )
        if not changetype and hasattr(entry, "changetype") and entry.changetype:
            changetype = entry.changetype.lower()
        if changetype == c.Ldif.LdifChangeType.MODIFY:
            return self.handle_schema_modify(entry)
        return self.handle_regular_add(entry)

    def handle_existing_entry(
        self, entry: p.Ldif.Entry
    ) -> p.Result[m.Ldap.LdapOperationResult]:
        """Handle an upsert when the entry already exists in LDAP.

        Business Rules:
            - Searches for existing entry using BASE scope on entry DN
            - If search fails, returns failure with the search context
            - If search returns empty (race condition), retries ADD
            - Compares existing vs new entry to compute MODIFY changes
            - If no differences, returns SKIPPED (idempotent)
            - Applies MODIFY_REPLACE/MODIFY_DELETE changes for sync

        Audit Implication:
            Critical for idempotent upserts; computes minimal change set.
            SKIPPED indicates no changes needed, enabling safe reruns.

        Returns:
            r with MODIFIED, SKIPPED, or ADDED (race condition).

        """
        if entry.dn is None or not entry.dn.value:
            return r[m.Ldap.LdapOperationResult].fail("Upsert entry missing DN")
        entry_dn = entry.dn.value
        search_options = m.Ldap.SearchOptions.base_scope(entry_dn)
        search_result = self._ops.search(search_options)
        if search_result.failure:
            result: p.Result[m.Ldap.LdapOperationResult] = r[
                m.Ldap.LdapOperationResult
            ].fail_op("Search for existing entry", search_result.error)
        else:
            search_data = search_result.map_or(None)
            existing_entries: t.SequenceOf[m.Ldif.Entry] = []
            if search_data is not None and search_data.entries:
                existing_entries = list(search_data.entries)
            if not existing_entries:
                retry_result = self._ops.add(entry)
                if retry_result.success:
                    result = r[m.Ldap.LdapOperationResult].ok(
                        m.Ldap.LdapOperationResult.with_operation(
                            c.Ldap.UpsertOperation.ADDED
                        )
                    )
                else:
                    result = r[m.Ldap.LdapOperationResult].fail(
                        u.to_str(retry_result.error)
                    )
            else:
                existing_entry = existing_entries[0]
                changes_result = u.Ldap.compare_entries(existing_entry, entry)
                if changes_result.failure:
                    result = r[m.Ldap.LdapOperationResult].fail_op(
                        "Entry comparison", changes_result.error
                    )
                else:
                    empty_changes: t.Ldap.OperationChanges = {}
                    changes = changes_result.unwrap_or(empty_changes)
                    if not changes:
                        result = r[m.Ldap.LdapOperationResult].ok(
                            m.Ldap.LdapOperationResult.with_operation(
                                c.Ldap.UpsertOperation.SKIPPED
                            )
                        )
                    else:
                        modify_result = self._ops.modify(entry_dn, changes)
                        result = modify_result.fold(
                            on_failure=lambda e: r[m.Ldap.LdapOperationResult].fail(
                                u.to_str(e)
                            ),
                            on_success=lambda _: r[m.Ldap.LdapOperationResult].ok(
                                m.Ldap.LdapOperationResult.with_operation(
                                    c.Ldap.UpsertOperation.MODIFIED
                                )
                            ),
                        )
        return result

    def handle_regular_add(
        self, entry: p.Ldif.Entry
    ) -> p.Result[m.Ldap.LdapOperationResult]:
        """Add a standard entry or fall back to existing-entry handling.

        Business Rules:
            - First attempts LDAP ADD operation for optimistic path
            - If ADD succeeds, returns ADDED operation result
            - If "entry already exists" error (68), delegates to handle_existing_entry
            - Other errors are propagated as r.fail()

        Audit Implication:
            Primary upsert entry point for non-schema entries.
            Optimistic add minimizes round trips for new entries.

        Returns:
            r with ADDED or delegates to existing entry handler.

        """
        entry_for_add = u.Ldif.as_entry(entry)
        return (
            self._ops
            .add(entry_for_add)
            .map(
                lambda _: m.Ldap.LdapOperationResult.with_operation(
                    c.Ldap.UpsertOperation.ADDED
                )
            )
            .lash(
                lambda e: (
                    self.handle_existing_entry(entry)
                    if self._ops.already_exists_error(u.to_str(e))
                    else r[m.Ldap.LdapOperationResult].fail(u.to_str(e))
                )
            )
        )

    def handle_schema_modify(
        self, entry: p.Ldif.Entry
    ) -> p.Result[m.Ldap.LdapOperationResult]:
        """Apply a schema modification entry (supports multiple add operations).

        Business Rules:
            - Entry must have 'add' attribute specifying schema attribute(s) to add
            - Loops ALL add operations (supports both split and interleaved entries)
            - Uses MODIFY_ADD operation (not REPLACE) for additive schema changes
            - LDAP modify failures are returned as failures with original context
            - Empty values are filtered out before modification

        Audit Implication:
            Schema modifications are critical; returns MODIFIED or error.
            Preserves LDAP error context for schema validation failures.

        Returns:
            r with operation type MODIFIED.

        """
        entry_model = u.Ldif.as_entry(entry)
        if entry_model.dn is None or not entry_model.dn.value:
            return r[m.Ldap.LdapOperationResult].fail("Schema modify entry missing DN")
        dn_str = entry_model.dn.value
        schema_additions: list[tuple[str, t.StrSequence]] = []
        for change_operation in entry_model.change_operations:
            if change_operation.operation != c.Ldif.ChangeOperation.ADD:
                continue
            filtered_values = [
                change_value.value
                for change_value in change_operation.values
                if change_value.value
            ]
            if filtered_values:
                schema_additions.append((change_operation.attribute, filtered_values))
        if not schema_additions:
            attrs = u.Ldap.extract_entry_attributes(entry_model)
            add_op_result = attrs.get(c.Ldif.ChangeOperation.ADD, [])
            add_op: t.StrSequence = list(add_op_result)
            for attr_type in add_op:
                attr_values_raw = attrs.get(attr_type, [])
                filtered_values = [item for item in attr_values_raw if item]
                if filtered_values:
                    schema_additions.append((attr_type, filtered_values))
        if not schema_additions:
            return r[m.Ldap.LdapOperationResult].fail(
                "Schema modify entry missing add operations"
            )
        last_result: p.Result[m.Ldap.LdapOperationResult] | None = None
        for attr_type, filtered in schema_additions:
            changes: t.Ldap.OperationChanges = {
                attr_type: [(c.Ldap.ModifyOperation.ADD, filtered)]
            }
            current_result: p.Result[m.Ldap.LdapOperationResult] = (
                self._ops
                .modify(dn_str, changes)
                .map(
                    lambda _: m.Ldap.LdapOperationResult.with_operation(
                        c.Ldap.UpsertOperation.MODIFIED
                    )
                )
                .lash(
                    lambda e: r[m.Ldap.LdapOperationResult].fail(
                        u.to_str(e) or c.Ldap.ErrorMessage.UNKNOWN_ERROR
                    )
                )
            )
            last_result = current_result
            if current_result.failure:
                return current_result
        if last_result is None:
            return r[m.Ldap.LdapOperationResult].fail(
                "Schema modify entry has only empty values"
            )
        return last_result
