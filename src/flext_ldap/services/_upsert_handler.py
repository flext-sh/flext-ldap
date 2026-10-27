"""Upsert state machine for LDAP add-or-modify flows.

Split from ``FlextLdapOperations`` so the operations model carries no
self-referencing field annotation (deferred-self-reference gate); the handler
delegates every LDAP call back to the operations service instance it is
constructed with.

Business Rules:
    - Schema modifications (changetype=modify) use MODIFY_ADD operations
    - Regular entries are read before ADD, comparison or MODIFY
    - Idempotent: SKIPPED if entry already matches desired state

Audit Implications:
    - Returns operation type (ADDED, MODIFIED, SKIPPED) for tracking
    - All operations return r for consistent error handling
    - Error messages preserve original LDAP error context

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import c, m, p, r, t, u


class FlextLdapUpsertHandler:
    """Handle add-or-modify flows for upsert calls."""

    def __init__(self, operations: p.Ldap.LdapOperations) -> None:
        """Initialize upsert handler with operations service.

        Business Rules:
            - Operations service is REQUIRED (no default, fail-fast pattern)
            - Handler stores reference for delegation to parent service
            - No connection validation at init (validated during execute)

        Architecture:
            - Encapsulates the upsert state machine
            - Delegates all LDAP operations to the injected operations service
            - Enables testability through dependency injection

        Args:
            operations: LDAP operations service (``p.Ldap.LdapOperations``)
                for LDAP operations. Must have active connection for
                execute() to succeed.

        """
        super().__init__()
        self._ops = operations

    def execute(self, entry: p.Ldif.Entry) -> p.Result[m.Ldap.LdapOperationResult]:
        """Execute an upsert operation for the provided entry.

        Business Rules:
            - Checks changetype attribute to route to schema modify vs regular add
            - Schema modifications use MODIFY_ADD for new schema elements
            - Regular entries use the same directory read as the dry-run plan

        Audit Implication:
            Entry point for all upsert operations; returns operation type
            for audit trail (ADDED, MODIFIED, or SKIPPED).

        Returns:
            r with LdapOperationResult indicating operation type.

        """
        if self._is_modify(entry):
            return self.handle_schema_modify(entry)
        return self.handle_regular_add(entry)

    @staticmethod
    def _is_modify(entry: p.Ldif.Entry) -> bool:
        """Whether the entry is a ``changetype: modify`` payload.

        The ``changetype`` attribute wins; the entry's own ``changetype``
        field is the fallback carrier when the attribute is absent.

        Returns:
            The resulting ``bool``.

        """
        attrs = u.Ldap.extract_entry_attributes(entry)
        changetype_val: t.StrSequence = list(
            attrs.get(c.Ldap.AttributeName.CHANGETYPE, []),
        )
        changetype = (
            u.Ldap.norm_str(changetype_val[0], case="lower") if changetype_val else ""
        )
        if not changetype and hasattr(entry, "changetype") and entry.changetype:
            changetype = entry.changetype.lower()
        return changetype == c.Ldif.ChangeType.MODIFY

    @staticmethod
    def _modify_additions(entry_model: m.Ldif.Entry) -> list[tuple[str, t.StrSequence]]:
        """Collect the non-empty MODIFY_ADD values of a modify entry.

        Change operations are the carrier; the legacy ``add:`` attribute
        form is read only when no add operation carries values.

        Returns:
            The resulting ``list[tuple[str, t.StrSequence]]``.

        """
        additions: list[tuple[str, t.StrSequence]] = []
        for change_operation in entry_model.change_operations:
            if change_operation.operation != c.Ldif.ChangeOperation.ADD:
                continue
            filtered_values = [
                change_value.value
                for change_value in change_operation.values
                if change_value.value
            ]
            if filtered_values:
                additions.append((change_operation.attribute, filtered_values))
        if additions:
            return additions
        attrs = u.Ldap.extract_entry_attributes(entry_model)
        for attr_type in list(attrs.get(c.Ldif.ChangeOperation.ADD, [])):
            filtered_values = [item for item in attrs.get(attr_type, []) if item]
            if filtered_values:
                additions.append((attr_type, filtered_values))
        return additions

    def handle_existing_entry(
        self,
        entry: p.Ldif.Entry,
        existing_entry: m.Ldif.Entry,
    ) -> p.Result[m.Ldap.LdapOperationResult]:
        """Compare a present entry and apply the required modification.

        Business Rules:
            - Compares existing vs new entry to compute MODIFY changes
            - If no differences, returns SKIPPED (idempotent)
            - Applies MODIFY_REPLACE/MODIFY_DELETE changes for sync

        Audit Implication:
            Critical for idempotent upserts; computes minimal change set.
            SKIPPED indicates no changes needed, enabling safe reruns.

        Returns:
            r with MODIFIED or SKIPPED.

        """
        if entry.dn is None or not entry.dn.value:
            return r[m.Ldap.LdapOperationResult].fail("Upsert entry missing DN")
        changes_result = u.Ldap.compare_entries(existing_entry, entry)
        if changes_result.failure:
            return r[m.Ldap.LdapOperationResult].from_failure(changes_result)
        changes = changes_result.value
        if not changes:
            return r[m.Ldap.LdapOperationResult].ok(
                m.Ldap.LdapOperationResult(operation=c.Ldap.UpsertOperation.SKIPPED),
            )
        modified = self._ops.modify(entry.dn.value, changes)
        if modified.failure:
            return r[m.Ldap.LdapOperationResult].from_failure(modified)
        return r[m.Ldap.LdapOperationResult].ok(
            m.Ldap.LdapOperationResult(operation=c.Ldap.UpsertOperation.MODIFIED),
        )

    def handle_regular_add(
        self,
        entry: p.Ldif.Entry,
    ) -> p.Result[m.Ldap.LdapOperationResult]:
        """Read a standard entry and then add or reconcile it.

        Business Rules:
            - Read with the same absence-aware boundary used by plan
            - Add absent entries once; compare present entries before modifying
            - Every read or write failure propagates unchanged

        Audit Implication:
            Existing entries do not trigger a rejected ADD before comparison.

        Returns:
            r with ADDED, MODIFIED or SKIPPED.

        """
        entry_for_add = u.Ldif.as_entry(entry)
        if entry_for_add.dn is None or not entry_for_add.dn.value:
            return r[m.Ldap.LdapOperationResult].fail("Upsert entry missing DN")
        found = self._ops.find_entry(entry_for_add.dn.value)
        if found.failure:
            return r[m.Ldap.LdapOperationResult].from_failure(found)
        if found.value.entries:
            return self.handle_existing_entry(entry, found.value.entries[0])
        added = self._ops.add(entry_for_add)
        if added.failure:
            return r[m.Ldap.LdapOperationResult].from_failure(added)
        return r[m.Ldap.LdapOperationResult].ok(
            m.Ldap.LdapOperationResult(operation=c.Ldap.UpsertOperation.ADDED),
        )

    def handle_schema_modify(
        self,
        entry: p.Ldif.Entry,
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
        schema_additions = self._modify_additions(entry_model)
        if not schema_additions:
            return r[m.Ldap.LdapOperationResult].fail(
                c.Ldap.ErrorMessage.MODIFY_ENTRY_WITHOUT_ADDITIONS,
            )
        changes: t.Ldap.OperationChanges = {}
        for attr_type, filtered in schema_additions:
            changes.setdefault(attr_type, []).append((
                c.Ldap.ModifyOperation.ADD,
                filtered,
            ))
        modified = self._ops.modify(dn_str, changes)
        if modified.failure:
            return r[m.Ldap.LdapOperationResult].from_failure(modified)
        return r[m.Ldap.LdapOperationResult].ok(
            m.Ldap.LdapOperationResult(operation=c.Ldap.UpsertOperation.MODIFIED),
        )

    def plan(self, entries: t.SequenceOf[p.Ldif.Entry]) -> p.Result[m.Ldap.UpsertPlan]:
        """Classify entries against the directory without writing anything.

        Business Rules:
            - Routes each entry exactly like :meth:`execute`: a
              ``changetype: modify`` entry is planned as ``modifies`` when it
              carries add operations (the write path issues MODIFY_ADD without
              searching) and fails like the write path when it carries none
            - Any other entry is read with ``find_entry`` and compared with
              ``u.Ldap.compare_entries``: absent counts as ``adds``,
              present-with-changes as ``modifies``, present-and-identical as
              ``unchanged``
            - Zero writes: no add/modify call is ever issued
            - First read/comparison failure aborts the plan with a typed
              failure (the owner of upsert semantics owns "what would change")

        Audit Implication:
            Enables dry-run migration reports: the plan is derived from the
            live directory, so reruns are deterministic between writes.

        Returns:
            r with UpsertPlan carrying add/modify/unchanged counts.

        """
        adds = 0
        modifies = 0
        unchanged = 0
        for entry in entries:
            if entry.dn is None or not entry.dn.value:
                return r[m.Ldap.UpsertPlan].fail("Plan entry missing DN")
            if self._is_modify(entry):
                if not self._modify_additions(u.Ldif.as_entry(entry)):
                    return r[m.Ldap.UpsertPlan].fail(
                        c.Ldap.ErrorMessage.MODIFY_ENTRY_WITHOUT_ADDITIONS,
                    )
                modifies += 1
                continue
            found = self._ops.find_entry(entry.dn.value)
            if found.failure:
                return r[m.Ldap.UpsertPlan].fail_op(
                    "Plan search for existing entry",
                    found.error,
                )
            existing_entries: t.SequenceOf[m.Ldif.Entry] = list(found.value.entries)
            if not existing_entries:
                adds += 1
                continue
            changes_result = u.Ldap.compare_entries(existing_entries[0], entry)
            if changes_result.failure:
                return r[m.Ldap.UpsertPlan].fail_op(
                    "Plan entry comparison",
                    changes_result.error,
                )
            empty_changes: t.Ldap.OperationChanges = {}
            changes = changes_result.unwrap_or(empty_changes)
            if changes:
                modifies += 1
            else:
                unchanged += 1
        return r[m.Ldap.UpsertPlan].ok(
            m.Ldap.UpsertPlan(adds=adds, modifies=modifies, unchanged=unchanged),
        )


__all__: list[str] = ["FlextLdapUpsertHandler"]
