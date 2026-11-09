"""One bounded-read preparation for LDAP upsert plans and writes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from flext_ldap import c, m, p, r, t, u
from flext_ldap.services._upsert.reader import FlextLdapServicesUpsertReader


@dataclass(frozen=True, repr=False)
class _Prepared:
    entry: p.Ldif.Entry
    operation: str
    changes: t.Ldap.OperationChanges


class FlextLdapServicesUpsertHandler:
    """Prepare bulk reads once, compare once and preserve ordered writes."""

    def __init__(self, operations: p.Ldap.LdapOperations) -> None:
        self._ops = operations
        self._reader = FlextLdapServicesUpsertReader(operations)

    @staticmethod
    def _validate(entries: Sequence[p.Ldif.Entry]) -> p.Result[dict[str, str]]:
        keys: dict[str, str] = {}
        for entry in entries:
            if not entry.dn_str:
                return r[dict[str, str]].fail("Upsert entry missing DN")
            if entry.dn_str not in keys:
                key = u.Ldif.dn_key(entry.dn_str)
                if key.failure:
                    return r[dict[str, str]].from_failure(key)
                keys[entry.dn_str] = key.value
            if entry.changetype not in {
                None,
                c.Ldif.ChangeType.ADD,
                c.Ldif.ChangeType.MODIFY,
            }:
                return r[dict[str, str]].fail(
                    f"Unsupported upsert changetype: {entry.changetype}"
                )
            if (
                entry.changetype == c.Ldif.ChangeType.MODIFY
                and not entry.change_operations
            ):
                return r[dict[str, str]].fail(
                    c.Ldap.ErrorMessage.MODIFY_ENTRY_WITHOUT_ADDITIONS
                )
        return r[dict[str, str]].ok(keys)

    @staticmethod
    def _waves(
        entries: Sequence[p.Ldif.Entry], keys: dict[str, str]
    ) -> Iterator[list[p.Ldif.Entry]]:
        wave: list[p.Ldif.Entry] = []
        seen: set[str] = set()
        for entry in entries:
            key = keys[entry.dn_str]
            if key in seen or len(wave) == c.Ldap.BATCH_SIZE:
                yield wave
                wave, seen = [], set()
            wave.append(entry)
            seen.add(key)
        if wave:
            yield wave

    @staticmethod
    def _project(
        existing: p.Ldif.Entry,
        changes: t.Ldap.OperationChanges,
    ) -> p.Ldif.Entry:
        """Project only declared RFC modifications, never server-generated rules.

        Returns:
            The entry containing just the declared attribute changes.

        """
        if not changes:
            return existing
        attrs = {
            name: list(values) for name, values in existing.attributes_dict.items()
        }
        for attribute, operations in changes.items():
            name = next((k for k in attrs if k.lower() == attribute.lower()), attribute)
            for operation, values in operations:
                if operation == c.Ldap.ModifyOperation.REPLACE:
                    if values:
                        attrs[name] = list(values)
                    else:
                        attrs.pop(name, None)
                elif operation == c.Ldap.ModifyOperation.ADD:
                    old = attrs.setdefault(name, [])
                    old.extend(value for value in values if value not in old)
                elif values:
                    attrs[name] = [
                        value for value in attrs.get(name, []) if value not in values
                    ]
                    if not attrs[name]:
                        attrs.pop(name)
                else:
                    attrs.pop(name, None)
        return m.Ldif.Entry(
            dn=existing.dn, attributes=m.Ldif.Attributes(attributes=attrs)
        )

    def _view(
        self,
        entry: p.Ldif.Entry,
        existing: p.Ldif.Entry,
        *,
        named: frozenset[str],
        declared_new: bool,
        effects: Sequence[t.Ldap.OperationChanges] = (),
    ) -> p.Result[p.Ldif.Entry]:
        """Restrict declared effects to this operation's real LDAP projection.

        Returns:
            The relevant observed state, or the missing native schema fact.

        """
        desired = {name.lower() for name in entry.attributes_dict}
        modified = {op.attribute.lower() for op in entry.change_operations}
        original = {name.lower() for name in existing.attributes_dict}
        is_modify = entry.changetype == c.Ldif.ChangeType.MODIFY
        coverage: dict[str, bool] = {}
        names = set(existing.attributes_dict)
        names.update(name for changes in effects for name in changes)
        for name in names:
            key = name.lower()
            if is_modify:
                coverage[key] = key in modified
            elif key in desired or (
                not declared_new
                and key in original
                and key not in named
                and "+" not in named
            ):
                coverage[key] = True
            else:
                usage = self._ops.is_user_attribute(name)
                if usage.failure:
                    return r[p.Ldif.Entry].from_failure(usage)
                coverage[key] = usage.value
        attrs = {
            k: list(vs)
            for k, vs in existing.attributes_dict.items()
            if coverage[k.lower()]
        }
        view = m.Ldif.Entry(
            dn=existing.dn, attributes=m.Ldif.Attributes(attributes=attrs)
        )
        for changes in effects:
            view = self._project(
                view, {k: vs for k, vs in changes.items() if coverage[k.lower()]}
            )
        return r[p.Ldif.Entry].ok(view)

    @classmethod
    def _modify_changes(
        cls, entry: p.Ldif.Entry, existing: p.Ldif.Entry
    ) -> p.Result[t.Ldap.OperationChanges]:
        """Prepare canonical RFC modifications against their requested attributes.

        Returns:
            Only operations not already at their declared state.

        """
        changes: t.Ldap.OperationChanges = {}
        current = {k.lower(): list(vs) for k, vs in existing.attributes_dict.items()}
        operations = {
            c.Ldif.ChangeOperation.ADD: c.Ldap.ModifyOperation.ADD,
            c.Ldif.ChangeOperation.REPLACE: c.Ldap.ModifyOperation.REPLACE,
            c.Ldif.ChangeOperation.DELETE: c.Ldap.ModifyOperation.DELETE,
        }
        for op in entry.change_operations:
            if op.operation not in operations:
                return r[t.Ldap.OperationChanges].fail(
                    f"Unsupported modify operation: {op.operation}"
                )
            values = [value.value for value in op.values]
            present = current.get(op.attribute.lower(), [])
            if op.operation == c.Ldif.ChangeOperation.ADD:
                values = [value for value in values if value not in present]
                if not values:
                    continue
            elif op.operation == c.Ldif.ChangeOperation.REPLACE:
                if set(values) == set(present):
                    continue
            elif not present:
                continue
            changes.setdefault(op.attribute, []).append((
                operations[op.operation],
                values,
            ))
            projected = cls._project(existing, changes)
            current = {
                k.lower(): list(vs) for k, vs in projected.attributes_dict.items()
            }
        return r[t.Ldap.OperationChanges].ok(changes)

    def _prepare(
        self,
        entry: p.Ldif.Entry,
        existing: p.Ldif.Entry | None,
        *,
        named: frozenset[str] = frozenset(),
        declared_new: bool = False,
        effects: Sequence[t.Ldap.OperationChanges] = (),
    ) -> p.Result[_Prepared]:
        """Use one comparison authority for both plans and writes.

        Returns:
            The native write or genuine no-op derived from observed state.

        """
        if entry.changetype != c.Ldif.ChangeType.MODIFY and existing is None:
            return r[_Prepared].ok(_Prepared(entry, c.Ldap.UpsertOperation.ADDED, {}))
        if existing is None:
            return r[_Prepared].fail("Modify target does not exist")
        view = self._view(
            entry, existing, named=named, declared_new=declared_new, effects=effects
        )
        if view.failure:
            return r[_Prepared].from_failure(view)
        compared = (
            self._modify_changes(entry, view.value)
            if entry.changetype == c.Ldif.ChangeType.MODIFY
            else u.Ldap.compare_entries(view.value, entry)
        )
        if compared.failure:
            return r[_Prepared].from_failure(compared)
        operation = (
            c.Ldap.UpsertOperation.MODIFIED
            if compared.value
            else c.Ldap.UpsertOperation.SKIPPED
        )
        return r[_Prepared].ok(_Prepared(entry, operation, compared.value))

    def plan(
        self,
        entries: Sequence[p.Ldif.Entry],
        *,
        planned_entries: Sequence[p.Ldif.Entry] = (),
    ) -> p.Result[p.Ldap.UpsertPlan]:
        """Plan a batch against live reads plus explicitly declared prior entries.

        Returns:
            Ordered action DNs with counters derived from those actions.

        """
        valid = self._validate((*planned_entries, *entries))
        if valid.failure:
            return r[p.Ldap.UpsertPlan].from_failure(valid)
        keys = valid.value
        declared = {keys[e.dn_str]: e for e in planned_entries}
        effects: dict[str, list[t.Ldap.OperationChanges]] = {}
        dns: dict[str, list[str]] = {
            c.Ldap.UpsertOperation.ADDED: [],
            c.Ldap.UpsertOperation.MODIFIED: [],
            c.Ldap.UpsertOperation.SKIPPED: [],
        }
        for wave in self._waves(entries, keys):
            observed = self._reader.read(wave, declared, keys)
            if observed.failure:
                return r[p.Ldap.UpsertPlan].from_failure(observed)
            for entry in wave:
                key = keys[entry.dn_str]
                prepared = self._prepare(
                    entry,
                    observed.value.entries.get(key),
                    named=observed.value.explicit.get(key, frozenset()),
                    declared_new=key in declared,
                    effects=effects.get(key, ()),
                )
                if prepared.failure:
                    return r[p.Ldap.UpsertPlan].from_failure(prepared)
                value = prepared.value
                dns[value.operation].append(entry.dn_str)
                if value.operation == c.Ldap.UpsertOperation.ADDED:
                    declared[key] = entry
                elif key in declared:
                    declared[key] = self._project(declared[key], value.changes)
                else:
                    effects.setdefault(key, []).append(value.changes)
        return r[p.Ldap.UpsertPlan].ok(
            m.Ldap.UpsertPlan(
                added_dns=tuple(dns[c.Ldap.UpsertOperation.ADDED]),
                modified_dns=tuple(dns[c.Ldap.UpsertOperation.MODIFIED]),
                unchanged_dns=tuple(dns[c.Ldap.UpsertOperation.SKIPPED]),
                planned_entries=tuple(declared.values()),
            )
        )

    def _write(self, prepared: _Prepared) -> p.Result[p.Ldap.LdapOperationResult]:
        """Emit one prepared write with no further directory lookup.

        Returns:
            The actual native operation result or its original error.

        """
        if prepared.operation == c.Ldap.UpsertOperation.SKIPPED:
            return r[p.Ldap.LdapOperationResult].ok(
                m.Ldap.LdapOperationResult(operation=prepared.operation)
            )
        written = (
            self._ops.add(u.Ldif.as_entry(prepared.entry))
            if prepared.operation == c.Ldap.UpsertOperation.ADDED
            else self._ops.modify(prepared.entry.dn_str, prepared.changes)
        )
        if written.failure:
            return r[p.Ldap.LdapOperationResult].from_failure(written)
        return r[p.Ldap.LdapOperationResult].ok(
            m.Ldap.LdapOperationResult(operation=prepared.operation)
        )

    def _apply_observed(
        self, entry: p.Ldif.Entry, existing: p.Ldif.Entry | None, named: frozenset[str]
    ) -> p.Result[p.Ldap.LdapOperationResult]:
        prepared = self._prepare(entry, existing, named=named)
        if prepared.failure:
            return r[p.Ldap.LdapOperationResult].from_failure(prepared)
        return self._write(prepared.value)

    def execute_many(
        self, entries: Sequence[p.Ldif.Entry]
    ) -> Iterator[tuple[p.Ldif.Entry, p.Result[p.Ldap.LdapOperationResult]]]:
        """Read every wave afresh before emitting its ordered native writes.

        Yields:
            Each original input with its actual operation outcome.

        """
        valid = self._validate(entries)
        if valid.failure:
            if entries:
                yield entries[0], r[p.Ldap.LdapOperationResult].from_failure(valid)
            return
        keys = valid.value
        for wave in self._waves(entries, keys):
            observed = self._reader.read(wave, {}, keys)
            if observed.failure:
                for entry in wave:
                    yield entry, r[p.Ldap.LdapOperationResult].from_failure(observed)
                continue
            for entry in wave:
                key = keys[entry.dn_str]
                yield (
                    entry,
                    self._apply_observed(
                        entry,
                        observed.value.entries.get(key),
                        observed.value.explicit.get(key, frozenset()),
                    ),
                )

    def execute(self, entry: p.Ldif.Entry) -> p.Result[p.Ldap.LdapOperationResult]:
        """Use the same preparation for a single upsert.

        Returns:
            The actual single-entry outcome.

        """
        return next(self.execute_many((entry,)))[1]


__all__: list[str] = ["FlextLdapServicesUpsertHandler"]
