"""Public batch planning from explicit prior state, with no transport required.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import FlextLdap
from tests import c, m, tm, u


class TestsFlextLdapBulkUpsert:
    """A projected ADD is real planning input, not an invented directory read."""

    @staticmethod
    def test_clear_on_previously_planned_add_is_a_noop() -> None:
        """A known new entry has no local ACI to clear or fetch."""
        client = FlextLdap()
        dn = m.Ldif.DN(value="uid=future,dc=example,dc=invalid")
        future = m.Ldif.Entry(
            dn=dn,
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["top", "inetOrgPerson"],
                    "uid": ["future"],
                    "cn": ["Future"],
                    "sn": ["Future"],
                }
            ),
        )
        clear = m.Ldif.Entry(
            dn=dn,
            attributes=m.Ldif.Attributes(attributes={"aci": []}),
            changetype=c.Ldif.ChangeType.MODIFY,
            change_operations=[
                m.Ldif.ChangeOperation(
                    operation=c.Ldif.ChangeOperation.REPLACE, attribute="aci", values=[]
                )
            ],
        )
        plan = tm.ok(client.plan_upsert([clear], planned_entries=[future]))
        tm.that(plan.added_dns, length=0)
        tm.that(plan.modified_dns, length=0)
        tm.that(plan.unchanged_dns, eq=(dn.value,))
        tm.that((plan.adds, plan.modifies, plan.unchanged), eq=(0, 0, 1))
        operation = plan.operations[0]
        tm.that(operation.entry is clear, eq=True)
        tm.that(operation.operation, eq=c.Ldap.UpsertOperation.SKIPPED)
        tm.that(operation.changes, eq={})
        tm.that(operation.observation_is_projected, eq=True)
        tm.that(operation.observed_entry is None, eq=False)
        if operation.observed_entry is not None:
            tm.that(operation.observed_entry.attributes_dict, eq={})
        tm.fail(client.is_connected)

    @staticmethod
    def test_partial_modify_state_is_carried_to_the_next_phase() -> None:
        """Only the supplier projects changes; the caller carries its final state."""
        client = FlextLdap()
        dn = m.Ldif.DN(value="uid=future,dc=example,dc=invalid")
        future = m.Ldif.Entry(
            dn=dn,
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["top", "inetOrgPerson"],
                    "uid": ["future"],
                    "cn": ["Future"],
                    "sn": ["Future"],
                }
            ),
        )
        modify = m.Ldif.Entry(
            dn=dn,
            attributes=m.Ldif.Attributes(attributes={"description": ["Declared"]}),
            changetype=c.Ldif.ChangeType.MODIFY,
            change_operations=[
                m.Ldif.ChangeOperation(
                    operation=c.Ldif.ChangeOperation.REPLACE,
                    attribute="description",
                    values=[m.Ldif.ChangeOperationValue(value="Declared")],
                )
            ],
        )
        first = tm.ok(client.plan_upsert([modify], planned_entries=[future]))
        tm.that(
            first.operations[0].changes,
            eq={"description": [(c.Ldap.ModifyOperation.REPLACE, ["Declared"])]},
        )
        tm.that(
            first.planned_entries[0].attributes_dict["description"], eq=["Declared"]
        )
        clear = modify.model_copy(
            update={
                "attributes": m.Ldif.Attributes(attributes={"aci": []}),
                "change_operations": [
                    m.Ldif.ChangeOperation(
                        operation=c.Ldif.ChangeOperation.REPLACE,
                        attribute="aci",
                        values=[],
                    )
                ],
            }
        )
        second = tm.ok(
            client.plan_upsert([clear], planned_entries=first.planned_entries)
        )
        tm.that((second.modifies, second.unchanged), eq=(0, 1))
        tm.that(
            second.planned_entries[0].attributes_dict["description"], eq=["Declared"]
        )
        tm.that("planned_entries" in second.model_dump(), eq=False)
        tm.that("operations" in second.model_dump(), eq=True)
        tm.that('"observation_is_projected":true' in second.model_dump_json(), eq=True)
        tm.that(dn.value in repr(second), eq=False)

    @staticmethod
    def test_empty_batch_needs_no_directory() -> None:
        """Empty plans and writes do not require a connection."""
        client = FlextLdap()
        planned = tm.ok(client.plan_upsert([]))
        tm.that((planned.adds, planned.modifies, planned.unchanged), eq=(0, 0, 0))
        applied = tm.ok(client.batch_upsert([], stop_on_error=True))
        tm.that((applied.synced, applied.failed, applied.skipped), eq=(0, 0, 0))
        tm.fail(client.is_connected)

    @staticmethod
    def test_acl_wave_preserves_earlier_planned_add_and_observed_effects() -> None:
        """ACL deltas carry their comparison state without becoming ADD payloads."""
        client = FlextLdap()
        dn = m.Ldif.DN(value="uid=future,dc=example,dc=invalid")
        future = m.Ldif.Entry(
            dn=dn,
            attributes=m.Ldif.Attributes(attributes={"cn": ["Future"]}),
        )
        acl = "declared-access-rule"
        values_by_wave: tuple[list[str], ...] = ([acl], [])
        entries = [
            m.Ldif.Entry(
                dn=dn,
                attributes=m.Ldif.Attributes(attributes={"aci": values}),
                changetype=c.Ldif.ChangeType.MODIFY,
                change_operations=[
                    m.Ldif.ChangeOperation(
                        operation=c.Ldif.ChangeOperation.REPLACE,
                        attribute="aci",
                        values=[
                            m.Ldif.ChangeOperationValue(value=value) for value in values
                        ],
                    )
                ],
            )
            for values in values_by_wave
        ]
        plan = tm.ok(client.plan_upsert(entries, planned_entries=[future]))
        tm.that((plan.adds, plan.modifies, plan.unchanged), eq=(0, 2, 0))
        first, second = plan.operations
        tm.that(first.entry is entries[0], eq=True)
        tm.that(first.changes, eq={"aci": [(c.Ldap.ModifyOperation.REPLACE, [acl])]})
        tm.that(second.changes, eq={"aci": [(c.Ldap.ModifyOperation.REPLACE, [])]})
        tm.that(second.observation_is_projected, eq=True)
        tm.that(second.observed_entry is None, eq=False)
        if second.observed_entry is not None:
            tm.that(second.observed_entry.attributes_dict, eq={"aci": [acl]})
        tm.that(plan.planned_entries[0].attributes_dict, eq={"cn": ["Future"]})
        tm.fail(client.is_connected)

    @staticmethod
    def test_old_mutable_counter_input_is_not_a_plan() -> None:
        """A count cannot contradict the actual operation DNs."""
        with u.Tests.raises(ValueError, match="Extra inputs are not permitted"):
            m.Ldap.UpsertPlan.model_validate({"adds": 1})
