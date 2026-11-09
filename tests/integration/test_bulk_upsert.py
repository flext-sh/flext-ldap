"""Real LDAP batch reads, ordered waves and projection semantics.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator, Mapping
from contextlib import contextmanager
from uuid import uuid4

import pytest

from flext_ldap import FlextLdap
from tests import c, m, p, t, tm, u

pytestmark = [pytest.mark.integration, pytest.mark.docker]


def _person(
    dn: str, uid: str, *, cn: str = "Bulk Person", description: str | None = None
) -> p.Ldif.Entry:
    attrs = {
        "objectClass": list(c.Ldap.Tests.ADD_WRAPPER_OBJECT_CLASSES),
        "uid": [uid],
        "cn": [cn],
        "sn": ["Bulk"],
    }
    if description is not None:
        attrs["description"] = [description]
    return m.Ldif.Entry(
        dn=m.Ldif.DN(value=dn), attributes=m.Ldif.Attributes(attributes=attrs)
    )


def _replace(
    dn: str,
    attribute: str,
    values: list[str],
    *,
    operation: c.Ldif.ChangeOperation = c.Ldif.ChangeOperation.REPLACE,
) -> p.Ldif.Entry:
    return m.Ldif.Entry(
        dn=m.Ldif.DN(value=dn),
        attributes=m.Ldif.Attributes(attributes={attribute: values}),
        changetype=c.Ldif.ChangeType.MODIFY,
        change_operations=[
            m.Ldif.ChangeOperation(
                operation=operation,
                attribute=attribute,
                values=[m.Ldif.ChangeOperationValue(value=value) for value in values],
            )
        ],
    )


@contextmanager
def _connected(
    config: Mapping[str, t.Scalar],
) -> Generator[tuple[p.Ldap.LdapClient, str]]:
    """Use only the selected service and an exclusively owned test subtree.

    Yields:
        The public client and UUID subtree; no Docker lifecycle is invoked here.

    """
    name = f"bulk-{uuid4().hex}"
    base_dn = config["base_dn"]
    assert isinstance(base_dn, str)
    root = f"ou={name},{base_dn}"
    with FlextLdap() as client:
        tm.ok(client.connect(u.Ldap.Tests.create_connection_config(config)))
        tm.ok(
            client.add(
                m.Ldif.Entry(
                    dn=m.Ldif.DN(value=root),
                    attributes=m.Ldif.Attributes(
                        attributes={
                            "objectClass": ["top", "organizationalUnit"],
                            "ou": [name],
                        }
                    ),
                )
            )
        )
        try:
            yield client, root
        finally:
            tm.ok(client.delete_subtree(root))


class TestsFlextLdapBulkIntegration:
    """Test public operations on a real server, never a protocol simulator."""

    @staticmethod
    def test_data_batch_preserves_counts_and_becomes_a_fixed_point(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """Planning writes nothing; application shares its preparation."""
        with _connected(ldap_container) as (client, root):
            stored = _person(f"uid=stored,{root}", "stored", cn="Before")
            changed = _person(stored.dn_str, "stored", cn="After")
            added = _person(f"uid=added,{root}", "added")
            tm.ok(client.add(stored))
            batch = [stored, changed, added]
            plan = tm.ok(client.plan_upsert(batch))
            tm.that((plan.adds, plan.modifies, plan.unchanged), eq=(1, 1, 1))
            tm.that(plan.added_dns, eq=(added.dn_str,))
            tm.that(plan.modified_dns, eq=(stored.dn_str,))
            tm.that(
                [value.entry.dn_str for value in plan.operations],
                eq=[value.dn_str for value in batch],
            )
            tm.that(plan.operations[2].observed_entry, eq=None)
            tm.that(plan.operations[2].changes, eq={})
            tm.that(
                plan.operations[1].changes,
                eq={"cn": [(c.Ldap.ModifyOperation.REPLACE, ["After"])]},
            )
            before = tm.ok(client.find_entry(stored.dn_str, attributes=["cn"]))
            tm.that(before.entries[0].attributes_dict["cn"], eq=["Before"])
            applied = tm.ok(client.batch_upsert(batch, stop_on_error=True))
            tm.that((applied.synced, applied.skipped, applied.failed), eq=(2, 1, 0))
            again = tm.ok(client.plan_upsert([changed, added]))
            tm.that((again.adds, again.modifies, again.unchanged), eq=(0, 0, 2))

    @staticmethod
    def test_repeated_modifies_read_fresh_ordered_waves(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """A later replace sees the preceding write, not its original snapshot."""
        with _connected(ldap_container) as (client, root):
            person = _person(f"uid=waves,{root}", "waves", description="Start")
            tm.ok(client.add(person))
            values_by_wave: list[list[str]] = [["Middle"], ["Middle"], ["Final"], []]
            batch = [
                _replace(person.dn_str, "description", values)
                for values in values_by_wave
            ]
            plan = tm.ok(client.plan_upsert(batch))
            tm.that((plan.modifies, plan.unchanged), eq=(3, 1))
            observations = [
                value.observed_entry.attributes_dict.get("description")
                if value.observed_entry is not None
                else None
                for value in plan.operations
            ]
            tm.that(observations, eq=[["Start"], ["Middle"], ["Middle"], ["Final"]])
            tm.that(plan.operations[0].observation_is_projected, eq=False)
            tm.that(plan.operations[2].observation_is_projected, eq=True)
            before = tm.ok(client.find_entry(person.dn_str, attributes=["description"]))
            tm.that(before.entries[0].attributes_dict["description"], eq=["Start"])
            applied = tm.ok(client.batch_upsert(batch, stop_on_error=True))
            tm.that((applied.synced, applied.skipped), eq=(3, 1))
            after = tm.ok(client.find_entry(person.dn_str, attributes=["description"]))
            tm.that(after.entries[0].attributes_dict.get("description"), eq=None)

    @staticmethod
    def test_native_add_and_delete_values_match_apply(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """Expose exact native value operations without writing during planning."""
        with _connected(ldap_container) as (client, root):
            person = _person(f"uid=values,{root}", "values", description="First")
            tm.ok(client.add(person))
            batch = [
                _replace(
                    person.dn_str,
                    "description",
                    ["First", "Second"],
                    operation=c.Ldif.ChangeOperation.ADD,
                ),
                _replace(
                    person.dn_str,
                    "description",
                    ["First"],
                    operation=c.Ldif.ChangeOperation.DELETE,
                ),
                _replace(person.dn_str, "description", ["Second"]),
            ]
            plan = tm.ok(client.plan_upsert(batch))
            tm.that(
                [value.changes for value in plan.operations],
                eq=[
                    {"description": [(c.Ldap.ModifyOperation.ADD, ["Second"])]},
                    {"description": [(c.Ldap.ModifyOperation.DELETE, ["First"])]},
                    {},
                ],
            )
            before = tm.ok(client.find_entry(person.dn_str, attributes=["description"]))
            tm.that(before.entries[0].attributes_dict["description"], eq=["First"])
            applied = tm.ok(client.batch_upsert(batch, stop_on_error=True))
            tm.that(
                (applied.synced, applied.skipped), eq=(plan.modifies, plan.unchanged)
            )
            after = tm.ok(client.find_entry(person.dn_str, attributes=["description"]))
            tm.that(after.entries[0].attributes_dict["description"], eq=["Second"])

    @staticmethod
    def test_multivalued_escaped_rdns_and_missing_parent(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """RDN filters cannot make another matching entry count as this DN."""
        with _connected(ldap_container) as (client, root):
            person = _person(
                r"cn=Comma\, Plus\+ Name+uid=multi," + root,
                "multi",
                cn="Comma, Plus+ Name",
            )
            tm.ok(client.add(person))
            extra = _person(f"cn=unrelated,{root}", "multi", cn="unrelated")
            extra_attrs = dict(extra.attributes_dict)
            extra_attrs["cn"] = ["unrelated", "Comma, Plus+ Name"]
            tm.ok(
                client.add(
                    extra.model_copy(
                        update={"attributes": m.Ldif.Attributes(attributes=extra_attrs)}
                    )
                )
            )
            alternate = person.model_copy(
                update={
                    "dn": m.Ldif.DN(value=r"uid=multi+cn=Comma\2c Plus\2b Name," + root)
                }
            )
            absent = _person(f"uid=absent,{root}", "absent")
            plan = tm.ok(client.plan_upsert([alternate, absent]))
            tm.that((plan.adds, plan.modifies, plan.unchanged), eq=(1, 0, 1))
            missing_parent = f"ou=missing,{root}"
            missing = tm.ok(
                client.plan_upsert([
                    _person(f"uid=one,{missing_parent}", "one"),
                    _person(f"uid=two,{missing_parent}", "two"),
                ])
            )
            tm.that((missing.adds, missing.modifies), eq=(2, 0))

    @staticmethod
    def test_native_usage_separates_operational_and_new_user_attributes(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """Projection preserves operational fields outside the user view."""
        with _connected(ldap_container) as (client, root):
            person = _person(f"uid=usage,{root}", "usage")
            tm.ok(client.add(person))
            tm.fail(tm.ok(client.is_user_attribute("entryUUID")))
            tm.ok(tm.ok(client.is_user_attribute("description")))
            original = tm.ok(client.find_entry(person.dn_str, attributes=["entryUUID"]))
            original_uuid = list(original.entries[0].attributes_dict["entryUUID"])
            batch = [
                _replace(person.dn_str, "entryUUID", [str(uuid4())]),
                person,
                _person(person.dn_str, "usage", description="Declared only"),
                person,
            ]
            plan = tm.ok(client.plan_upsert(batch))
            tm.that((plan.modifies, plan.unchanged), eq=(3, 1))
            unchanged = tm.ok(
                client.find_entry(
                    person.dn_str, attributes=["entryUUID", "description"]
                )
            )
            tm.that(unchanged.entries[0].attributes_dict["entryUUID"], eq=original_uuid)
            tm.that(unchanged.entries[0].attributes_dict.get("description"), eq=None)

    @staticmethod
    def test_first_write_error_stops_without_positive_batch_result(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """The actual LDAP failure stops subsequent writes in the same wave."""
        with _connected(ldap_container) as (client, root):
            first = _person(f"uid=first,{root}", "first")
            bad = _person(f"uid=bad,{root}", "bad")
            attrs = dict(bad.attributes_dict)
            attrs["unregisteredBulkAttribute" + uuid4().hex] = ["Invalid"]
            bad = bad.model_copy(
                update={"attributes": m.Ldif.Attributes(attributes=attrs)}
            )
            last = _person(f"uid=last,{root}", "last")
            result = client.batch_upsert([first, bad, last], stop_on_error=True)
            tm.fail(result)
            tm.that(tm.ok(client.find_entry(first.dn_str)).entries, length=1)
            tm.that(tm.ok(client.find_entry(last.dn_str)).entries, length=0)
