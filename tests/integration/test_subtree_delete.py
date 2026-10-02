"""Docker integration tests for subtree deletion and dry upsert planning.

Exercises the public ``ldap`` facade against the real LDAP container:
deepest-first deletion semantics, typed absent-base failure, and the
read-only upsert plan (directory provably unchanged).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
from flext_tests import tm

from flext_ldap import ldap, m
from tests import c, u

if TYPE_CHECKING:
    from tests import t

pytestmark = [pytest.mark.integration, pytest.mark.docker]


def _ou_entry(dn: str, ou: str) -> m.Ldif.Entry:
    """Build an organizationalUnit entry for the real directory.

    Returns:
        The resulting ``m.Ldif.Entry`` value.

    """
    return m.Ldif.Entry(
        dn=m.Ldif.DN(value=dn),
        attributes=m.Ldif.Attributes.model_validate({
            "attributes": {"objectClass": ["organizationalUnit", "top"], "ou": [ou]},
            "attribute_metadata": {},
            "metadata": None,
        }),
        changetype=None,
        metadata=None,
        validation_metadata=None,
    )


def _user_entry(dn: str, identifier: str, *, cn: str) -> m.Ldif.Entry:
    """Build an inetOrgPerson entry for the real directory.

    Returns:
        The resulting ``m.Ldif.Entry`` value.

    """
    return m.Ldif.Entry(
        dn=m.Ldif.DN(value=dn),
        attributes=m.Ldif.Attributes.model_validate({
            "attributes": {
                "objectClass": list(c.Ldap.Tests.ADD_WRAPPER_OBJECT_CLASSES),
                "uid": [identifier],
                "cn": [cn],
                "sn": [identifier],
            },
            "attribute_metadata": {},
            "metadata": None,
        }),
        changetype=None,
        metadata=None,
        validation_metadata=None,
    )


def _modify_add_entry(dn: str, attribute: str, value: str) -> m.Ldif.Entry:
    """Build a ``changetype: modify`` entry adding one attribute value.

    Returns:
        The resulting ``m.Ldif.Entry`` value.

    """
    return m.Ldif.Entry(
        dn=m.Ldif.DN(value=dn),
        attributes=m.Ldif.Attributes.model_validate({
            "attributes": {
                c.Ldap.AttributeName.CHANGETYPE: [c.Ldif.LdifChangeType.MODIFY.value],
                c.Ldif.ChangeOperation.ADD: [attribute],
                attribute: [value],
            },
            "attribute_metadata": {},
            "metadata": None,
        }),
        changetype=None,
        metadata=None,
        validation_metadata=None,
    )


def _attribute_values(dn: str, attribute: str) -> t.StrSequence:
    """Read one attribute of one entry through the public ``find_entry``.

    Returns:
        The resulting ``t.StrSequence`` value.

    """
    found = ldap.find_entry(dn, attributes=[attribute])
    tm.ok(found)
    tm.that(len(found.value.entries), eq=1)
    attributes = tm.not_none(found.value.entries[0].attributes)
    return list(attributes.attributes.get(attribute, []))


class TestsFlextLdapSubtreeDeleteIntegration:
    """Subtree deletion through the public facade against a real directory."""

    @staticmethod
    def test_removes_children_first_and_reports_count(
        ldap_container: t.MappingKV[str, t.Scalar],
    ) -> None:
        """A three-level tree is deleted deepest-first with deleted_count=3."""
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        base_dn = str(ldap_container["base_dn"])
        token = f"st{uuid4().hex[:10]}"
        root_dn = f"ou={token},{base_dn}"
        child_dn = f"ou=leaf,{root_dn}"
        leaf_dn = f"cn=user,{child_dn}"
        tm.ok(ldap.connect(conn_config))
        try:
            tm.ok(ldap.add(_ou_entry(root_dn, token)))
            tm.ok(ldap.add(_ou_entry(child_dn, "leaf")))
            identifier = f"st-{uuid4().hex[:8]}"
            tm.ok(ldap.add(_user_entry(leaf_dn, identifier, cn="Stored Name")))

            result = ldap.delete_subtree(root_dn)

            tm.ok(result)
            tm.that(result.value.deleted_count, eq=3)
            tm.that(result.value.base_dn, eq=root_dn)
            absent = ldap.search(m.Ldap.SearchOptions.base_scope(root_dn))
            tm.that(absent.failure, eq=True)
            residue = ldap.search(
                m.Ldap.SearchOptions(
                    base_dn=base_dn,
                    filter_str=f"(ou={token})",
                    scope=c.Ldap.SearchScope.SUBTREE,
                    attributes=["ou"],
                ),
            )
            tm.ok(residue)
            tm.that(len(residue.value.entries), eq=0)
        finally:
            _ = ldap.delete_subtree(root_dn)
            ldap.disconnect()

    @staticmethod
    def test_absent_base_returns_typed_failure(
        ldap_container: t.MappingKV[str, t.Scalar],
    ) -> None:
        """Deleting a subtree whose base does not exist fails naming the DN."""
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        base_dn = str(ldap_container["base_dn"])
        absent_dn = f"ou=absent{uuid4().hex[:8]},{base_dn}"
        tm.ok(ldap.connect(conn_config))
        try:
            result = ldap.delete_subtree(absent_dn)
            tm.that(result.failure, eq=True)
            tm.that(absent_dn in str(result.error), eq=True)
        finally:
            ldap.disconnect()


class TestsFlextLdapPlanUpsertIntegration:
    """Dry-run planning through the public facade against a real directory."""

    @staticmethod
    def test_plan_counts_and_directory_stays_unchanged(
        ldap_container: t.MappingKV[str, t.Scalar],
    ) -> None:
        """Plans 1 add / 1 modify / 1 unchanged and writes nothing."""
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        base_dn = str(ldap_container["base_dn"])
        identifier = f"pl-{uuid4().hex[:8]}"
        stored_dn = f"uid={identifier},{base_dn}"
        new_dn = f"uid=planned-{identifier},{base_dn}"
        stored = _user_entry(stored_dn, identifier, cn="Stored Name")
        tm.ok(ldap.connect(conn_config))
        try:
            tm.ok(ldap.add(stored))

            plan_result = ldap.plan_upsert([
                stored,
                _user_entry(stored_dn, identifier, cn="Desired Name"),
                _user_entry(new_dn, f"planned-{identifier}", cn="Fresh"),
            ])

            tm.ok(plan_result)
            tm.that(plan_result.value.adds, eq=1)
            tm.that(plan_result.value.modifies, eq=1)
            tm.that(plan_result.value.unchanged, eq=1)

            stored_now = ldap.search(
                m.Ldap.SearchOptions(
                    base_dn=stored_dn,
                    filter_str=f"(uid={identifier})",
                    scope=c.Ldap.SearchScope.BASE,
                    attributes=["cn"],
                ),
            )
            tm.ok(stored_now)
            tm.that(len(stored_now.value.entries), eq=1)
            cn_values = tm.not_none(
                stored_now.value.entries[0].attributes,
            ).attributes.get("cn", [])
            tm.that("Stored Name" in cn_values, eq=True)

            fresh_now = ldap.search(
                m.Ldap.SearchOptions(
                    base_dn=base_dn,
                    filter_str=f"(uid=planned-{identifier})",
                    scope=c.Ldap.SearchScope.SUBTREE,
                    attributes=["cn"],
                ),
            )
            tm.ok(fresh_now)
            tm.that(len(fresh_now.value.entries), eq=0)
        finally:
            _ = ldap.delete(stored_dn)
            ldap.disconnect()

    @staticmethod
    def test_modify_entries_plan_as_the_write_path_applies_them(
        ldap_container: t.MappingKV[str, t.Scalar],
    ) -> None:
        """A modify-add entry plans as one modify.

        Applying the batch matches the plan.
        """
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        base_dn = str(ldap_container["base_dn"])
        identifier = f"pm-{uuid4().hex[:8]}"
        stored_dn = f"uid={identifier},{base_dn}"
        new_dn = f"uid=planned-{identifier},{base_dn}"
        description = f"planned {identifier}"
        stored = _user_entry(stored_dn, identifier, cn="Stored Name")
        batch = [
            stored,
            _user_entry(new_dn, f"planned-{identifier}", cn="Fresh"),
            _modify_add_entry(stored_dn, "description", description),
        ]
        tm.ok(ldap.connect(conn_config))
        try:
            tm.ok(ldap.add(stored))

            plan_result = ldap.plan_upsert(batch)

            tm.ok(plan_result)
            plan = plan_result.value
            tm.that((plan.adds, plan.modifies, plan.unchanged), eq=(1, 1, 1))
            tm.that(_attribute_values(stored_dn, "description"), eq=[])
            absent = ldap.find_entry(new_dn)
            tm.ok(absent)
            tm.that(len(absent.value.entries), eq=0)

            applied = ldap.batch_upsert(batch, stop_on_error=True)

            tm.ok(applied)
            tm.that(applied.value.synced, eq=plan.adds + plan.modifies)
            tm.that(applied.value.skipped, eq=plan.unchanged)
            tm.that(_attribute_values(stored_dn, "description"), eq=[description])
        finally:
            _ = ldap.delete(new_dn)
            _ = ldap.delete(stored_dn)
            ldap.disconnect()


class TestsFlextLdapFindEntryIntegration:
    """Absence-aware single-entry reads against a real directory."""

    @staticmethod
    def test_absent_entry_is_an_empty_result(
        ldap_container: t.MappingKV[str, t.Scalar],
    ) -> None:
        """A DN that does not exist reads as a successful empty result."""
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        base_dn = str(ldap_container["base_dn"])
        absent_dn = f"uid=absent-{uuid4().hex[:8]},{base_dn}"
        tm.ok(ldap.connect(conn_config))
        try:
            found = ldap.find_entry(absent_dn)
            tm.ok(found)
            tm.that(len(found.value.entries), eq=0)
        finally:
            ldap.disconnect()

    @staticmethod
    def test_present_entry_reads_the_requested_attributes(
        ldap_container: t.MappingKV[str, t.Scalar],
    ) -> None:
        """A present entry is returned with the attributes asked for."""
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        base_dn = str(ldap_container["base_dn"])
        identifier = f"fe-{uuid4().hex[:8]}"
        stored_dn = f"uid={identifier},{base_dn}"
        tm.ok(ldap.connect(conn_config))
        try:
            tm.ok(ldap.add(_user_entry(stored_dn, identifier, cn="Found Name")))
            tm.that(_attribute_values(stored_dn, "cn"), eq=["Found Name"])
        finally:
            _ = ldap.delete(stored_dn)
            ldap.disconnect()
