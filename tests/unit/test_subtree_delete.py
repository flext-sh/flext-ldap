"""Unit tests for subtree deletion and dry upsert planning.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

import pytest
from flext_ldif import r

from flext_ldap.services.operations import FlextLdapOperations
from tests import c, m, u

if TYPE_CHECKING:
    from tests import p, t

pytestmark = pytest.mark.unit


class TestsFlextLdapSubtreeDelete:
    """Public behavior tests for FlextLdapOperations.delete_subtree."""

    class SubtreeOperations(FlextLdapOperations):
        """Deterministic operations double for subtree-delete semantics."""

        _subtree_entries: list[m.Ldif.Entry] = u.PrivateAttr(default_factory=list)
        _fail_on_dn: str | None = u.PrivateAttr(default=None)
        _deleted_dns: list[str] = u.PrivateAttr(default_factory=list)
        _write_calls: list[str] = u.PrivateAttr(default_factory=list)

        def __init__(
            self,
            subtree_entries: t.SequenceOf[m.Ldif.Entry],
            *,
            fail_on_dn: str | None = None,
        ) -> None:
            """Initialize the double with the directory snapshot it serves."""
            super().__init__()
            self._subtree_entries = list(subtree_entries)
            self._fail_on_dn = fail_on_dn

        @override
        def search(
            self, search_options: p.Ldap.SearchOptions, server_type: str = "rfc"
        ) -> p.Result[m.Ldap.SearchResult]:
            _ = server_type
            if search_options.scope == c.Ldap.SearchScope.BASE:
                matched = [
                    entry
                    for entry in self._subtree_entries
                    if entry.dn is not None and entry.dn.value == search_options.base_dn
                ]
                if not matched:
                    return r[m.Ldap.SearchResult].fail(
                        f"LDAP search failed: noSuchObject - {search_options.base_dn}"
                    )
            else:
                matched = list(self._subtree_entries)
            return r[m.Ldap.SearchResult].ok(
                m.Ldap.SearchResult(entries=matched, search_options=search_options)
            )

        @override
        def delete(self, dn: str | p.Ldif.DN) -> p.Result[m.Ldap.OperationResult]:
            dn_value = dn if isinstance(dn, str) else dn.value
            self._write_calls.append(f"delete:{dn_value}")
            if self._fail_on_dn is not None and dn_value == self._fail_on_dn:
                return r[m.Ldap.OperationResult].fail(
                    f"simulated failure on {dn_value}"
                )
            self._deleted_dns.append(dn_value)
            return r[m.Ldap.OperationResult].ok(m.Ldap.OperationResult(success=True))

        @override
        def add(self, entry: p.Ldif.Entry) -> p.Result[m.Ldap.OperationResult]:
            self._write_calls.append(f"add:{entry.dn.value if entry.dn else ''}")
            return r[m.Ldap.OperationResult].fail("planning must not add")

        @override
        def modify(
            self, dn: str | p.Ldif.DN, changes: t.Ldap.LdapModifyChanges
        ) -> p.Result[m.Ldap.OperationResult]:
            dn_value = dn if isinstance(dn, str) else dn.value
            self._write_calls.append(f"modify:{dn_value}")
            return r[m.Ldap.OperationResult].fail("planning must not modify")

        def deleted_order(self) -> list[str]:
            """Public read of the deletion order the double observed."""
            return list(self._deleted_dns)

        def write_log(self) -> list[str]:
            """Public read of every write attempt the double observed."""
            return list(self._write_calls)

    BASE_DN = "ou=flext-tests,dc=flext,dc=local"
    CHILD_DN = "ou=children,ou=flext-tests,dc=flext,dc=local"
    LEAF_DN = "cn=leaf,ou=children,ou=flext-tests,dc=flext,dc=local"

    @staticmethod
    def _entry(dn: str, *, cn: str = "value") -> m.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(
                attributes={"cn": [cn]}, attribute_metadata={}
            ),
        )

    def test_missing_base_dn_fails_typed(self) -> None:
        """An empty base DN is rejected without touching the directory."""
        operations = FlextLdapOperations()
        result = operations.delete_subtree("   ")
        u.Ldap.Tests.that(result.failure, eq=True)
        u.Ldap.Tests.that("non-empty base DN" in u.Ldap.Tests.fail(result), eq=True)

    def test_not_connected_existence_check_fails_typed(self) -> None:
        """Without a connection the existence search fails as a typed failure."""
        operations = FlextLdapOperations()
        result = operations.delete_subtree(self.BASE_DN)
        u.Ldap.Tests.that(result.failure, eq=True)

    def test_absent_base_fails_typed(self) -> None:
        """A base that does not exist fails naming the DN."""
        operations = self.SubtreeOperations([])
        result = operations.delete_subtree(self.BASE_DN)
        u.Ldap.Tests.that(result.failure, eq=True)
        u.Ldap.Tests.that(self.BASE_DN in u.Ldap.Tests.fail(result), eq=True)

    def test_subtree_deleted_deepest_first(self) -> None:
        """Children are deleted before parents and the count covers all entries."""
        operations = self.SubtreeOperations([
            self._entry(self.BASE_DN),
            self._entry(self.CHILD_DN),
            self._entry(self.LEAF_DN),
        ])
        result = operations.delete_subtree(self.BASE_DN)
        u.Ldap.Tests.ok(result)
        u.Ldap.Tests.that(result.value.deleted_count, eq=3)
        u.Ldap.Tests.that(result.value.base_dn, eq=self.BASE_DN)
        u.Ldap.Tests.that(
            operations.deleted_order(), eq=[self.LEAF_DN, self.CHILD_DN, self.BASE_DN]
        )

    def test_first_failure_stops_and_reports_progress(self) -> None:
        """A failed deletion stops the run with DN, count, and cause."""
        operations = self.SubtreeOperations(
            [
                self._entry(self.BASE_DN),
                self._entry(self.CHILD_DN),
                self._entry(self.LEAF_DN),
            ],
            fail_on_dn=self.LEAF_DN,
        )
        result = operations.delete_subtree(self.BASE_DN)
        u.Ldap.Tests.that(result.failure, eq=True)
        message = u.Ldap.Tests.fail(result)
        u.Ldap.Tests.that(self.LEAF_DN in message, eq=True)
        u.Ldap.Tests.that("deleted_count=0" in message, eq=True)
        u.Ldap.Tests.that(operations.deleted_order(), eq=[])

    def test_dn_model_input_is_accepted(self) -> None:
        """The public API accepts an m.Ldif.DN model as the subtree root."""
        operations = self.SubtreeOperations([self._entry(self.BASE_DN)])
        result = operations.delete_subtree(m.Ldif.DN(value=self.BASE_DN))
        u.Ldap.Tests.ok(result)
        u.Ldap.Tests.that(result.value.deleted_count, eq=1)


class TestsFlextLdapPlanUpsert:
    """Public behavior tests for FlextLdapOperations.plan_upsert."""

    EXISTS_DN = "cn=exists,dc=flext,dc=local"
    DRIFTED_DN = "cn=drifted,dc=flext,dc=local"
    NEW_DN = "cn=new,dc=flext,dc=local"

    @staticmethod
    def _entry(dn: str, *, cn: str = "value", sn: str = "surname") -> m.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(
                attributes={"cn": [cn], "sn": [sn]}, attribute_metadata={}
            ),
        )

    def test_plan_classifies_without_writing(self) -> None:
        """Adds/modifies/unchanged are counted and no write is issued.

        The drifted entry differs in ``sn`` (a non-RDN attribute): the compare
        owner deliberately excludes RDN attributes from modify changes
        (notAllowedOnRDN), so only non-RDN drift classifies as a modification.
        """
        directory = [
            self._entry(self.EXISTS_DN, cn="same", sn="stored"),
            self._entry(self.DRIFTED_DN, cn="drifted", sn="stored"),
        ]
        operations = TestsFlextLdapSubtreeDelete.SubtreeOperations(directory)
        plan_result = operations.plan_upsert([
            self._entry(self.EXISTS_DN, cn="same", sn="stored"),
            self._entry(self.DRIFTED_DN, cn="drifted", sn="desired"),
            self._entry(self.NEW_DN, cn="fresh", sn="fresh"),
        ])
        u.Ldap.Tests.ok(plan_result)
        u.Ldap.Tests.that(plan_result.value.adds, eq=1)
        u.Ldap.Tests.that(plan_result.value.modifies, eq=1)
        u.Ldap.Tests.that(plan_result.value.unchanged, eq=1)
        u.Ldap.Tests.that(operations.write_log(), eq=[])

    def test_plan_missing_dn_fails_typed(self) -> None:
        """An entry without a DN aborts the plan with a typed failure."""
        operations = TestsFlextLdapSubtreeDelete.SubtreeOperations([])
        entry = m.Ldif.Entry(
            dn=None,
            attributes=m.Ldif.Attributes(
                attributes={"cn": ["orphan"]}, attribute_metadata={}
            ),
        )
        plan_result = operations.plan_upsert([entry])
        u.Ldap.Tests.that(plan_result.failure, eq=True)
        u.Ldap.Tests.that("missing DN" in u.Ldap.Tests.fail(plan_result), eq=True)

    def test_plan_search_failure_fails_typed(self) -> None:
        """A failing search aborts the plan without any write."""
        operations = FlextLdapOperations()
        plan_result = operations.plan_upsert([self._entry(self.NEW_DN)])
        u.Ldap.Tests.that(plan_result.failure, eq=True)

    @staticmethod
    def _modify_entry(dn: str, *, additions: t.MappingKV[str, str]) -> m.Ldif.Entry:
        attributes: dict[str, list[str]] = {
            c.Ldap.AttributeName.CHANGETYPE: [c.Ldif.LdifChangeType.MODIFY.value],
            c.Ldif.ChangeOperation.ADD: list(additions),
        }
        attributes.update({name: [value] for name, value in additions.items()})
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(attributes=attributes, attribute_metadata={}),
        )

    def test_plan_modify_entry_counts_without_reading_the_directory(self) -> None:
        """A modify-add entry plans as a modify with no read, like the write path.

        The operations service is not connected, so any directory read would
        fail the plan: success proves the modify entry was routed without one.
        """
        operations = FlextLdapOperations()
        plan_result = operations.plan_upsert([
            self._modify_entry(self.EXISTS_DN, additions={"description": "added"})
        ])
        u.Ldap.Tests.ok(plan_result)
        plan = plan_result.value
        u.Ldap.Tests.that((plan.adds, plan.modifies, plan.unchanged), eq=(0, 1, 0))

    def test_plan_modify_without_additions_fails_like_the_write_path(self) -> None:
        """A modify entry without add operations fails the plan and the upsert alike."""
        operations = FlextLdapOperations()
        entry = self._modify_entry(self.EXISTS_DN, additions={})
        plan_error = u.Ldap.Tests.fail(operations.plan_upsert([entry]))
        write_error = u.Ldap.Tests.fail(operations.upsert(entry))
        u.Ldap.Tests.that(plan_error, eq=write_error)
