"""Unit tests for subtree deletion and dry upsert planning.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import override

import pytest

from tests import FlextLdap, c, m, p, r, u

pytestmark = pytest.mark.unit


class TestsFlextLdapSubtreeDelete:
    """Public behavior tests for FlextLdap.delete_subtree."""

    class SubtreeOperations(FlextLdap):
        """Deterministic operations double for subtree-delete semantics."""

        _subtree_entries: list[p.Ldif.Entry] = m.PrivateAttr(
            default_factory=list[p.Ldif.Entry],
        )
        _fail_on_dn: str | None = m.PrivateAttr(default=None)
        _deleted_dns: list[str] = m.PrivateAttr(default_factory=list[str])

        def __init__(
            self,
            subtree_entries: Sequence[p.Ldif.Entry],
            *,
            fail_on_dn: str | None = None,
        ) -> None:
            """Initialize the double with the directory snapshot it serves."""
            super().__init__()
            self._subtree_entries = list(subtree_entries)
            self._fail_on_dn = fail_on_dn

        @override
        def search(
            self,
            search_options: p.Ldap.SearchOptions,
            server_type: str = "rfc",
        ) -> p.Result[p.Ldap.SearchResult]:
            _ = server_type
            concrete_options = (
                search_options
                if isinstance(search_options, m.Ldap.SearchOptions)
                else m.Ldap.SearchOptions.model_validate(search_options)
            )
            if concrete_options.scope == c.Ldap.SearchScope.BASE:
                matched = [
                    entry
                    for entry in self._subtree_entries
                    if entry.dn is not None
                    and entry.dn.value == concrete_options.base_dn
                ]
                if not matched:
                    return r[p.Ldap.SearchResult].fail(
                        f"LDAP search failed: noSuchObject "
                        f"- {concrete_options.base_dn}",
                    )
            else:
                matched = list(self._subtree_entries)
            return r[p.Ldap.SearchResult].ok(
                m.Ldap.SearchResult(entries=matched, search_options=concrete_options),
            )

        @override
        def delete(self, dn: str | p.Ldif.DN) -> p.Result[p.Ldap.OperationResult]:
            dn_value = dn if isinstance(dn, str) else dn.value
            if self._fail_on_dn is not None and dn_value == self._fail_on_dn:
                return r[p.Ldap.OperationResult].fail(
                    f"simulated failure on {dn_value}",
                )
            self._deleted_dns.append(dn_value)
            return r[p.Ldap.OperationResult].ok(m.Ldap.OperationResult(success=True))

        def deleted_order(self) -> list[str]:
            """Public read of the deletion order the double observed.

            Returns:
                The resulting ``list[str]``.

            """
            return list(self._deleted_dns)

    BASE_DN = "ou=flext-tests,dc=flext,dc=local"
    CHILD_DN = "ou=children,ou=flext-tests,dc=flext,dc=local"
    LEAF_DN = "cn=leaf,ou=children,ou=flext-tests,dc=flext,dc=local"

    @staticmethod
    def _entry(dn: str, *, cn: str = "value") -> p.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(
                attributes={"cn": [cn]},
                attribute_metadata={},
            ),
            domain_events=[],
        )

    @staticmethod
    def test_missing_base_dn_fails_typed() -> None:
        """An empty base DN is rejected without touching the directory."""
        operations = FlextLdap()
        result = operations.delete_subtree("   ")
        u.Tests.that(result.failure, eq=True)
        u.Tests.that("non-empty base DN" in u.Tests.fail(result), eq=True)

    def test_not_connected_existence_check_fails_typed(self) -> None:
        """Without a connection the existence search fails as a typed failure."""
        operations = FlextLdap()
        result = operations.delete_subtree(self.BASE_DN)
        u.Tests.that(result.failure, eq=True)

    def test_absent_base_fails_typed(self) -> None:
        """A base that does not exist fails naming the DN."""
        operations = self.SubtreeOperations([])
        result = operations.delete_subtree(self.BASE_DN)
        u.Tests.that(result.failure, eq=True)
        u.Tests.that(self.BASE_DN in u.Tests.fail(result), eq=True)

    def test_subtree_deleted_deepest_first(self) -> None:
        """Children are deleted before parents and the count covers all entries."""
        operations = self.SubtreeOperations([
            self._entry(self.BASE_DN),
            self._entry(self.CHILD_DN),
            self._entry(self.LEAF_DN),
        ])
        result = operations.delete_subtree(self.BASE_DN)
        u.Tests.ok(result)
        u.Tests.that(result.value.deleted_count, eq=3)
        u.Tests.that(result.value.base_dn, eq=self.BASE_DN)
        u.Tests.that(
            operations.deleted_order(),
            eq=[self.LEAF_DN, self.CHILD_DN, self.BASE_DN],
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
        u.Tests.that(result.failure, eq=True)
        message = u.Tests.fail(result)
        u.Tests.that(self.LEAF_DN in message, eq=True)
        u.Tests.that("deleted_count=0" in message, eq=True)
        u.Tests.that(operations.deleted_order(), eq=[])

    def test_dn_model_input_is_accepted(self) -> None:
        """The public API accepts an m.Ldif.DN model as the subtree root."""
        operations = self.SubtreeOperations([self._entry(self.BASE_DN)])
        result = operations.delete_subtree(m.Ldif.DN(value=self.BASE_DN))
        u.Tests.ok(result)
        u.Tests.that(result.value.deleted_count, eq=1)


class TestsFlextLdapPlanUpsert:
    """Public behavior tests for FlextLdap.plan_upsert."""

    EXISTS_DN = "cn=exists,dc=flext,dc=local"
    DRIFTED_DN = "cn=drifted,dc=flext,dc=local"
    NEW_DN = "cn=new,dc=flext,dc=local"

    @staticmethod
    def _modify_entry(dn: str, *, additions: Mapping[str, str]) -> p.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes(attributes={}),
            changetype=c.Ldif.ChangeType.MODIFY,
            change_operations=[
                m.Ldif.ChangeOperation(
                    operation=c.Ldif.ChangeOperation.ADD,
                    attribute=name,
                    values=[m.Ldif.ChangeOperationValue(value=value)],
                )
                for name, value in additions.items()
            ],
        )

    def test_plan_modify_requires_directory_or_declared_state(self) -> None:
        """A modify cannot claim a write without observing its current state."""
        operations = FlextLdap()
        plan_result = operations.plan_upsert([
            self._modify_entry(self.EXISTS_DN, additions={"description": "added"}),
        ])
        u.Tests.that(plan_result.failure, eq=True)

    def test_plan_modify_without_additions_fails_like_the_write_path(self) -> None:
        """A modify entry without add operations fails the plan and the upsert alike."""
        operations = FlextLdap()
        entry = self._modify_entry(self.EXISTS_DN, additions={})
        plan_error = u.Tests.fail(operations.plan_upsert([entry]))
        write_error = u.Tests.fail(operations.upsert(entry))
        u.Tests.that(plan_error, eq=write_error)
