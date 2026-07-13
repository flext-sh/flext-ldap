"""Unit tests for flext_ldap.constants.FlextLdapConstants.

Behavioural coverage of the public constants contract exposed via ``c.Ldap.*``:
enum member values, closed-set membership invariants, keyed-mapping completeness,
the ``ENTRY_ALREADY_EXISTS_RE`` matching behaviour, the boundary exception tuple,
and the status-validation contract that consumes ``c.Ldap.Status``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from ldap3.core.exceptions import LDAPException as _Ldap3LDAPException

from tests.constants import c
from tests.utilities import u

pytestmark = pytest.mark.unit


class TestsFlextLdapConstantsUnit:
    """Behavioural tests for the ``FlextLdapConstants`` public contract."""

    # ------------------------------------------------------------------ #
    # Status enum + validation contract
    # ------------------------------------------------------------------ #

    @pytest.mark.parametrize(
        ("status", "expected_value"),
        [
            (c.Ldap.Status.PENDING, "pending"),
            (c.Ldap.Status.RUNNING, "running"),
            (c.Ldap.Status.COMPLETED, "completed"),
            (c.Ldap.Status.FAILED, "failed"),
        ],
    )
    def test_status_member_exposes_expected_string_value(
        self,
        status: c.Ldap.Status,
        expected_value: str,
    ) -> None:
        u.Ldap.Tests.that(status.value, eq=expected_value)

    def test_valid_statuses_covers_every_status_member(self) -> None:
        u.Ldap.Tests.that(
            frozenset(c.Ldap.Status) == c.Ldap.VALID_STATUSES,
            eq=True,
        )

    @pytest.mark.parametrize("status", list(c.Ldap.Status))
    def test_is_valid_status_accepts_every_enum_member(
        self,
        status: c.Ldap.Status,
    ) -> None:
        u.Ldap.Tests.that(u.Ldap.Validation.is_valid_status(status), eq=True)

    @pytest.mark.parametrize("status", list(c.Ldap.Status))
    def test_is_valid_status_accepts_every_status_string_value(
        self,
        status: c.Ldap.Status,
    ) -> None:
        u.Ldap.Tests.that(u.Ldap.Validation.is_valid_status(status.value), eq=True)

    def test_is_valid_status_rejects_unknown_string(self) -> None:
        u.Ldap.Tests.that(
            u.Ldap.Validation.is_valid_status(c.Ldap.Tests.CONSTANT_INVALID_STATUS),
            eq=False,
        )

    # ------------------------------------------------------------------ #
    # ResultCode + partial-success closed set
    # ------------------------------------------------------------------ #

    @pytest.mark.parametrize(
        ("code", "expected_int"),
        [
            (c.Ldap.ResultCode.SUCCESS, 0),
            (c.Ldap.ResultCode.OPERATIONS_ERROR, 1),
            (c.Ldap.ResultCode.PROTOCOL_ERROR, 2),
            (c.Ldap.ResultCode.REFERRAL, 10),
            (c.Ldap.ResultCode.NO_SUCH_OBJECT, 32),
        ],
    )
    def test_result_code_exposes_expected_int_value(
        self,
        code: c.Ldap.ResultCode,
        expected_int: int,
    ) -> None:
        u.Ldap.Tests.that(int(code), eq=expected_int)

    @pytest.mark.parametrize(
        ("code", "is_partial_success"),
        [
            (c.Ldap.ResultCode.SUCCESS, True),
            (c.Ldap.ResultCode.REFERRAL, True),
            (c.Ldap.ResultCode.OPERATIONS_ERROR, False),
            (c.Ldap.ResultCode.NO_SUCH_OBJECT, False),
        ],
    )
    def test_partial_success_codes_membership(
        self,
        code: c.Ldap.ResultCode,
        is_partial_success: bool,
    ) -> None:
        u.Ldap.Tests.that(
            code in c.Ldap.PARTIAL_SUCCESS_CODES,
            eq=is_partial_success,
        )

    # ------------------------------------------------------------------ #
    # Search-scope mapping to ldap3 integer values
    # ------------------------------------------------------------------ #

    def test_ldap3_scope_mapping_covers_every_search_scope(self) -> None:
        u.Ldap.Tests.that(
            set(c.Ldap.LDAP3_SCOPE_BY_SEARCH_SCOPE) == set(c.Ldap.SearchScope),
            eq=True,
        )

    @pytest.mark.parametrize(
        ("scope", "expected"),
        [
            (c.Ldap.SearchScope.BASE, c.Ldap.SearchScopeValue.BASE),
            (c.Ldap.SearchScope.ONELEVEL, c.Ldap.SearchScopeValue.LEVEL),
            (c.Ldap.SearchScope.SUBTREE, c.Ldap.SearchScopeValue.SUBTREE),
        ],
    )
    def test_ldap3_scope_mapping_translates_scope(
        self,
        scope: c.Ldap.SearchScope,
        expected: c.Ldap.SearchScopeValue,
    ) -> None:
        u.Ldap.Tests.that(
            c.Ldap.LDAP3_SCOPE_BY_SEARCH_SCOPE[scope],
            eq=expected,
        )

    def test_default_scope_is_subtree(self) -> None:
        u.Ldap.Tests.that(c.Ldap.DEFAULT_SCOPE, eq=c.Ldap.SearchScope.SUBTREE)

    # ------------------------------------------------------------------ #
    # Operation message maps keyed by every OperationType
    # ------------------------------------------------------------------ #

    @pytest.mark.parametrize("operation", list(c.Ldap.OperationType))
    def test_operation_success_messages_defined_for_every_operation(
        self,
        operation: c.Ldap.OperationType,
    ) -> None:
        message: str = c.Ldap.OPERATION_SUCCESS_MESSAGES[operation]
        u.Ldap.Tests.that(bool(message), eq=True)

    @pytest.mark.parametrize("operation", list(c.Ldap.OperationType))
    def test_operation_failure_prefixes_defined_for_every_operation(
        self,
        operation: c.Ldap.OperationType,
    ) -> None:
        prefix: str = c.Ldap.OPERATION_FAILURE_PREFIXES[operation]
        u.Ldap.Tests.that(prefix.endswith("failed"), eq=True)

    # ------------------------------------------------------------------ #
    # ENTRY_ALREADY_EXISTS_RE matching behaviour
    # ------------------------------------------------------------------ #

    @pytest.mark.parametrize(
        "message",
        [
            "entry already exists",
            "Entry Already Exists",
            "LDAP_ALREADY_EXISTS",
            "the object already exists in the tree",
            "entryAlreadyExists",
        ],
    )
    def test_entry_already_exists_re_matches_known_phrases(
        self,
        message: str,
    ) -> None:
        u.Ldap.Tests.that(
            c.Ldap.ENTRY_ALREADY_EXISTS_RE.search(message) is not None,
            eq=True,
        )

    @pytest.mark.parametrize(
        "message",
        [
            "no such object",
            "connection refused",
            "insufficient access rights",
        ],
    )
    def test_entry_already_exists_re_rejects_unrelated_phrases(
        self,
        message: str,
    ) -> None:
        u.Ldap.Tests.that(
            c.Ldap.ENTRY_ALREADY_EXISTS_RE.search(message) is None,
            eq=True,
        )

    # ------------------------------------------------------------------ #
    # Boundary exception tuple contract
    # ------------------------------------------------------------------ #

    def test_exc_connection_is_a_tuple_of_exception_types(self) -> None:
        expected_exceptions = {_Ldap3LDAPException, *c.EXC_BROAD_IO_TYPE}
        u.Ldap.Tests.that(
            set(c.Ldap.EXC_CONNECTION) == expected_exceptions,
            eq=True,
        )

    def test_exc_connection_extends_broad_io_boundary_types(self) -> None:
        broad_io: tuple[type[BaseException], ...] = c.EXC_BROAD_IO_TYPE
        u.Ldap.Tests.that(
            set(broad_io).issubset(set(c.Ldap.EXC_CONNECTION))
            and len(c.Ldap.EXC_CONNECTION) > len(broad_io),
            eq=True,
        )
