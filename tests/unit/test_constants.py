"""Unit tests for flext_ldap.constants.FlextLdapConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from tests.constants import c
from tests.utilities import u

pytestmark = pytest.mark.unit


class TestsFlextLdapConstantsUnit:
    """Behavioural tests for ``u.Ldap.Validation.is_valid_status``."""

    def test_is_valid_status_with_enum(self) -> None:
        u.Ldap.Tests.that(
            u.Ldap.Validation.is_valid_status(c.Ldap.Status.PENDING),
            eq=True,
        )

    def test_is_valid_status_with_string(self) -> None:
        u.Ldap.Tests.that(
            u.Ldap.Validation.is_valid_status(
                c.Ldap.Status.PENDING.value,
            ),
            eq=True,
        )

    def test_is_valid_status_invalid(self) -> None:
        u.Ldap.Tests.that(
            not u.Ldap.Validation.is_valid_status(
                c.Ldap.Tests.CONSTANT_INVALID_STATUS,
            ),
            eq=True,
        )
