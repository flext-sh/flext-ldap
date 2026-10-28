"""Validate explicit test credentials without authentication or cached identities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from uuid import uuid4

import pytest

from flext_ldap import settings
from tests import tm, u


class TestsFlextLdapAdminCredentials:
    """Exercise the public test utility against its environment contract."""

    @staticmethod
    @pytest.mark.parametrize(
        "missing", ["FLEXT_LDAP_BIND_DN", "FLEXT_LDAP_BIND_PASSWORD"]
    )
    def test_missing_credentials_do_not_select_a_default(missing: str) -> None:
        """Missing declared credentials fail instead of probing fallback identities."""
        configured = {
            "FLEXT_LDAP_BIND_DN": f"cn={uuid4().hex}",
            "FLEXT_LDAP_BIND_PASSWORD": uuid4().hex,
        }
        del configured[missing]
        with (
            u.Tests.env_vars_context(configured, vars_to_clear=(missing,)),
            pytest.raises(KeyError) as failure,
        ):
            u.Ldap.Tests.get_admin_credentials()
        tm.that(failure.value.args, eq=(missing,))

    @staticmethod
    def test_each_read_uses_current_credentials_without_mutating_settings() -> None:
        """Repeated reads observe changed inputs and preserve the settings owner."""
        original = settings.Ldap.model_dump()
        for _ in range(2):
            configured = {
                "FLEXT_LDAP_BIND_DN": f"cn={uuid4().hex}",
                "FLEXT_LDAP_BIND_PASSWORD": uuid4().hex,
            }
            with u.Tests.env_vars_context(configured):
                tm.that(
                    u.Ldap.Tests.get_admin_credentials(),
                    eq=(
                        configured["FLEXT_LDAP_BIND_DN"],
                        configured["FLEXT_LDAP_BIND_PASSWORD"],
                    ),
                )
        tm.that(settings.Ldap.model_dump(), eq=original)
