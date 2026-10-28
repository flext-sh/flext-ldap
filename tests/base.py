"""Service base for flext-ldap tests.

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

from typing import override

from flext_tests.base import FlextTestsServiceBase

from flext_ldap import m
from tests import TestsFlextLdapSettings, p


class TestsFlextLdapServiceBase[TDomainResult: p.Base = p.Base](
    FlextTestsServiceBase[TDomainResult],
):
    """LDAP test service base with source and test settings namespaces."""

    # NOTE (multi-agent): flext-tests owns fetch_settings; this project
    # declares only its more-specific bootstrap settings type.
    @classmethod
    @override
    def runtime_bootstrap_options(cls) -> m.RuntimeBootstrapOptions:
        return m.RuntimeBootstrapOptions(settings_type=TestsFlextLdapSettings)


s = TestsFlextLdapServiceBase

__all__: list[str] = ["TestsFlextLdapServiceBase", "s"]
