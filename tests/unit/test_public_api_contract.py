"""Contract test for the frozen flext-ldap public API surface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TypeAlias

import pytest

import flext_ldap
from flext_ldap import (
    FlextLdap,
    FlextLdapApiRuntime,
    FlextLdapConnection,
    FlextLdapConstants,
    FlextLdapModels,
    FlextLdapOperations,
    FlextLdapProtocols,
    FlextLdapService,
    FlextLdapSync,
    FlextLdapTypes,
    FlextLdapUtilities,
)

pytestmark = pytest.mark.unit

FlextLdapFacadeType: TypeAlias = (
    type[FlextLdapConstants]
    | type[FlextLdapModels]
    | type[FlextLdapProtocols]
    | type[FlextLdapService]
    | type[FlextLdapTypes]
    | type[FlextLdapUtilities]
)

_FROZEN_ROOT_EXPORTS: frozenset[str] = frozenset({
    "ConnectionManager",
    "FlextLdap",
    "FlextLdapApiRuntime",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapLdap3Wrappers",
    "FlextLdapModels",
    "FlextLdapModelsLdap",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapSync",
    "FlextLdapSyncCallbacks",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "OperationExecutor",
    "ResultConverter",
    "ResultConverterExtractMixin",
    "SearchExecutor",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "c",
    "d",
    "e",
    "h",
    "ldap",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
})

_ALIAS_TO_FACADE: Mapping[str, FlextLdapFacadeType] = MappingProxyType({
    "c": FlextLdapConstants,
    "m": FlextLdapModels,
    "p": FlextLdapProtocols,
    "s": FlextLdapService,
    "t": FlextLdapTypes,
    "u": FlextLdapUtilities,
})

_ADAPTER_SUPPORT_EXPORTS: frozenset[str] = frozenset({
    "ConnectionManager",
    "FlextLdapLdap3Wrappers",
    "FlextLdapModelsLdap",
    "OperationExecutor",
    "ResultConverter",
    "ResultConverterExtractMixin",
    "SearchExecutor",
})


class TestsFlextLdapPublicApiContract:
    """Lock flext-ldap root exports and canonical alias identities."""

    def test_root_all_equals_frozen_exports(self) -> None:
        actual = set(flext_ldap.__all__)
        assert actual == _FROZEN_ROOT_EXPORTS, (
            "flext_ldap.__all__ drift detected.\n"
            f"  extra: {sorted(actual - _FROZEN_ROOT_EXPORTS)}\n"
            f"  missing: {sorted(_FROZEN_ROOT_EXPORTS - actual)}"
        )

    def test_root_exports_are_importable(self) -> None:
        missing = [name for name in flext_ldap.__all__ if not hasattr(flext_ldap, name)]
        assert not missing, f"Not importable from flext_ldap: {missing}"

    def test_canonical_aliases_are_facades(self) -> None:
        for alias, facade in _ALIAS_TO_FACADE.items():
            assert getattr(flext_ldap, alias) is facade

    def test_api_facade_mro_is_frozen(self) -> None:
        assert FlextLdap.__mro__[:4] == (
            FlextLdap,
            FlextLdapConnection,
            FlextLdapSync,
            FlextLdapOperations,
        )
        assert issubclass(FlextLdap, FlextLdapApiRuntime)

    def test_adapter_support_exports_are_frozen(self) -> None:
        root_exports = set(flext_ldap.__all__)
        missing = sorted(_ADAPTER_SUPPORT_EXPORTS - root_exports)
        assert not missing, (
            f"Adapter support exports removed from flext_ldap root API: {missing}"
        )

    def test_global_ldap_is_public_facade_instance(self) -> None:
        assert isinstance(flext_ldap.ldap, FlextLdap)
