"""Behavioral contract test for the frozen flext-ldap public API surface.

Asserts the OBSERVABLE public contract of the ``flext_ldap`` package: the
frozen root export set, the importability of every exported name, the identity
of the canonical single-letter aliases, and the operations the ``FlextLdap``
facade promises its callers. It deliberately avoids internal implementation
details (MRO ordering, private attributes, adapter modules).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

import flext_ldap
from flext_ldap import (
    FlextLdap,
    FlextLdapConstants,
    FlextLdapModels,
    FlextLdapProtocols,
    FlextLdapService,
    FlextLdapTypes,
    FlextLdapUtilities,
)

pytestmark = pytest.mark.unit

_FROZEN_ROOT_EXPORTS: frozenset[str] = frozenset({
    "FlextLdap",
    "FlextLdapAdapterHost",
    "FlextLdapApiRuntime",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapModels",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapService",
    "FlextLdapSettings",
    "FlextLdapSync",
    "FlextLdapTypes",
    "FlextLdapUtilities",
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
    # NOTE (multi-agent): settings singleton export is the SSOT convention
    # (same as flext-core/flext-cli roots); frozen after ADR-005 namespacing.
    "settings",
    "t",
    "u",
    "x",
})

# Canonical single-letter alias -> the domain facade it must resolve to.
# This identity is the public contract that lets consumers write ``c.Ldap.*``,
# ``m.Ldap.*`` etc. without importing the long facade names.
_ALIAS_FACADE_CASES: tuple[tuple[str, type], ...] = (
    ("c", FlextLdapConstants),
    ("m", FlextLdapModels),
    ("p", FlextLdapProtocols),
    ("s", FlextLdapService),
    ("t", FlextLdapTypes),
    ("u", FlextLdapUtilities),
)

# Operations the public ``FlextLdap`` facade promises to expose to callers.
# Composition strategy (which mixin supplies each) is an internal detail; that
# the facade *offers* these callables is the observable contract.
_FACADE_OPERATIONS: tuple[str, ...] = (
    "connect",
    "disconnect",
    "execute",
    "add",
    "modify",
    "delete",
    "search",
    "upsert",
    "batch_upsert",
    "sync_multiple_phases",
    "sync_phase_entries",
)


class TestsFlextLdapPublicApiContract:
    """Lock the observable public surface of the flext-ldap package."""

    def test_root_all_equals_frozen_export_set(self) -> None:
        actual: frozenset[str] = frozenset(flext_ldap.__all__)
        assert actual == _FROZEN_ROOT_EXPORTS, (
            "flext_ldap.__all__ drift detected.\n"
            f"  extra: {sorted(actual - _FROZEN_ROOT_EXPORTS)}\n"
            f"  missing: {sorted(_FROZEN_ROOT_EXPORTS - actual)}"
        )

    @pytest.mark.parametrize("name", sorted(_FROZEN_ROOT_EXPORTS))
    def test_every_declared_export_is_importable(self, name: str) -> None:
        assert hasattr(flext_ldap, name), (
            f"declared in __all__ but not importable: {name}"
        )

    def test_declared_exports_are_unique(self) -> None:
        names: tuple[str, ...] = flext_ldap.__all__
        assert len(names) == len(set(names)), "duplicate names in flext_ldap.__all__"

    @pytest.mark.parametrize(("alias", "facade"), _ALIAS_FACADE_CASES)
    def test_canonical_alias_resolves_to_domain_facade(
        self, alias: str, facade: type
    ) -> None:
        assert getattr(flext_ldap, alias) is facade

    def test_ldap_facade_is_a_service(self) -> None:
        # FlextLdapService is exported as the service base; the public facade
        # honouring that relationship is part of the contract.
        assert issubclass(FlextLdap, FlextLdapService)

    @pytest.mark.parametrize("operation", _FACADE_OPERATIONS)
    def test_facade_exposes_documented_operation(self, operation: str) -> None:
        member = getattr(FlextLdap, operation, None)
        assert member is not None, f"public facade is missing operation: {operation}"
        assert callable(member), f"facade operation is not callable: {operation}"

    def test_global_ldap_is_public_facade_instance(self) -> None:
        assert isinstance(flext_ldap.ldap, FlextLdap)

    def test_fetch_global_returns_shared_singleton(self) -> None:
        # The module-level ``ldap`` is produced by ``FlextLdap.fetch_global()``;
        # repeated resolution must yield the same shared instance (idempotence).
        assert FlextLdap.fetch_global() is flext_ldap.ldap
        assert FlextLdap.fetch_global() is FlextLdap.fetch_global()
