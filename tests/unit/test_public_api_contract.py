"""Behavioral contract test for the flext-ldap public API surface.

Asserts the OBSERVABLE public contract of the ``flext_ldap`` package: the
root export set propagated from each module's declarations, the
importability of every exported name, the identity of the canonical
single-letter aliases, and the operations the ``FlextLdap`` facade
promises its callers. It deliberately avoids internal implementation
details (MRO ordering, private attributes, adapter modules).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import ModuleType
from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

import flext_ldap
import flext_ldap._config
import flext_ldap._settings
import flext_ldap.api
import flext_ldap.base
import flext_ldap.cli
import flext_ldap.constants
import flext_ldap.models
import flext_ldap.protocols
import flext_ldap.typings
import flext_ldap.utilities
from flext_ldap import (
    FlextLdap,
    FlextLdapConstants,
    FlextLdapModels,
    FlextLdapProtocols,
    FlextLdapService,
    FlextLdapTypes,
    FlextLdapUtilities,
)

if TYPE_CHECKING:
    from flext_ldap import t
pytestmark = pytest.mark.unit

# Top-level facade-owner modules of ``flext_ldap``, statically enumerated so the
# propagation contract below stays static and typed: every non-package module
# except dunder metadata (``__init__``, ``__version__``). Packages (``adapters``,
# ``services``, ``config``, private ``_constants``/``_models``/``_utilities``)
# are not facade owners.
_DECLARING_MODULES: tuple[ModuleType, ...] = (
    flext_ldap._config,
    flext_ldap._settings,
    flext_ldap.api,
    flext_ldap.base,
    flext_ldap.cli,
    flext_ldap.constants,
    flext_ldap.models,
    flext_ldap.protocols,
    flext_ldap.typings,
    flext_ldap.utilities,
)

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
_FACADE_OPERATIONS: t.VariadicTuple[str] = (
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

    @staticmethod
    def test_root_all_propagates_every_module_declaration() -> None:
        """Verify root exports every name its top-level modules declare.

        The owner of each public name is the module that lists it in its own
        ``__all__``; the root only propagates. Dunder metadata modules (for
        example ``__version__``) are not facade owners and are excluded; the
        owner set is statically enumerated in ``_DECLARING_MODULES``.
        """
        declared: set[str] = set()
        for module in _DECLARING_MODULES:
            declared.update(module.__all__)
        tm.that(declared, empty=False)
        tm.that(declared - frozenset(flext_ldap.__all__), empty=True)

    @pytest.mark.parametrize("name", sorted(flext_ldap.__all__))
    @staticmethod
    def test_every_declared_export_is_importable(name: str) -> None:
        """Verify every declared export is importable."""
        tm.that(
            hasattr(flext_ldap, name),
            eq=True,
            msg=f"declared in __all__ but not importable: {name}",
        )

    @staticmethod
    def test_declared_exports_are_unique() -> None:
        """Verify declared exports are unique."""
        names: t.VariadicTuple[str] = flext_ldap.__all__
        tm.that(len(names), eq=len(set(names)))

    @pytest.mark.parametrize(("alias", "facade"), _ALIAS_FACADE_CASES)
    @staticmethod
    def test_canonical_alias_resolves_to_domain_facade(
        alias: str,
        facade: type,
    ) -> None:
        """Verify canonical alias resolves to domain facade."""
        tm.that(getattr(flext_ldap, alias) is facade, eq=True)

    @staticmethod
    def test_ldap_facade_is_a_service() -> None:
        """Verify ldap facade is a service."""
        # FlextLdapService is exported as the service base; the public facade
        # honouring that relationship is part of the contract.
        tm.that(FlextLdapService in FlextLdap.__mro__, eq=True)

    @pytest.mark.parametrize("operation", _FACADE_OPERATIONS)
    @staticmethod
    def test_facade_exposes_documented_operation(operation: str) -> None:
        """Verify facade exposes documented operation."""
        member = getattr(FlextLdap, operation, None)
        tm.that(member, none=False)
        tm.that(
            callable(member),
            eq=True,
            msg=f"facade operation is not callable: {operation}",
        )

    @staticmethod
    def test_global_ldap_is_public_facade_instance() -> None:
        """Verify global ldap is public facade instance."""
        tm.that(flext_ldap.ldap, is_=FlextLdap)

    @staticmethod
    def test_fetch_global_returns_shared_singleton() -> None:
        """Verify fetch global returns shared singleton."""
        # The module-level ``ldap`` is produced by ``FlextLdap.fetch_global()``;
        # repeated resolution must yield the same shared instance (idempotence).
        tm.that(FlextLdap.fetch_global() is flext_ldap.ldap, eq=True)
        tm.that(FlextLdap.fetch_global() is FlextLdap.fetch_global(), eq=True)
