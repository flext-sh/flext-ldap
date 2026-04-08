# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.unit.test_api as _tests_unit_test_api

    test_api = _tests_unit_test_api
    import tests.unit.test_base as _tests_unit_test_base

    test_base = _tests_unit_test_base
    import tests.unit.test_config as _tests_unit_test_config

    test_config = _tests_unit_test_config
    import tests.unit.test_constants as _tests_unit_test_constants

    test_constants = _tests_unit_test_constants
    import tests.unit.test_detection as _tests_unit_test_detection

    test_detection = _tests_unit_test_detection
    import tests.unit.test_entry_adapter as _tests_unit_test_entry_adapter

    test_entry_adapter = _tests_unit_test_entry_adapter
    import tests.unit.test_ldap3_adapter as _tests_unit_test_ldap3_adapter

    test_ldap3_adapter = _tests_unit_test_ldap3_adapter
    import tests.unit.test_models as _tests_unit_test_models

    test_models = _tests_unit_test_models
    import tests.unit.test_models_search as _tests_unit_test_models_search

    test_models_search = _tests_unit_test_models_search
    import tests.unit.test_models_sync as _tests_unit_test_models_sync

    test_models_sync = _tests_unit_test_models_sync
    import tests.unit.test_operations as _tests_unit_test_operations

    test_operations = _tests_unit_test_operations
    import tests.unit.test_sync as _tests_unit_test_sync

    test_sync = _tests_unit_test_sync
    import tests.unit.test_utilities as _tests_unit_test_utilities

    test_utilities = _tests_unit_test_utilities
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
_LAZY_IMPORTS = {
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_api": "tests.unit.test_api",
    "test_base": "tests.unit.test_base",
    "test_config": "tests.unit.test_config",
    "test_constants": "tests.unit.test_constants",
    "test_detection": "tests.unit.test_detection",
    "test_entry_adapter": "tests.unit.test_entry_adapter",
    "test_ldap3_adapter": "tests.unit.test_ldap3_adapter",
    "test_models": "tests.unit.test_models",
    "test_models_search": "tests.unit.test_models_search",
    "test_models_sync": "tests.unit.test_models_sync",
    "test_operations": "tests.unit.test_operations",
    "test_sync": "tests.unit.test_sync",
    "test_utilities": "tests.unit.test_utilities",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "test_api",
    "test_base",
    "test_config",
    "test_constants",
    "test_detection",
    "test_entry_adapter",
    "test_ldap3_adapter",
    "test_models",
    "test_models_search",
    "test_models_sync",
    "test_operations",
    "test_sync",
    "test_utilities",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
