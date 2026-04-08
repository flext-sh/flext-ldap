# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
