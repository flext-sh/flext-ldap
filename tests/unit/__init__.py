# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.tests.unit.test_api import TestsFlextLdapApi as TestsFlextLdapApi
    from flext_ldap.tests.unit.test_base import TestsFlextLdapBase as TestsFlextLdapBase
    from flext_ldap.tests.unit.test_config import (
        TestsFlextLdapConfig as TestsFlextLdapConfig,
    )
    from flext_ldap.tests.unit.test_connection import (
        TestsFlextLdapConnection as TestsFlextLdapConnection,
    )
    from flext_ldap.tests.unit.test_constants import (
        TestsFlextLdapConstantsUnit as TestsFlextLdapConstantsUnit,
    )
    from flext_ldap.tests.unit.test_detection import (
        TestsFlextLdapDetection as TestsFlextLdapDetection,
    )
    from flext_ldap.tests.unit.test_entry_adapter import (
        TestsFlextLdapEntryAdapter as TestsFlextLdapEntryAdapter,
    )
    from flext_ldap.tests.unit.test_ldap3_adapter import (
        TestsFlextLdapLdap3Adapter as TestsFlextLdapLdap3Adapter,
    )
    from flext_ldap.tests.unit.test_ldap3_adapter_helpers import (
        TestsFlextLdapLdap3AdapterHelpers as TestsFlextLdapLdap3AdapterHelpers,
    )
    from flext_ldap.tests.unit.test_models import (
        TestsFlextLdapModelsUnit as TestsFlextLdapModelsUnit,
    )
    from flext_ldap.tests.unit.test_models_search import (
        TestsFlextLdapModelsSearch as TestsFlextLdapModelsSearch,
    )
    from flext_ldap.tests.unit.test_models_sync import (
        TestsFlextLdapModelsSync as TestsFlextLdapModelsSync,
    )
    from flext_ldap.tests.unit.test_operations import (
        TestsFlextLdapOperations as TestsFlextLdapOperations,
    )
    from flext_ldap.tests.unit.test_public_api_contract import (
        TestsFlextLdapPublicApiContract as TestsFlextLdapPublicApiContract,
    )
    from flext_ldap.tests.unit.test_sync import TestsFlextLdapSync as TestsFlextLdapSync
    from flext_ldap.tests.unit.test_utilities import (
        TestsFlextLdapUtilitiesUnit as TestsFlextLdapUtilitiesUnit,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_api": ("TestsFlextLdapApi",),
        ".test_base": ("TestsFlextLdapBase",),
        ".test_config": ("TestsFlextLdapConfig",),
        ".test_connection": ("TestsFlextLdapConnection",),
        ".test_constants": ("TestsFlextLdapConstantsUnit",),
        ".test_detection": ("TestsFlextLdapDetection",),
        ".test_entry_adapter": ("TestsFlextLdapEntryAdapter",),
        ".test_ldap3_adapter": ("TestsFlextLdapLdap3Adapter",),
        ".test_ldap3_adapter_helpers": ("TestsFlextLdapLdap3AdapterHelpers",),
        ".test_models": ("TestsFlextLdapModelsUnit",),
        ".test_models_search": ("TestsFlextLdapModelsSearch",),
        ".test_models_sync": ("TestsFlextLdapModelsSync",),
        ".test_operations": ("TestsFlextLdapOperations",),
        ".test_public_api_contract": ("TestsFlextLdapPublicApiContract",),
        ".test_sync": ("TestsFlextLdapSync",),
        ".test_utilities": ("TestsFlextLdapUtilitiesUnit",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
