# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.adapters package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.adapters._ldap3.connection_manager import (
        FlextLdapLdap3ConnectionManager,
    )
    from flext_ldap.adapters._ldap3.operation_executor import (
        FlextLdapLdap3OperationExecutor,
    )
    from flext_ldap.adapters._ldap3.result_converter import (
        FlextLdapLdap3ResultConverter,
    )
    from flext_ldap.adapters._ldap3.result_extract import FlextLdapLdap3ResultExtract
    from flext_ldap.adapters._ldap3.search_executor import FlextLdapLdap3SearchExecutor
    from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.host import FlextLdapAdapterHost
    from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter


__all__: tuple[str, ...] = (
    "FlextLdapAdapterHost",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapLdap3ConnectionManager",
    "FlextLdapLdap3OperationExecutor",
    "FlextLdapLdap3ResultConverter",
    "FlextLdapLdap3ResultExtract",
    "FlextLdapLdap3SearchExecutor",
    "FlextLdapLdap3Wrappers",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdapAdapterHost": ".host",
        "FlextLdapEntryAdapter": ".entry",
        "FlextLdapLdap3Adapter": ".ldap3",
        "FlextLdapLdap3ConnectionManager": "._ldap3.connection_manager",
        "FlextLdapLdap3OperationExecutor": "._ldap3.operation_executor",
        "FlextLdapLdap3ResultConverter": "._ldap3.result_converter",
        "FlextLdapLdap3ResultExtract": "._ldap3.result_extract",
        "FlextLdapLdap3SearchExecutor": "._ldap3.search_executor",
        "FlextLdapLdap3Wrappers": "._ldap3.wrappers",
    }),
    public_exports=__all__,
)
