# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.adapters. Ldap3 package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

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


__all__: tuple[str, ...] = (
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
        "FlextLdapLdap3ConnectionManager": ".connection_manager",
        "FlextLdapLdap3OperationExecutor": ".operation_executor",
        "FlextLdapLdap3ResultConverter": ".result_converter",
        "FlextLdapLdap3ResultExtract": ".result_extract",
        "FlextLdapLdap3SearchExecutor": ".search_executor",
        "FlextLdapLdap3Wrappers": ".wrappers",
    }),
    public_exports=__all__,
)
