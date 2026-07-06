# AUTO-GENERATED FILE — Regenerate with: make gen
"""Ldap3 package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.adapters._ldap3.connection_manager import (
        ConnectionManager as ConnectionManager,
    )
    from flext_ldap.adapters._ldap3.operation_executor import (
        OperationExecutor as OperationExecutor,
    )
    from flext_ldap.adapters._ldap3.result_converter import (
        ResultConverter as ResultConverter,
    )
    from flext_ldap.adapters._ldap3.result_extract import (
        ResultConverterExtractMixin as ResultConverterExtractMixin,
    )
    from flext_ldap.adapters._ldap3.search_executor import (
        SearchExecutor as SearchExecutor,
    )
    from flext_ldap.adapters._ldap3.wrappers import (
        FlextLdapLdap3Wrappers as FlextLdapLdap3Wrappers,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".connection_manager": ("ConnectionManager",),
        ".operation_executor": ("OperationExecutor",),
        ".result_converter": ("ResultConverter",),
        ".result_extract": ("ResultConverterExtractMixin",),
        ".search_executor": ("SearchExecutor",),
        ".wrappers": ("FlextLdapLdap3Wrappers",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
