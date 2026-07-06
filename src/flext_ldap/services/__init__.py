# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.services.api_runtime import FlextLdapApiRuntime
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations
    from flext_ldap.services.sync import FlextLdapSync
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".api_runtime": ("FlextLdapApiRuntime",),
        ".connection": ("FlextLdapConnection",),
        ".detection": ("FlextLdapServerDetector",),
        ".operations": ("FlextLdapOperations",),
        ".sync": ("FlextLdapSync",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)
