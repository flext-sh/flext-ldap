"""FlextLdap internal models package.

This package contains the actual model implementations.
The public models.py facade imports and exposes these.

NOTE: Collections is inherited from FlextModels - no custom implementation needed.
"""

from __future__ import annotations

from flext_ldap._models.ldap import FlextLdapModelsLdap

__all__ = [
    "FlextLdapModelsLdap",
]
