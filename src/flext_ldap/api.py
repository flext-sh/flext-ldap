"""Public API facade for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import FlextLdapConnection, FlextLdapSync
from flext_ldap.services.api_runtime import FlextLdapApiRuntime


class FlextLdap(FlextLdapConnection, FlextLdapSync, FlextLdapApiRuntime):
    """Public LDAP facade composed through cooperative MRO."""

    pass


ldap = FlextLdap.fetch_global()


__all__: list[str] = ["FlextLdap", "ldap"]
