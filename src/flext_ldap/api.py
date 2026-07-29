"""Public API facade for flext-ldap.

The package root freezes this facade as the stable user entrypoint. Public
consumers import ``FlextLdap`` or ``ldap`` from ``flext_ldap`` and reach
domain concerns through canonical aliases and namespaces, not private adapter
modules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.services.api_runtime import FlextLdapApiRuntime
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.sync import FlextLdapSync


class FlextLdap(FlextLdapConnection, FlextLdapSync, FlextLdapApiRuntime):
    """Public LDAP facade composed through cooperative MRO."""


ldap: FlextLdap = FlextLdap.fetch_global()
"""Process-wide FlextLdap facade singleton resolved from the global container."""


__all__: list[str] = ["FlextLdap", "ldap"]
