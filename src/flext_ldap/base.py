"""Base service patterns for flext-ldap services.

Defines the canonical LDAP service root used by service mixins and the API facade:
- FlextLdapService provides typed settings access via self.settings
- All services MUST inherit from this base through cooperative MRO

Settings access goes through ``self.settings`` from the service runtime.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import s
from flext_ldap import FlextLdapSettings, c, p, t
from flext_ldap.models import FlextLdapModels as m
from flext_ldap.utilities import FlextLdapUtilities as u
from flext_ldif import FlextLdif


class FlextLdapService[
    TResult: t.JsonPayload | t.SequenceOf[t.JsonPayload] = t.JsonPayload
    | t.SequenceOf[t.JsonPayload],
](s[TResult]):
    """Base class for all flext-ldap services.

    Services default to the centralized ``m.Ldap.Response`` pipeline and may
    specialize only when bridging adapter-level protocols.
    """

    _ldif: p.Ldif.LdifClient = u.PrivateAttr(default_factory=FlextLdif)
    _server_type: str = u.PrivateAttr(default_factory=lambda: c.Ldap.DEFAULT_TYPE)

    @classmethod
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services."""
        return m.RuntimeBootstrapOptions(settings_type=FlextLdapSettings)


s = FlextLdapService

__all__: list[str] = ["FlextLdapService", "s"]
